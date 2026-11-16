"""
ReconMind standard pipeline.

run_plan(target, plan) runs every action in the operator's scan plan, on every
port where that action fits, in one fixed order. No model decides anything
here: the plan picks the actions and nmap's results pick the ports.

    1. nmap_scan, which also runs the Exploit-DB lookup for every port when
       Exploit Hunt is in the plan. The lookup still runs inside nmap_scan,
       but right after nmap's done event it gets its own step events (action
       "exploits", tool "searchsploit", start then done with "count", the
       number of services with matches), so Live run shows it as its own
       row. If the scan did not complete (refused, nmap missing, an error),
       the pipeline stops here.
    2. web_fingerprint on every web port            (web)
    3. web_discover on every web port               (paths)
    4. vuln_templates on every web port             (vulns)
    5. tls_check on every TLS or STARTTLS port      (crypto)
    6. smb_enum when port 139 or 445 is open        (smb)
    7. cve_lookup, after the web steps on purpose,  (cves)
       because it also reads the PHP versions httpx found
    8. attack_map, always

Every step goes through ToolBox.call, so the scope lock, the plan check and
the authorization gate inside each tool still apply. Ports come only from the
nmap results, never from the request. A step that returns an error is
recorded and the pipeline carries on with the next one.

Stopping: StopRequested subclasses BaseException, not Exception, because
ToolBox.call catches Exception and would swallow it. The CLI raises it from
its SIGTERM handler. run_plan catches it, marks the scan "stopped" with the
steps that finished and the ones that did not run (mark_stopped), and returns
the toolbox so the caller can save a partial report.

Progress goes to events.emit (see reconmind/core/events.py) and, with
trace=True, to the terminal.
"""

import json
import shlex

from reconmind.core import events as events_mod
from reconmind.tools.smb_enum import smb_ports
from reconmind.tools.testssl_scan import is_tls_capable
from reconmind.tools.web_common import is_web_service

STOPPED = "stopped"
ANALYSIS_STEP = "AI analysis"
STOPPED_WHILE_RUNNING = "{l} (stopped while running)"
NEEDS_NMAP = "{t} (needed the nmap results)"

# attack_map belongs to no action; this is its action label in events.
ATTACK_ACTION = "attack_map"

# Exploit Hunt runs inside nmap_scan, but gets its own step events right
# after nmap's done event, under this tool name.
EXPLOIT_ACTION = "exploits"
EXPLOIT_TOOL = "searchsploit"

# The web steps, in run order: (action id, tool).
WEB_STEPS = (("web", "web_fingerprint"), ("paths", "web_discover"), ("vulns", "vuln_templates"))

# Every step after nmap, in run order: (action id, tool). Used to list what
# did not run when a stop came before nmap finished.
LATER_STEPS = WEB_STEPS + (("crypto", "tls_check"), ("smb", "smb_enum"),
                           ("cves", "cve_lookup"), (ATTACK_ACTION, "attack_map"))

NO_WEB_PORT = "no open HTTP or HTTPS port"
NO_TLS_PORT = "no open TLS or STARTTLS capable port"
NO_SMB_PORT = "port 139 and port 445 are not open"
NMAP_DID_NOT_COMPLETE = "the nmap scan did not complete (status {s})"

# Where each per port tool keeps its result in the scan dict.
RESULT_KEYS = {"web_fingerprint": "web", "web_discover": "discovery",
               "vuln_templates": "nuclei", "tls_check": "tls"}

ERROR_CHARS = 300


class StopRequested(BaseException):
    """
    The operator asked the run to stop (SIGTERM from the web app's Stop).
    A BaseException on purpose: ToolBox.call catches Exception.
    """


def _say(trace, kind, text):
    """Print one line of the pipeline trace, in the same style as the agent's."""
    if trace:
        print("[{k:<7}] {t}".format(k=kind, t=text))


def step_label(step):
    """"nmap_scan", "web_fingerprint port 80" for a step dict or tuple."""
    if isinstance(step, dict):
        tool, port = step.get("tool"), step.get("port")
    else:
        tool, port = step[1], step[2]
    return tool if port is None else "{t} port {p}".format(t=tool, p=port)


def plan_steps(plan, ports):
    """
    Every step after nmap_scan for these open ports, in run order, as
    (action id, tool, port, skip reason). port is None for a tool that takes
    no port. skip reason is None for a step that runs, or says why a selected
    action has nothing to run on. Actions outside the plan are left out.
    """
    ports = ports or []
    steps = []
    web = [p.get("port") for p in ports if is_web_service(p)]
    for action, tool in WEB_STEPS:
        if not plan.has(action):
            continue
        if web:
            steps.extend((action, tool, number, None) for number in web)
        else:
            steps.append((action, tool, None, NO_WEB_PORT))
    if plan.has("crypto"):
        tls = [p.get("port") for p in ports if is_tls_capable(p)]
        if tls:
            steps.extend(("crypto", "tls_check", number, None) for number in tls)
        else:
            steps.append(("crypto", "tls_check", None, NO_TLS_PORT))
    if plan.has("smb"):
        steps.append(("smb", "smb_enum", None, None if smb_ports(ports) else NO_SMB_PORT))
    if plan.has("cves"):
        steps.append(("cves", "cve_lookup", None, None))
    steps.append((ATTACK_ACTION, "attack_map", None, None))
    return steps


def _commands(scan, tool, port):
    """The exact command line(s) a tool ran, from its stored result."""
    if tool == "nmap_scan":
        values = (scan.get("scan_info") or {}).get("commands") or []
    elif tool == "smb_enum":
        smb = scan.get("smb")
        values = [smb.get("command")] if isinstance(smb, dict) else []
    elif tool in RESULT_KEYS:
        results = scan.get(RESULT_KEYS[tool])
        result = results.get(port) if isinstance(results, dict) else None
        values = [result.get("command")] if isinstance(result, dict) else []
    else:
        values = []
    found = []
    for value in values:
        if isinstance(value, (list, tuple)):
            value = shlex.join(str(v) for v in value)
        if value:
            found.append(str(value))
    return found


def _error_text(observation):
    """The short error message from a ToolBox error observation."""
    try:
        text = json.loads(observation).get("error") or ""
    except (TypeError, ValueError, AttributeError):
        text = str(observation)
    text = " ".join(str(text).split())
    return text if len(text) <= ERROR_CHARS else text[:ERROR_CHARS] + " ..."


class _Run:
    """One pipeline run: the toolbox, where events go, and the step in progress."""

    def __init__(self, toolbox, plan, emit, trace):
        self.toolbox = toolbox
        self.plan = plan
        self.emit = emit
        self.trace = trace
        self.current = None

    def step(self, action, tool, port, args):
        """Run one tool through ToolBox.call and record how it ended."""
        step = {"action": action, "tool": tool, "port": port}
        label = step_label(step)
        self.current = step
        self.emit("step", status="start", **step)
        _say(self.trace, "RUN", label)
        observation, is_error = self.toolbox.call(tool, args)
        for command in _commands(self.toolbox.scan, tool, port):
            self.emit("command", tool=tool, port=port, command=command)
        if is_error:
            message = _error_text(observation)
            self.toolbox.steps.append(dict(step, status="error", message=message))
            self.emit("step", status="error", message=message, **step)
            _say(self.trace, "ERROR", "{l}: {m}".format(l=label, m=message))
        else:
            self.toolbox.steps.append(dict(step, status="done"))
            self.emit("step", status="done", **step)
            _say(self.trace, "DONE", label)
        self.current = None
        return not is_error

    def skip(self, action, tool, port, reason):
        self.emit("step", action=action, tool=tool, port=port, status="skipped", reason=reason)
        _say(self.trace, "SKIP", "{t}: {r}".format(t=tool, r=reason))

    def exploit_hunt(self, ports):
        """
        Report Exploit Hunt as its own step. The lookup itself already ran
        inside nmap_scan, so this only emits the start and done events, with
        the number of services that had at least one Exploit-DB match.
        """
        step = {"action": EXPLOIT_ACTION, "tool": EXPLOIT_TOOL, "port": None}
        self.emit("step", status="start", **step)
        count = sum(1 for p in ports if isinstance(p, dict) and p.get("exploits"))
        self.emit("step", status="done", count=count, **step)
        _say(self.trace, "DONE", "{t}: matches on {n} service(s)".format(t=EXPLOIT_TOOL, n=count))

    def run(self, target):
        self.step("surface", "nmap_scan", None, {"target": target})
        scan = self.toolbox.scan
        if scan.get("status") != "ok":
            reason = NMAP_DID_NOT_COMPLETE.format(s=scan.get("status") or "unknown")
            if self.plan.has(EXPLOIT_ACTION):
                self.skip(EXPLOIT_ACTION, EXPLOIT_TOOL, None, reason)
            for action, tool in LATER_STEPS:
                if action == ATTACK_ACTION or self.plan.has(action):
                    self.skip(action, tool, None, reason)
            return

        ports = scan.get("ports") or []
        if self.plan.has(EXPLOIT_ACTION):
            self.exploit_hunt(ports)
        self.emit("ports", ports=[{"port": p.get("port"), "service": p.get("service", ""),
                                   "product": p.get("product", ""),
                                   "version": p.get("version", "")} for p in ports])
        # Ports come from nmap's results only, never from the request.
        for action, tool, port, reason in plan_steps(self.plan, ports):
            if reason:
                self.skip(action, tool, port, reason)
            else:
                self.step(action, tool, port, {} if port is None else {"port": port})


def not_run_steps(toolbox, plan, current=None):
    """
    Labels of the steps that did not run, in run order. current is the step
    that was running when the stop came; it is marked as stopped while
    running.
    """
    scan = toolbox.scan
    done = {(s.get("tool"), s.get("port")) for s in getattr(toolbox, "steps", [])}
    current_key = (current.get("tool"), current.get("port")) if current else None

    def label(key, text):
        return STOPPED_WHILE_RUNNING.format(l=text) if key == current_key else text

    if ("nmap_scan", None) not in done or scan.get("status") != "ok":
        labels = [label(("nmap_scan", None), "nmap_scan")]
        for action, tool in LATER_STEPS:
            if action == ATTACK_ACTION or plan.has(action):
                labels.append(NEEDS_NMAP.format(t=tool))
        return labels
    labels = []
    for action, tool, port, reason in plan_steps(plan, scan.get("ports") or []):
        key = (tool, port)
        if reason is None and key not in done:
            labels.append(label(key, step_label((action, tool, port))))
    return labels


def finished_steps(toolbox):
    """Labels of the steps that finished, with "(error)" on the ones that failed."""
    labels = []
    for s in getattr(toolbox, "steps", []):
        text = step_label(s)
        if s.get("status") == "error":
            text += " (error)"
        labels.append(text)
    return labels


def mark_stopped(toolbox, plan, current=None, not_run=None):
    """
    Mark the toolbox's scan as stopped: status "stopped" and a "stop" entry
    listing the steps that finished and the steps that did not run. not_run
    replaces the computed list (the runner uses it when the stop came during
    the AI analysis). Returns the scan.
    """
    if not_run is None:
        not_run = not_run_steps(toolbox, plan, current)
    scan = toolbox.scan
    scan["stop"] = {"finished": finished_steps(toolbox), "not_run": list(not_run)}
    scan["status"] = STOPPED
    return scan


def run_plan(target, plan, toolbox=None, events=None, mode=None, trace=True):
    """
    Run the plan's actions in the fixed order above and return the toolbox;
    toolbox.scan holds every result and toolbox.steps how each step ended.

    toolbox defaults to a new ToolBox for target and plan. events replaces
    events.emit (tests pass a recorder). mode ("standard" or "ai") only goes
    into the "plan" event. On StopRequested the scan is marked stopped (see
    mark_stopped) and the toolbox is returned; nothing else is raised.
    """
    emit = events or events_mod.emit
    if toolbox is None:
        # Imported here so this module never loads the tool runners on its own.
        from reconmind.agent.tools import ToolBox
        toolbox = ToolBox(target, plan=plan)
    if getattr(toolbox, "steps", None) is None:
        toolbox.steps = []

    emit("plan", target=str(target), preset=plan.preset, ports=plan.ports,
         actions=list(plan.actions), mode=mode)
    run = _Run(toolbox, plan, emit, trace)
    try:
        run.run(str(target).strip())
    except StopRequested:
        scan = mark_stopped(toolbox, plan, current=run.current)
        emit("stopped", finished=scan["stop"]["finished"], not_run=scan["stop"]["not_run"])
        _say(trace, "STOP", "stop requested, {n} step(s) did not run".format(
            n=len(scan["stop"]["not_run"])))
    return toolbox
