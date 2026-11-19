"""
MORVAIN-X0: the AI agent mode.

The agent plans; the operator approves; the existing pipeline runs.

    1. Surface: Surface Map and Exploit Hunt (the Quick preset's checks) on
       the one authorized target.
    2. Plan: the model reads the stored results and proposes a numbered plan,
       choosing only from the remaining checks of scan_plan.ACTIONS, each with
       a reason grounded in what was found. If the model cannot be reached or
       answers with nothing usable, a fixed rule plan is used and the operator
       is told so.
    3. Approval: nothing runs until the operator approves the plan (unticked
       steps are skipped), redirects it with a message, or finishes. Check ins
       are per plan, never per tool. Each plan comes with a short brief of the
       riskiest things found so far, built from the tool results by fixed
       rules. While it waits, the operator can also ask questions: answers
       come from the results and the plan only, and asking never runs,
       changes or approves anything.
    4. Run: approved checks go through the same pipeline steps and
       ToolBox.call as every scan, so the authorization gate inside each tool
       and the single target scope lock still apply. Approval never bypasses
       them, and the agent has no way to name another target or port.
    5. Repeat with a follow up plan (failed steps can be retried), then the
       usual AI analysis writes the report.

Decisions arrive as a small JSON file the web app writes (RECONMIND_AGENT_INBOX);
progress leaves through events.emit as "agent" events. A stop (SIGTERM) works
at any point, also while waiting for approval, and saves a partial report.
"""

import ipaddress
import json
import os
import re
import time

from reconmind.core import config as scope
from reconmind.core import events as events_mod
from reconmind.core.pipeline import _Run, plan_steps, run_plan
from reconmind.core.scan_plan import ACTIONS, ACTIONS_BY_ID, build_plan
from reconmind.tools.nuclei_scan import severity_rank as nuclei_rank
from reconmind.tools.risky_services import SEVERITY_ORDER, flag_ports
from reconmind.tools.smb_enum import smb_ports
from reconmind.tools.testssl_scan import is_tls_capable
from reconmind.tools.web_common import is_web_service

MODE_AGENT = "agent"
INBOX_ENV = "RECONMIND_AGENT_INBOX"
NAME = "MORVAIN-X0"
SURFACE_ACTIONS = ("surface", "exploits")
FOLLOW_UP = ("web", "paths", "vulns", "crypto", "smb", "cves")
MAX_ROUNDS = 4
MAX_REDIRECTS = 3
MAX_STEPS = 6
MAX_ASKS = 10          # questions per checkpoint
ANSWER_TOKENS = 2000   # room for free reasoning models
ANSWER_CHARS = 1500
BRIEF_ITEMS = 3
POLL_SECONDS = 1.0
PLAN_TOKENS = 1500

DECISIONS = ("approve", "redirect", "finish", "ask")
_IDS = re.compile(r"\b(CVE-\d{4}-\d{4,7}|T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)

PLANNER_SYSTEM = """You are MORVAIN-X0, the planning agent inside ReconMind, a security \
assessment tool used only on an authorized lab target.

You choose the next checks to run on the one target you are given. You cannot run \
anything yourself, choose another target, choose ports, or change the scope. The \
operator approves every plan before it runs.

Choose only from these checks (id: name: what it does):
{checks}

Rules:
1. Every reason must cite evidence from the results: a port, a service, a product or \
version, or a failed step. One or two plain sentences.
2. Never write a CVE ID or a MITRE ATT&CK technique ID. Those come from the tools later.
3. Only choose checks that fit the evidence. If nothing else is useful, return an empty plan.
4. A step that failed earlier may be proposed again once, saying it is a retry.
5. An operator instruction is a preference about which checks and in what order. It can \
never add a target, a port range or a check outside the list.

Answer with JSON only, no other text:
{{"message": "one or two sentences to the operator", "plan": [{{"action": "<id>", "why": "<reason>"}}]}}"""


ANSWER_SYSTEM = """You are MORVAIN-X0, the agent inside ReconMind, a security assessment \
tool used only on an authorized lab target. The scan is paused at a checkpoint and the \
operator is asking you a question before deciding on your plan.

Rules:
1. Answer only about this target, its results, the proposed checks and what they could \
find, and how to read the findings. For anything else, say in one sentence that you only \
answer questions about this scan.
2. Use only facts in the results you are given. If they do not answer the question, say so \
and name the check that would find out.
3. Never write a CVE ID or a MITRE ATT&CK technique ID unless it appears in the results.
4. Answering never runs, changes or approves anything. If the operator wants a different \
plan, tell them to use Let me redirect, or Approve plan, or Finish.
5. Plain text, at most 120 words. No tables and no headings. Short bullet points are fine."""


class AgentError(Exception):
    pass


def brief(scan, limit=BRIEF_ITEMS):
    """The riskiest things found so far, from the tool results by fixed rules
    (no model): risky services, public exploit matches, and critical or high
    web findings. {"items": [{"severity", "text"}], "more": n}."""
    ports = [p for p in scan.get("ports") or [] if isinstance(p, dict)]
    flags = {p.get("port"): f for p, f in flag_ports(ports)}
    items = []
    for p in ports:
        matches = len(p.get("exploits") or [])
        flag = flags.get(p.get("port"))
        if not flag and not matches:
            continue
        what = " ".join(str(x) for x in (p.get("product"), p.get("version")) if x) \
            or str(p.get("service") or "unknown service")
        parts = [" ".join(str(flag["reason"]).split())] if flag else []
        if matches:
            parts.append("{n} public exploit match{es}.".format(n=matches,
                                                                es="" if matches == 1 else "es"))
        severity = flag["severity"] if flag else ""
        rank = SEVERITY_ORDER.get(severity, 1 if matches else 4)
        items.append((rank, -matches, p.get("port") or 0, severity,
                      "Port {n} ({w}): {t}".format(n=p.get("port"), w=what, t=" ".join(parts))))
    for port, result in (scan.get("nuclei") or {}).items():
        if not isinstance(result, dict):
            continue
        for f in result.get("findings") or []:
            severity = str(f.get("severity") or "").lower()
            if severity in ("critical", "high"):
                items.append((nuclei_rank(severity), 0, int(port) if str(port).isdigit() else 0,
                              severity, "Port {n}: {t}, a {s} web finding.".format(
                                  n=port, t=f.get("name") or f.get("template_id") or "finding",
                                  s=severity)))
    items.sort(key=lambda x: x[:3])
    return {"items": [{"severity": sev, "text": text} for _, _, _, sev, text in items[:limit]],
            "more": max(0, len(items) - limit)}


def model_answer(client, model, scan, steps, done, round_number, plan, question, history=()):
    """Answer one operator question at a checkpoint, from the results only."""
    content = ("Results so far:\n" + json.dumps(facts(scan, steps, done, round_number), indent=1)
               + "\n\nRiskiest so far:\n" + json.dumps(brief(scan)["items"], indent=1)
               + "\n\nYour proposed plan:\n" + json.dumps(
                   [{"check": s.get("name"), "why": s.get("why")} for s in plan], indent=1))
    if history:
        content += "\n\nEarlier questions at this checkpoint:\n" + json.dumps(list(history), indent=1)
    content += "\n\nOperator question:\n" + json.dumps(question[:500])
    response = client.messages.create(
        model=model, max_tokens=ANSWER_TOKENS, system=ANSWER_SYSTEM,
        messages=[{"role": "user", "content": content}])
    text = "\n".join(getattr(b, "text", "") for b in response.content
                     if getattr(b, "type", "") == "text").strip()
    if not text:
        raise AgentError("the model returned no answer")
    if len(text) > ANSWER_CHARS:
        text = text[:ANSWER_CHARS].rsplit(" ", 1)[0] + "..."
    return scrub_ids(text, scan)


# ---- facts ---------------------------------------------------------------

def lab_network(target):
    """The allowed network the target sits in, for the opening message."""
    try:
        address = ipaddress.ip_address(str(target))
    except ValueError:
        return None
    for net in scope.ALLOWLIST:
        try:
            if address in ipaddress.ip_network(net, strict=False):
                return str(net)
        except ValueError:
            continue
    return None


def port_facts(scan):
    out = []
    for p in scan.get("ports") or []:
        if not isinstance(p, dict):
            continue
        out.append({"port": p.get("port"), "service": p.get("service", ""),
                    "product": p.get("product", ""), "version": p.get("version", ""),
                    "exploit_matches": len(p.get("exploits") or [])})
    return out


def facts(scan, steps, done, round_number):
    failed = [{"tool": s.get("tool"), "port": s.get("port"), "message": s.get("message", "")}
              for s in steps or [] if s.get("status") == "error"]
    return {"target": scan.get("target"), "round": round_number,
            "open_ports": port_facts(scan), "checks_already_run": sorted(done),
            "failed_steps": failed,
            "results_stored": sorted(k for k in ("web", "discovery", "nuclei", "tls", "smb",
                                                  "nvd") if scan.get(k))}


def scrub_ids(text, scan):
    """Drop any CVE or ATT&CK ID the tools did not produce, so the agent can
    never present an invented ID as a finding."""
    known = json.dumps(scan, default=str).upper()

    def keep(match):
        return match.group(0) if match.group(0).upper() in known else "[ID removed]"
    return _IDS.sub(keep, str(text))


# ---- planning ------------------------------------------------------------

def remaining(done, failed_actions=()):
    """Checks that may still be proposed: not run yet, or failed once."""
    return [a for a in FOLLOW_UP if a not in done or a in failed_actions]


def rule_plan(scan, done, failed_actions=()):
    """A fixed plan from the open ports, used when the model is unavailable."""
    ports = [p for p in scan.get("ports") or [] if isinstance(p, dict)]
    allowed = set(remaining(done, failed_actions))
    web = [p.get("port") for p in ports if is_web_service(p)]
    tls = [p.get("port") for p in ports if is_tls_capable(p)]
    versioned = [p for p in ports if p.get("product") and p.get("version")]
    steps = []

    def add(action, why):
        if action in allowed:
            retry = action in failed_actions and action in done
            steps.append({"action": action, "why": ("Retry: " if retry else "") + why})

    if web:
        listed = ", ".join(str(n) for n in web[:6])
        add("web", "Web ports {p} are open, so the technology behind them is worth "
                   "identifying.".format(p=listed))
        add("paths", "Hidden files and folders on ports {p} can expose admin pages or "
                     "backups.".format(p=listed))
        add("vulns", "Safe nuclei templates can confirm known web issues on ports "
                     "{p}.".format(p=listed))
    if tls:
        add("crypto", "Ports {p} speak TLS, so the protocol and cipher setup should be "
                      "checked.".format(p=", ".join(str(n) for n in tls[:6])))
    if smb_ports(ports):
        add("smb", "Port 139 or 445 is open, so anonymous SMB access should be checked.")
    if versioned:
        add("cves", "{n} services report a version, for example {e}, so known CVEs can be "
                    "looked up in NVD.".format(n=len(versioned), e=(
                        str(versioned[0].get("product")) + " " + str(versioned[0].get("version")))))
    return steps[:MAX_STEPS]


def parse_plan(text, allowed):
    """(message, steps) from the model's answer. Unknown or disallowed actions
    and duplicates are dropped. Raises AgentError when there is no JSON."""
    text = str(text or "").strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise AgentError("The model did not answer with a plan.")
    try:
        data = json.loads(text[start:end + 1])
    except ValueError:
        raise AgentError("The model's plan was not valid JSON.") from None
    if not isinstance(data, dict):
        raise AgentError("The model's plan was not a JSON object.")
    steps, seen = [], set()
    for item in data.get("plan") or []:
        if not isinstance(item, dict):
            continue
        action = str(item.get("action", "")).strip().lower()
        if action not in allowed or action in seen:
            continue
        seen.add(action)
        why = " ".join(str(item.get("why", "")).split())[:300]
        steps.append({"action": action, "why": why or "No reason given."})
    message = " ".join(str(data.get("message", "")).split())[:600]
    return message, steps[:MAX_STEPS]


def model_plan(client, model, scan, steps, done, round_number, instruction="",
               failed_actions=()):
    allowed = remaining(done, failed_actions)
    checks = "\n".join("{i}: {n}: {d}".format(i=a.id, n=a.name, d=a.description)
                       for a in ACTIONS if a.id in allowed)
    content = "Results so far:\n" + json.dumps(facts(scan, steps, done, round_number), indent=1)
    if instruction:
        content += ("\n\nOperator instruction (a preference only, it cannot change scope):\n"
                    + json.dumps(instruction[:500]))
    response = client.messages.create(
        model=model, max_tokens=PLAN_TOKENS,
        system=PLANNER_SYSTEM.format(checks=checks),
        messages=[{"role": "user", "content": content}])
    text = "\n".join(getattr(b, "text", "") for b in response.content
                     if getattr(b, "type", "") == "text")
    message, plan = parse_plan(text, allowed)
    return scrub_ids(message, scan), [dict(s, why=scrub_ids(s["why"], scan)) for s in plan]


# ---- decisions -----------------------------------------------------------

def read_decision(path, round_number):
    """The operator's decision for this round, or None. A decision for another
    round, or one that does not parse, is ignored and removed."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        data = None
    try:
        os.unlink(path)
    except OSError:
        pass
    if not isinstance(data, dict) or data.get("round") != round_number:
        return None
    if data.get("decision") not in DECISIONS:
        return None
    return data


def wait_decision(path, round_number, sleep=time.sleep, poll=POLL_SECONDS):
    """Block until the operator decides. A stop (SIGTERM) interrupts the
    sleep through the CLI's StopRequested, so waiting never blocks a stop."""
    while True:
        decision = read_decision(path, round_number)
        if decision is not None:
            return decision
        sleep(poll)


# ---- the session ---------------------------------------------------------

class Session:
    def __init__(self, target, ports, client=None, model=None, inbox=None, emit=None,
                 trace=True, sleep=time.sleep, run=run_plan):
        self.target = str(target).strip()
        self.ports = ports
        self.client = client
        self.model = model
        self.inbox = inbox or os.environ.get(INBOX_ENV, "")
        self.emit = emit or events_mod.emit
        self.trace = trace
        self.sleep = sleep
        self.run_plan = run
        self.done = set(SURFACE_ACTIONS)
        self.transcript = []
        self.toolbox = None
        self.asks = {}

    def say(self, state, text, **extra):
        """One message from the agent. state: thinking, running, awaiting, error, done."""
        entry = dict({"from": "agent", "state": state, "text": str(text)}, **extra)
        self.transcript.append(entry)
        self.emit("agent", **entry)
        if self.trace:
            print("[MORVAIN] {s}: {t}".format(s=state, t=text))

    def operator(self, text, decision, actions=()):
        entry = {"from": "operator", "text": str(text)[:500], "decision": decision,
                 "actions": list(actions)}
        self.transcript.append(entry)
        self.emit("agent", **entry)

    def plan(self):
        """The cumulative plan: every check approved so far."""
        actions = [a.id for a in ACTIONS if a.id in self.done]
        return build_plan(self.target, preset="standard", ports=self.ports, actions=actions)

    def surface(self):
        network = lab_network(self.target)
        self.say("running", "Connected to {t}. The authorization gate cleared it{n}. Starting "
                 "with a surface map and an exploit lookup so I can see what is exposed."
                 .format(t=self.target, n=", it is inside " + network if network else ""))
        surface_plan = build_plan(self.target, preset="quick", ports=self.ports)
        self.toolbox = self.run_plan(self.target, surface_plan, events=self.emit, mode=MODE_AGENT,
                                     trace=self.trace)
        return self.toolbox

    def propose(self, round_number, instruction=""):
        scan, steps = self.toolbox.scan, getattr(self.toolbox, "steps", [])
        failed = {self._action_of(s) for s in steps if s.get("status") == "error"}
        self.say("thinking", "Reading the results and working out the next checks.")
        source = "model"
        try:
            if self.client is None:
                raise AgentError("no AI model is configured")
            message, plan = model_plan(self.client, self.model, scan, steps, self.done,
                                       round_number, instruction, failed)
            if not plan and round_number == 1 and rule_plan(scan, self.done, failed):
                raise AgentError("the model proposed nothing although checks fit the results")
        except BaseException as exc:
            if not isinstance(exc, Exception):
                raise  # a stop, never swallowed
            source = "rules"
            plan = rule_plan(scan, self.done, failed)
            message = ("I could not get a plan from the AI model ({e}), so this plan comes "
                       "from fixed rules based on the open ports.".format(e=_short(exc)))
            self.say("error", message)
            message = "Here is the rule based plan."
        return source, message, plan

    @staticmethod
    def _action_of(step):
        for action in ACTIONS:
            if step.get("tool") in action.tools:
                return action.id
        return None

    def run_checks(self, actions):
        names = ", ".join(ACTIONS_BY_ID[a].name for a in actions)
        self.say("running", "Running " + names + ".")
        self.done.update(actions)
        # The toolbox allows exactly the checks approved so far.
        self.toolbox.plan = self.plan()
        # Live run lists a row per check in the plan, so it hears the new one.
        self.emit("plan", target=self.target, preset=self.toolbox.plan.preset,
                  ports=self.toolbox.plan.ports, actions=list(self.toolbox.plan.actions),
                  mode=MODE_AGENT)
        round_plan = build_plan(self.target, preset="standard", ports=self.ports,
                                actions=list(actions))
        before = len(self.toolbox.steps)
        run = _Run(self.toolbox, round_plan, self.emit, self.trace)
        for action, tool, port, reason in plan_steps(round_plan, self.toolbox.scan.get("ports")):
            if reason:
                run.skip(action, tool, port, reason)
            else:
                run.step(action, tool, port, {} if port is None else {"port": port})
        failed = [s for s in self.toolbox.steps[before:] if s.get("status") == "error"]
        if failed:
            lines = "; ".join("{t}{p}: {m}".format(
                t=s.get("tool"), p=" port " + str(s["port"]) if s.get("port") else "",
                m=_short(s.get("message", ""), 160)) for s in failed[:4])
            self.say("error", "{n} step{s} failed: {l}. I can propose a retry in the "
                     "next plan, or you can skip it.".format(
                         n=len(failed), s="" if len(failed) == 1 else "s", l=lines),
                     failed=[{"tool": s.get("tool"), "port": s.get("port")} for s in failed])
        return failed

    def run(self):
        """Surface, then plan and approval rounds. Returns the toolbox; the
        transcript is stored in toolbox.scan["agent"]."""
        self.surface()
        scan = self.toolbox.scan
        if scan.get("status") != "ok":
            self.say("error", "The surface map did not complete (status {s}), so there is "
                     "nothing to plan from. The report keeps what was found.".format(
                         s=scan.get("status")))
            return self._finish()
        open_ports = port_facts(scan)
        risky = [p for p in open_ports if p["exploit_matches"]]
        self.say("thinking", "I found {n} open port{s}{r}.".format(
            n=len(open_ports), s="" if len(open_ports) == 1 else "s",
            r=", {k} with public exploit matches".format(k=len(risky)) if risky else ""))
        for round_number in range(1, MAX_ROUNDS + 1):
            instruction = ""
            for _ in range(MAX_REDIRECTS + 1):
                source, message, plan = self.propose(round_number, instruction)
                if not plan:
                    self.say("done", (message + " " if message and source == "model" else "")
                             + "There is nothing else worth running. Writing the report.")
                    return self._finish()
                steps = [{"n": i, "action": s["action"], "name": ACTIONS_BY_ID[s["action"]].name,
                          "why": s["why"]} for i, s in enumerate(plan, 1)]
                self.say("awaiting", message or "Here is my plan.", round=round_number,
                         plan=steps, source=source, brief=brief(self.toolbox.scan))
                decision = self.checkpoint(round_number, steps)
                kind = decision["decision"]
                if kind == "redirect":
                    instruction = " ".join(str(decision.get("message", "")).split())[:500]
                    self.operator(instruction or "Redirect.", "redirect")
                    continue
                break
            else:
                self.say("done", "We went back and forth several times, so I will stop here "
                         "and write the report with what we have.")
                return self._finish()
            if kind == "finish":
                self.operator("Finish with what we have.", "finish")
                self.say("done", "Understood. Writing the report with what we have.")
                return self._finish()
            proposed = [s["action"] for s in steps]
            chosen = [a for a in decision.get("actions") or [] if a in proposed]
            skipped = [a for a in proposed if a not in chosen]
            self.operator("Approved: " + (", ".join(ACTIONS_BY_ID[a].name for a in chosen)
                                          or "nothing") + (
                ". Skipped: " + ", ".join(ACTIONS_BY_ID[a].name for a in skipped)
                if skipped else "") + ".", "approve", chosen)
            if not chosen:
                self.say("done", "Nothing approved, so I will write the report with what we have.")
                return self._finish()
            self.run_checks(chosen)
        self.say("done", "That was the last planning round. Writing the report.")
        return self._finish()

    def checkpoint(self, round_number, steps):
        """Wait for the operator's decision on this plan. Questions are
        answered here and the plan stays open; only approve, redirect or
        finish moves the session on."""
        while True:
            decision = wait_decision(self.inbox, round_number, sleep=self.sleep)
            if decision["decision"] != "ask":
                return decision
            self.answer(round_number, steps, decision)

    def answer(self, round_number, steps, decision):
        question = " ".join(str(decision.get("message", "")).split())[:500]
        proposed = {s["action"]: s for s in steps}
        step = next((proposed[a] for a in decision.get("actions") or [] if a in proposed), None)
        if not question and step:
            question = "Tell me more about " + step["name"] + "."
        if not question:
            return
        self.operator(question, "ask", [step["action"]] if step else [])
        self.asks[round_number] = asked = self.asks.get(round_number, 0) + 1
        if asked > MAX_ASKS:
            self.say("answer", "That is {n} questions at this checkpoint, the limit. Approve, "
                     "redirect or finish to move on.".format(n=MAX_ASKS), round=round_number)
            return
        history = [{"q": e["text"], "a": n["text"]} for e, n in zip(self.transcript, self.transcript[1:])
                   if e.get("decision") == "ask" and n.get("state") == "answer"
                   and n.get("round") == round_number][-4:]
        scan, done_steps = self.toolbox.scan, getattr(self.toolbox, "steps", [])
        try:
            if self.client is None:
                raise AgentError("no AI model is configured")
            text = model_answer(self.client, self.model, scan, done_steps, self.done,
                                round_number, steps, question, history)
        except BaseException as exc:
            if not isinstance(exc, Exception):
                raise  # a stop, never swallowed
            if step:
                action = ACTIONS_BY_ID[step["action"]]
                text = ("{n}: {d} Why it is in the plan: {w} (The AI model could not answer, "
                        "so this comes from the check's description.)".format(
                            n=action.name, d=action.description.rstrip(".") + ".", w=step["why"]))
            else:
                text = ("I could not reach the AI model to answer that ({e}). The results and "
                        "the plan are unchanged, so you can still approve, redirect or "
                        "finish.".format(e=_short(exc)))
        self.say("answer", text, round=round_number)

    def _finish(self):
        self.toolbox.plan = self.plan()
        self.toolbox.scan["agent"] = {"name": NAME, "transcript": self.transcript,
                                      "checks": [a.id for a in ACTIONS if a.id in self.done]}
        return self.toolbox


def _short(value, limit=200):
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[:limit] + "..."
