"""
ReconMind scan plans.

A scan plan says what one agent run does: the target, which ports nmap scans,
which actions run and how nuclei picks its templates. The operator picks a
preset (quick, standard or full) and can override the ports and the actions.

A plan is plain data and never runs anything. Its safety job is the ports
spec: parse_ports accepts only "top", "all" or port numbers and ranges, and
rebuilds the list from integers, so what the operator typed can never put an
option or shell text on the nmap command line. run_nmap checks the spec again
after the authorization gate, before it builds the command.
"""

import re
from collections import namedtuple
from dataclasses import dataclass

# One selectable piece of a scan. tools are the agent tools it enables.
Action = namedtuple("Action", "id name description tools")

ACTIONS = (
    Action("surface", "Surface Map",
           "Find open ports and identify the service and version on each with nmap. "
           "Always on.",
           ("nmap_scan",)),
    Action("exploits", "Exploit Hunt",
           "Match each service version to public exploits in Exploit-DB and flag "
           "services that are risky just by being exposed.",
           ("exploit_lookup",)),
    Action("cves", "CVE Intel",
           "Look up known CVEs for each versioned product in the NVD database.",
           ("cve_lookup",)),
    Action("web", "Web Fingerprint",
           "Identify the technology behind each web port with whatweb.",
           ("web_fingerprint",)),
    Action("paths", "Hidden Paths",
           "Find hidden files and folders on each web port with ffuf.",
           ("web_discover",)),
    Action("vulns", "Vuln Probe",
           "Run safe nuclei templates against each web port.",
           ("vuln_templates",)),
    Action("crypto", "Crypto Check",
           "Check the TLS setup of each TLS or STARTTLS port with testssl.sh.",
           ("tls_check",)),
    Action("smb", "SMB Recon",
           "Enumerate SMB anonymously with enum4linux-ng when port 139 or 445 is open.",
           ("smb_enum",)),
)
ACTIONS_BY_ID = {a.id: a for a in ACTIONS}
ACTION_IDS = tuple(a.id for a in ACTIONS)
ALWAYS_ON = "surface"
# Agent tool name to the action that enables it.
TOOL_ACTIONS = {tool: a.id for a in ACTIONS for tool in a.tools}

PORTS_TOP = "top"
PORTS_ALL = "all"
MAX_PORT_ENTRIES = 100
MAX_PORTS_SPEC_LENGTH = 1000
# ASCII digits only: \d would also accept other scripts' digits.
_PORT_LIST = re.compile(r"[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*")
PORTS_HELP = ('Use "top" (nmap\'s default top 1000 ports), "all" (every TCP port), or '
              'port numbers and ranges separated by commas with no spaces, such as '
              '21,22,80,8000-8100.')

VULN_MODE_AUTO = "auto"
VULN_MODE_DEEP = "deep"
VULN_MODES = (VULN_MODE_AUTO, VULN_MODE_DEEP)
VULN_MODE_TEXT = {
    VULN_MODE_AUTO: "auto (nuclei picks templates for the detected technology)",
    VULN_MODE_DEEP: "deep (every safe template)",
}

Preset = namedtuple("Preset", "name actions ports vuln_mode")
PRESETS = {
    "quick": Preset("quick", ("surface", "exploits", "cves"), PORTS_TOP, VULN_MODE_AUTO),
    "standard": Preset("standard", ACTION_IDS, PORTS_TOP, VULN_MODE_AUTO),
    "full": Preset("full", ACTION_IDS, PORTS_ALL, VULN_MODE_DEEP),
}
DEFAULT_PRESET = "standard"


class PlanError(ValueError):
    """The scan plan is not valid. The message says why."""


class PortsSpecError(PlanError):
    """The ports spec is not valid. The message says why."""


def parse_ports(spec):
    """
    Return the normalized ports spec: "top", "all", or a list such as
    "21,22,80,8000-8100" rebuilt from integers. Raise PortsSpecError for
    anything else: other characters, a port outside 1 to 65535, a range that
    starts above its end, or more than MAX_PORT_ENTRIES entries.
    """
    if not isinstance(spec, str):
        raise PortsSpecError("The ports spec must be text. " + PORTS_HELP)
    text = spec.strip()
    if text.lower() in (PORTS_TOP, PORTS_ALL):
        return text.lower()
    if not text:
        raise PortsSpecError("The ports spec is empty. " + PORTS_HELP)
    if len(text) > MAX_PORTS_SPEC_LENGTH or not _PORT_LIST.fullmatch(text):
        raise PortsSpecError("Ports spec {s!r} is not valid. {h}".format(s=text, h=PORTS_HELP))

    entries = text.split(",")
    if len(entries) > MAX_PORT_ENTRIES:
        raise PortsSpecError("Ports spec has {n} entries; at most {m} are allowed.".format(
            n=len(entries), m=MAX_PORT_ENTRIES))
    normalized = []
    for entry in entries:
        start, _, end = entry.partition("-")
        first = int(start)
        last = int(end) if end else first
        for number in (first, last):
            if not 1 <= number <= 65535:
                raise PortsSpecError("Port {n} in {s!r} is out of range. Ports must be "
                                     "1 to 65535.".format(n=number, s=text))
        if first > last:
            raise PortsSpecError("Range {e} starts above where it ends.".format(e=entry))
        normalized.append("{a}-{b}".format(a=first, b=last) if end else str(first))
    return ",".join(normalized)


def port_count(spec):
    """How many ports an explicit list covers. None for "top" and "all"."""
    spec = parse_ports(spec)
    if spec in (PORTS_TOP, PORTS_ALL):
        return None
    total = 0
    for entry in spec.split(","):
        start, _, end = entry.partition("-")
        total += (int(end) if end else int(start)) - int(start) + 1
    return total


def parse_actions(actions):
    """
    Normalize action ids, given as a list or as comma separated text, into a
    tuple in ACTIONS order. surface is always added. Raise PlanError for an
    unknown id.
    """
    items = actions.split(",") if isinstance(actions, str) else list(actions)
    chosen = {ALWAYS_ON}
    for item in items:
        name = str(item).strip().lower()
        if not name:
            continue
        if name not in ACTIONS_BY_ID:
            raise PlanError("Unknown action {n!r}. Valid actions: {v}.".format(
                n=name, v=", ".join(ACTION_IDS)))
        chosen.add(name)
    return tuple(a for a in ACTION_IDS if a in chosen)


@dataclass(frozen=True)
class ScanPlan:
    """What one run does. Every field is validated and normalized on creation."""

    target: str
    ports: str = PORTS_TOP
    actions: tuple = PRESETS[DEFAULT_PRESET].actions
    preset: str = DEFAULT_PRESET
    vuln_mode: str = PRESETS[DEFAULT_PRESET].vuln_mode

    def __post_init__(self):
        preset = str(self.preset).strip().lower()
        if preset not in PRESETS:
            raise PlanError("Unknown preset {p!r}. Valid presets: {v}.".format(
                p=self.preset, v=", ".join(PRESETS)))
        vuln_mode = str(self.vuln_mode).strip().lower()
        if vuln_mode not in VULN_MODES:
            raise PlanError("Unknown vuln probe mode {m!r}. Valid modes: {v}.".format(
                m=self.vuln_mode, v=", ".join(VULN_MODES)))
        object.__setattr__(self, "target", str(self.target).strip())
        object.__setattr__(self, "ports", parse_ports(self.ports))
        object.__setattr__(self, "actions", parse_actions(self.actions))
        object.__setattr__(self, "preset", preset)
        object.__setattr__(self, "vuln_mode", vuln_mode)

    def has(self, action_id):
        return action_id in self.actions

    def allows_tool(self, tool_name):
        return TOOL_ACTIONS.get(tool_name) in self.actions

    @property
    def tools(self):
        """Enabled agent tool names, in ACTIONS order."""
        return [t for a in self.actions for t in ACTIONS_BY_ID[a].tools]

    @property
    def customized(self):
        """True when the ports, actions or mode differ from the preset's."""
        base = PRESETS[self.preset]
        return (self.actions, self.ports, self.vuln_mode) != (base.actions, base.ports,
                                                             base.vuln_mode)

    def ports_text(self):
        if self.ports == PORTS_TOP:
            return "top (nmap's default top 1000 ports)"
        if self.ports == PORTS_ALL:
            return "all (every TCP port, 1 to 65535)"
        count = port_count(self.ports)
        return "{s} ({n} port{p})".format(s=self.ports, n=count, p="" if count == 1 else "s")

    def to_dict(self):
        return {"target": self.target, "preset": self.preset, "customized": self.customized,
                "ports": self.ports, "actions": list(self.actions),
                "vuln_mode": self.vuln_mode}

    def describe(self):
        """Lines for the terminal, printed before the scan starts."""
        lines = ["Scan plan: preset {p}{c}, ports {r}".format(
            p=self.preset, c=" (customized)" if self.customized else "", r=self.ports_text())]
        for action in ACTIONS:
            lines.append("  [{m}] {i:<9}{n}".format(
                m="x" if self.has(action.id) else " ", i=action.id, n=action.name))
        if self.has("vulns"):
            lines.append("  Vuln Probe mode: " + VULN_MODE_TEXT[self.vuln_mode])
        return lines


def build_plan(target, preset=None, ports=None, actions=None, vuln_mode=None):
    """
    A ScanPlan from a preset (default standard) plus optional overrides. Any
    override left as None keeps the preset's value. actions replaces the
    preset's actions; surface is always kept. Raise PlanError if anything is
    not valid.
    """
    name = str(preset if preset is not None else DEFAULT_PRESET).strip().lower()
    if name not in PRESETS:
        raise PlanError("Unknown preset {p!r}. Valid presets: {v}.".format(
            p=preset, v=", ".join(PRESETS)))
    base = PRESETS[name]
    return ScanPlan(target=target,
                    ports=base.ports if ports is None else ports,
                    actions=base.actions if actions is None else actions,
                    preset=name,
                    vuln_mode=base.vuln_mode if vuln_mode is None else vuln_mode)
