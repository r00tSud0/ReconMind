"""
ReconMind agent toolbox.

This is the only door between the LLM brain and the real security tools. The
model never runs a command itself. It can only ask for one of the tools
described in TOOL_SPECS, and every request comes through ToolBox.call(), which:

  1. checks the request against the scope lock (the agent may only touch the
     one target the human gave it on the command line),
  2. hands the request to the real tool, which runs the authorization gate
     again before anything is launched,
  3. returns a compact JSON observation for the model to read, and
  4. keeps the structured results so the report is built from real tool
     output, not from whatever the model claims it saw.

A ToolBox can carry a ScanPlan. Then only the tools of the plan's actions run
(any other request gets an error observation saying it is not part of this
scan), nmap scans the plan's ports, nuclei uses the plan's vuln probe mode,
and the Exploit-DB lookup and risk flags run only when Exploit Hunt is
selected. plan_tool_specs gives the matching tool specs for the model.
Without a plan every tool runs exactly as before.

Adding a tool later means adding one spec and one handler here, and listing it
under an action in reconmind/core/scan_plan.py. The agent loop does not change.
"""

import copy
import json
import os

from reconmind.core.scan_plan import ACTIONS_BY_ID, TOOL_ACTIONS
from reconmind.tools.nmap_scan import run_nmap
from reconmind.tools.exploit_lookup import (
    STATUS_FAILED, STATUS_NO_PRODUCT, lookup_port, primary_label, search_exploits)
from reconmind.tools.risky_services import flag_port
from reconmind.tools.version_normalizer import planned_queries
from reconmind.tools.whatweb_scan import is_web_service, run_whatweb, wants_https
from reconmind.tools.ffuf_scan import run_ffuf
from reconmind.tools.nuclei_scan import run_nuclei
from reconmind.tools.nuclei_scan import severity_rank as nuclei_severity_rank
from reconmind.tools.testssl_scan import (
    SEVERITY_ORDER, is_tls_capable, run_testssl, severity_rank, starttls_protocol)
from reconmind.tools.smb_enum import SMB_PORTS, policy_fields, run_enum4linux, smb_ports
from reconmind.tools import nvd_lookup

# Severities shown in full in the tls_check observation.
TLS_OBSERVED_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM")

# How many usernames the smb_enum observation lists. The full list is always
# stored for the report.
SMB_USERS_IN_OBSERVATION = 20

# How many paths the web_discover observation lists, sorted by path. The full
# list is always stored for the report.
DISCOVERY_RESULTS_IN_OBSERVATION = 40

# Severities counted in the vuln_templates observation, the same ones nuclei
# is asked to run. Every finding is listed in full.
NUCLEI_OBSERVED_SEVERITIES = ("critical", "high", "medium", "low")

# How many of the highest CVSS CVEs the cve_lookup observation lists per
# product. Every CISA KEV CVE is always listed, and the full list is always
# stored for the report.
TOP_CVES_IN_OBSERVATION = 5

# How many titles each port shows in the compact nmap_scan summary. The full
# list comes from exploit_lookup and is always stored for the report.
TOP_MATCHES_IN_SUMMARY = 3

# What the model is told about each weaker match label.
MATCH_NOTES = {
    "version_family": "Matched on major.minor only; the patch level is not "
                      "confirmed. Treat these matches as unconfirmed.",
    "product_only": "nmap gave no usable version; matched on product name "
                    "only. Treat these matches as unconfirmed.",
    "unverified": "The title's version range could not be checked against the "
                  "scanned version. Treat these matches as unconfirmed.",
}

LOOKUP_FAILED_NOTE = ("The exploit lookup failed, so this service was not "
                      "checked. This does not mean there are no exploits.")

UNCONFIRMED_NOTE = ("These ports answered as open in the discovery pass but not "
                    "in the detail pass, usually because of packet loss on the "
                    "network path. They are not confirmed findings; the scan "
                    "should be rerun.")

NOT_IN_PLAN = ("{tool} is not part of this scan. The operator's scan plan does not "
               "include {action} ({action_id}), so it was not run. Tools in this scan: "
               "{tools}. Do not call it again.")

# nmap_scan's description when Exploit Hunt is not selected: no automatic
# lookup and no risk flags.
NMAP_DESCRIPTION_NO_EXPLOITS = (
    "Run an nmap service and version scan (-sV) against the authorized "
    "target, on the ports in this scan's plan. Returns every open port with "
    "its service, product and version. Run this first. Only the target given "
    "by the operator is allowed."
)


# Tool descriptions in the JSON schema format the LLM API expects.
TOOL_SPECS = [
    {
        "name": "nmap_scan",
        "description": (
            "Run an nmap service and version scan (-sV) against the authorized "
            "target. Returns every open port with its service, product and "
            "version. The Exploit-DB lookup then runs automatically for every "
            "port with a product, and each port carries a compact summary: "
            "exploit_label, match_count and the top 3 titles with EDB-IDs. "
            "Ports that are risky just by being exposed carry a risk flag "
            "with severity and reason. Run this first. Only the target given "
            "by the operator is allowed."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "IPv4 address of the authorized target.",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "exploit_lookup",
        "description": (
            "Return the full Exploit-DB (searchsploit) results for one port. "
            "nmap_scan already ran the lookup for every port, so this only "
            "returns the stored list, without searching again. Use it when the "
            "top 3 titles in the nmap_scan summary are not enough. Each match "
            "is labeled exact_version (full version matched), version_family "
            "(major.minor only, patch level not confirmed), product_only "
            "(version unknown, unconfirmed) or unverified (version range could "
            "not be checked, unconfirmed). match lookup_failed means the "
            "service was not checked, not that it has no exploits."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "port": {
                    "type": "integer",
                    "description": "Port number the service was found on.",
                },
            },
            "required": ["port"],
        },
    },
    {
        "name": "web_fingerprint",
        "description": (
            "Identify the web server technology on one open HTTP or HTTPS port "
            "found by nmap_scan, using whatweb with one normal request, plus "
            "any redirects the server sends. Returns "
            "the URL, the HTTP status and each component whatweb recognized "
            "(server, language, framework and so on) with the versions and "
            "strings exactly as whatweb reported them. HTTPS is used "
            "automatically when nmap saw SSL on the port. Run nmap_scan first."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "port": {
                    "type": "integer",
                    "description": "An open HTTP or HTTPS port from nmap_scan.",
                },
            },
            "required": ["port"],
        },
    },
    {
        "name": "web_discover",
        "description": (
            "Discover content on one open HTTP or HTTPS port found by "
            "nmap_scan, using ffuf with a common paths wordlist. Sends one GET "
            "request per word at no more than 50 requests per second. No "
            "parameters, no POST bodies, no credentials and no recursion. "
            "Returns the URL, the wordlist name and size, the result count and "
            "the first 40 results sorted by path, each with its HTTP status, "
            "size and redirect target exactly as ffuf reported them. HTTPS is "
            "used automatically when nmap saw SSL on the port. Run nmap_scan "
            "first."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "port": {
                    "type": "integer",
                    "description": "An open HTTP or HTTPS port from nmap_scan.",
                },
            },
            "required": ["port"],
        },
    },
    {
        "name": "vuln_templates",
        "description": (
            "Run safe nuclei templates against one open HTTP or HTTPS port "
            "found by nmap_scan. Only HTTP templates rated low, medium, high "
            "or critical are used. Denial of service, fuzzing, intrusive, "
            "default login and brute force templates are excluded, outside "
            "callbacks (interactsh) are off and templates are never updated "
            "during the scan. At most 50 requests per second. Returns the URL, "
            "the templates version, counts by severity and every finding, most "
            "severe first, with its template id, name, severity, where it "
            "matched and any CVE IDs, exactly as nuclei reported them. HTTPS is "
            "used automatically when nmap saw SSL on the port. Run nmap_scan "
            "first."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "port": {
                    "type": "integer",
                    "description": "An open HTTP or HTTPS port from nmap_scan.",
                },
            },
            "required": ["port"],
        },
    },
    {
        "name": "tls_check",
        "description": (
            "Check the TLS setup of one open port found by nmap_scan, using "
            "testssl.sh with its default checks. Allowed ports: ports where "
            "nmap saw an SSL tunnel or a service named https or ssl/something, "
            "and smtp, ftp, imap, pop3 or postgresql ports, which are checked "
            "through STARTTLS. Returns counts of LOW, MEDIUM, HIGH and "
            "CRITICAL findings plus every finding rated MEDIUM or higher, with "
            "the text, CVE and CWE exactly as testssl.sh reported them. Run "
            "nmap_scan first."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "port": {
                    "type": "integer",
                    "description": "An open TLS or STARTTLS capable port from nmap_scan.",
                },
            },
            "required": ["port"],
        },
    },
    {
        "name": "smb_enum",
        "description": (
            "Enumerate SMB on the authorized target with enum4linux-ng, using "
            "anonymous (null session) checks only. No credentials are used and "
            "no passwords are guessed. Allowed only after nmap_scan, and only "
            "when port 139 or 445 is open. Returns whether a null session was "
            "allowed, the domain or workgroup, OS details, the user count with "
            "the first 20 usernames, the group count, every share with its "
            "mapping and listing results, and the password policy, all as "
            "enum4linux-ng reported them. Takes no inputs."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "cve_lookup",
        "description": (
            "Look up known CVEs in the NVD database for every product nmap_scan "
            "found with a versioned CPE (or a versionless CPE plus a port "
            "version), plus PHP when web_fingerprint reported a PHP version. "
            "Each CPE is first matched to NVD's official CPE dictionary name. "
            "Only the CPE strings are sent to NVD, never the "
            "target or any other scan detail. Returns, per product, the CPE, "
            "the CVE count by severity, every CVE in the CISA KEV catalog and "
            "the 5 highest CVSS CVEs with id, score and severity, plus the "
            "CPEs skipped for having no version. NVD matches the upstream "
            "version only, so a distribution may already have patched some of "
            "these. Run nmap_scan first. Takes no inputs."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
]


def plan_tool_specs(plan):
    """
    The tool specs the model may see for this plan, in TOOL_SPECS order.
    None gives TOOL_SPECS itself. Specs are copied, never changed in place.
    """
    if plan is None:
        return TOOL_SPECS
    specs = []
    for spec in TOOL_SPECS:
        if not plan.allows_tool(spec["name"]):
            continue
        spec = copy.deepcopy(spec)
        if spec["name"] == "nmap_scan" and not plan.has("exploits"):
            spec["description"] = NMAP_DESCRIPTION_NO_EXPLOITS
        specs.append(spec)
    return specs


class ToolBox:
    """Holds the scope lock and the results gathered during one agent run."""

    def __init__(self, target, all_ports=False, plan=None):
        self.target = str(target).strip()
        # Passed straight through to run_nmap. Default False, so the agent and
        # brain.py scan exactly as before; only callers that ask for a full
        # sweep set it. A plan's ports spec takes its place.
        self.all_ports = all_ports
        # Scope lock: a plan for any other target is refused outright.
        if plan is not None and plan.target != self.target:
            raise ValueError("The scan plan is for {p}, not {t}.".format(
                p=plan.target, t=self.target))
        self.plan = plan
        # Same shape the report builder already reads.
        self.scan = {"target": self.target, "status": "not-run", "ports": []}
        self.calls = []  # (tool name, input) history, for the trace and tests

    def _enabled(self, action_id):
        """True if the action runs in this scan. Without a plan, everything does."""
        return self.plan is None or self.plan.has(action_id)

    # ---- dispatch -------------------------------------------------------

    def call(self, name, args):
        """
        Run one tool request from the model. Always returns
        (observation_text, is_error). Never raises, so a bad request from the
        model becomes an observation it can react to instead of a crash.
        """
        self.calls.append((name, dict(args or {})))
        handler = {
            "nmap_scan": self._nmap_scan,
            "exploit_lookup": self._exploit_lookup,
            "web_fingerprint": self._web_fingerprint,
            "web_discover": self._web_discover,
            "vuln_templates": self._vuln_templates,
            "tls_check": self._tls_check,
            "smb_enum": self._smb_enum,
            "cve_lookup": self._cve_lookup,
        }.get(name)

        if handler is None:
            return self._err("Unknown tool '{n}'.".format(n=name))
        action_id = TOOL_ACTIONS.get(name)
        if not self._enabled(action_id):
            return self._err(NOT_IN_PLAN.format(
                tool=name, action=ACTIONS_BY_ID[action_id].name, action_id=action_id,
                tools=", ".join(self.plan.tools)))
        try:
            return handler(**(args or {}))
        except TypeError as exc:
            return self._err("Bad arguments for {n}: {e}".format(n=name, e=exc))
        except Exception as exc:  # tool crashed, report it to the model
            return self._err("{n} failed: {e}".format(n=name, e=exc))

    # ---- handlers -------------------------------------------------------

    def _nmap_scan(self, target):
        # Scope lock: the model may only scan the target the human chose.
        if str(target).strip() != self.target:
            return self._err(
                "Refused: {t} is outside this run's scope. The only authorized "
                "target is {s}.".format(t=target, s=self.target))

        # run_nmap asks the authorization gate again before nmap starts, and
        # checks the plan's ports spec again before it builds the command.
        if self.plan is None:
            result = run_nmap(self.target, all_ports=self.all_ports)
        else:
            result = run_nmap(self.target, ports=self.plan.ports)
        self.scan = result

        if result["status"] == "refused":
            return self._err(
                "Refused by the authorization gate: {t} is not on the "
                "allowlist. No scan was run. Do not retry.".format(t=self.target))
        if result["status"] != "ok":
            return self._err("Scan did not run: status={s}".format(s=result["status"]))

        # Completeness: every open port is looked up, not just the ones the
        # model would have picked. Only when Exploit Hunt is in the plan.
        exploits = self._enabled("exploits")
        if exploits:
            for port in result["ports"]:
                self._lookup_port(port)

        observation = {
            "target": result["target"],
            "open_ports": [self._port_summary(p, exploits=exploits) for p in result["ports"]],
        }
        # How every scanned port answered, so the model can tell a firewall
        # (many filtered, no-response) from a host with nothing listening.
        if result.get("port_states"):
            observation["port_states"] = result["port_states"]
        # Ports the discovery pass saw open but the detail pass did not. They
        # are not findings. raw_xml stays in self.scan and is never sent.
        unconfirmed = result.get("unconfirmed_ports") or []
        observation["unconfirmed_ports"] = unconfirmed
        if unconfirmed:
            observation["unconfirmed_note"] = UNCONFIRMED_NOTE
        return json.dumps(observation), False

    def _exploit_lookup(self, port, product=None, version=None):
        # product and version from the model are accepted but ignored: the
        # results always come from what nmap recorded for the port.
        if self.scan.get("status") != "ok":
            return self._err("Run nmap_scan first; there are no scan results yet.")

        match = next((p for p in self.scan["ports"] if p.get("port") == int(port)), None)
        if match is None:
            return self._err("Port {p} was not found open in the scan.".format(p=port))

        # Normally nmap_scan already looked the port up. Search only if not.
        if "exploit_status" not in match:
            self._lookup_port(match)

        status = match.get("exploit_status")
        if status == STATUS_NO_PRODUCT:
            observation = {
                "port": int(port),
                "match": "none",
                "note": "nmap recorded no product for port {p}; nothing to "
                        "search.".format(p=port),
            }
            return json.dumps(observation), False

        product = (match.get("product") or "").strip()
        version = (match.get("version") or "").strip()
        exploits = match.get("exploits", [])
        observation = {"port": int(port), "product": product, "version": version}

        if status == STATUS_FAILED:
            observation["match"] = STATUS_FAILED
            observation["error"] = match.get("lookup_error", "")
            observation["note"] = LOOKUP_FAILED_NOTE
            observation["queries_tried"] = self._queries_tried(match)
        elif exploits:
            label = primary_label(exploits)
            observation["match"] = label
            observation["query"] = exploits[0].get("query")
            if label in MATCH_NOTES:
                observation["note"] = MATCH_NOTES[label]
            if label != "unverified" and any(e.get("match") == "unverified" for e in exploits):
                observation["unverified_note"] = MATCH_NOTES["unverified"]
        else:
            observation["match"] = "none"
            observation["queries_tried"] = self._queries_tried(match)
        observation["total_matches"] = len(exploits)
        observation["exploits"] = exploits
        return json.dumps(observation), False

    def _web_port(self, port, action):
        """
        Shared port rules for the web tools. Return (number, port dict, None)
        for an open HTTP or HTTPS port from nmap_scan, or (None, None, error)
        where error is the (observation, is_error) pair to return. action
        finishes the sentence "Web ports you can ...".
        """
        if self.scan.get("status") != "ok":
            return None, None, self._err("Run nmap_scan first; there are no scan results yet.")

        web_ports = [p for p in self.scan.get("ports", []) if is_web_service(p)]
        allowed = ", ".join(str(p.get("port")) for p in web_ports) or "none"
        try:
            number = int(port)
        except (TypeError, ValueError):
            return None, None, self._err("Port must be a number. Web ports you can {v}: "
                                         "{a}.".format(v=action, a=allowed))

        match = next((p for p in self.scan.get("ports", []) if p.get("port") == number), None)
        if match is None:
            return None, None, self._err(
                "Port {p} was not found open in the scan. Web ports you can "
                "{v}: {a}.".format(p=number, v=action, a=allowed))
        if not is_web_service(match):
            return None, None, self._err(
                "Port {p} ({s}) is not an HTTP or HTTPS service. Web ports "
                "you can {v}: {a}.".format(
                    p=number, s=match.get("service") or "unknown", v=action, a=allowed))
        return number, match, None

    def _web_fingerprint(self, port):
        number, match, error = self._web_port(port, "fingerprint")
        if error:
            return error

        # Scope lock: whatweb only ever runs against this run's target, and
        # run_whatweb asks the authorization gate again before it starts.
        result = run_whatweb(self.target, number, use_https=wants_https(match))
        self.scan.setdefault("web", {})[number] = result

        status = result.get("status")
        if status == "refused":
            return self._err(
                "Refused by the authorization gate: {t} is not on the allowlist. "
                "whatweb was not run. Do not retry.".format(t=self.target))
        if status == "whatweb-not-found":
            return self._err("whatweb is not installed, so port {p} was not checked. "
                             "Do not retry.".format(p=number))
        if status != "ok":
            return self._err("whatweb did not complete for port {p}: status={s}. {e} "
                             "This port was not checked.".format(
                                 p=number, s=status, e=result.get("error", "")).replace("  ", " "))

        components = []
        for c in result.get("components", []):
            item = {"name": c.get("name", "")}
            if c.get("versions"):
                item["versions"] = c["versions"]
            if c.get("strings"):
                item["strings"] = c["strings"]
            components.append(item)
        observation = {"port": number, "url": result.get("url", ""),
                       "http_status": result.get("http_status"), "components": components}
        return json.dumps(observation), False

    def _web_discover(self, port):
        number, match, error = self._web_port(port, "discover content on")
        if error:
            return error

        # Scope lock: ffuf only ever runs against this run's target, and
        # run_ffuf asks the authorization gate again before it starts.
        result = run_ffuf(self.target, number, use_https=wants_https(match))
        self.scan.setdefault("discovery", {})[number] = result

        status = result.get("status")
        if status == "refused":
            return self._err(
                "Refused by the authorization gate: {t} is not on the allowlist. "
                "ffuf was not run. Do not retry.".format(t=self.target))
        if status == "ffuf-not-found":
            return self._err("ffuf is not installed, so port {p} was not checked. "
                             "Do not retry.".format(p=number))
        if status == "wordlist-not-found":
            return self._err("No wordlist was found, so port {p} was not checked. "
                             "Do not retry.".format(p=number))
        if status != "ok":
            return self._err("ffuf did not complete for port {p}: status={s}. {e} "
                             "This port was not checked.".format(
                                 p=number, s=status, e=result.get("error", "")).replace("  ", " "))

        # Compact view only. raw_json, the command and the wordlist hash stay
        # in self.scan as evidence and are never sent.
        results = sorted(result.get("results") or [], key=lambda r: str(r.get("path", "")))
        items = []
        for r in results[:DISCOVERY_RESULTS_IN_OBSERVATION]:
            item = {"path": r.get("path", ""), "status": r.get("status"),
                    "length": r.get("length")}
            if r.get("redirect"):
                item["redirect"] = r["redirect"]
            items.append(item)
        observation = {"port": number, "url": result.get("url", ""),
                       "wordlist": os.path.basename(result.get("wordlist") or ""),
                       "wordlist_lines": result.get("wordlist_lines"),
                       "result_count": len(results), "results": items}
        return json.dumps(observation), False

    def _vuln_templates(self, port):
        number, match, error = self._web_port(port, "run templates against")
        if error:
            return error

        # Scope lock: nuclei only ever runs against this run's target, and
        # run_nuclei asks the authorization gate again before it starts.
        if self.plan is None:
            result = run_nuclei(self.target, number, use_https=wants_https(match))
        else:
            result = run_nuclei(self.target, number, use_https=wants_https(match),
                                mode=self.plan.vuln_mode)
        self.scan.setdefault("nuclei", {})[number] = result

        status = result.get("status")
        if status == "refused":
            return self._err(
                "Refused by the authorization gate: {t} is not on the allowlist. "
                "nuclei was not run. Do not retry.".format(t=self.target))
        if status == "nuclei-not-found":
            return self._err("nuclei is not installed, so port {p} was not checked. "
                             "Do not retry.".format(p=number))
        if status == "templates-not-found":
            return self._err("No nuclei templates are installed, so port {p} was not "
                             "checked. The operator must run nuclei -update-templates "
                             "once. Do not retry.".format(p=number))
        if status != "ok":
            return self._err("nuclei did not complete for port {p}: status={s}. {e} "
                             "This port was not checked.".format(
                                 p=number, s=status, e=result.get("error", "")).replace("  ", " "))

        # Compact view only. raw_jsonl, the command, extracted values, CWE
        # IDs and tags stay in self.scan as evidence and are never sent.
        findings = sorted(result.get("findings") or [],
                          key=lambda f: nuclei_severity_rank(f.get("severity")))
        counts = {sev: sum(1 for f in findings if str(f.get("severity", "")).lower() == sev)
                  for sev in NUCLEI_OBSERVED_SEVERITIES}
        items = [{"template_id": f.get("template_id", ""), "name": f.get("name", ""),
                  "severity": f.get("severity", ""), "matched_at": f.get("matched_at", ""),
                  "cve": f.get("cve") or []}
                 for f in findings]
        observation = {"port": number, "url": result.get("url", ""),
                       "templates_version": result.get("templates_version", ""),
                       "severity_counts": counts, "finding_count": len(findings),
                       "findings": items}
        if result.get("mode"):
            observation["mode"] = result["mode"]
        return json.dumps(observation), False

    @staticmethod
    def _tls_port_label(port):
        proto = starttls_protocol(port)
        label = str(port.get("port"))
        return label + (" (STARTTLS {s})".format(s=proto) if proto else "")

    def _tls_check(self, port):
        if self.scan.get("status") != "ok":
            return self._err("Run nmap_scan first; there are no scan results yet.")

        tls_ports = [p for p in self.scan.get("ports", []) if is_tls_capable(p)]
        allowed = ", ".join(self._tls_port_label(p) for p in tls_ports) or "none"
        try:
            number = int(port)
        except (TypeError, ValueError):
            return self._err("Port must be a number. TLS ports you can check: "
                             "{a}.".format(a=allowed))

        match = next((p for p in self.scan.get("ports", []) if p.get("port") == number), None)
        if match is None:
            return self._err("Port {p} was not found open in the scan. TLS ports you can "
                             "check: {a}.".format(p=number, a=allowed))
        if not is_tls_capable(match):
            return self._err("Port {p} ({s}) is not a TLS or STARTTLS capable service. TLS "
                             "ports you can check: {a}.".format(
                                 p=number, s=match.get("service") or "unknown", a=allowed))

        # Scope lock: testssl.sh only ever runs against this run's target, and
        # run_testssl asks the authorization gate again before it starts.
        starttls = starttls_protocol(match)
        result = run_testssl(self.target, number, starttls=starttls)
        self.scan.setdefault("tls", {})[number] = result

        status = result.get("status")
        if status == "refused":
            return self._err(
                "Refused by the authorization gate: {t} is not on the allowlist. "
                "testssl.sh was not run. Do not retry.".format(t=self.target))
        if status == "testssl-not-found":
            return self._err("testssl.sh is not installed, so port {p} was not checked. "
                             "Do not retry.".format(p=number))
        if status == "not-tls":
            observation = {"port": number, "starttls": starttls, "status": "not-tls",
                           "note": "testssl.sh reports this port does not speak TLS."}
            return json.dumps(observation), False
        if status != "ok":
            return self._err("testssl.sh did not complete for port {p}: status={s}. {e} "
                             "This port was not checked.".format(
                                 p=number, s=status, e=result.get("error", "")).replace("  ", " "))

        # Findings only. The per cipher rows ("ciphers") and the full JSON
        # ("raw_json") stay in self.scan as evidence and are never sent.
        findings = result.get("findings", [])
        counts = {sev: sum(1 for f in findings if str(f.get("severity", "")).upper() == sev)
                  for sev in SEVERITY_ORDER}
        serious = sorted((f for f in findings
                          if str(f.get("severity", "")).upper() in TLS_OBSERVED_SEVERITIES),
                         key=lambda f: severity_rank(f.get("severity")))
        items = []
        for f in serious:
            item = {"id": f.get("id", ""), "severity": f.get("severity", ""),
                    "finding": f.get("finding", "")}
            if f.get("cve"):
                item["cve"] = f["cve"]
            if f.get("cwe"):
                item["cwe"] = f["cwe"]
            items.append(item)
        observation = {"port": number, "starttls": starttls, "severity_counts": counts,
                       "findings": items}
        return json.dumps(observation), False

    def _smb_enum(self):
        if self.scan.get("status") != "ok":
            return self._err("Run nmap_scan first; there are no scan results yet.")

        open_smb = smb_ports(self.scan.get("ports", []))
        if not open_smb:
            return self._err(
                "smb_enum is only allowed when port {a} is open, and nmap_scan "
                "found neither open. SMB was not enumerated.".format(
                    a=" or ".join(str(p) for p in SMB_PORTS)))

        # Scope lock: enum4linux-ng only ever runs against this run's target,
        # and run_enum4linux asks the authorization gate again before it starts.
        result = run_enum4linux(self.target)
        self.scan["smb"] = result

        status = result.get("status")
        if status == "refused":
            return self._err(
                "Refused by the authorization gate: {t} is not on the allowlist. "
                "enum4linux-ng was not run. Do not retry.".format(t=self.target))
        if status == "enum4linux-ng-not-found":
            return self._err("enum4linux-ng is not installed, so SMB was not checked. "
                             "Do not retry.")
        if status != "ok":
            return self._err("enum4linux-ng did not complete: status={s}. {e} "
                             "SMB was not checked.".format(
                                 s=status, e=result.get("error", "")).replace("  ", " "))

        # Compact view only. raw_json and the command stay in self.scan as
        # evidence and are never sent.
        users = result.get("users") or []
        observation = {
            "smb_ports": [p.get("port") for p in open_smb],
            "null_session": result.get("null_session"),
            "domain": result.get("domain", ""),
            "os": result.get("os") or {},
            "user_count": len(users),
            "usernames": [u.get("username", "") for u in users[:SMB_USERS_IN_OBSERVATION]],
            "group_count": len(result.get("groups") or []),
            "shares": [{k: s.get(k, "") for k in ("name", "type", "comment", "mapping",
                                                  "listing")}
                       for s in result.get("shares") or []],
            "password_policy": dict(policy_fields(result.get("policy"))),
        }
        return json.dumps(observation), False

    def _cve_lookup(self):
        if self.scan.get("status") != "ok":
            return self._err("Run nmap_scan first; there are no scan results yet.")

        # Privacy: lookup_targets reads only CPE strings and whatweb's PHP
        # versions, and only the CPE strings are sent to NVD. self.target is
        # never passed in.
        products, skipped = nvd_lookup.lookup_targets(self.scan.get("ports", []),
                                                      self.scan.get("web"))
        result = nvd_lookup.run_cve_lookup(products, skipped)
        self.scan["nvd"] = result

        observation = {"status": result.get("status"),
                       "skipped": [{"cpe": s.get("cpe", ""), "ports": s.get("ports", []),
                                    "reason": s.get("reason", "")}
                                   for s in result.get("skipped", [])]}
        if result.get("status") == nvd_lookup.STATUS_NO_CPE:
            observation["note"] = result.get("error", "")
            return json.dumps(observation), False

        # Compact view only. Descriptions, vectors, CWE IDs and the full CVE
        # list stay in self.scan for the report.
        items = []
        for p in result.get("products", []):
            item = {"product": p.get("product", ""), "ports": p.get("ports", []),
                    "cpe": p.get("cpe", ""), "status": p.get("status", "")}
            if p.get("resolved_from") and p.get("resolved_from") != p.get("cpe"):
                item["resolved_from"] = p["resolved_from"]
            if p.get("version_from"):
                item["version_from"] = p["version_from"]
            if p.get("status") != nvd_lookup.STATUS_OK:
                item["error"] = p.get("error", "")
                item["note"] = "This product was not checked. This does not mean it has no CVEs."
                items.append(item)
                continue
            cves = p.get("cves") or []
            if not cves:
                # Never a bare 0: an empty answer is about this exact CPE only.
                item["note"] = nvd_lookup.NO_RESULTS_NOTE
                items.append(item)
                continue
            item["cve_count"] = len(cves)
            item["severity_counts"] = nvd_lookup.severity_counts(cves)
            item["cisa_kev"] = [{"id": c.get("id", ""), "score": c.get("cvss_score"),
                                 "severity": c.get("cvss_severity", ""),
                                 "kev_added": c.get("kev_added", "")}
                                for c in nvd_lookup.by_score(cves) if c.get("kev")]
            item["top_cvss"] = [{"id": c.get("id", ""), "score": c.get("cvss_score"),
                                 "severity": c.get("cvss_severity", "")}
                                for c in nvd_lookup.top_cves(cves, TOP_CVES_IN_OBSERVATION)]
            items.append(item)
        observation["products"] = items
        observation["note"] = nvd_lookup.PATCH_NOTE
        return json.dumps(observation), False

    # ---- lookup helpers -------------------------------------------------

    @staticmethod
    def _lookup_port(port):
        # search_exploits is looked up here at call time, so tests can
        # replace this module's reference with a fake.
        lookup_port(port, search=search_exploits)

    @staticmethod
    def _queries_tried(port):
        return port.get("queries_tried") or [
            q for q, _ in planned_queries(port.get("product", ""), port.get("version", ""))]

    @staticmethod
    def _port_summary(port, exploits=True):
        """
        Compact per port line for the nmap_scan observation. exploits=False
        (Exploit Hunt not selected) leaves out the exploit fields and risk flag.
        """
        summary = {k: port.get(k, "") for k in ("port", "protocol", "service", "product", "version")}
        if not exploits:
            return summary
        status = port.get("exploit_status")
        exploits = port.get("exploits", [])
        if status in (STATUS_FAILED, STATUS_NO_PRODUCT):
            summary["exploit_label"] = status
        elif exploits:
            summary["exploit_label"] = primary_label(exploits)
        else:
            summary["exploit_label"] = "none"
        if status == STATUS_FAILED:
            summary["lookup_error"] = port.get("lookup_error", "")
        summary["match_count"] = len(exploits)
        summary["top_matches"] = [
            {"title": e.get("title", ""), "edb_id": e.get("edb_id", ""), "match": e.get("match")}
            for e in exploits[:TOP_MATCHES_IN_SUMMARY]
        ]
        risk = flag_port(port)
        if risk:
            summary["risk"] = risk
        return summary

    # ---- helpers --------------------------------------------------------

    @staticmethod
    def _err(message):
        return json.dumps({"error": message}), True
