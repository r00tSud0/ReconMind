"""
ReconMind analyst tools: read only access to a finished scan.

In an AI enhanced run the standard pipeline (reconmind/core/pipeline.py) has
already run every tool. The model then works as an analyst over the stored
results, and ReadOnlyTools is the only thing it can call:

    list_findings()      every finding, compact, with the tool it came from
    get_port(port)       everything stored for one open port
    get_section(name)    one whole section: nvd, smb, attack_map, port_states
                         or unconfirmed_ports

ReadOnlyTools only reads the scan dict it was given. It never changes it, and
nothing in this module imports or calls a runner from reconmind/tools: the
model cannot run a scanner, send a packet or reach any address from here. The
one import from reconmind/tools is risky_services, a plain table of rules
that runs nothing.

ReadOnlyTools has the same call(name, args) -> (observation, is_error) shape
as ToolBox, and the same .scan and .calls, so brain.run_agent drives it
unchanged. call never raises.
"""

import json

from reconmind.tools.risky_services import flag_port

EVIDENCE_KEYS = ("raw_xml", "raw_json", "raw_jsonl")
# Left out of every observation: raw tool output, per cipher rows and the
# finding text written for the mapper model.
DROPPED_KEYS = EVIDENCE_KEYS + ("ciphers", "text")

SECTIONS = ("nvd", "smb", "attack_map", "port_states", "unconfirmed_ports")
# The plan action behind each section, for "not selected" answers.
SECTION_ACTIONS = {"nvd": "cves", "smb": "smb"}
# Per port results: (scan key, tool name, plan action).
PORT_RESULTS = (("web", "web_fingerprint", "web"), ("discovery", "web_discover", "paths"),
                ("nuclei", "vuln_templates", "vulns"), ("tls", "tls_check", "crypto"))

MAX_EXPLOITS = 20
MAX_PATHS = 60
MAX_CVES = 15
MAX_CVES_IN_FINDINGS = 5
MAX_USERS = 50
DESCRIPTION_CHARS = 200
TLS_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
CVE_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")

NOT_SELECTED = "not run: {a} was not selected in the scan plan"
NOT_STORED = "no result stored: the tool did not run for this"
READ_ONLY_NOTE = ("These are stored results from tools that already ran. Nothing was "
                  "scanned again to answer this.")
UNKNOWN_TOOL = ("Unknown tool '{n}'. The analyst can only read stored results with "
                "list_findings, get_port and get_section. No scanner can be run from here.")


ANALYST_TOOL_SPECS = [
    {
        "name": "list_findings",
        "description": (
            "Return every finding from the finished scan in one compact list, each "
            "with the tool it came from: risk flags, Exploit-DB matches, nuclei "
            "findings, testssl.sh findings, the most severe NVD CVEs per product, "
            "SMB results, web technologies, discovered path counts and the ATT&CK "
            "techniques attack_map confirmed. Reads stored results only; nothing "
            "is scanned. Start here. Takes no inputs."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_port",
        "description": (
            "Return everything stored for one open port: the nmap fields, the "
            "Exploit-DB matches and risk flag, and the httpx, ffuf, nuclei and "
            "testssl.sh results for that port, plus its confirmed ATT&CK "
            "techniques. Reads stored results only; nothing is scanned."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "port": {"type": "integer", "description": "An open port from the scan."},
            },
            "required": ["port"],
        },
    },
    {
        "name": "get_section",
        "description": (
            "Return one whole stored section of the scan: nvd (CVE lookup per "
            "product), smb (enum4linux-ng results), attack_map (ATT&CK mapping "
            "per port), port_states (how every scanned port answered) or "
            "unconfirmed_ports. Reads stored results only; nothing is scanned."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "enum": list(SECTIONS),
                         "description": "The section to read."},
            },
            "required": ["name"],
        },
    },
]


def _clean(value):
    """A copy without raw evidence, cipher rows or mapper text, at any depth."""
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items() if k not in DROPPED_KEYS}
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value]
    return value


def _short(text, limit=DESCRIPTION_CHARS):
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[:limit] + " ..."


def _port_result(results, number):
    """One port's stored result; int keys from the run, str keys from JSON."""
    if not isinstance(results, dict):
        return None
    result = results.get(number)
    if result is None:
        result = results.get(str(number))
    return result if isinstance(result, dict) else None


def _score(cve):
    try:
        return float(cve.get("cvss_score"))
    except (TypeError, ValueError):
        return -1.0


def _ranked_cves(cves):
    """CISA KEV first, then by CVSS score, highest first."""
    return sorted((c for c in cves or [] if isinstance(c, dict)),
                  key=lambda c: (not c.get("kev"), -_score(c)))


def _cve_counts(cves):
    counts = dict.fromkeys(CVE_SEVERITIES, 0)
    counts["UNSCORED"] = 0
    for cve in cves or []:
        severity = str(cve.get("cvss_severity") or "").upper()
        counts[severity if severity in counts else "UNSCORED"] += 1
    return counts


def _cve_item(cve, description=True):
    item = {"id": cve.get("id", ""), "score": cve.get("cvss_score"),
            "severity": cve.get("cvss_severity", ""), "kev": bool(cve.get("kev"))}
    if cve.get("kev_added"):
        item["kev_added"] = cve["kev_added"]
    if description and cve.get("description"):
        item["description"] = _short(cve["description"])
    return item


class ReadOnlyTools:
    """Read only tools over one finished scan dict. Never changes the scan."""

    def __init__(self, scan, plan=None, steps=None):
        self.scan = scan
        self.plan = plan
        self.target = str((scan or {}).get("target", "")).strip()
        self.steps = list(steps or [])  # how each pipeline step ended, for the overview
        self.calls = []  # (tool name, input) history, like ToolBox.calls

    def _selected(self, action_id):
        return self.plan is None or self.plan.has(action_id)

    def _ports(self):
        return [p for p in self.scan.get("ports") or [] if isinstance(p, dict)]

    # ---- dispatch -------------------------------------------------------

    def call(self, name, args):
        """Answer one read request. Always returns (observation, is_error); never raises."""
        try:
            self.calls.append((name, dict(args) if isinstance(args, dict) else {}))
            handler = {
                "list_findings": self._list_findings,
                "get_port": self._get_port,
                "get_section": self._get_section,
            }.get(name)
            if handler is None:
                return self._err(UNKNOWN_TOOL.format(n=name))
            if args is not None and not isinstance(args, dict):
                return self._err("Bad arguments for {n}: expected an object.".format(n=name))
            try:
                return handler(**(args or {}))
            except TypeError as exc:
                return self._err("Bad arguments for {n}: {e}".format(n=name, e=exc))
        except Exception as exc:  # a read must never crash the analyst loop
            return self._err("{n} failed: {e}".format(n=name, e=exc))

    # ---- tools ----------------------------------------------------------

    def _get_port(self, port):
        ports = self._ports()
        allowed = ", ".join(str(p.get("port")) for p in ports) or "none"
        try:
            number = int(port)
        except (TypeError, ValueError):
            return self._err("Port must be a number. Open ports: {a}.".format(a=allowed))
        match = next((p for p in ports if p.get("port") == number), None)
        if match is None:
            return self._err("Port {p} was not found open in the scan. Open ports: "
                             "{a}.".format(p=number, a=allowed))

        skip = ("exploits", "exploit_status", "lookup_error", "queries_tried")
        data = {"port": number,
                "nmap": _clean({k: v for k, v in match.items() if k not in skip})}
        if self._selected("exploits"):
            exploits = match.get("exploits") or []
            lookup = {"status": match.get("exploit_status", ""),
                      "match_count": len(exploits),
                      "matches": _clean(exploits[:MAX_EXPLOITS])}
            if match.get("lookup_error"):
                lookup["lookup_error"] = match["lookup_error"]
            data["exploit_lookup"] = lookup
            data["risk"] = flag_port(match) or None
        else:
            data["exploit_lookup"] = NOT_SELECTED.format(a="Exploit Hunt (exploits)")

        for key, tool, action in PORT_RESULTS:
            result = _port_result(self.scan.get(key), number)
            if result is not None:
                result = _clean(result)
                if tool == "web_discover":
                    rows = sorted(result.get("results") or [], key=lambda r: str(r.get("path", "")))
                    result["result_count"] = len(rows)
                    result["results"] = rows[:MAX_PATHS]
                data[tool] = result
            elif not self._selected(action):
                data[tool] = NOT_SELECTED.format(a=action)

        mapping = self.scan.get("attack_map")
        if isinstance(mapping, dict):
            entry = next((p for p in mapping.get("ports") or []
                          if isinstance(p, dict) and p.get("port") == number), None)
            if entry is not None:
                data["attack_map"] = _clean({k: entry.get(k) for k in
                                             ("techniques", "lower_confidence", "dropped")
                                             if entry.get(k)})
        data["note"] = READ_ONLY_NOTE
        return json.dumps(data, default=str), False

    def _get_section(self, name):
        name = str(name or "").strip().lower()
        if name not in SECTIONS:
            return self._err("Unknown section '{n}'. Sections: {s}.".format(
                n=name, s=", ".join(SECTIONS)))
        action = SECTION_ACTIONS.get(name)
        if action and not self._selected(action):
            return json.dumps({"section": name,
                               "status": NOT_SELECTED.format(a=action)}), False

        if name in ("port_states", "unconfirmed_ports"):
            return json.dumps({"section": name, name: _clean(self.scan.get(name) or [])},
                              default=str), False

        value = self.scan.get(name)
        if not isinstance(value, dict):
            return json.dumps({"section": name, "status": NOT_STORED}), False
        value = _clean(value)
        if name == "nvd":
            value["products"] = [self._nvd_product(p) for p in value.get("products") or []
                                 if isinstance(p, dict)]
        elif name == "smb":
            users = value.get("users") or []
            value["user_count"] = len(users)
            value["users"] = users[:MAX_USERS]
        return json.dumps({"section": name, name: value, "note": READ_ONLY_NOTE},
                          default=str), False

    @staticmethod
    def _nvd_product(product):
        cves = product.pop("cves", None) or []
        ranked = _ranked_cves(cves)
        product["cve_count"] = len(cves)
        product["severity_counts"] = _cve_counts(cves)
        product["cves_shown"] = [_cve_item(c) for c in ranked[:MAX_CVES]]
        product["cisa_kev"] = [c.get("id", "") for c in ranked if c.get("kev")]
        return product

    def _list_findings(self):
        findings = []
        ports = self._ports()
        if self._selected("exploits"):
            for p in ports:
                risk = flag_port(p)
                if risk:
                    findings.append(dict({"source": "risk_flags", "port": p.get("port")},
                                         **_clean(risk)))
                if p.get("exploit_status") == "lookup_failed":
                    findings.append({"source": "exploit_lookup", "port": p.get("port"),
                                     "match": "lookup_failed",
                                     "error": p.get("lookup_error", "")})
                for e in (p.get("exploits") or [])[:MAX_EXPLOITS]:
                    findings.append({"source": "exploit_lookup", "port": p.get("port"),
                                     "title": e.get("title", ""), "edb_id": e.get("edb_id", ""),
                                     "match": e.get("match")})

        for number, result in self._results("web"):
            if result.get("status") != "ok":
                continue
            item = {"source": "web_fingerprint", "port": number,
                    "server": result.get("server", ""), "title": result.get("title", ""),
                    "technologies": [{k: t.get(k) for k in ("name", "version") if t.get(k)}
                                     for t in result.get("technologies") or []]}
            if result.get("x_powered_by"):
                item["x_powered_by"] = result["x_powered_by"]
            findings.append(item)
        for number, result in self._results("discovery"):
            if result.get("status") == "ok":
                findings.append({"source": "web_discover", "port": number,
                                 "result_count": len(result.get("results") or []),
                                 "note": "call get_port for the paths"})
        for number, result in self._results("nuclei"):
            if result.get("status") != "ok":
                continue
            for f in result.get("findings") or []:
                findings.append({"source": "vuln_templates", "port": number,
                                 "severity": f.get("severity", ""), "name": f.get("name", ""),
                                 "template_id": f.get("template_id", ""),
                                 "matched_at": f.get("matched_at", ""), "cve": f.get("cve") or []})
        for number, result in self._results("tls"):
            if result.get("status") != "ok":
                continue
            for f in result.get("findings") or []:
                if str(f.get("severity", "")).upper() not in TLS_SEVERITIES:
                    continue
                item = {"source": "tls_check", "port": number, "severity": f.get("severity", ""),
                        "id": f.get("id", ""), "finding": f.get("finding", "")}
                if f.get("cve"):
                    item["cve"] = f["cve"]
                findings.append(item)

        smb = self.scan.get("smb")
        if isinstance(smb, dict) and smb.get("status") == "ok":
            findings.append({"source": "smb_enum", "null_session": smb.get("null_session"),
                             "domain": smb.get("domain", ""),
                             "user_count": len(smb.get("users") or []),
                             "shares": [{k: s.get(k, "") for k in ("name", "mapping", "listing")}
                                        for s in smb.get("shares") or []]})

        nvd = self.scan.get("nvd")
        if isinstance(nvd, dict):
            for product in nvd.get("products") or []:
                if product.get("status") != "ok":
                    continue
                ranked = _ranked_cves(product.get("cves"))
                shown = [c for c in ranked if c.get("kev")]
                shown += [c for c in ranked if not c.get("kev")][:MAX_CVES_IN_FINDINGS]
                for cve in shown:
                    findings.append(dict({"source": "cve_lookup",
                                          "product": product.get("product", ""),
                                          "ports": product.get("ports", [])},
                                         **_cve_item(cve, description=False)))

        mapping = self.scan.get("attack_map")
        if isinstance(mapping, dict):
            for p in mapping.get("ports") or []:
                for t in p.get("techniques") or []:
                    findings.append({"source": "attack_map", "port": p.get("port"),
                                     "id": t.get("id", ""), "name": t.get("name", ""),
                                     "sources": t.get("sources") or []})
        return json.dumps({"finding_count": len(findings), "findings": findings,
                           "note": READ_ONLY_NOTE}, default=str), False

    def _results(self, key):
        """(port, result) for every stored per port result of one tool, by port."""
        results = self.scan.get(key)
        if not isinstance(results, dict):
            return []
        out = []
        for number, result in results.items():
            if isinstance(result, dict):
                try:
                    number = int(number)
                except (TypeError, ValueError):
                    pass
                out.append((number, result))
        return sorted(out, key=lambda item: str(item[0]))

    # ---- overview for the first message ---------------------------------

    def overview(self):
        """Compact facts for the analyst's first message."""
        ports = self._ports()
        stored = {}
        for key, tool, _ in PORT_RESULTS:
            numbers = [n for n, _ in self._results(key)]
            if numbers:
                stored[tool] = numbers
        for key, tool in (("smb", "smb_enum"), ("nvd", "cve_lookup"), ("attack_map", "attack_map")):
            if isinstance(self.scan.get(key), dict):
                stored[tool] = True
        facts = {
            "target": self.scan.get("target", ""),
            "scan_status": self.scan.get("status"),
            "open_ports": [{k: p.get(k, "") for k in ("port", "protocol", "service", "product",
                                                      "version")} for p in ports],
            "unconfirmed_port_count": len(self.scan.get("unconfirmed_ports") or []),
            "results_stored": stored,
        }
        if self.plan is not None:
            facts["plan"] = {"preset": self.plan.preset, "ports": self.plan.ports,
                             "actions": list(self.plan.actions)}
        if self.steps:
            facts["steps"] = [{k: s.get(k) for k in ("tool", "port", "status", "message")
                               if s.get(k) is not None} for s in self.steps]
        return facts

    @staticmethod
    def _err(message):
        return json.dumps({"error": message}), True
