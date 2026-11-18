"""
ReconMind web: saved runs and job progress events, read only.

Saved runs live in <report_dir>/<run id>/ (see reconmind/core/history.py):

    valid_run_id(run_id)              True for "<YYYYmmdd>_<HHMMSS>_<name>" ids
                                      that new_run_id can produce
    run_file(report_dir, run_id, name)
                                      the real path of report.md, scan.json or
                                      evidence.json for that run, or None. The
                                      path must resolve to exactly
                                      <report_dir>/<run id>/<name>, so ".." in
                                      the id, a symlinked run folder or a
                                      symlinked file that points anywhere else
                                      is refused.
    find_entry(report_dir, run_id)    the run's index entry, or None
    report_view(report_dir, run_id)   everything the Report screen reads: the
                                      index entry, report.md, scan.json and
                                      what is derived from them (findings,
                                      the port spectrum, the AI summary).
                                      Never evidence.json. A code scan's
                                      input path is cut to its name.

Job progress events (see reconmind/core/events.py):

    read_events(path, since, limit)   the complete JSON lines after the first
                                      `since` lines, as (events, next, more)

Nothing here writes a file.
"""

import json
import os
import re

from reconmind.core import history
from reconmind.core import report as report_mod
from reconmind.tools.risky_services import SEVERITY_ORDER, flag_ports
from reconmind.tools.testssl_scan import finding_severity as tls_finding_severity
from reconmind.tools.testssl_scan import finding_title as tls_finding_title

# new_run_id makes "<YYYYmmdd_HHMMSS>_<target with [A-Za-z0-9.] kept>", and a
# clash adds "_<n>". Nothing else is a run id.
RUN_ID = re.compile(r"[0-9]{8}_[0-9]{6}_[A-Za-z0-9._]{1,160}")
RUN_FILES = (history.REPORT_NAME, history.SCAN_NAME, history.EVIDENCE_NAME)

MAX_EVENTS = 500
MAX_EVIDENCE_LINES = 12
MAX_TITLE_CHARS = 160
MAX_EXPLOITS_SHOWN = 3

SEVERITY_RANK = dict(SEVERITY_ORDER, unknown=len(SEVERITY_ORDER))
RECON_SEVERITIES = tuple(SEVERITY_ORDER)

SUMMARY_HEAD = "## Analyst summary (ReconMind agent)"
SUMMARY_STOP_MARKS = ("**Unverified references**", "**ATT&CK check**")
UNVERIFIED_HEAD = "**Unverified references**"

SUMMARY_OK = "ok"
SUMMARY_OFF = "off"
SUMMARY_FAILED = "failed"
SUMMARY_RATE_LIMITED = "rate_limited"
SUMMARY_NONE = "none"

SOURCE_NAMES = {"semgrep": "Semgrep", "bandit": "Bandit"}


# ---- run ids and files -------------------------------------------------------

def valid_run_id(run_id):
    """True for a run id history.new_run_id can produce, never with "..". """
    return (isinstance(run_id, str) and bool(RUN_ID.fullmatch(run_id))
            and ".." not in run_id)


def run_file(report_dir, run_id, name):
    """
    The real path of one file of a saved run, or None when the id is not
    valid, the file is missing, or it does not resolve to exactly
    <report_dir>/<run id>/<name>.
    """
    if name not in RUN_FILES:
        raise ValueError("Unknown run file {n!r}.".format(n=name))
    if not valid_run_id(run_id):
        return None
    root = os.path.realpath(report_dir)
    expected = os.path.join(root, run_id, name)
    path = os.path.realpath(expected)
    # realpath follows every symlink, so a link anywhere on the way that
    # points elsewhere gives a different path and is refused here.
    if path != expected or os.path.commonpath([root, path]) != root:
        return None
    if not os.path.isfile(path):
        return None
    return path


def find_entry(report_dir, run_id):
    """The newest index entry for run_id, or None. Raises OSError or ValueError."""
    for entry in reversed(history.read_index(report_dir)):
        if isinstance(entry, dict) and entry.get("run_id") == run_id:
            return entry
    return None


# ---- progress events ---------------------------------------------------------

def read_events(path, since=0, limit=MAX_EVENTS):
    """
    The events after the first `since` lines of a job's events file.

    Returns (events, next, more): events are the JSON objects found, next is
    the number of lines read so far (the `since` for the next call), and more
    is True when limit stopped the read before the end of the file.

    Only complete lines count: a last line without its newline is still being
    written and is left for the next call. A line that is not a JSON object is
    skipped but still counted, so it is never read again. A missing or
    unreadable file gives no events and leaves `since` as it was.
    """
    since = max(0, int(since))
    events = []
    line_no = 0
    more = False
    try:
        fh = open(path, "rb")
    except OSError:
        return [], since, False
    with fh:
        try:
            for raw in fh:
                if not raw.endswith(b"\n"):
                    break
                if line_no < since:
                    line_no += 1
                    continue
                if len(events) >= limit:
                    more = True
                    break
                line_no += 1
                try:
                    record = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    continue
                if isinstance(record, dict):
                    events.append(record)
        except OSError:
            pass
    # A file shorter than `since` has nothing new: keep waiting at `since`.
    return events, max(line_no, since), more


# ---- deriving the report screen ---------------------------------------------

def _text(value):
    return " ".join(str(value if value is not None else "").split())


def _short(value, limit=MAX_TITLE_CHARS):
    text = _text(value)
    return text if len(text) <= limit else text[:limit - 4].rstrip() + " ..."


def _severity(value):
    key = str(value or "").strip().lower()
    return key if key in SEVERITY_RANK else None


def _port_number(value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if 1 <= number <= 65535 else None


def _ports_by_number(results):
    ports = {}
    for p in results.get("ports") or []:
        if isinstance(p, dict) and _port_number(p.get("port")) is not None:
            ports[_port_number(p.get("port"))] = p
    return ports


def _where(number, port):
    service = _text((port or {}).get("service"))
    return "Port {n}".format(n=number) + (", " + service if service else "")


def _techniques_by_port(results):
    """Port number to its confirmed ATT&CK technique ids, from attack_map."""
    mapping = results.get("attack_map")
    found = {}
    if not isinstance(mapping, dict):
        return found
    for p in mapping.get("ports") or []:
        number = _port_number(p.get("port")) if isinstance(p, dict) else None
        if number is None:
            continue
        ids = [_text(t.get("id")) for t in p.get("techniques") or []
               if isinstance(t, dict) and t.get("id")]
        found[number] = [i for n, i in enumerate(ids) if i not in ids[:n]]
    return found


def _nmap_line(port):
    parts = ["{p}/{t}".format(p=port.get("port"), t=port.get("protocol") or "tcp"), "open",
             _text(port.get("service")), _text(port.get("product")), _text(port.get("version"))]
    return "nmap  " + " ".join(part for part in parts if part)


def _flag_findings(results, ports, techniques):
    found = []
    for port, flag in flag_ports(list(ports.values())):
        number = _port_number(port.get("port"))
        reason = _text(flag.get("reason"))
        title = reason.split(". ")[0].rstrip(".") if reason else "Risky service exposed"
        evidence = [_nmap_line(port), "rule  " + reason]
        for exploit in (port.get("exploits") or [])[:MAX_EXPLOITS_SHOWN]:
            if not isinstance(exploit, dict):
                continue
            line = "searchsploit  " + _text(exploit.get("title"))
            if exploit.get("edb_id"):
                line += " (EDB-{i})".format(i=_text(exploit.get("edb_id")))
            if exploit.get("match"):
                line += " [{m}]".format(m=_text(exploit.get("match")))
            evidence.append(line)
        found.append({"severity": flag["severity"], "title": _short(title),
                      "where": _where(number, port), "port": number, "source": "Risk rule",
                      "ids": techniques.get(number, []), "evidence": evidence})
    return found


def _nuclei_line(f):
    line = "nuclei  {t}  [{s}]".format(t=_text(f.get("template_id")), s=_text(f.get("severity")))
    if f.get("matched_at"):
        line += "  matched at " + _text(f.get("matched_at"))
    return line


def _tls_line(f):
    line = "testssl.sh  {i}  [{s}]  {f}".format(i=_text(f.get("id")), s=_text(f.get("severity")),
                                                f=_text(f.get("finding")))
    if f.get("cve"):
        line += "  " + _text(f.get("cve"))
    return line


def _nuclei_severity(f):
    severity = _severity(f.get("severity"))
    # The same four levels the index counts.
    return severity if severity in RECON_SEVERITIES else None


def _tool_findings(results, ports, techniques):
    found = []
    for key, source, severity_of, title_of, line_of in (
            ("nuclei", "nuclei", _nuclei_severity,
             lambda f: f.get("name") or f.get("template_id"), _nuclei_line),
            # testssl.sh's own rule: CRITICAL to LOW only, never a cipher or
            # rating row, titled "<id> <finding>" (see testssl_scan).
            ("tls", "testssl.sh", tls_finding_severity, tls_finding_title, _tls_line)):
        results_by_port = results.get(key)
        if not isinstance(results_by_port, dict):
            continue
        for port_key, result in results_by_port.items():
            if not isinstance(result, dict) or result.get("status") != "ok":
                continue
            number = _port_number(port_key)
            for f in result.get("findings") or []:
                severity = severity_of(f) if isinstance(f, dict) else None
                if severity not in RECON_SEVERITIES:
                    continue
                evidence = [line_of(f)]
                cves = f.get("cve")
                if key == "nuclei" and cves:
                    cves = cves if isinstance(cves, list) else [cves]
                    evidence.append("CVE  " + ", ".join(_text(c) for c in cves if c))
                found.append({"severity": severity, "title": _short(title_of(f) or source),
                              "where": _where(number, ports.get(number)) if number else "",
                              "port": number, "source": source,
                              "ids": techniques.get(number, []) if number else [],
                              "evidence": evidence})
    return found


def recon_findings(results, plan=None):
    """
    The findings the index counts for a recon run, most severe first: risk
    flags (only when Exploit Hunt was in the plan, or there is no plan),
    nuclei findings and testssl.sh findings at low severity or above. Each is
    {"severity", "title", "where", "port", "source", "ids", "evidence"}; ids
    are the port's confirmed ATT&CK techniques and evidence is tool output.
    """
    if not isinstance(results, dict):
        return []
    ports = _ports_by_number(results)
    techniques = _techniques_by_port(results)
    actions = plan.get("actions") if isinstance(plan, dict) else None
    found = []
    if not isinstance(actions, list) or "exploits" in actions:
        found.extend(_flag_findings(results, ports, techniques))
    found.extend(_tool_findings(results, ports, techniques))
    found.sort(key=lambda f: (SEVERITY_RANK[f["severity"]], f["port"] or 0))
    return found


def code_findings(results):
    """
    The findings of a code run, in the order the scan sorted them. where is
    the file name and line only, never the folder it sits in. code holds only
    the saved, scan-time snippet and range, not a fresh read of source code.
    """
    found = []
    for f in (results.get("findings") if isinstance(results, dict) else None) or []:
        if not isinstance(f, dict):
            continue
        severity = _severity(f.get("severity")) or "unknown"
        messages = f.get("messages") if isinstance(f.get("messages"), dict) else {}
        rule_ids = f.get("rule_ids") if isinstance(f.get("rule_ids"), dict) else {}
        message = next((_text(m) for m in messages.values() if m), "")
        title = message.split(". ")[0] if message else next(
            (_text(r) for r in rule_ids.values() if r), "Finding")
        name = os.path.basename(str(f.get("file") or "").replace("\\", "/")) or "a file"
        where = "{n}, line {l}".format(n=name, l=f.get("line")) if f.get("line") else name
        sources = [SOURCE_NAMES.get(s, _text(s)) for s in f.get("sources") or []]
        evidence = []
        for tool, rule in rule_ids.items():
            line = "{t}  {r}".format(t=_text(tool), r=_text(rule))
            if messages.get(tool):
                line += "  " + _text(messages.get(tool))
            evidence.append(line)
        snippet = str(f.get("snippet") or "").rstrip()
        if snippet:
            evidence.extend(snippet.splitlines()[:MAX_EVIDENCE_LINES])
        # Code scans store the exact flagged snippet at scan time. Reuse that
        # saved evidence; never read the user's source files when viewing a report.
        line = f.get("line")
        try:
            line = max(1, int(line))
        except (ValueError, TypeError):
            line = 1
        end_line = f.get("end_line")
        try:
            end_line = max(line, int(end_line))
        except (ValueError, TypeError):
            end_line = line
        context = str(f.get("display_context") or "")[:12000]
        try:
            context_start = max(1, int(f.get("display_context_start")))
        except (ValueError, TypeError):
            context_start = line
        found.append({"severity": severity, "title": _short(title), "where": where,
                      "port": None, "source": " and ".join(sources),
                      "ids": [_text(c) for c in f.get("cwe") or [] if c], "evidence": evidence,
                      "code": {"file": name, "line": line, "end_line": end_line,
                               "snippet": snippet[:12000],
                               "context": context, "context_start": context_start,
                               "rule_ids": {str(k): _short(v) for k, v in rule_ids.items()}}})
    return found


def spectrum(results, findings):
    """Every open port with its worst finding: [{"port", "service", "severity"}]."""
    worst = {}
    for f in findings:
        if f.get("port") is None:
            continue
        old = worst.get(f["port"])
        if old is None or SEVERITY_RANK[f["severity"]] < SEVERITY_RANK[old]:
            worst[f["port"]] = f["severity"]
    ports = _ports_by_number(results) if isinstance(results, dict) else {}
    return [{"port": n, "service": _text(p.get("service")), "severity": worst.get(n, "none")}
            for n, p in sorted(ports.items())]


def summary(markdown, entry=None):
    """
    The AI summary from report.md: {"state", "text", "unverified"}. state is
    "ok", "off" (AI analysis was off), "failed", "rate_limited" or "none"
    (no summary section, as for a refused or stopped run).
    """
    result = {"state": SUMMARY_NONE, "text": None, "unverified": []}
    if not isinstance(markdown, str):
        return result
    if report_mod.STANDARD_NOTE in markdown or (
            isinstance(entry, dict) and entry.get("mode") == report_mod.MODE_STANDARD):
        result["state"] = SUMMARY_OFF
        return result
    lines = markdown.splitlines()
    try:
        start = lines.index(SUMMARY_HEAD) + 1
    except ValueError:
        return result
    end = next((i for i in range(start, len(lines)) if lines[i].startswith("## ")), len(lines))
    section = lines[start:end]
    body = "\n".join(section)
    if report_mod.SUMMARY_RATE_LIMITED in body:
        result["state"] = SUMMARY_RATE_LIMITED
        return result
    if report_mod.SUMMARY_UNAVAILABLE in body:
        result["state"] = SUMMARY_FAILED
        return result
    text = []
    for line in section:
        if line.strip() in SUMMARY_STOP_MARKS:
            break
        if line.strip() != report_mod.SUMMARY_LABEL:
            text.append(line)
    if UNVERIFIED_HEAD in section:
        for line in section[section.index(UNVERIFIED_HEAD) + 1:]:
            if line.strip() in SUMMARY_STOP_MARKS:
                break
            if line.startswith("- "):
                result["unverified"].append(line[2:].strip())
    result["text"] = "\n".join(text).strip() or None
    result["state"] = SUMMARY_OK if result["text"] else SUMMARY_FAILED
    return result


def _base_name(path):
    """The last part of a path, whichever separator it uses."""
    text = str(path).replace("\\", "/").rstrip("/")
    return text.rsplit("/", 1)[-1] or text


def _read_text(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def report_view(report_dir, run_id):
    """
    The Report screen's data, or None when there is no such run:

        {"run_id", "kind", "entry", "markdown", "scan", "findings",
         "spectrum", "summary", "has_evidence", "warnings"}

    entry is the index entry (None when the index does not list the run).
    scan is scan.json as saved (None with a warning when it cannot be read).
    Raises OSError when report.md exists but cannot be read.
    """
    report_path = run_file(report_dir, run_id, history.REPORT_NAME)
    if report_path is None:
        return None
    markdown = _read_text(report_path)
    warnings = []

    entry = None
    try:
        entry = find_entry(report_dir, run_id)
    except (OSError, ValueError):
        warnings.append("The report history could not be read, so some details are missing.")

    scan = None
    scan_path = run_file(report_dir, run_id, history.SCAN_NAME)
    if scan_path is not None:
        try:
            with open(scan_path, encoding="utf-8") as fh:
                scan = json.load(fh)
        except (OSError, ValueError):
            scan = None
        if not isinstance(scan, dict):
            scan = None
            warnings.append("The scan data could not be read, so only the summary is shown.")
    else:
        warnings.append("This run has no scan data, so only the summary is shown.")

    kind = history.entry_kind(entry) if isinstance(entry, dict) else (
        (scan or {}).get("kind") or history.KIND_RECON)
    results = (scan or {}).get("results")
    results = results if isinstance(results, dict) else {}
    if kind == history.KIND_CODE:
        # A code scan's input is a path on this machine: hand out its name only.
        if isinstance(entry, dict) and entry.get("input"):
            entry = dict(entry, input=_base_name(entry["input"]))
        if results.get("input"):
            results = dict(results, input=_base_name(results["input"]))
            scan = dict(scan, results=results)
        findings = code_findings(results)
        ports = []
    else:
        findings = recon_findings(results, (scan or {}).get("plan"))
        ports = spectrum(results, findings)

    return {
        "run_id": run_id,
        "kind": kind,
        "entry": entry,
        "markdown": markdown,
        "scan": scan,
        "findings": findings,
        "spectrum": ports,
        "summary": summary(markdown, entry),
        "has_evidence": run_file(report_dir, run_id, history.EVIDENCE_NAME) is not None,
        "warnings": warnings,
    }
