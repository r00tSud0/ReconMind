"""
ReconMind code scan.

run_code_scan(path, explain=False) checks the input, runs Semgrep and, when
the input holds Python files, Bandit, then merges what they found. Findings
come only from these two tools. The analyzed code is only read, never run or
imported.

Merging: a Semgrep finding and a Bandit finding on the same file and line
that share a CWE become one finding listing both tools. Every other finding
stays as its tool reported it.

Severity is normalized to high, medium or low (SEMGREP_SEVERITY,
BANDIT_SEVERITY); a value outside those tables becomes "unknown". Each
tool's own value is kept in "tool_severity". Findings are ordered most
severe first, with unknown after low, then by file and line.

Only with explain=True does explain.py write the optional AI explanation,
after both tools finished. It never changes the findings.
"""

import re

from reconmind.code.bandit_scan import not_run_result, run_bandit
from reconmind.code.inputs import resolve_reported, validate_input
from reconmind.code.semgrep_scan import run_semgrep

SEVERITIES = ("high", "medium", "low")
SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low",
                    "CRITICAL": "high", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
BANDIT_SEVERITY = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
UNKNOWN_SEVERITY = "unknown"  # the tool's own value is always kept beside it
SEVERITY_ORDER = SEVERITIES + (UNKNOWN_SEVERITY,)  # unknown sorts after low

STATUS_OK = "ok"
STATUS_NO_TOOL_RAN = "no-tool-ran"

_CWE = re.compile(r"CWE[\s:_-]*(\d+)", re.I)


def normalize_severity(table, value):
    """high, medium or low for a tool's severity value, "unknown" outside the table."""
    return table.get(str(value or "").strip().upper(), UNKNOWN_SEVERITY)


def severity_rank(severity):
    """0 for high, then medium, low and unknown."""
    if severity in SEVERITY_ORDER:
        return SEVERITY_ORDER.index(severity)
    return len(SEVERITY_ORDER)


def cwe_ids(values):
    """Sorted unique "CWE-<n>" ids from CWE strings or numbers."""
    numbers = set()
    for value in values or []:
        if isinstance(value, int) and not isinstance(value, bool):
            if value > 0:
                numbers.add(value)
            continue
        numbers.update(int(m.group(1)) for m in _CWE.finditer(str(value or "")))
    return ["CWE-{n}".format(n=n) for n in sorted(numbers)]


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _unique(values):
    out = []
    for value in values:
        if value and value not in out:
            out.append(value)
    return out


def _semgrep_item(finding, root):
    _, display = resolve_reported(root, finding.get("file"))
    line = _int(finding.get("start_line"))
    return {
        "severity": normalize_severity(SEMGREP_SEVERITY, finding.get("severity")),
        "file": display,
        "line": line,
        "end_line": max(_int(finding.get("end_line")), line),
        "cwe": cwe_ids(finding.get("cwe")),
        "sources": ["semgrep"],
        "rule_ids": {"semgrep": finding.get("rule_id", "")},
        "tool_severity": {"semgrep": finding.get("severity", "")},
        "messages": {"semgrep": finding.get("message", "")},
        "snippet": finding.get("snippet", ""),
        "references": _unique(finding.get("references") or []),
        "semgrep": finding,
        "bandit": None,
    }


def _bandit_item(finding, root):
    _, display = resolve_reported(root, finding.get("filename"))
    line = _int(finding.get("line_number"))
    numbers = [n for n in finding.get("line_range") or [] if isinstance(n, int)]
    return {
        "severity": normalize_severity(BANDIT_SEVERITY, finding.get("issue_severity")),
        "file": display,
        "line": line,
        "end_line": max(numbers + [line]),
        "cwe": cwe_ids([finding.get("cwe_id")]),
        "sources": ["bandit"],
        "rule_ids": {"bandit": finding.get("test_id", "")},
        "tool_severity": {"bandit": finding.get("issue_severity", "")},
        "messages": {"bandit": finding.get("issue_text", "")},
        "snippet": finding.get("snippet", ""),
        "references": _unique([finding.get("more_info"), finding.get("cwe_link")]),
        "semgrep": None,
        "bandit": finding,
    }


def _combine(item, other):
    """Add a Bandit item to a Semgrep item on the same file, line and CWE."""
    if severity_rank(other["severity"]) < severity_rank(item["severity"]):
        item["severity"] = other["severity"]
    item["end_line"] = max(item["end_line"], other["end_line"])
    item["cwe"] = cwe_ids(item["cwe"] + other["cwe"])
    item["sources"] = item["sources"] + other["sources"]
    for key in ("rule_ids", "tool_severity", "messages"):
        item[key] = dict(item[key], **other[key])
    item["snippet"] = item["snippet"] or other["snippet"]
    item["references"] = _unique(item["references"] + other["references"])
    item["bandit"] = other["bandit"]


def sort_key(item):
    return (severity_rank(item["severity"]), item["file"], item["line"])


def merge(semgrep_findings, bandit_findings, root):
    """One list of findings from both tools, merged and sorted."""
    items = [_semgrep_item(f, root) for f in semgrep_findings or []]
    for finding in bandit_findings or []:
        other = _bandit_item(finding, root)
        match = next((i for i in items
                      if i["semgrep"] is not None and i["bandit"] is None
                      and i["file"] == other["file"] and i["line"] == other["line"]
                      and set(i["cwe"]) & set(other["cwe"])), None)
        if match is None:
            items.append(other)
        else:
            _combine(match, other)
    items.sort(key=sort_key)
    return items


def severity_counts(findings):
    """{"high", "medium", "low"} counts, plus "unknown" only when there is one."""
    counts = dict.fromkeys(SEVERITIES, 0)
    unknown = 0
    for finding in findings or []:
        if finding.get("severity") in counts:
            counts[finding["severity"]] += 1
        else:
            unknown += 1
    if unknown:
        counts[UNKNOWN_SEVERITY] = unknown
    return counts


def run_code_scan(path, explain=False, provider=None, model=None, client=None):
    """
    Scan the code at path and return the scan dict:
        {"kind": "code", "input", "input_type", "status", "files": {"count",
         "bytes", "languages"}, "tools": {"semgrep", "bandit"}, "findings",
         "counts", "explanation"}
    Raises inputs.InputError when the input cannot be scanned. explanation is
    None unless explain is True. provider, model and client are used only by
    the explanation.
    """
    code_input = validate_input(path)
    languages = dict(sorted(code_input.languages.items()))

    semgrep = run_semgrep(code_input.root, list(languages))
    bandit = run_bandit(code_input.root) if "python" in languages else not_run_result()

    findings = merge(semgrep["findings"] if semgrep["status"] == STATUS_OK else [],
                     bandit["findings"] if bandit["status"] == STATUS_OK else [],
                     code_input.root)
    ran = any(t["status"] == STATUS_OK for t in (semgrep, bandit))
    scan = {
        "kind": "code",
        "input": code_input.root,
        "input_type": "folder" if code_input.is_dir else "file",
        "status": STATUS_OK if ran else STATUS_NO_TOOL_RAN,
        "files": {"count": len(code_input.files), "bytes": code_input.total_bytes,
                  "languages": languages},
        "tools": {"semgrep": semgrep, "bandit": bandit},
        "findings": findings,
        "counts": severity_counts(findings),
        "explanation": None,
    }
    if explain:
        # Imported here so a scan without --explain never loads the LLM code.
        from reconmind.code.explain import explain_findings
        scan["explanation"] = explain_findings(findings, provider=provider, model=model,
                                               client=client)
    return scan
