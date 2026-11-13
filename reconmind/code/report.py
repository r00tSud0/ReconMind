"""
ReconMind Code Report.

build_code_report(scan, path) writes the Markdown report for one code scan
(the dict run_code_scan returns):

    input path, scan status and the fixed line on what a finding means
    files scanned per language
    each tool with its version, the Semgrep rules commit and any warning,
    the exact commands, and every tool that did not run with its status
    counts by severity
    every finding, most severe first, then by file and line: severity,
    file:line, CWE, which tool or tools found it, rule or test id, each
    tool's own message, the snippet and the reference links
    the AI explanation, only when --explain was given, after the findings,
    labeled as AI interpretation

Tool values are printed exactly as the tool wrote them.
"""

import os
from datetime import datetime

from reconmind.code.code_scan import SEVERITIES, UNKNOWN_SEVERITY
from reconmind.code.inputs import language_of

TITLE = "# ReconMind Code Report"
FIXED_LINE = ("Findings come from Semgrep and Bandit pattern rules. Each one marks code that "
              "matches a known vulnerable pattern and needs a human review to confirm.")
TOOL_NAMES = {"semgrep": "Semgrep", "bandit": "Bandit"}
NOT_REPORTED = "not reported"

FILES_HEAD = "## Files scanned"
TOOLS_HEAD = "## Tools"
COUNTS_HEAD = "## Findings by severity"
FINDINGS_HEAD = "## Findings"
NO_FINDINGS = "_Neither tool reported a security finding._"
NO_TOOL_RAN = "_No tool ran, so the code was not checked._"
NO_SNIPPET = "_The snippet could not be read from the file._"

EXPLAIN_HEAD = "## AI explanation"
EXPLAIN_LABEL = ("_AI interpretation of the tool findings above. It does not add, remove or "
                 "change any finding._")
EXPLAIN_SENT = ("_Finding details and code snippets were sent to the configured LLM provider "
                "({p}, model {m}). Whole files were not sent._")
EXPLAIN_SKIPPED = "AI explanation skipped: {r}. This report has the tool findings only."
UNVERIFIED_HEAD = "**Unverified references**"
UNVERIFIED_NOTE = "_Not found in any finding the tools reported:_"


def _tool_name(key):
    return TOOL_NAMES.get(key, key)


def _cell(text):
    return str(text or "").replace("|", "\\|").replace("\n", " ")


def _files_section(lines, files):
    lines.append(FILES_HEAD)
    lines.append("")
    lines.append("| Language | Files |")
    lines.append("|----------|-------|")
    for language, count in sorted((files.get("languages") or {}).items()):
        lines.append("| {l} | {n} |".format(l=language, n=count))
    lines.append("")
    lines.append("Total: {n} source file(s), {b} bytes.".format(
        n=files.get("count", 0), b=files.get("bytes", 0)))
    lines.append("")


def _tools_section(lines, tools):
    lines.append(TOOLS_HEAD)
    lines.append("")
    lines.append("| Tool | Status | Version |")
    lines.append("|------|--------|---------|")
    for key, result in tools.items():
        lines.append("| {t} | {s} | {v} |".format(
            t=_tool_name(key), s=_cell(result.get("status")),
            v=_cell(result.get("version")) or NOT_REPORTED))
    lines.append("")

    semgrep = tools.get("semgrep") or {}
    if semgrep.get("rules_path"):
        lines.append("**Semgrep rules:** `{p}`, commit `{c}` (pinned `{x}`)".format(
            p=semgrep["rules_path"], c=semgrep.get("rules_commit") or "unknown",
            x=semgrep.get("pinned_commit", "")))
        if semgrep.get("languages"):
            lines.append("")
            lines.append("**Semgrep rule folders used:** {l}".format(
                l=", ".join(semgrep["languages"])))
        if semgrep.get("warning"):
            lines.append("")
            lines.append("**Warning:** {w}".format(w=semgrep["warning"]))
        lines.append("")

    for key, result in tools.items():
        if result.get("command"):
            lines.append("**{t} command:** `{c}`".format(t=_tool_name(key), c=result["command"]))
            lines.append("")
        if result.get("tool_error_count"):
            lines.append("**{t} reported {n} error(s) while scanning:**".format(
                t=_tool_name(key), n=result["tool_error_count"]))
            for error in result.get("tool_errors") or []:
                lines.append("* {e}".format(e=str(error).replace("\n", " ")))
            lines.append("")

    did_not_run = [(k, r) for k, r in tools.items() if r.get("status") != "ok"]
    if did_not_run:
        lines.append("**Did not run:**")
        lines.append("")
        for key, result in did_not_run:
            lines.append("* {t}: {s}. {e}".format(
                t=_tool_name(key), s=result.get("status"),
                e=result.get("error", "")).rstrip())
        lines.append("")


def _counts_section(lines, counts):
    lines.append(COUNTS_HEAD)
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for severity in SEVERITIES:
        lines.append("| {s} | {n} |".format(s=severity.capitalize(), n=counts.get(severity, 0)))
    if counts.get(UNKNOWN_SEVERITY):
        lines.append("| {s} | {n} |".format(s=UNKNOWN_SEVERITY.capitalize(),
                                            n=counts[UNKNOWN_SEVERITY]))
    lines.append("")


def _location(finding):
    text = "{f}:{n}".format(f=finding.get("file", ""), n=finding.get("line", 0))
    if (finding.get("end_line") or 0) > (finding.get("line") or 0):
        text += " (lines {a} to {b})".format(a=finding["line"], b=finding["end_line"])
    return text


def _fence(snippet):
    fence = "```"
    while fence in snippet:
        fence += "`"
    return fence


def _semgrep_lines(lines, s):
    details = ", ".join("{k} {v}".format(k=k, v=s.get(k)) for k in
                        ("severity", "confidence", "likelihood", "impact") if s.get(k))
    lines.append("* **Semgrep rule:** `{r}`{d}".format(
        r=s.get("rule_id", ""), d=" ({d})".format(d=details) if details else ""))
    lines.append("* **Semgrep message:** {m}".format(m=s.get("message", "")))
    if s.get("cwe"):
        lines.append("* **Semgrep CWE:** {c}".format(c="; ".join(str(c) for c in s["cwe"])))
    if s.get("owasp"):
        lines.append("* **Semgrep OWASP:** {o}".format(o="; ".join(str(o) for o in s["owasp"])))


def _bandit_lines(lines, b):
    lines.append("* **Bandit test:** `{i}` {n} (severity {s}, confidence {c})".format(
        i=b.get("test_id", ""), n=b.get("test_name", ""), s=b.get("issue_severity", ""),
        c=b.get("issue_confidence", "")))
    lines.append("* **Bandit message:** {m}".format(m=b.get("issue_text", "")))


def _finding_section(lines, number, finding):
    lines.append("### {n}. {s} at {l}".format(
        n=number, s=finding.get("severity", "").upper(), l=_location(finding)))
    lines.append("")
    lines.append("* **Severity:** {s} (tool values: {t})".format(
        s=finding.get("severity", ""),
        t=", ".join("{k} {v}".format(k=_tool_name(k), v=v)
                    for k, v in (finding.get("tool_severity") or {}).items())))
    lines.append("* **CWE:** {c}".format(c=", ".join(finding.get("cwe") or []) or "none given"))
    lines.append("* **Found by:** {t}".format(
        t=" and ".join(_tool_name(s) for s in finding.get("sources") or [])))
    if finding.get("semgrep"):
        _semgrep_lines(lines, finding["semgrep"])
    if finding.get("bandit"):
        _bandit_lines(lines, finding["bandit"])
    lines.append("")

    snippet = finding.get("snippet") or ""
    if snippet:
        fence = _fence(snippet)
        lines.append(fence + (language_of(finding.get("file", "")) or ""))
        lines.append(snippet)
        lines.append(fence)
    else:
        lines.append(NO_SNIPPET)
    lines.append("")

    if finding.get("references"):
        lines.append("**References:**")
        lines.append("")
        for ref in finding["references"]:
            lines.append("* {r}".format(r=ref))
        lines.append("")


def _findings_section(lines, scan):
    lines.append(FINDINGS_HEAD)
    lines.append("")
    findings = scan.get("findings") or []
    if not findings:
        lines.append(NO_FINDINGS if scan.get("status") == "ok" else NO_TOOL_RAN)
        lines.append("")
        return
    for number, finding in enumerate(findings, start=1):
        _finding_section(lines, number, finding)


def _explanation_section(lines, explanation):
    if explanation is None:
        return
    lines.append(EXPLAIN_HEAD)
    lines.append("")
    if explanation.get("sent"):
        lines.append(EXPLAIN_SENT.format(p=explanation.get("provider") or "unknown",
                                         m=explanation.get("model") or "unknown"))
        lines.append("")
    if explanation.get("status") != "ok":
        lines.append(EXPLAIN_SKIPPED.format(r=explanation.get("reason") or "no reason given"))
        lines.append("")
        return
    lines.append(EXPLAIN_LABEL)
    lines.append("")
    lines.append(explanation.get("text", "").strip())
    lines.append("")
    if explanation.get("unverified"):
        lines.append(UNVERIFIED_HEAD)
        lines.append("")
        lines.append(UNVERIFIED_NOTE)
        for ref in explanation["unverified"]:
            lines.append("* {r}".format(r=ref))
        lines.append("")


def render_code_report(scan, generated=None):
    """The report text for one code scan."""
    generated = generated or datetime.now()
    lines = [
        TITLE,
        "",
        "**Input:** {i}".format(i=scan.get("input", "")),
        "**Scan status:** {s}".format(s=scan.get("status", "unknown")),
        "**Generated:** {g}".format(g=generated.strftime("%Y-%m-%d %H:%M:%S")),
        "",
        FIXED_LINE,
        "",
    ]
    _files_section(lines, scan.get("files") or {})
    _tools_section(lines, scan.get("tools") or {})
    _counts_section(lines, scan.get("counts") or {})
    _findings_section(lines, scan)
    _explanation_section(lines, scan.get("explanation"))
    return "\n".join(lines).rstrip("\n") + "\n"


def build_code_report(scan, path):
    """Write the report for one code scan to path. Return path."""
    if os.path.dirname(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(render_code_report(scan))
    return path
