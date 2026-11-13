"""
ReconMind Bandit tool (code scan, Python only).

run_bandit(path) runs "bandit -r <path> -f json -q" on Python code that is
only read, never run. Bandit works offline and makes no network calls.
code_scan runs it only when the input holds Python files; otherwise
not_run_result() records why it did not run.

Each finding keeps test_id, test_name, issue_text, issue_severity,
issue_confidence, the CWE id and link, filename, line_number, line_range,
code and more_info exactly as Bandit wrote them, plus a snippet ReconMind
reads from the file using line_range.
"""

import json
import os
import shlex
import shutil
import subprocess

from reconmind.code.inputs import read_snippet

BINARY_NAME = "bandit"
SCAN_TIMEOUT = 600
VERSION_TIMEOUT = 60
# 0: no issues. 1: issues were found. Neither is an error.
OK_EXIT_CODES = (0, 1)
SHOWN_ERRORS = 20

STATUS_OK = "ok"
STATUS_NOT_FOUND = "bandit-not-found"
STATUS_NO_PYTHON = "no-python-files"
STATUS_TIMEOUT = "timeout"
STATUS_FAILED = "failed"
STATUS_BAD_JSON = "bad-json"

NOT_INSTALLED = ("bandit is not installed on this machine. Install it with: "
                 "pip install -r requirements-code.txt")
NO_PYTHON = "The input has no Python files, so Bandit was not run."


def tool_version():
    """The first line "bandit --version" prints, or "" when it gives none."""
    try:
        proc = subprocess.run([BINARY_NAME, "--version"], capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=VERSION_TIMEOUT)
    except (subprocess.TimeoutExpired, OSError):
        return ""
    for line in (proc.stdout or "").splitlines():
        if line.strip():
            return line.strip()
    return ""


def _finding(obj, root):
    cwe = obj.get("issue_cwe") if isinstance(obj.get("issue_cwe"), dict) else {}
    line_range = obj.get("line_range") if isinstance(obj.get("line_range"), list) else []
    finding = {
        "test_id": obj.get("test_id", ""),
        "test_name": obj.get("test_name", ""),
        "issue_text": obj.get("issue_text", ""),
        "issue_severity": obj.get("issue_severity", ""),
        "issue_confidence": obj.get("issue_confidence", ""),
        "cwe_id": cwe.get("id"),
        "cwe_link": cwe.get("link", ""),
        "filename": obj.get("filename", ""),
        "line_number": obj.get("line_number"),
        "line_range": line_range,
        "code": obj.get("code", ""),
        "more_info": obj.get("more_info", ""),
    }
    numbers = [n for n in line_range if isinstance(n, int)] or [finding["line_number"]]
    numbers = [n for n in numbers if isinstance(n, int)]
    finding["snippet"] = (read_snippet(root, finding["filename"], min(numbers), max(numbers))
                          if numbers else "")
    return finding


def _error_text(error):
    if isinstance(error, dict):
        return "{f}: {r}".format(f=error.get("filename", ""), r=error.get("reason", ""))
    return str(error)


def parse_output(text, root):
    """(status, findings, tool_errors, error) for Bandit's JSON output."""
    try:
        data = json.loads(text or "")
    except ValueError as exc:
        return STATUS_BAD_JSON, [], [], "Bandit output is not valid JSON: {e}".format(e=exc)
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return STATUS_BAD_JSON, [], [], "Bandit output has no results list."
    findings = [_finding(obj, root) for obj in data["results"] if isinstance(obj, dict)]
    errors = [_error_text(e) for e in data.get("errors") or []]
    return STATUS_OK, findings, errors, ""


def _result(status, version="", command="", findings=None, tool_errors=(), error=""):
    tool_errors = list(tool_errors)
    result = {"tool": "bandit", "status": status, "version": version, "command": command,
              "findings": findings or [], "tool_errors": tool_errors[:SHOWN_ERRORS],
              "tool_error_count": len(tool_errors)}
    if error:
        result["error"] = error
    return result


def not_run_result():
    """The result recorded when the input holds no Python files."""
    return _result(STATUS_NO_PYTHON, error=NO_PYTHON)


def run_bandit(path):
    """
    Run Bandit on path and return:
        {"tool", "status", "version", "command", "findings": [{"test_id",
         "test_name", "issue_text", "issue_severity", "issue_confidence",
         "cwe_id", "cwe_link", "filename", "line_number", "line_range",
         "code", "more_info", "snippet"}], "tool_errors", "tool_error_count"}
    plus "error" when status is not "ok". Never raises for a tool problem.
    """
    root = os.path.realpath(path)
    if shutil.which(BINARY_NAME) is None:
        return _result(STATUS_NOT_FOUND, error=NOT_INSTALLED)
    version = tool_version()

    cmd = [BINARY_NAME, "-r", root, "-f", "json", "-q"]
    command = shlex.join(cmd)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL,
                              timeout=SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        return _result(STATUS_TIMEOUT, version=version, command=command,
                       error="Bandit did not finish within {s} seconds.".format(
                           s=SCAN_TIMEOUT))
    except OSError as exc:
        return _result(STATUS_FAILED, version=version, command=command,
                       error="Bandit could not be started: {e}".format(e=exc))

    if proc.returncode not in OK_EXIT_CODES:
        stderr = (proc.stderr or "").strip().splitlines()
        error = "Bandit exited with code {c}".format(c=proc.returncode)
        error += ": {s}".format(s=stderr[0]) if stderr else "."
        return _result(STATUS_FAILED, version=version, command=command, error=error)

    status, findings, tool_errors, error = parse_output(proc.stdout, root)
    return _result(status, version=version, command=command, findings=findings,
                   tool_errors=tool_errors, error=error)
