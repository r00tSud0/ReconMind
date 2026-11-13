"""
ReconMind nuclei tool (Stage 2, template checks).

A thin wrapper around nuclei. The only entry point is
run_nuclei(target_ip, port, use_https=False), and like run_nmap its very first
action is to ask the authorization gate whether the target is allowed. If the
gate says no, nuclei is never launched.

Safe templates only: HTTP templates rated low or higher, with denial of
service, fuzzing, intrusive, default login and brute force templates excluded
by tag. Interactsh is off, so no template can make the target call out to an
outside server. Update checks are off, so templates are never downloaded or
updated during a scan; the operator installs them once with
"nuclei -update-templates". The rate is capped at 50 requests per second.

Findings are read from nuclei's JSONL output, one JSON object per line, with
values kept exactly as nuclei wrote them. The whole JSONL file is kept as
"raw_jsonl", which is evidence only: it is never sent to the model or printed
in the report.
"""

import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile

from reconmind.core.authorization import is_authorized
from reconmind.tools.whatweb_scan import build_url

BINARY_NAME = "nuclei"

SEVERITIES = "low,medium,high,critical"
EXCLUDED_TAGS = "dos,fuzz,intrusive,default-login,bruteforce,brute-force"

# No -update-templates, no credentials, no headers, no proxies, no interactsh.
NUCLEI_FLAGS = ["-type", "http", "-severity", SEVERITIES, "-exclude-tags", EXCLUDED_TAGS,
                "-no-interactsh", "-disable-update-check", "-rate-limit", "50",
                "-concurrency", "10", "-timeout", "10", "-retries", "1", "-omit-raw",
                "-no-color", "-silent", "-jsonl"]
NUCLEI_TIMEOUT = 1800
JSONL_BASENAME = "nuclei.jsonl"

# How templates are picked. Both keep every flag in NUCLEI_FLAGS.
# deep: exactly the command above, every safe template.
# auto: adds -automatic-scan, so nuclei detects the web technology first and
#       runs only the templates tagged for it.
MODE_DEEP = "deep"
MODE_AUTO = "auto"
MODES = (MODE_DEEP, MODE_AUTO)
MODE_FLAGS = {MODE_DEEP: [], MODE_AUTO: ["-automatic-scan"]}

# -disable-update-check stops nuclei from installing templates on its own
# when none are present, so this check never downloads anything.
VERSION_FLAGS = ["-templates-version", "-no-color", "-disable-update-check"]
VERSION_TIMEOUT = 60
# nuclei's banner also prints its own engine version, so only the templates
# line counts, e.g. "[INF] Public nuclei-templates version: v10.5.2 (...)".
_TEMPLATES_VERSION = re.compile(r"templates version:?\s*(v?\d+(?:\.\d+)+)", re.IGNORECASE)
UPDATE_HINT = ("No nuclei templates are installed. Run \"nuclei -update-templates\" "
               "once, then scan again.")

# Most severe first. Anything not listed sorts last.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")

STATUS_OK = "ok"
STATUS_REFUSED = "refused"
STATUS_BAD_PORT = "bad-port"
STATUS_BAD_MODE = "bad-mode"
STATUS_NOT_FOUND = "nuclei-not-found"
STATUS_NO_TEMPLATES = "templates-not-found"
STATUS_TIMEOUT = "timeout"
STATUS_FAILED = "failed"
STATUS_BAD_JSONL = "bad-jsonl"


def _result(status, url="", templates_version="", command="", findings=None,
            raw_jsonl="", error="", mode=""):
    result = {"status": status, "url": url, "templates_version": templates_version,
              "mode": mode, "command": command, "findings": findings or [],
              "raw_jsonl": raw_jsonl or ""}
    if error:
        result["error"] = error
    return result


def severity_rank(severity):
    """Sort key: 0 for critical, then high, medium, low, info, unknown."""
    text = str(severity or "").lower()
    return SEVERITY_ORDER.index(text) if text in SEVERITY_ORDER else len(SEVERITY_ORDER)


def parse_templates_version(text):
    """The templates version nuclei printed, e.g. "v10.5.2", or "" if none."""
    match = _TEMPLATES_VERSION.search(text or "")
    return match.group(1) if match else ""


def _as_list(value):
    """nuclei writes these as lists; null becomes [], a lone string [string]."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _finding(obj):
    info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
    classification = (info.get("classification")
                      if isinstance(info.get("classification"), dict) else {})
    return {"template_id": obj.get("template-id", ""), "name": info.get("name", ""),
            "severity": info.get("severity", ""), "matched_at": obj.get("matched-at", ""),
            "matcher_name": obj.get("matcher-name", ""),
            "extracted": _as_list(obj.get("extracted-results")),
            "cve": _as_list(classification.get("cve-id")),
            "cwe": _as_list(classification.get("cwe-id")),
            "tags": _as_list(info.get("tags"))}


def parse_jsonl(text):
    """Return (status, findings, error) for nuclei's JSONL output, in nuclei's
    order. Blank lines are skipped."""
    findings = []
    for number, line in enumerate((text or "").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except ValueError as exc:
            return STATUS_BAD_JSONL, [], "nuclei JSONL line {n} is not valid JSON: {e}".format(
                n=number, e=exc)
        if not isinstance(obj, dict):
            return STATUS_BAD_JSONL, [], "nuclei JSONL line {n} is not an object.".format(
                n=number)
        findings.append(_finding(obj))
    return STATUS_OK, findings, ""


def templates_version():
    """Return (version, error). version is "" when no templates are installed."""
    try:
        proc = subprocess.run([BINARY_NAME] + VERSION_FLAGS, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=VERSION_TIMEOUT)
    except subprocess.TimeoutExpired:
        return "", "nuclei did not report its templates version within {s} seconds.".format(
            s=VERSION_TIMEOUT)
    except OSError as exc:
        return "", "nuclei could not be started: {e}".format(e=exc)
    output = "\n".join(x for x in (proc.stdout, proc.stderr) if x)
    return parse_templates_version(output), ""


def run_nuclei(target_ip, port, use_https=False, mode=MODE_DEEP):
    """
    Run safe nuclei templates against one web port of one authorized target
    and return:
        {"status", "url", "templates_version", "mode", "command", "findings":
         [{"template_id", "name", "severity", "matched_at", "matcher_name",
         "extracted", "cve", "cwe", "tags"}], "raw_jsonl"}
    plus "error" when status is not "ok". No findings is status "ok" with an
    empty list. raw_jsonl is nuclei's whole JSONL file, kept as evidence; it
    is never sent to the model or printed in the report.
    mode is "deep" (the default, every safe template) or "auto" (adds
    -automatic-scan); anything else gives status "bad-mode" and nuclei never
    runs. The mode used is recorded in "mode".
    If the gate refuses the target, status is "refused" and nuclei never runs.
    If nuclei is not installed, status is "nuclei-not-found". If no templates
    are installed, status is "templates-not-found".
    """
    # The gate decides first. Nothing happens if it says no.
    if not is_authorized(target_ip):
        return _result(STATUS_REFUSED)

    if mode not in MODES:
        return _result(STATUS_BAD_MODE, error="Mode {m!r} is not one of: {v}.".format(
            m=mode, v=", ".join(MODES)))

    try:
        port = int(port)
    except (TypeError, ValueError):
        return _result(STATUS_BAD_PORT, error="Port {p} is not a number.".format(p=port))
    if not 1 <= port <= 65535:
        return _result(STATUS_BAD_PORT, error="Port {p} is out of range.".format(p=port))
    url = build_url(target_ip, port, use_https)

    # Make sure nuclei is actually present before trying to call it.
    if shutil.which(BINARY_NAME) is None:
        return _result(STATUS_NOT_FOUND, url=url, mode=mode,
                       error="nuclei is not installed on this machine.")

    version, error = templates_version()
    if error:
        return _result(STATUS_FAILED, url=url, mode=mode, error=error)
    if not version:
        return _result(STATUS_NO_TEMPLATES, url=url, mode=mode, error=UPDATE_HINT)
    facts = {"url": url, "templates_version": version, "mode": mode}

    # A fresh temp directory, so the output name is always new.
    temp_dir = tempfile.mkdtemp(prefix="reconmind_nuclei_")
    jsonl_path = os.path.join(temp_dir, JSONL_BASENAME)
    cmd = [BINARY_NAME, "-u", url] + NUCLEI_FLAGS + MODE_FLAGS[mode] + ["-o", jsonl_path]
    command = shlex.join(cmd)
    try:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  stdin=subprocess.DEVNULL, timeout=NUCLEI_TIMEOUT)
        except subprocess.TimeoutExpired:
            return _result(STATUS_TIMEOUT, command=command,
                           error="nuclei did not finish within {s} seconds.".format(
                               s=NUCLEI_TIMEOUT), **facts)
        except OSError as exc:
            return _result(STATUS_FAILED, command=command,
                           error="nuclei could not be started: {e}".format(e=exc), **facts)
        text = ""
        # nuclei writes no file when it finds nothing.
        if os.path.exists(jsonl_path):
            try:
                with open(jsonl_path) as fh:
                    text = fh.read()
            except OSError as exc:
                return _result(STATUS_BAD_JSONL, command=command,
                               error="nuclei JSONL could not be read: {e}".format(e=exc),
                               **facts)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    returncode = getattr(proc, "returncode", 0)
    if returncode and not text.strip():
        stderr = (getattr(proc, "stderr", "") or "").strip().splitlines()
        error = "nuclei exited with code {c}".format(c=returncode)
        error += (": {s}".format(s=stderr[0]) if stderr else ".")
        return _result(STATUS_FAILED, command=command, raw_jsonl=text, error=error, **facts)

    status, findings, error = parse_jsonl(text)
    return _result(status, command=command, findings=findings, raw_jsonl=text,
                   error=error, **facts)


if __name__ == "__main__":
    import sys
    args = [a for a in sys.argv[1:] if a != "--https"]
    if len(args) != 2:
        print("usage: python3 -m reconmind.tools.nuclei_scan <target_ip> <port> [--https]")
        sys.exit(1)
    result = run_nuclei(args[0], args[1], use_https="--https" in sys.argv[1:])
    print("url:", result["url"], " status:", result["status"],
          " templates:", result["templates_version"] or "unknown")
    if result.get("error"):
        print("error:", result["error"])
    for f in sorted(result["findings"], key=lambda f: severity_rank(f["severity"])):
        print("  [{s}] {n} ({t}) at {m}{c}".format(
            s=f["severity"], n=f["name"], t=f["template_id"], m=f["matched_at"],
            c="  " + ", ".join(f["cve"]) if f["cve"] else ""))
