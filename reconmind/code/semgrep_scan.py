"""
ReconMind Semgrep tool (code scan).

run_semgrep(path, languages) runs Semgrep on code that is only read, never
run, and with no network access:

    rules come from a local clone of semgrep-rules (RECONMIND_SEMGREP_RULES,
    default ~/.local/share/reconmind/semgrep-rules), one --config folder per
    detected language that has one, never from the registry
    --metrics=off plus SEMGREP_SEND_METRICS=off, so nothing is reported home
    --disable-version-check plus SEMGREP_ENABLE_VERSION_CHECK=0, so Semgrep
    never asks for a newer version (also for "semgrep --version")

The rules commit is read from the clone's .git files (no git command) and
compared with PINNED_COMMIT; a different or unreadable commit adds a warning.

Only results whose extra.metadata.category is "security" are kept, with
values exactly as Semgrep wrote them. The snippet is read by ReconMind from
the file using the line numbers, because Semgrep may print "requires login"
in place of the lines.
"""

import json
import os
import re
import shlex
import shutil
import subprocess

from reconmind.code.inputs import read_snippet

BINARY_NAME = "semgrep"
RULES_ENV = "RECONMIND_SEMGREP_RULES"
DEFAULT_RULES = "~/.local/share/reconmind/semgrep-rules"
RULES_REPO = "https://github.com/semgrep/semgrep-rules"
PINNED_COMMIT = "311ca4e9ba59d700624539bf658e3d29b134ee77"
SETUP_COMMAND = "git clone {repo} {d} && git -C {d} checkout {c}"

SCAN_FLAGS = ["--json", "--metrics=off", "--disable-version-check", "--quiet",
              "--timeout", "30", "--max-target-bytes", "1000000"]
QUIET_ENV = {"SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
SCAN_TIMEOUT = 600
VERSION_TIMEOUT = 60
# 0: scan finished. 1: findings were found and the rules asked Semgrep to
# fail on them. Neither is an error.
OK_EXIT_CODES = (0, 1)
SECURITY_CATEGORY = "security"
SHOWN_ERRORS = 20

STATUS_OK = "ok"
STATUS_NOT_FOUND = "semgrep-not-found"
STATUS_NO_RULES = "rules-not-found"
STATUS_NO_LANGUAGE_RULES = "no-rules-for-languages"
STATUS_TIMEOUT = "timeout"
STATUS_FAILED = "failed"
STATUS_BAD_JSON = "bad-json"

NOT_INSTALLED = ("semgrep is not installed on this machine. Install it with: "
                 "pip install -r requirements-code.txt")
NO_RULES = "Semgrep rules were not found at {r}. Set them up once with:\n    {cmd}"
NO_LANGUAGE_RULES = "The rules folder {r} has no rules folder for: {langs}."
UNKNOWN_COMMIT = ("The rules commit could not be read from the .git folder of {r}, so "
                  "the rule set version is unknown.")
OTHER_COMMIT = ("Rules commit {c} differs from the pinned commit {p}. Findings may "
                "differ from the tested rule set. To pin it, run: git -C {r} checkout {p}")

_COMMIT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


def rules_dir():
    """The rules folder: RECONMIND_SEMGREP_RULES, else DEFAULT_RULES."""
    return os.path.expanduser(os.environ.get(RULES_ENV, "").strip() or DEFAULT_RULES)


def setup_command(rules=None):
    """The command that clones the rules and checks out the pinned commit."""
    rules = rules or rules_dir()
    shown = DEFAULT_RULES if rules == os.path.expanduser(DEFAULT_RULES) else rules
    return SETUP_COMMAND.format(repo=RULES_REPO, d=shown, c=PINNED_COMMIT)


def scan_env():
    """The environment for every Semgrep call: ours plus QUIET_ENV."""
    env = dict(os.environ)
    env.update(QUIET_ENV)
    return env


def _read(path):
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _git_dir(rules):
    dot_git = os.path.join(rules, ".git")
    if os.path.isfile(dot_git):  # a worktree or submodule: "gitdir: <path>"
        text = _read(dot_git)
        if text.startswith("gitdir:"):
            return os.path.join(rules, text[len("gitdir:"):].strip())
        return ""
    return dot_git if os.path.isdir(dot_git) else ""


def read_rules_commit(rules):
    """The commit the rules clone has checked out, read from .git, or ""."""
    git_dir = _git_dir(rules)
    if not git_dir:
        return ""
    head = _read(os.path.join(git_dir, "HEAD"))
    if head.startswith("ref:"):
        ref = head[len("ref:"):].strip()
        commit = _read(os.path.join(git_dir, *ref.split("/")))
        if not commit:
            for line in _read(os.path.join(git_dir, "packed-refs")).splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[1] == ref:
                    commit = parts[0]
                    break
    else:
        commit = head
    commit = commit.strip().lower()
    return commit if _COMMIT.match(commit) else ""


def rules_warning(commit, rules):
    """"" for the pinned commit, otherwise the warning for the report."""
    if not commit:
        return UNKNOWN_COMMIT.format(r=rules)
    if commit != PINNED_COMMIT:
        return OTHER_COMMIT.format(c=commit, p=PINNED_COMMIT, r=rules)
    return ""


def tool_version():
    """The first line "semgrep --version" prints, or "" when it gives none."""
    try:
        proc = subprocess.run([BINARY_NAME, "--version"], capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=VERSION_TIMEOUT,
                              env=scan_env())
    except (subprocess.TimeoutExpired, OSError):
        return ""
    for line in (proc.stdout or "").splitlines():
        if line.strip():
            return line.strip()
    return ""


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _dict(value):
    return value if isinstance(value, dict) else {}


def _finding(obj):
    """One kept finding, or None when the rule is not in the security category."""
    extra = _dict(obj.get("extra"))
    meta = _dict(extra.get("metadata"))
    if meta.get("category") != SECURITY_CATEGORY:
        return None
    return {
        "rule_id": obj.get("check_id", ""),
        "file": obj.get("path", ""),
        "start_line": _dict(obj.get("start")).get("line"),
        "end_line": _dict(obj.get("end")).get("line"),
        "message": extra.get("message", ""),
        "severity": extra.get("severity", ""),
        "cwe": _as_list(meta.get("cwe")),
        "owasp": _as_list(meta.get("owasp")),
        "confidence": meta.get("confidence", ""),
        "likelihood": meta.get("likelihood", ""),
        "impact": meta.get("impact", ""),
        "references": _as_list(meta.get("references")),
    }


def _error_text(error):
    if isinstance(error, dict):
        return error.get("message") or error.get("type") or json.dumps(error)
    return str(error)


def parse_output(text, root):
    """(status, findings, tool_errors, error) for Semgrep's JSON output."""
    try:
        data = json.loads(text or "")
    except ValueError as exc:
        return STATUS_BAD_JSON, [], [], "Semgrep output is not valid JSON: {e}".format(e=exc)
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return STATUS_BAD_JSON, [], [], "Semgrep output has no results list."
    findings = []
    for obj in data["results"]:
        if not isinstance(obj, dict):
            continue
        finding = _finding(obj)
        if finding is None:
            continue
        finding["snippet"] = read_snippet(root, finding["file"], finding["start_line"],
                                          finding["end_line"])
        findings.append(finding)
    errors = [_error_text(e) for e in data.get("errors") or []]
    return STATUS_OK, findings, errors, ""


def _result(status, version="", command="", rules_path="", rules_commit="", warning="",
            languages=(), findings=None, tool_errors=(), error=""):
    tool_errors = list(tool_errors)
    result = {"tool": "semgrep", "status": status, "version": version, "command": command,
              "rules_path": rules_path, "rules_commit": rules_commit,
              "pinned_commit": PINNED_COMMIT, "warning": warning,
              "languages": list(languages), "findings": findings or [],
              "tool_errors": tool_errors[:SHOWN_ERRORS], "tool_error_count": len(tool_errors)}
    if error:
        result["error"] = error
    return result


def run_semgrep(path, languages):
    """
    Run Semgrep's local rules for the given languages on path and return:
        {"tool", "status", "version", "command", "rules_path", "rules_commit",
         "pinned_commit", "warning", "languages", "findings": [{"rule_id",
         "file", "start_line", "end_line", "message", "severity", "cwe",
         "owasp", "confidence", "likelihood", "impact", "references",
         "snippet"}], "tool_errors", "tool_error_count"}
    plus "error" when status is not "ok". Never raises for a tool problem.
    """
    root = os.path.realpath(path)
    if shutil.which(BINARY_NAME) is None:
        return _result(STATUS_NOT_FOUND, error=NOT_INSTALLED)
    version = tool_version()

    rules = rules_dir()
    if not os.path.isdir(rules):
        return _result(STATUS_NO_RULES, version=version, rules_path=rules,
                       error=NO_RULES.format(r=rules, cmd=setup_command(rules)))
    commit = read_rules_commit(rules)
    facts = {"version": version, "rules_path": rules, "rules_commit": commit,
             "warning": rules_warning(commit, rules)}

    wanted = sorted(set(languages))
    used = [lang for lang in wanted if os.path.isdir(os.path.join(rules, lang))]
    if not used:
        return _result(STATUS_NO_LANGUAGE_RULES, error=NO_LANGUAGE_RULES.format(
            r=rules, langs=", ".join(wanted) or "(none)"), **facts)

    cmd = [BINARY_NAME, "scan"] + SCAN_FLAGS
    for lang in used:
        cmd += ["--config", os.path.join(rules, lang)]
    cmd.append(root)
    command = shlex.join(cmd)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL,
                              timeout=SCAN_TIMEOUT, env=scan_env())
    except subprocess.TimeoutExpired:
        return _result(STATUS_TIMEOUT, command=command, languages=used,
                       error="Semgrep did not finish within {s} seconds.".format(
                           s=SCAN_TIMEOUT), **facts)
    except OSError as exc:
        return _result(STATUS_FAILED, command=command, languages=used,
                       error="Semgrep could not be started: {e}".format(e=exc), **facts)

    if proc.returncode not in OK_EXIT_CODES:
        stderr = (proc.stderr or "").strip().splitlines()
        error = "Semgrep exited with code {c}".format(c=proc.returncode)
        error += ": {s}".format(s=stderr[0]) if stderr else "."
        return _result(STATUS_FAILED, command=command, languages=used, error=error, **facts)

    status, findings, tool_errors, error = parse_output(proc.stdout, root)
    return _result(status, command=command, languages=used, findings=findings,
                   tool_errors=tool_errors, error=error, **facts)
