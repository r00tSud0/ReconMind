"""
ReconMind code scan explanation (only with --explain, off by default).

After Semgrep and Bandit finished, explain_findings sends the findings to the
LLM provider the agent uses (.env, --provider, --model, through
reconmind/agent/llm.py) and asks for a short explanation of each one: why it
is dangerous, how an attacker could use it and how to fix it, citing every
finding by its file:line.

Only finding details go out: tools, rule or test id, CWE, severity,
file:line, each tool's message and the snippet (at most
inputs.MAX_SNIPPET_LINES lines). Whole files are never sent.

The answer is checked by plain code: every file:line and every CWE it
mentions must match a finding the tools reported, anything else is listed as
unverified. The explanation never changes the findings. With no provider
configured, a missing client package, a failed call or an empty answer the
explanation is skipped and the reason is kept for the report.

This is the only part of the code scan that uses the network.
"""

import json
import re

from reconmind.agent import llm
from reconmind.core.summary_check import clean_published

MAX_TOKENS = 4000

STATUS_OK = "ok"
STATUS_SKIPPED = "skipped"

SYSTEM_PROMPT = (
    "You explain static analysis findings for a security report. The user gives you "
    "the findings that Semgrep and Bandit reported, as JSON. Discuss only these "
    "findings. Never add a finding, a file, a line number or a CWE ID that is not in "
    "the JSON.\n\n"
    "For each finding write one section. Start it with the heading line "
    "'### <file:line>' using the exact file_line value given. Under it write three "
    "short paragraphs that start with 'Why it is dangerous:', 'How an attacker could "
    "use it:' and 'How to fix it:'. Cite findings only by their file:line. Use plain "
    "English and do not use dashes as separators."
)
USER_INTRO = ("These are the findings Semgrep and Bandit reported. Explain each one.\n\n")

NO_FINDINGS = "the tools reported no findings, so there was nothing to explain"
NO_PROVIDER = "no LLM provider is configured ({e})"
NO_PACKAGE = "the LLM client package is not installed (pip install -r requirements.txt)"
CALL_FAILED = "the LLM call failed ({e})"
EMPTY_ANSWER = "the model returned no text"

_EXTENSIONS = r"(?:py|jsx|js|mjs|tsx|ts|php|java|go|rb|c|h)"
_FILE_LINE = re.compile(r"([\w./-]+\." + _EXTENSIONS + r"):(\d+)", re.I)
_CWE_REF = re.compile(r"\bCWE[\s-]*(\d+)\b", re.I)


def cite(finding):
    """How a finding is cited: "<file>:<line>"."""
    return "{f}:{n}".format(f=finding.get("file", ""), n=finding.get("line", 0))


def finding_payload(findings):
    """What is sent per finding. No whole files, only the reported snippet."""
    return [{
        "file_line": cite(f),
        "tools": list(f.get("sources") or []),
        "rules": dict(f.get("rule_ids") or {}),
        "cwe": list(f.get("cwe") or []),
        "severity": f.get("severity", ""),
        "messages": dict(f.get("messages") or {}),
        "snippet": f.get("snippet", ""),
    } for f in findings]


def user_message(findings):
    return USER_INTRO + json.dumps(finding_payload(findings), indent=1)


def _same_file(mentioned, reported):
    return (mentioned == reported or reported.endswith("/" + mentioned)
            or mentioned.endswith("/" + reported))


def _known_location(path, line, findings):
    for f in findings:
        start = f.get("line") or 0
        end = max(f.get("end_line") or 0, start)
        if _same_file(path, f.get("file", "")) and start <= line <= end:
            return True
    return False


def verify_explanation(text, findings):
    """Every file:line and CWE in text that no reported finding has, in order, no repeats."""
    known_cwes = {c.upper() for f in findings for c in f.get("cwe") or []}
    found = []
    for match in _FILE_LINE.finditer(text or ""):
        path, line = match.group(1), int(match.group(2))
        if not _known_location(path, line, findings):
            found.append((match.start(), "{p}:{n}".format(p=path, n=line)))
    for match in _CWE_REF.finditer(text or ""):
        cwe = "CWE-{n}".format(n=int(match.group(1)))
        if cwe not in known_cwes:
            found.append((match.start(), cwe))
    refs = []
    for _, ref in sorted(found):
        if ref not in refs:
            refs.append(ref)
    return refs


def _result(status, reason="", text="", unverified=(), provider="", model="", sent=False):
    return {"status": status, "reason": reason, "text": text, "unverified": list(unverified),
            "provider": provider, "model": model, "sent": sent}


def _response_text(response):
    blocks = getattr(response, "content", None) or []
    return "\n".join(getattr(b, "text", "") or "" for b in blocks
                     if getattr(b, "type", "") == "text")


def explain_findings(findings, provider=None, model=None, client=None):
    """
    Ask the configured model to explain the findings. Returns:
        {"status": "ok" or "skipped", "reason", "text", "unverified",
         "provider", "model", "sent"}
    sent is True once finding details were handed to the provider. client
    replaces the configured one (tests). Never raises.
    """
    findings = list(findings or [])
    if not findings:
        return _result(STATUS_SKIPPED, NO_FINDINGS)

    provider_name = provider or ""
    if client is None:
        try:
            config = llm.load_config(provider=provider, model=model)
        except llm.ConfigError as exc:
            first_line = (str(exc).splitlines() or [""])[0].rstrip(": ")
            return _result(STATUS_SKIPPED, NO_PROVIDER.format(e=first_line))
        try:
            client = llm.make_client(config)
        except ImportError:
            return _result(STATUS_SKIPPED, NO_PACKAGE, provider=config.name,
                           model=config.model)
        provider_name, model = config.name, config.model

    facts = {"provider": provider_name, "model": model or "", "sent": True}
    try:
        response = client.messages.create(
            model=model, max_tokens=MAX_TOKENS, system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message(findings)}])
    except Exception as exc:  # rate limits included: the findings stand on their own
        return _result(STATUS_SKIPPED, CALL_FAILED.format(e=exc), **facts)

    text = clean_published(_response_text(response)).strip()
    if not text:
        return _result(STATUS_SKIPPED, EMPTY_ANSWER, **facts)
    return _result(STATUS_OK, text=text, unverified=verify_explanation(text, findings), **facts)
