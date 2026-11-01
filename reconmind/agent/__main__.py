"""
ReconMind agent runner (the LLM brain).

    python3 -m reconmind.agent [--provider NAME] [--model ID] <target_ip>

The target is checked against the authorization gate before the model is even
called, so an out of scope target costs nothing and touches nothing. Inside
the run, every tool call is checked again (scope lock + gate).

Settings come from the environment or a .env file in the repo root. The
--provider and --model flags override them for one run.

    RECONMIND_PROVIDER   openrouter (default), anthropic, huggingface, ollama
    RECONMIND_MODEL      model id; required for every provider except
                         openrouter, which defaults to openrouter/free
    RECONMIND_BASE_URL   optional custom endpoint (then RECONMIND_MODEL is required)
    OPENROUTER_API_KEY   key for openrouter
    ANTHROPIC_API_KEY    key for anthropic
    HF_TOKEN             key for huggingface (ollama needs no key)
"""

import argparse
import json
import os
import sys

from reconmind.agent import llm
from reconmind.core.authorization import is_authorized
from reconmind.core.report import build_report
from reconmind.core.summary_check import check_summary

MISSING_PACKAGE = ("Missing package. Activate your venv and run:\n"
                   "    pip install -r requirements.txt")


def _load_dotenv(path=".env"):
    """Tiny .env reader (KEY=value lines) so we don't need another package."""
    if not os.path.exists(path):
        return
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _parse_args(args):
    parser = argparse.ArgumentParser(prog="python3 -m reconmind.agent")
    parser.add_argument("target", help="IPv4 address of the authorized target")
    parser.add_argument("--provider", help="one of: " + ", ".join(sorted(llm.PROVIDERS)))
    parser.add_argument("--model", help="model id for this run")
    return parser.parse_args(args)


def _scan_facts(target, scan):
    """Compact JSON of the verified tool results, for the repair call."""
    from reconmind.agent.tools import ToolBox
    return json.dumps({
        "target": target,
        "scan_status": scan.get("status"),
        "open_ports": [ToolBox._port_summary(p) for p in scan.get("ports", [])],
    }, indent=1)


def _final_summary(client, model, target, scan, draft):
    """
    Check the model's draft. If it fails, make ONE repair call (no tools) and
    check again. Returns (text, unverified_refs); text is None when both fail,
    so the raw draft is never published.
    """
    from reconmind.agent.brain import MAX_TOKENS
    from reconmind.agent.prompts import REPAIR_SYSTEM_PROMPT, repair_message

    result = check_summary(draft, scan)
    if result.valid:
        print("summary:     ok")
        return result.text, result.unverified_refs

    print("summary:     draft failed validation ({p}), asking for one repair".format(
        p="; ".join(result.problems)))
    try:
        response = client.messages.create(
            model=model,
            max_tokens=MAX_TOKENS,
            system=REPAIR_SYSTEM_PROMPT,
            messages=[{"role": "user",
                       "content": repair_message(_scan_facts(target, scan), draft)}],
        )
        repaired = "\n".join(b.text for b in response.content
                             if getattr(b, "type", "") == "text")
    except Exception as exc:  # any failure here just means no repair
        print("summary:     repair call failed: {e}".format(e=exc))
        return None, []

    result = check_summary(repaired, scan)
    if result.valid:
        print("summary:     repaired")
        return result.text, result.unverified_refs
    print("summary:     repair failed validation ({p}), no model text published".format(
        p="; ".join(result.problems)))
    return None, []


def main(argv):
    try:
        args = _parse_args(argv[1:])
    except SystemExit:  # argparse already printed the usage
        return 1
    target = args.target.strip()

    # Gate first. A refused target never reaches the model or any tool.
    if not is_authorized(target):
        path = build_report({"target": target, "status": "refused", "ports": []})
        print("REFUSED: {t} is not on the allowlist. Nothing was run.".format(t=target))
        print("report:  ", path)
        return 2

    _load_dotenv()
    try:
        config = llm.load_config(provider=args.provider, model=args.model)
    except llm.ConfigError as exc:
        print(exc)
        return 1

    from reconmind.agent.brain import run_agent

    try:
        client = llm.make_client(config)
    except ImportError:
        print(MISSING_PACKAGE)
        return 1
    print("ReconMind agent  target={t}  provider={p}  model={m}".format(
        t=target, p=config.name, m=config.model))
    print("-" * 60)
    tools, draft = run_agent(target, client=client, model=config.model)
    print("-" * 60)

    summary, refs = _final_summary(client, config.model, target, tools.scan, draft)
    path = build_report(tools.scan, analyst_summary=summary, unverified_refs=refs,
                        summary_failed=summary is None)
    ports = tools.scan.get("ports", [])
    print("status:     ", tools.scan.get("status"))
    print("open ports: ", len(ports))
    print("exploits:   ", sum(len(p.get("exploits", [])) for p in ports))
    print("tool calls: ", len(tools.calls))
    print("report:     ", path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
