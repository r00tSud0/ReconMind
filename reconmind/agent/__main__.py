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
import os
import sys

from reconmind.agent import llm
from reconmind.core.authorization import is_authorized
from reconmind.core.report import build_report


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

    client = llm.make_client(config)
    print("ReconMind agent  target={t}  provider={p}  model={m}".format(
        t=target, p=config.name, m=config.model))
    print("-" * 60)
    tools, summary = run_agent(target, client=client, model=config.model)
    print("-" * 60)

    path = build_report(tools.scan, analyst_summary=summary)
    ports = tools.scan.get("ports", [])
    print("status:     ", tools.scan.get("status"))
    print("open ports: ", len(ports))
    print("exploits:   ", sum(len(p.get("exploits", [])) for p in ports))
    print("tool calls: ", len(tools.calls))
    print("report:     ", path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
