"""
ReconMind agent runner (the LLM brain).

    python3 -m reconmind.agent <target_ip>

The target is checked against the authorization gate before the model is even
called, so an out of scope target costs nothing and touches nothing. Inside
the run, every tool call is checked again (scope lock + gate).

Needs ANTHROPIC_API_KEY in the environment or in a .env file in the repo root.
Optional: RECONMIND_MODEL to pick a different model.
"""

import os
import sys

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


def main(argv):
    if len(argv) != 2:
        print("usage: python3 -m reconmind.agent <target_ip>")
        return 1
    target = argv[1].strip()

    # Gate first. A refused target never reaches the model or any tool.
    if not is_authorized(target):
        path = build_report({"target": target, "status": "refused", "ports": []})
        print("REFUSED: {t} is not on the allowlist. Nothing was run.".format(t=target))
        print("report:  ", path)
        return 2

    _load_dotenv()
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ANTHROPIC_API_KEY is not set. Put it in .env in the repo root:")
        print("    ANTHROPIC_API_KEY=sk-ant-...")
        return 1

    from reconmind.agent.brain import run_agent  # needs the anthropic package

    print("ReconMind agent  target={t}".format(t=target))
    print("-" * 60)
    tools, summary = run_agent(target)
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
