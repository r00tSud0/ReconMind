"""
ReconMind agent runner (the LLM brain).

    python3 -m reconmind.agent [--provider NAME] [--model ID]
                               [--preset quick|standard|full] [--ports SPEC]
                               [--actions LIST] <target_ip>

The target is checked against the authorization gate before the model is even
called, so an out of scope target costs nothing and touches nothing. Inside
the run, every tool call is checked again (scope lock + gate).

The scan plan comes from --preset (default standard), optionally changed by
--ports ("top", "all" or a list like 21,22,80,8000-8100) and --actions
(comma separated action ids; surface is always added). It is checked right
after the gate and printed before the scan starts. Every run is saved to the
report history: reports/<run id>/ plus one entry in reports/index.json.

Settings come from the environment or a .env file in the repo root. The
--provider and --model flags override them for one run.

    RECONMIND_PROVIDER   openrouter (default), anthropic, huggingface, ollama
    RECONMIND_MODEL      model id; required for every provider except
                         openrouter, which defaults to openrouter/free
    RECONMIND_BASE_URL   optional custom endpoint (then RECONMIND_MODEL is required)
    OPENROUTER_API_KEY   key for openrouter
    ANTHROPIC_API_KEY    key for anthropic
    HF_TOKEN             key for huggingface (ollama needs no key)

Every report carries the ATT&CK mapping: if the agent finished without
calling attack_map, the runner calls it once, before the summary is checked.
An ATT&CK ID in the summary that attack_map did not confirm is shown as
not_mapped in the ATT&CK check table.

If a reasoning model's final answer is empty because it used its whole length
budget (see llm.py), the runner says so and the usual summary fallback runs.

On a provider rate limit (429) the client waits and retries once. If the main
loop is still rate limited, the run stops with exit 1 and no report. If only
the repair call is, the report is still written with every fact section and a
"model was busy" notice, then the run stops with exit 1.
"""

import argparse
import json
import os
import sys
from datetime import datetime

from reconmind.agent import llm
from reconmind.core.attack_check import check_attack
from reconmind.core.authorization import is_authorized
from reconmind.core.history import save_run
from reconmind.core.scan_plan import ACTION_IDS, PRESETS, PlanError, build_plan
from reconmind.core.summary_check import NOT_MAPPED, check_summary, mark_not_mapped

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
    parser.add_argument("--preset", choices=list(PRESETS),
                        help="scan preset (default standard)")
    parser.add_argument("--ports", help='"top" (default), "all", or ports and ranges '
                                        'such as 21,22,80,8000-8100')
    parser.add_argument("--actions", help="comma separated action ids from: "
                                          + ", ".join(ACTION_IDS)
                                          + " (surface is always added)")
    return parser.parse_args(args)


def _build_plan(target, args):
    """The ScanPlan from the command line. Raises PlanError."""
    return build_plan(target, preset=args.preset, ports=args.ports, actions=args.actions)


def _scan_facts(target, scan, plan=None):
    """Compact JSON of the verified tool results, for the repair call."""
    from reconmind.agent.tools import ToolBox
    exploits = plan is None or plan.has("exploits")
    return json.dumps({
        "target": target,
        "scan_status": scan.get("status"),
        "open_ports": [ToolBox._port_summary(p, exploits=exploits)
                       for p in scan.get("ports", [])],
    }, indent=1)


def _final_summary(client, model, target, scan, draft, plan=None):
    """
    Check the model's draft. If it fails, make ONE repair call (no tools) and
    check again. Returns (text, unverified_refs); text is None when both fail,
    so the raw draft is never published. llm.RateLimited from the repair call
    is raised to the caller.
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
                       "content": repair_message(_scan_facts(target, scan, plan), draft)}],
        )
        repaired = "\n".join(b.text for b in response.content
                             if getattr(b, "type", "") == "text")
    except llm.RateLimited:
        raise
    except Exception as exc:  # any other failure here just means no repair
        print("summary:     repair call failed: {e}".format(e=exc))
        return None, []

    result = check_summary(repaired, scan)
    if result.valid:
        print("summary:     repaired")
        return result.text, result.unverified_refs
    print("summary:     repair failed validation ({p}), no model text published".format(
        p="; ".join(result.problems)))
    return None, []


def _ensure_attack_map(tools):
    """
    Run attack_map once if the agent did not leave a mapping in the scan
    (it never called the tool, or called it before nmap_scan had results).
    """
    if "attack_map" not in tools.scan:
        observation, is_error = tools.call("attack_map", {})
        if is_error:
            print("attack map:  not built: {e}".format(
                e=json.loads(observation).get("error", "")))
        else:
            print("attack map:  built after the agent finished (the agent did not call it)")
    mapping = tools.scan.get("attack_map")
    if mapping:
        confirmed = sum(len(p.get("techniques") or []) for p in mapping.get("ports") or [])
        print("attack map:  {n} technique(s) confirmed, mapper status {s}".format(
            n=confirmed, s=mapping.get("status")))


def main(argv):
    try:
        args = _parse_args(argv[1:])
    except SystemExit:  # argparse already printed the usage
        return 1
    target = args.target.strip()

    # Gate first. A refused target never reaches the model or any tool.
    if not is_authorized(target):
        started = datetime.now()
        try:
            plan = _build_plan(target, args)
        except PlanError:
            plan = None  # nothing ran either way; the history entry has no plan
        record = save_run({"target": target, "status": "refused", "ports": []}, plan=plan,
                          started=started, finished=started)
        print("REFUSED: {t} is not on the allowlist. Nothing was run.".format(t=target))
        print("report:  ", record.report_path)
        return 2

    # The plan is checked before anything else happens. A bad ports spec or
    # action list stops here, before config, client or model.
    try:
        plan = _build_plan(target, args)
    except PlanError as exc:
        print("Bad scan plan: {e}".format(e=exc))
        return 1

    _load_dotenv()
    try:
        config = llm.load_config(provider=args.provider, model=args.model)
    except llm.ConfigError as exc:
        print(exc)
        return 1

    from reconmind.agent.brain import run_agent
    from reconmind.agent.prompts import build_system_prompt
    from reconmind.agent.tools import plan_tool_specs

    try:
        client = llm.make_client(config)
    except ImportError:
        print(MISSING_PACKAGE)
        return 1
    print("ReconMind agent  target={t}  provider={p}  model={m}".format(
        t=target, p=config.name, m=config.model))
    for line in plan.describe():
        print(line)
    print("-" * 60)
    started = datetime.now()
    try:
        tools, draft = run_agent(target, client=client, model=config.model,
                                 tool_specs=plan_tool_specs(plan),
                                 system_prompt=build_system_prompt(plan), plan=plan)
    except llm.RateLimited as exc:
        print(exc)
        return 1
    finished = datetime.now()
    print("-" * 60)

    # A reasoning model can spend its whole length budget before answering.
    # llm marks that answer, and the fallback below then handles it as usual.
    if getattr(getattr(client, "last_response", None), "empty_reason", None):
        print("summary: model ran out of length budget while reasoning")

    _ensure_attack_map(tools)

    try:
        summary, refs = _final_summary(client, config.model, target, tools.scan, draft, plan)
    except llm.RateLimited as exc:
        # The scan and lookups finished, so the facts are still worth a report.
        record = save_run(tools.scan, plan=plan, started=started, finished=finished,
                          rate_limited=True)
        print("run id:     ", record.run_id)
        print("report:     ", record.report_path)
        print(exc)
        return 1

    attack = None
    if summary is not None:
        attack = mark_not_mapped(check_attack(summary), tools.scan.get("attack_map"))
        if attack.skipped:
            print(attack.skipped)
        else:
            ok = sum(1 for r in attack.rows if r.result == "verified")
            not_mapped = sum(1 for r in attack.rows if r.result == NOT_MAPPED)
            print("attack:      {v} verified, {f} flagged ({n} not mapped)".format(
                v=ok, f=len(attack.rows) - ok, n=not_mapped))
    record = save_run(tools.scan, plan=plan, started=started, finished=finished,
                      analyst_summary=summary, unverified_refs=refs,
                      summary_failed=summary is None, attack_check=attack)
    ports = tools.scan.get("ports", [])
    print("status:     ", tools.scan.get("status"))
    print("open ports: ", len(ports))
    if plan.has("exploits"):
        print("exploits:   ", sum(len(p.get("exploits", [])) for p in ports))
    else:
        print("exploits:    Not run (not selected)")
    print("tool calls: ", len(tools.calls))
    print("run id:     ", record.run_id)
    print("report:     ", record.report_path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
