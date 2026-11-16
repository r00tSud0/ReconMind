"""
ReconMind agent runner.

    python3 -m reconmind.agent [--mode standard|ai] [--provider NAME] [--model ID]
                               [--preset quick|standard|full] [--ports SPEC]
                               [--actions LIST] <target_ip>

The target is checked against the authorization gate before anything else, so
an out of scope target costs nothing and touches nothing. Inside the run,
every tool call is checked again (scope lock + gate).

The scan plan comes from --preset (default standard), optionally changed by
--ports ("top", "all" or a list like 21,22,80,8000-8100) and --actions
(comma separated action ids; surface is always added). It is checked right
after the gate and printed before the scan starts. Every run is saved to the
report history: reports/<run id>/ plus one entry in reports/index.json.

Two report modes. The tools run exactly the same way in both:

    standard  the standard pipeline (reconmind/core/pipeline.py) runs every
              action in the plan, on every port where it fits, in a fixed
              order, and the fine tuned ATT&CK model maps the findings. No
              LLM is used and no API key is needed.
    ai        the same standard run first, so the tool results are identical.
              Then the LLM works as an analyst over the finished results. It
              can only read them (reconmind/agent/analyst_tools.py); it never
              runs a scanner. Its summary goes through the usual checks:
              check_summary, one repair call, check_attack, mark_not_mapped.

--mode defaults to ai when an LLM is configured and to standard otherwise.
--provider or --model without --mode counts as asking for ai. Asking for ai
without a working LLM configuration prints the problem and exits 1.
The operator always chooses the target, ports and actions; the LLM never
chooses which tools run.

Settings come from the environment or a .env file in the repo root. The
--provider and --model flags override them for one run.

    RECONMIND_PROVIDER   openrouter (default), anthropic, huggingface, ollama
    RECONMIND_MODEL      model id; required for every provider except
                         openrouter, which defaults to openrouter/free
    RECONMIND_BASE_URL   optional custom endpoint (then RECONMIND_MODEL is required)
    OPENROUTER_API_KEY   key for openrouter
    ANTHROPIC_API_KEY    key for anthropic
    HF_TOKEN             key for huggingface (ollama needs no key)

Every report carries the ATT&CK mapping: the pipeline always ends with
attack_map, and if the mapping is still missing the runner calls it once,
before the summary is checked. An ATT&CK ID in the summary that attack_map
did not confirm is shown as not_mapped in the ATT&CK check table.

If a reasoning model's final answer is empty because it used its whole length
budget (see llm.py), the runner says so and the usual summary fallback runs.

If the analyst fails, the report is still written with every tool section:
a provider rate limit (429, after the client's one retry) gives the "model
was busy" notice and exit 1; any other error, or a summary that fails
validation after the repair, gives the "summary unavailable" notice and exit 0.

Stopping: SIGTERM (the web app's Stop) raises StopRequested. The run saves a
partial report from everything that finished, with scan status "stopped" and
a Stopped notice listing the steps that finished and the ones that did not
run, prints "run id:" and "report:" as usual and exits 4. Once the final
report starts being saved, a SIGTERM does nothing: the save finishes and the
run exits normally, so a stop never starts a second save.

Exit codes: 0 finished, 1 error, 2 refused by the gate, 4 stopped.
"""

import argparse
import contextlib
import json
import os
import signal
import sys
from datetime import datetime

from reconmind.agent import llm
from reconmind.agent.analyst_tools import ANALYST_TOOL_SPECS, ReadOnlyTools
from reconmind.core.attack_check import check_attack
from reconmind.core.authorization import is_authorized
from reconmind.core.events import emit
from reconmind.core.history import save_run
from reconmind.core.pipeline import (
    ANALYSIS_STEP, STOPPED, STOPPED_WHILE_RUNNING, StopRequested, mark_stopped, run_plan)
from reconmind.core.report import MODE_AI, MODE_STANDARD, MODES
from reconmind.core.scan_plan import ACTION_IDS, PRESETS, PlanError, build_plan
from reconmind.core.summary_check import NOT_MAPPED, check_summary, mark_not_mapped

MISSING_PACKAGE = ("Missing package. Activate your venv and run:\n"
                   "    pip install -r requirements.txt")
NO_KEY_STANDARD = "No API key set, so this is a Standard report."
MODE_TEXT = {
    MODE_STANDARD: "Standard (tools only, no LLM)",
    MODE_AI: "AI enhanced (tools first, then a read only AI analyst)",
}

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_REFUSED = 2
EXIT_STOPPED = 4


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


def ai_config(provider=None, model=None):
    """
    (config, None) when an LLM is configured, after reading .env, or
    (None, the config error text) when it is not. Never raises ConfigError.
    """
    _load_dotenv()
    try:
        return llm.load_config(provider=provider, model=model), None
    except llm.ConfigError as exc:
        return None, str(exc)


def default_mode():
    """"ai" when an LLM is configured, otherwise "standard"."""
    config, _ = ai_config()
    return MODE_AI if config is not None else MODE_STANDARD


def _parse_args(args):
    parser = argparse.ArgumentParser(prog="python3 -m reconmind.agent")
    parser.add_argument("target", help="IPv4 address of the authorized target")
    parser.add_argument("--mode", choices=list(MODES),
                        help="report mode: standard (tools only) or ai (tools, then a read "
                             "only AI analyst). Default ai when an LLM is configured, "
                             "otherwise standard")
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


def _choose_mode(args):
    """
    (mode, config, error). error is the text to print when --mode ai was
    asked for and no LLM is configured; mode is None then.
    """
    if args.mode == MODE_STANDARD:
        return MODE_STANDARD, None, None
    config, error = ai_config(provider=args.provider, model=args.model)
    if config is not None:
        return MODE_AI, config, None
    # --provider or --model without --mode is a request for AI mode too.
    if args.mode == MODE_AI or args.provider or args.model:
        return None, None, error
    print(NO_KEY_STANDARD)
    return MODE_STANDARD, None, None


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
    Run attack_map once if there is no mapping in the scan yet. The pipeline
    always ends with it, so this is only a safety net.
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


# ---- stopping ---------------------------------------------------------------

# Set once the final report starts being saved. While it is set, SIGTERM does
# nothing, so a stop can never start a second save.
_saving = {"started": False}


def _on_sigterm(signum, frame):
    """
    The first SIGTERM stops the run. Later ones are ignored, so the partial
    report is written in peace (the web app sends SIGKILL if it takes too long).
    Once the final save has started, SIGTERM does nothing at all.
    """
    if _saving["started"]:
        return
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    raise StopRequested()


def _save_final(scan, **kwargs):
    """save_run for the run's one report, with the saving flag set first."""
    _saving["started"] = True
    return save_run(scan, **kwargs)


@contextlib.contextmanager
def _stop_on_sigterm():
    """Install the SIGTERM handler for the run and put the old one back after."""
    _saving["started"] = False
    try:
        previous = signal.signal(signal.SIGTERM, _on_sigterm)
    except (ValueError, OSError):  # not the main thread: nothing to install
        previous = None
    try:
        yield
    finally:
        _saving["started"] = False
        if previous is not None:
            try:
                signal.signal(signal.SIGTERM, previous)
            except (ValueError, OSError):
                pass


# ---- saving -----------------------------------------------------------------

def _print_record(record):
    """The two lines the web app reads."""
    print("run id:     ", record.run_id)
    print("report:     ", record.report_path)


def _print_totals(tools, plan, record, analyst=None):
    ports = tools.scan.get("ports", [])
    print("status:     ", tools.scan.get("status"))
    print("open ports: ", len(ports))
    if plan.has("exploits"):
        print("exploits:   ", sum(len(p.get("exploits", [])) for p in ports))
    else:
        print("exploits:    Not run (not selected)")
    print("tool calls: ", len(tools.calls))
    if analyst is not None:
        print("analyst reads:", len(analyst.calls))
    _print_record(record)


def _save_stopped(tools, plan, mode, started):
    record = _save_final(tools.scan, plan=plan, started=started, finished=datetime.now(),
                      mode=mode)
    stop = tools.scan.get("stop") or {}
    print("-" * 60)
    print("status:      stopped")
    print("finished:    " + (", ".join(stop.get("finished") or []) or "none"))
    print("not run:     " + (", ".join(stop.get("not_run") or []) or "none"))
    _print_record(record)
    emit("finished", status=STOPPED, run_id=record.run_id)
    return EXIT_STOPPED


def _save_rate_limited(tools, plan, started, finished, exc):
    """The tools finished, so the facts are still worth a report."""
    record = _save_final(tools.scan, plan=plan, started=started, finished=finished,
                      mode=MODE_AI, rate_limited=True)
    _print_record(record)
    print(exc)
    emit("finished", status="rate-limited", run_id=record.run_id)
    return EXIT_ERROR


def _finish_standard(tools, plan, started):
    finished = datetime.now()
    print("-" * 60)
    _ensure_attack_map(tools)
    record = _save_final(tools.scan, plan=plan, started=started, finished=finished,
                         mode=MODE_STANDARD)
    _print_totals(tools, plan, record)
    emit("finished", status=tools.scan.get("status"), run_id=record.run_id)
    return EXIT_OK


def _finish_ai(target, plan, tools, config, client, started):
    print("-" * 60)
    if tools.scan.get("status") != "ok":
        # Nothing was scanned, so there is nothing to analyse.
        print("analysis:    skipped, the scan did not complete (status {s})".format(
            s=tools.scan.get("status")))
        record = _save_final(tools.scan, plan=plan, started=started, finished=datetime.now(),
                             mode=MODE_AI)
        _print_totals(tools, plan, record)
        emit("finished", status=tools.scan.get("status"), run_id=record.run_id)
        return EXIT_OK

    from reconmind.agent.brain import run_agent
    from reconmind.agent.prompts import analyst_first_message, build_analyst_system_prompt

    print("analysis:    the AI analyst reads the stored results (read only, nothing is "
          "scanned)")
    emit("phase", phase="analysis")
    reader = ReadOnlyTools(tools.scan, plan, steps=getattr(tools, "steps", None))
    failed = False
    draft = None
    try:
        _, draft = run_agent(target, client=client, model=config.model,
                             tool_specs=ANALYST_TOOL_SPECS,
                             system_prompt=build_analyst_system_prompt(plan), plan=plan,
                             toolbox=reader,
                             first_message=analyst_first_message(target, reader.overview()))
    except llm.RateLimited as exc:
        return _save_rate_limited(tools, plan, started, datetime.now(), exc)
    except Exception as exc:  # the scan must never be lost to an analyst error
        print("analysis:    failed: {e}".format(e=exc))
        failed = True
    finished = datetime.now()
    print("-" * 60)

    # A reasoning model can spend its whole length budget before answering.
    # llm marks that answer, and the fallback below then handles it as usual.
    if getattr(getattr(client, "last_response", None), "empty_reason", None):
        print("summary: model ran out of length budget while reasoning")

    _ensure_attack_map(tools)

    if failed:
        summary, refs = None, []
    else:
        try:
            summary, refs = _final_summary(client, config.model, target, tools.scan, draft,
                                           plan)
        except llm.RateLimited as exc:
            return _save_rate_limited(tools, plan, started, finished, exc)

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
    record = _save_final(tools.scan, plan=plan, started=started, finished=finished,
                         mode=MODE_AI, analyst_summary=summary, unverified_refs=refs,
                         summary_failed=summary is None, attack_check=attack)
    _print_totals(tools, plan, record, analyst=reader)
    emit("finished", status=tools.scan.get("status"), run_id=record.run_id)
    return EXIT_OK


def _run(target, plan, mode, config, client):
    """Run the plan, then the analyst in ai mode, and save the report. Returns the exit code."""
    started = datetime.now()
    tools = None
    try:
        tools = run_plan(target, plan, mode=mode)
        if tools.scan.get("status") == STOPPED:
            return _save_stopped(tools, plan, mode, started)
        if mode == MODE_STANDARD:
            return _finish_standard(tools, plan, started)
        return _finish_ai(target, plan, tools, config, client, started)
    except StopRequested:
        # The stop came outside the pipeline's own steps: before it started,
        # or after it finished (during the AI analysis or the save).
        if tools is None:
            from reconmind.agent.tools import ToolBox
            tools = ToolBox(target, plan=plan)
            tools.steps = []
            mark_stopped(tools, plan)
        elif tools.scan.get("status") != STOPPED:
            not_run = []
            if mode == MODE_AI:
                not_run.append(STOPPED_WHILE_RUNNING.format(l=ANALYSIS_STEP))
            mark_stopped(tools, plan, not_run=not_run)
        return _save_stopped(tools, plan, mode, started)


def main(argv):
    try:
        args = _parse_args(argv[1:])
    except SystemExit:  # argparse already printed the usage
        return EXIT_ERROR
    target = args.target.strip()

    # Gate first. A refused target never reaches the model or any tool.
    if not is_authorized(target):
        started = datetime.now()
        try:
            plan = _build_plan(target, args)
        except PlanError:
            plan = None  # nothing ran either way; the history entry has no plan
        record = save_run({"target": target, "status": "refused", "ports": []}, plan=plan,
                          started=started, finished=started,
                          mode=args.mode or MODE_STANDARD)
        print("REFUSED: {t} is not on the allowlist. Nothing was run.".format(t=target))
        print("report:  ", record.report_path)
        emit("finished", status="refused", run_id=record.run_id)
        return EXIT_REFUSED

    # The plan is checked before anything else happens. A bad ports spec or
    # action list stops here, before config, client or model.
    try:
        plan = _build_plan(target, args)
    except PlanError as exc:
        print("Bad scan plan: {e}".format(e=exc))
        return EXIT_ERROR

    mode, config, error = _choose_mode(args)
    if mode is None:
        print(error)
        return EXIT_ERROR

    client = None
    if mode == MODE_AI:
        try:
            client = llm.make_client(config)
        except ImportError:
            print(MISSING_PACKAGE)
            return EXIT_ERROR
        print("ReconMind agent  target={t}  provider={p}  model={m}  mode={o}".format(
            t=target, p=config.name, m=config.model, o=mode))
    else:
        print("ReconMind agent  target={t}  mode={o}".format(t=target, o=mode))
    for line in plan.describe():
        print(line)
    print("Report mode: " + MODE_TEXT[mode])
    print("-" * 60)

    with _stop_on_sigterm():
        return _run(target, plan, mode, config, client)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
