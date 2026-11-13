"""
ReconMind input router.

    python3 -m reconmind INPUT [options]

INPUT decides what runs:

    an IPv4 address       the recon agent, exactly as python3 -m reconmind.agent
                          runs it: the authorization gate first, then the scan
                          plan (--preset, --ports, --actions) and the model
                          (--provider, --model)
    an existing file      the code scan: Semgrep and Bandit on code that is
    or folder             only read, saved to the report history; --explain
                          adds the optional AI explanation, using --provider
                          and --model (off by default)

Anything else is refused with an error naming both choices. An IPv4 address
always means recon, even if a file with that name exists.
python3 -m reconmind.agent keeps working on its own.
"""

import argparse
import ipaddress
import os
import sys
from datetime import datetime

from reconmind.agent import __main__ as agent_main

AGENT_PROG = "python3 -m reconmind.agent"
RECON_ONLY_FLAGS = (("preset", "--preset"), ("ports", "--ports"), ("actions", "--actions"))

NOT_UNDERSTOOD = ("{i!r} is neither an IPv4 address nor an existing file or folder.\n"
                  "Give an IPv4 address of an authorized target to run recon, or the path "
                  "of a source file or folder to run a code scan.")
EXPLAIN_NEEDS_CODE = ("--explain is only for a code scan (a file or folder), not for an "
                      "IPv4 target.")
RECON_FLAGS_NEED_IP = "{f} only apply to an IPv4 target, not to a code scan."
MODEL_FLAGS_UNUSED = "note: --provider and --model are only used with --explain."


def _parse_args(args):
    parser = argparse.ArgumentParser(
        prog="python3 -m reconmind",
        description="Recon on an IPv4 target, or a code scan of a file or folder.")
    parser.add_argument("input", help="IPv4 address of an authorized target, or the path "
                                      "of a source file or folder")
    parser.add_argument("--provider", help="LLM provider for this run")
    parser.add_argument("--model", help="model id for this run")
    parser.add_argument("--preset", help="recon only: scan preset")
    parser.add_argument("--ports", help="recon only: ports to scan")
    parser.add_argument("--actions", help="recon only: comma separated action ids")
    parser.add_argument("--explain", action="store_true",
                        help="code scan only: add the AI explanation (off by default)")
    return parser.parse_args(args)


def is_ipv4(text):
    try:
        ipaddress.IPv4Address(str(text).strip())
    except ValueError:
        return False
    return True


def _run_code(path, args):
    from reconmind.code.code_scan import run_code_scan
    from reconmind.code.inputs import InputError
    from reconmind.core.history import save_code_run

    if args.explain:
        agent_main._load_dotenv()
    elif args.provider or args.model:
        print(MODEL_FLAGS_UNUSED)

    started = datetime.now()
    try:
        scan = run_code_scan(path, explain=args.explain, provider=args.provider,
                             model=args.model)
    except InputError as exc:
        print("Cannot scan: {e}".format(e=exc))
        return 1
    finished = datetime.now()
    record = save_code_run(scan, started=started, finished=finished)

    print("ReconMind code scan  input={i}".format(i=scan["input"]))
    print("files:       " + ", ".join("{l} {n}".format(l=l, n=n)
                                       for l, n in scan["files"]["languages"].items()))
    for name, result in scan["tools"].items():
        print("{t:<12} {s}{v}".format(t=name + ":", s=result["status"],
                                      v="  " + result["version"] if result.get("version") else ""))
        if result.get("warning"):
            print("warning:     " + result["warning"])
    counts = scan["counts"]
    print("findings:    {h} high, {m} medium, {l} low".format(
        h=counts["high"], m=counts["medium"], l=counts["low"]))
    explanation = scan.get("explanation")
    if explanation is None:
        print("explanation: not requested")
    elif explanation["status"] == "ok":
        print("explanation: written, {n} unverified reference(s)".format(
            n=len(explanation["unverified"])))
    else:
        print("explanation: skipped, " + explanation["reason"])
    print("run id:      " + record.run_id)
    print("report:      " + record.report_path)
    return 0


def main(argv):
    try:
        args = _parse_args(argv[1:])
    except SystemExit:  # argparse already printed the usage
        return 1
    value = args.input.strip()

    if is_ipv4(value):
        if args.explain:
            print(EXPLAIN_NEEDS_CODE)
            return 1
        # The agent parses the same options and runs the gate before anything else.
        return agent_main.main([AGENT_PROG] + list(argv[1:]))

    if value and os.path.exists(value):
        used = [flag for attr, flag in RECON_ONLY_FLAGS if getattr(args, attr) is not None]
        if used:
            print(RECON_FLAGS_NEED_IP.format(f=", ".join(used)))
            return 1
        return _run_code(value, args)

    print(NOT_UNDERSTOOD.format(i=value))
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
