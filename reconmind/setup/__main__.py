"""
ReconMind setup.

    python3 -m reconmind.setup --check     show what is ready and the install plan (changes nothing)
    python3 -m reconmind.setup --install   install or repair everything in the plan
    python3 -m reconmind.setup --install --yes   same, without the confirmation question

Exit codes: 0 all 9 tools ready, 1 some still missing, 2 preflight blocked, 3 cancelled.
"""

import argparse
import sys

from reconmind import toolpath
from reconmind.setup import detect, install, preflight

LINE = "  "


def _print_checks(checks):
    print("Preflight")
    for i, c in enumerate(checks, 1):
        print("{p}{i}. {n}: {s}. {d}".format(p=LINE, i=i, n=c.name,
                                             s="OK" if c.ok else ("BLOCKED" if c.blocking else "Note"),
                                             d=c.detail))


def _print_tools(tools):
    ready = sum(1 for t in tools if t["status"] == "ready")
    print("Security tools: {r} of {n} ready".format(r=ready, n=len(tools)))
    for i, t in enumerate(tools, 1):
        print("{p}{i}. {n} ({a}): {s}{v}".format(
            p=LINE, i=i, n=t["name"], a=t["action"],
            s="Ready" if t["status"] == "ready" else "Missing",
            v=(". " + t["version"]) if t["version"] else ""))
    return ready


def _print_plan(plan):
    print("Install plan")
    if not plan:
        print(LINE + "Nothing to do.")
    for i, (title, detail) in enumerate(plan, 1):
        print("{p}{i}. {t}: {d}".format(p=LINE, i=i, t=title, d=detail))


def main(argv=None, inp=input):
    parser = argparse.ArgumentParser(prog="python3 -m reconmind.setup",
                                     description="Install or repair ReconMind's scanning tools.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="show status and plan, change nothing")
    mode.add_argument("--install", action="store_true", help="install or repair")
    parser.add_argument("--yes", action="store_true", help="do not ask before installing")
    args = parser.parse_args(argv)

    toolpath.activate()
    checks = preflight.run_checks()
    _print_checks(checks)
    print()
    tools = detect.tools()
    _print_tools(tools)
    print()
    blocked = preflight.blocking_failures(checks)
    if blocked:
        print("Setup cannot continue: " + "; ".join(c.name for c in blocked) + ".")
        return 2

    info = preflight.read_os_release()
    worker = install.Installer(preflight.distro(info), preflight.arch())
    plan = worker.plan()
    _print_plan(plan)
    print()
    print("Installs into " + toolpath.DATA_DIR + ". Nothing is scanned and the lab "
          "network lists are never changed.")

    if not args.install:
        print("This was a check only. Run again with --install to install.")
        return 0

    if not args.yes:
        try:
            answer = inp("Install now? Type y and press Enter: ").strip().lower()
        except EOFError:
            answer = ""
        if answer not in ("y", "yes"):
            print("Cancelled. Nothing was installed.")
            return 3

    print()
    results, tools = worker.install()
    print()
    failed = [r for r in results if r[1] == install.FAILED]
    ready = _print_tools(tools)
    print()
    if failed:
        print("Steps that failed:")
        for i, (title, _, message) in enumerate(failed, 1):
            print("{p}{i}. {t}: {m}".format(p=LINE, i=i, t=title, m=message))
        print("Run the same command again to retry. Details are in "
              + toolpath.DATA_DIR + "/setup.log")
    if ready == len(tools) and not failed:
        print("Setup complete. All {n} tools are ready.".format(n=len(tools)))
        return 0
    if ready == len(tools):
        print("All {n} tools are ready, but {f} step(s) failed. Run the same command again "
              "to retry.".format(n=len(tools), f=len(failed)))
    else:
        print("Setup finished with {m} of {n} tools missing.".format(
            m=len(tools) - ready, n=len(tools)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
