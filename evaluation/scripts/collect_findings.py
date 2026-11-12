"""
Collect the hand labeling queue for the ReconMind ATT&CK test set.

Run from the repo root:

    python3 evaluation/scripts/collect_findings.py TARGET [--all-ports] [--out PATH]
    python3 evaluation/scripts/collect_findings.py --from-scan PATH [--out PATH]

With TARGET it scans one authorized target with the real ReconMind toolbox,
saves the full scan, and appends one JSON line per open port to the findings
file. With --from-scan it rebuilds the same lines from a scan JSON file this
script saved earlier. Nothing touches the network then, so there is no gate
check and no scan; the target comes from the file. Give exactly one of TARGET
or --from-scan.

Each line holds id, target, port, protocol, scan_file and the exact
finding_text the ATT&CK mapper will read. Findings are questions only: the
ATT&CK answer key lives in a separate file. Re-running never duplicates a
finding: a line whose id is already present is skipped.

Exit codes: 0 clean scan, 1 scan failed or the saved scan could not be read,
2 target not authorized or bad arguments, 3 the scan has unconfirmed ports
(open in discovery, not in the detail pass). On 3 the scan file and the
confirmed findings are still written, and the scan should be rerun.

No model is ever called here. The text comes straight from the tool, so the
labeled set stays an independent check on the mapper.
"""

import argparse
import json
import os
import sys
from datetime import datetime

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from reconmind.core.authorization import is_authorized  # noqa: E402
from reconmind.agent.tools import ToolBox  # noqa: E402
from reconmind.ai.finding_text import finding_text  # noqa: E402

EVAL_DIR = os.path.join(REPO_ROOT, "evaluation", "data", "reconmind_eval")
DEFAULT_OUT = os.path.join(EVAL_DIR, "findings.jsonl")
SCANS_DIR = os.path.join(EVAL_DIR, "scans")


def _parse_args(args):
    parser = argparse.ArgumentParser(
        prog="python3 evaluation/scripts/collect_findings.py")
    parser.add_argument("target", nargs="?",
                        help="IPv4 address of the authorized target")
    parser.add_argument("--from-scan", metavar="PATH",
                        help="build findings from a scan JSON file this script "
                             "saved; no gate check and no scanning")
    parser.add_argument("--all-ports", action="store_true",
                        help="scan every TCP port (slower: up to 1800 seconds "
                             "for discovery plus 300 for the detail pass); "
                             "ignored with --from-scan")
    parser.add_argument(
        "--out", default=DEFAULT_OUT,
        help="findings JSONL file (default "
             "evaluation/data/reconmind_eval/findings.jsonl)")
    parsed = parser.parse_args(args)
    if (parsed.target is None) == (parsed.from_scan is None):
        parser.error("give exactly one of TARGET or --from-scan")
    return parsed


def _existing_ids(path):
    """Ids already in the findings file, so a rerun adds no duplicates."""
    ids = set()
    if not os.path.exists(path):
        return ids
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line:
                ids.add(json.loads(line)["id"])
    return ids


def _save_scan(scan, target):
    """Write the full scan dict and return its absolute path."""
    os.makedirs(SCANS_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_path = os.path.join(SCANS_DIR, "{t}_{s}.json".format(t=target, s=stamp))
    with open(scan_path, "w") as fh:
        json.dump(scan, fh, indent=1)
        fh.write("\n")
    return scan_path


def _load_scan(path):
    """Read a saved scan file. Returns (scan, error message or None)."""
    try:
        with open(path) as fh:
            scan = json.load(fh)
    except (OSError, ValueError) as exc:
        return None, "could not read {p}: {e}".format(p=path, e=exc)
    if not isinstance(scan, dict) or not str(scan.get("target") or "").strip():
        return None, "{p} has no target, so it is not a saved scan".format(p=path)
    return scan, None


def _write_findings(scan, target, scan_rel, out):
    """Append one record per port, skipping ids already in the file."""
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    existing = _existing_ids(out)

    added = skipped = 0
    with open(out, "a") as fh:
        for port in scan.get("ports", []):
            record_id = "{t}:{p}/{proto}".format(
                t=target, p=port.get("port"), proto=port.get("protocol"))
            if record_id in existing:
                skipped += 1
                continue
            existing.add(record_id)
            record = {
                "id": record_id,
                "target": target,
                "port": port.get("port"),
                "protocol": port.get("protocol"),
                "text": finding_text(port),
                "scan_file": scan_rel,
            }
            fh.write(json.dumps(record) + "\n")
            added += 1
    return added, skipped


def main(argv):
    args = _parse_args(argv[1:])

    if args.from_scan:
        # A saved scan: nothing touches the network, so no gate and no scan.
        scan, error = _load_scan(args.from_scan)
        if error:
            print("Scan file error: {e}".format(e=error))
            return 1
        target = str(scan["target"]).strip()
        scan_rel = os.path.relpath(os.path.abspath(args.from_scan), REPO_ROOT)
    else:
        target = args.target.strip()

        # The authorization gate decides first, before any scan is set up.
        if not is_authorized(target):
            print("Refused: {t} is not authorized. Nothing was scanned.".format(t=target))
            return 2

        tb = ToolBox(target, all_ports=args.all_ports)
        observation, is_error = tb.call("nmap_scan", {"target": target})
        if is_error:
            print("Scan failed: {o}".format(o=observation))
            return 1

        scan = tb.scan
        scan_path = _save_scan(scan, target)
        scan_rel = os.path.relpath(scan_path, REPO_ROOT)

    added, skipped = _write_findings(scan, target, scan_rel, args.out)

    print("Added {a} finding(s), skipped {s} duplicate(s).".format(a=added, s=skipped))
    print("Findings: {o}".format(o=args.out))
    print("Scan:     {s}".format(s=scan_rel))

    # A lossy scan must never pass for a clean one. The scan file above is
    # already saved as evidence; only confirmed ports became findings.
    unconfirmed = scan.get("unconfirmed_ports") or []
    if unconfirmed:
        listed = ", ".join("{p}/{proto}".format(p=u.get("port"), proto=u.get("protocol"))
                           for u in unconfirmed)
        print("WARNING: {n} port(s) answered as open in discovery but not in the "
              "detail pass: {l}. This usually means packet loss on the network "
              "path. Rerun the scan.".format(n=len(unconfirmed), l=listed))
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
