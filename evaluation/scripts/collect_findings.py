"""
Collect the hand labeling queue for the ReconMind ATT&CK test set.

Run from the repo root:

    python3 evaluation/scripts/collect_findings.py TARGET [--all-ports] [--out PATH]

It scans one authorized target with the real ReconMind toolbox, saves the full
scan, and appends one JSON line per open port to the findings file. Each line
carries the exact finding_text the ATT&CK mapper will read, plus "labels": null
so a human can fill the ATT&CK technique IDs in later. Re-running never
duplicates a finding: a line whose id is already present is skipped.

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
    parser.add_argument("target", help="IPv4 address of the authorized target")
    parser.add_argument("--all-ports", action="store_true",
                        help="scan every TCP port (slower, 900 second timeout)")
    parser.add_argument(
        "--out", default=DEFAULT_OUT,
        help="findings JSONL file (default "
             "evaluation/data/reconmind_eval/findings.jsonl)")
    return parser.parse_args(args)


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


def main(argv):
    args = _parse_args(argv[1:])
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

    scan_path = _save_scan(tb.scan, target)
    scan_rel = os.path.relpath(scan_path, REPO_ROOT)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    existing = _existing_ids(args.out)

    added = skipped = 0
    with open(args.out, "a") as fh:
        for port in tb.scan.get("ports", []):
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
                "labels": None,  # not labeled yet; a human fills these in
                "scan_file": scan_rel,
            }
            fh.write(json.dumps(record) + "\n")
            added += 1

    print("Added {a} finding(s), skipped {s} duplicate(s).".format(a=added, s=skipped))
    print("Findings: {o}".format(o=args.out))
    print("Scan:     {s}".format(s=scan_rel))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
