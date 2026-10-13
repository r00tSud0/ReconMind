"""
ReconMind Stage 1 runner.

The whole pipeline for now: take a target IP, run the gated nmap scan, and
write a Markdown report. The authorization gate lives inside run_nmap, so a
target that is not on the allowlist is refused before anything touches it, and
the report says so.

The LLM agent brain (the ReAct loop that chooses tools) is added in a later
stage. This runner is the deterministic skeleton it will replace.

Usage:
    python3 -m reconmind.recon <target_ip>
"""

import sys

from reconmind.tools.nmap_scan import run_nmap
from reconmind.core.report import build_report


def run(target_ip):
    """Run the scan and write the report. Return (scan_dict, report_path)."""
    scan = run_nmap(target_ip)
    path = build_report(scan)
    return scan, path


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python3 -m reconmind.recon <target_ip>")
        sys.exit(1)

    target = sys.argv[1]
    scan, path = run(target)
    print("target:     ", scan["target"])
    print("status:     ", scan["status"])
    print("open ports: ", len(scan["ports"]))
    print("report:     ", path)
