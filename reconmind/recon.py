"""
ReconMind Stage 2 runner.

Pipeline: authorized nmap scan -> exploit lookup -> Markdown report.
The authorization gate lives inside run_nmap, so a target that is not on the
allowlist is refused before anything touches it.

Usage:
    python3 -m reconmind.recon <target_ip>
"""

import sys

from reconmind.tools.nmap_scan import run_nmap
from reconmind.tools.exploit_lookup import enrich_with_exploits
from reconmind.core.report import build_report


def run(target_ip):
    """Scan, enrich with known exploits, and write the report."""
    scan = run_nmap(target_ip)
    enrich_with_exploits(scan)
    path = build_report(scan)
    return scan, path


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python3 -m reconmind.recon <target_ip>")
        sys.exit(1)

    target = sys.argv[1]
    scan, path = run(target)
    total_exploits = sum(len(p.get("exploits", [])) for p in scan["ports"])
    print("target:     ", scan["target"])
    print("status:     ", scan["status"])
    print("open ports: ", len(scan["ports"]))
    print("exploits:   ", total_exploits)
    print("report:     ", path)
