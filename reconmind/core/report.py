"""
ReconMind report builder.

Takes a scan result dict (whatever a tool returned) and writes a Markdown
report into the reports/ folder. It knows nothing about nmap or any other
tool; it only reads the plain dict shape {target, status, ports}. That keeps
the report builder reusable as more tools are added later.
"""

import os
from datetime import datetime

REPORT_DIR = "reports"


def build_report(scan):
    """Write one Markdown report for a scan result. Return the file path."""
    os.makedirs(REPORT_DIR, exist_ok=True)

    target = scan.get("target", "unknown")
    status = scan.get("status", "unknown")
    ports = scan.get("ports", [])

    now = datetime.now()
    stamp = now.strftime("%Y-%m-%d %H:%M:%S")
    safe_target = str(target).replace("/", "_").replace(":", "_")
    fname = "recon_{t}_{s}.md".format(t=safe_target, s=now.strftime("%Y%m%d_%H%M%S"))
    path = os.path.join(REPORT_DIR, fname)

    lines = [
        "# ReconMind Report",
        "",
        "**Target:** {t}".format(t=target),
        "**Scan status:** {s}".format(s=status),
        "**Generated:** {ts}".format(ts=stamp),
        "",
    ]

    if status == "refused":
        lines.append("The target was refused by the authorization gate. "
                      "It is not on the allowlist, so no scan was run.")
    elif status == "nmap-not-found":
        lines.append("nmap is not installed on this machine, so no scan was run. "
                     "Run this on the Kali box where nmap is present.")
    elif not ports:
        lines.append("The scan ran but found no open ports.")
    else:
        lines.append("## Open ports")
        lines.append("")
        lines.append("| Port | Protocol | Service | Product | Version |")
        lines.append("|------|----------|---------|---------|---------|")
        for p in ports:
            lines.append("| {port} | {protocol} | {service} | {product} | {version} |".format(
                port=p.get("port", ""),
                protocol=p.get("protocol", ""),
                service=p.get("service", ""),
                product=p.get("product", ""),
                version=p.get("version", ""),
            ))
        lines.append("")
        lines.append("## Notes")
        lines.append("")
        lines.append("{n} open port(s) found. Next steps planned for later stages: "
                     "match each service version to known vulnerabilities, and map "
                     "each finding to its MITRE ATT&CK technique.".format(n=len(ports)))

    text = "\n".join(lines) + "\n"
    with open(path, "w") as fh:
        fh.write(text)
    return path
