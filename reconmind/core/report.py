"""
ReconMind report builder.

Takes a scan result dict (whatever a tool returned) and writes a Markdown
report into the reports/ folder. It knows nothing about nmap or searchsploit;
it only reads the plain dict shape {target, status, ports}, where each port may
carry an optional "exploits" list added by the exploit lookup tool.
"""

import os
from datetime import datetime

from reconmind.tools.exploit_lookup import exploit_url

REPORT_DIR = "reports"

# How each match label is described above a port's exploit list.
MATCH_WORDING = {
    "exact_version": "Matched on exact version",
    "version_family": "Matched on version family only (patch level not confirmed)",
    "product_only": "Matched on product name only (version unknown, unconfirmed)",
}


def _ports_table(lines, ports):
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


def _exploits_section(lines, ports):
    """Only runs if at least one port carries exploit matches."""
    hits = [p for p in ports if p.get("exploits")]
    if not hits:
        return
    lines.append("## Known exploits (Exploit-DB)")
    lines.append("")
    for p in hits:
        header = "{port}/{protocol}  {product} {version}".format(
            port=p.get("port", ""),
            protocol=p.get("protocol", ""),
            product=p.get("product", ""),
            version=p.get("version", ""),
        ).strip()
        lines.append("**{h}**".format(h=header))
        exploits = p["exploits"]
        label = exploits[0].get("match")
        if label in MATCH_WORDING:
            lines.append("_{w}. Query: `{q}`_".format(
                w=MATCH_WORDING[label], q=exploits[0].get("query", "")))
        for e in exploits[:5]:
            edb = e.get("edb_id", "")
            line = "- {title}".format(title=e.get("title", ""))
            if edb:
                line += " (EDB-{id})".format(id=edb)
            if e.get("match"):
                line += " [{m}]".format(m=e["match"])
            if edb:
                line += " Link: {url}".format(url=exploit_url(edb))
            lines.append(line)
        if len(exploits) > 5:
            lines.append("- ...and {n} more".format(n=len(exploits) - 5))
        lines.append("")


def build_report(scan, analyst_summary=None):
    """
    Write one Markdown report for a scan result. Return the file path.

    analyst_summary is optional free text written by the agent brain. When it
    is present it goes at the top of the report, above the raw tables.
    """
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

    if analyst_summary:
        lines.append("## Analyst summary (ReconMind agent)")
        lines.append("")
        lines.append(analyst_summary.strip())
        lines.append("")

    if status == "refused":
        lines.append("The target was refused by the authorization gate. "
                      "It is not on the allowlist, so no scan was run.")
    elif status == "nmap-not-found":
        lines.append("nmap is not installed on this machine, so no scan was run. "
                     "Run this on the Kali box where nmap is present.")
    elif not ports:
        lines.append("The scan ran but found no open ports.")
    else:
        _ports_table(lines, ports)
        _exploits_section(lines, ports)
        all_exploits = [e for p in ports for e in p.get("exploits", [])]
        counts = {k: sum(1 for e in all_exploits if e.get("match") == k)
                  for k in MATCH_WORDING}
        lines.append("## Notes")
        lines.append("")
        lines.append("{n} open port(s) found, {e} known exploit match(es) across "
                     "those services: {x} exact version, {f} version family "
                     "(unconfirmed), {o} product only (unconfirmed). Next stage: "
                     "map each finding to its MITRE ATT&CK technique.".format(
                         n=len(ports), e=len(all_exploits),
                         x=counts["exact_version"], f=counts["version_family"],
                         o=counts["product_only"]))

    text = "\n".join(lines) + "\n"
    with open(path, "w") as fh:
        fh.write(text)
    return path
