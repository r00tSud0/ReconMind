"""
ReconMind report builder.

Takes a scan result dict (whatever a tool returned) and writes a Markdown
report into the reports/ folder. It knows nothing about nmap or searchsploit;
it only reads the plain dict shape {target, status, ports}, where each port may
carry an optional "exploits" list added by the exploit lookup tool.
"""

import os
from datetime import datetime

from reconmind.tools.exploit_lookup import exploit_url, primary_label
from reconmind.tools.risky_services import flag_ports

REPORT_DIR = "reports"

# How each match label is described above a port's exploit list.
MATCH_WORDING = {
    "exact_version": "Matched on exact version",
    "version_family": "Matched on version family only (patch level not confirmed)",
    "product_only": "Matched on product name only (version unknown, unconfirmed)",
    "unverified": "Version range could not be checked against the scanned "
                  "version (unconfirmed)",
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


def _lookup_failed(port):
    return port.get("exploit_status") == "lookup_failed"


def _risky_section(lines, ports):
    """Only runs if at least one port matches a risky service rule."""
    flagged = flag_ports(ports)
    if not flagged:
        return
    lines.append("## Exposed risky services")
    lines.append("")
    lines.append("| Port | Service | Product | Severity | Reason |")
    lines.append("|------|---------|---------|----------|--------|")
    for p, flag in flagged:
        lines.append("| {port}/{protocol} | {service} | {product} | {sev} | {reason} |".format(
            port=p.get("port", ""),
            protocol=p.get("protocol", ""),
            service=p.get("service", ""),
            product=p.get("product", "") or "",
            sev=flag["severity"],
            reason=flag["reason"],
        ))
    lines.append("")


def _exploits_section(lines, ports):
    """Only runs if at least one port carries exploit matches or a failed lookup."""
    hits = [p for p in ports if p.get("exploits") or _lookup_failed(p)]
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
        if _lookup_failed(p) and not p.get("exploits"):
            error = (p.get("lookup_error") or "unknown error").rstrip(".")
            lines.append("_Exploit lookup failed: {e}. Not checked. This does not "
                         "mean there are no exploits._".format(e=error))
            lines.append("")
            continue
        exploits = p["exploits"]
        label = primary_label(exploits)
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


SUMMARY_LABEL = "_AI interpretation. The tables below are the verified tool results._"
SUMMARY_UNAVAILABLE = "Analyst summary unavailable: the model output failed validation."
SUMMARY_RATE_LIMITED = "Analyst summary unavailable: the model was busy (rate limited)."
NO_TECHNIQUES = "No ATT&CK technique IDs found in the summary."


def _cell(text):
    return str(text or "").replace("|", "\\|").replace("\n", " ")


def _attack_section(lines, attack_check):
    """The ATT&CK check table under the summary. Never raises."""
    if attack_check is None:
        return
    lines.append("**ATT&CK check**")
    lines.append("")
    if attack_check.skipped:
        lines.append(attack_check.skipped)
        lines.append("")
        return
    if not attack_check.rows:
        lines.append(NO_TECHNIQUES)
        lines.append("")
        return
    lines.append("| ID | Name given | Official name | Result |")
    lines.append("|----|------------|---------------|--------|")
    for row in attack_check.rows:
        lines.append("| {i} | {g} | {o} | {r} |".format(
            i=_cell(row.id), g=_cell(row.given) or "(none)",
            o=_cell(row.official) or "(not in MITRE data)", r=_cell(row.result)))
    lines.append("")


def _summary_section(lines, analyst_summary, unverified_refs, summary_failed,
                     rate_limited=False, attack_check=None):
    if not analyst_summary and not summary_failed and not rate_limited:
        return
    lines.append("## Analyst summary (ReconMind agent)")
    lines.append("")
    if not analyst_summary:
        lines.append(SUMMARY_RATE_LIMITED if rate_limited else SUMMARY_UNAVAILABLE)
        lines.append("")
        return
    lines.append(SUMMARY_LABEL)
    lines.append("")
    lines.append(analyst_summary.strip())
    lines.append("")
    if unverified_refs:
        lines.append("**Unverified references**")
        lines.append("")
        lines.append("_Not found in any tool result for this scan:_")
        for ref in unverified_refs:
            lines.append("- {r}".format(r=ref))
        lines.append("")
    _attack_section(lines, attack_check)


def build_report(scan, analyst_summary=None, unverified_refs=(), summary_failed=False,
                 rate_limited=False, attack_check=None):
    """
    Write one Markdown report for a scan result. Return the file path.

    analyst_summary is optional text written by the agent brain, already
    checked by summary_check. It goes at the top, labeled as AI interpretation,
    with any unverified_refs listed under it. summary_failed means the model
    output failed validation: no model text is shown, only a notice. The fact
    sections render the same either way. rate_limited means the repair call
    hit a provider rate limit: same as summary_failed, with its own notice.
    attack_check is an attack_check.AttackCheck, shown as a table under the
    summary.
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

    _summary_section(lines, analyst_summary, unverified_refs, summary_failed,
                     rate_limited, attack_check)

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
        _risky_section(lines, ports)
        _exploits_section(lines, ports)
        all_exploits = [e for p in ports for e in p.get("exploits", [])]
        counts = {k: sum(1 for e in all_exploits if e.get("match") == k)
                  for k in MATCH_WORDING}
        lines.append("## Notes")
        lines.append("")
        failed = sum(1 for p in ports if _lookup_failed(p))
        risky = len(flag_ports(ports))
        note = ("{n} open port(s) found, {e} known exploit match(es) across "
                "those services: {x} exact version, {f} version family "
                "(unconfirmed), {o} product only (unconfirmed). {u} match(es) "
                "unverified because the version range could not be checked "
                "(unconfirmed). {r} risky service(s) flagged.".format(
                    n=len(ports), e=len(all_exploits),
                    x=counts["exact_version"], f=counts["version_family"],
                    o=counts["product_only"], u=counts["unverified"], r=risky))
        if failed:
            note += (" Exploit lookup failed for {k} port(s), so those services "
                     "were not checked.".format(k=failed))
        note += " Next stage: map each finding to its MITRE ATT&CK technique."
        lines.append(note)

    text = "\n".join(lines) + "\n"
    with open(path, "w") as fh:
        fh.write(text)
    return path
