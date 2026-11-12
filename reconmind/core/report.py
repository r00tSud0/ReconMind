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
from reconmind.tools.nuclei_scan import severity_rank as nuclei_severity_rank
from reconmind.tools.nvd_lookup import (
    NO_RESULTS_NOTE, NOT_IN_DICTIONARY, PATCH_NOTE, RANGE_NOTE, RESOLUTION_FAILED,
    VERSION_FROM_PORT, by_score, severity_counts)
from reconmind.tools.risky_services import flag_ports
from reconmind.tools.smb_enum import format_value, os_summary, policy_fields, smb_ports
from reconmind.tools.testssl_scan import (
    CERT_PREFIX, PROTOCOL_IDS, SEVERITY_ORDER, is_tls_capable, severity_rank,
    starttls_protocol)
from reconmind.tools.whatweb_scan import is_web_service

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


FILTERED_NOTE = ("Filtered ports gave no answer or returned a firewall block "
                 "message, so their true state is unknown from this scan "
                 "location. A firewall is likely between the scanner and the target.")

PASS_LABELS = ("Pass 1 (discovery)", "Pass 2 (detail)")


def _scan_details_section(lines, scan_info):
    """Where, how and with what the scan ran. Only for scans that ran."""
    if not scan_info:
        return
    mode = scan_info.get("mode") or "unknown"
    commands = scan_info.get("commands") or []
    two_pass = "two pass" in mode or len(commands) > 1
    lines.append("## Scan details")
    lines.append("")
    lines.append("- Scanned from: {v}".format(v=scan_info.get("source_ip") or "unknown"))
    lines.append("- nmap version: {v}".format(v=scan_info.get("nmap_version") or "unknown"))
    lines.append("- Mode: {v}".format(v=mode))
    for i, cmd in enumerate(commands):
        if not two_pass:
            label = "Command"
        elif i < len(PASS_LABELS):
            label = PASS_LABELS[i]
        else:
            label = "Pass {n}".format(n=i + 1)
        lines.append("- {label}: `{cmd}`".format(label=label, cmd=cmd))
    if two_pass and len(commands) == 1:
        lines.append("- {label}: skipped, pass 1 found no open ports.".format(
            label=PASS_LABELS[1]))
    lines.append("- Duration: {s:.2f} seconds".format(
        s=float(scan_info.get("elapsed_seconds") or 0)))
    lines.append("")


def _is_filtered(state):
    return state == "filtered" or state.endswith("|filtered")


def _reasons_text(reasons):
    if not reasons:
        return ""
    if len(reasons) == 1:
        return " ({r})".format(r=next(iter(reasons)))
    ordered = sorted(reasons.items(), key=lambda kv: -kv[1])
    return " ({r})".format(r=", ".join("{c:,} {r}".format(c=c, r=r) for r, c in ordered))


UNCONFIRMED_WARNING = (
    "**Warning: unconfirmed ports.** These ports answered as open in the "
    "discovery pass but not in the detail pass: {ports}. This usually means "
    "packets were lost along the network path, for example by a firewall "
    "whose state table filled up during discovery. They are not listed as "
    "findings. Rerun the scan to confirm them.")


def _unconfirmed_section(lines, unconfirmed):
    """Warn about ports pass 1 saw open that pass 2 did not. Only if any."""
    if not unconfirmed:
        return
    items = []
    for u in unconfirmed:
        why = ", ".join(x for x in (u.get("pass2_state") or "unknown",
                                    u.get("pass2_reason") or "") if x)
        items.append("{port}/{protocol} (detail pass: {why})".format(
            port=u.get("port", ""), protocol=u.get("protocol") or "tcp", why=why))
    lines.append(UNCONFIRMED_WARNING.format(ports=", ".join(items)))
    lines.append("")


def _port_states_section(lines, port_states, unconfirmed=()):
    """
    One line counting every scanned port by state, then the unconfirmed
    ports warning (if any), then the firewall note.
    """
    if not port_states:
        _unconfirmed_section(lines, unconfirmed)
        return

    def count(name):
        return sum(s.get("count", 0) for s in port_states if s.get("state") == name)

    others = [s for s in port_states if s.get("state") not in ("open", "closed")]
    others.sort(key=lambda s: s.get("state") != "filtered")  # filtered first
    parts = []
    if not any(s.get("state") == "filtered" for s in others):
        parts.append("0 filtered")
    for s in others:
        parts.append("{c:,} {state}{why}".format(
            c=s.get("count", 0), state=s.get("state", ""),
            why=_reasons_text(s.get("reasons"))))
    parts.append("{c:,} closed".format(c=count("closed")))
    parts.append("{c:,} open".format(c=count("open")))
    lines.append("**Port states:** {p}.".format(p=", ".join(parts)))
    lines.append("")
    _unconfirmed_section(lines, unconfirmed)
    if any(_is_filtered(s.get("state", "")) and s.get("count", 0) for s in port_states):
        lines.append(FILTERED_NOTE)
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


CVE_HEAD = "## Known CVEs (NVD)"
CVE_NOT_CHECKED = ("**Not checked:** open ports carry CPEs, but cve_lookup did not run, "
                   "so no CVEs were looked up.")
CVE_NO_CPE = "_No open port has a CPE with a version, so nothing was looked up._"
CVE_FAILED = ("_NVD lookup failed (status {s}), so this product was not checked. This "
              "does not mean it has no CVEs._")
CVE_NONE = "_{n}_".format(n=NO_RESULTS_NOTE)
CVE_SKIPPED = "**Skipped, no version:** {items}."
CVE_AMBIGUOUS = "**Skipped, no single NVD CPE name:** {items}."
CVE_CPE_RESOLVED = "NVD dictionary name for `{f}`"
CVE_CPE_NOT_IN_DICTIONARY = "not found in NVD's CPE dictionary, kept as found"
CVE_CPE_RESOLUTION_FAILED = "NVD's CPE dictionary could not be checked, kept as found"
CVE_VERSION_FROM_PORT = "version from nmap's port version"
CVE_MORE = "...and {n} more stored in the scan data."
CVE_CONFIRMED = "confirmed live by nuclei"
CVE_SHOWN = 10
CVE_DESCRIPTION_CHARS = 160


def _nuclei_cve_ids(nuclei):
    """Every CVE ID nuclei reported for this target, upper case."""
    found = set()
    for result in (nuclei or {}).values():
        if not isinstance(result, dict) or result.get("status") != "ok":
            continue
        for f in result.get("findings") or []:
            for cve in f.get("cve") or []:
                if cve:
                    found.add(str(cve).strip().upper())
    return found


def _ordered_cves(cves, confirmed):
    """Confirmed by nuclei first, then CISA KEV, then the rest; each by CVSS score."""
    ranked = by_score(cves)
    first = [c for c in ranked if str(c.get("id", "")).upper() in confirmed]
    taken = {id(c) for c in first}
    kev = [c for c in ranked if id(c) not in taken and c.get("kev")]
    taken.update(id(c) for c in kev)
    return first + kev + [c for c in ranked if id(c) not in taken]


def _short(text):
    text = " ".join(str(text or "").split())
    if len(text) <= CVE_DESCRIPTION_CHARS:
        return text
    cut = text[:CVE_DESCRIPTION_CHARS]
    if " " in cut:
        cut = cut[:cut.rindex(" ")]
    return cut + "..."


def _cve_line(cve, confirmed):
    cve_id = cve.get("id", "")
    line = "- {i}".format(i=cve_id)
    if str(cve_id).upper() in confirmed:
        line += " ({c})".format(c=CVE_CONFIRMED)
    score = cve.get("cvss_score")
    if score is None:
        line += ": no CVSS score"
    else:
        line += ": CVSS {s} {v} ({k})".format(s=score, v=cve.get("cvss_severity", ""),
                                             k=cve.get("cvss_version", ""))
    if cve.get("kev"):
        line += ", CISA KEV yes (added {d})".format(d=cve.get("kev_added", ""))
    else:
        line += ", CISA KEV no"
    description = _short(cve.get("description"))
    if description:
        line += ". " + description
    return line


def _cve_counts_line(cves):
    counts = severity_counts(cves)
    parts = ["{s} {n}".format(s=s, n=counts[s]) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]
    if counts["NONE"]:
        parts.append("NONE {n}".format(n=counts["NONE"]))
    if counts["UNSCORED"]:
        parts.append("no score {n}".format(n=counts["UNSCORED"]))
    return "By severity: {p} ({t} total)".format(p=", ".join(parts), t=len(cves))


def _cve_product(lines, product, confirmed):
    ports = ", ".join(product.get("ports") or [])
    lines.append("**{p}**{o}".format(p=product.get("product") or product.get("cpe", ""),
                                      o=" ({x})".format(x=ports) if ports else ""))
    lines.append("")
    cpe = product.get("cpe", "")
    notes = []
    origin = product.get("resolved_from")
    resolution = product.get("cpe_resolution")
    if resolution == NOT_IN_DICTIONARY:
        notes.append(CVE_CPE_NOT_IN_DICTIONARY)
    elif resolution == RESOLUTION_FAILED:
        notes.append(CVE_CPE_RESOLUTION_FAILED)
    elif origin and origin != cpe:
        notes.append(CVE_CPE_RESOLVED.format(f=origin))
    if product.get("version_from") == VERSION_FROM_PORT:
        notes.append(CVE_VERSION_FROM_PORT)
    lines.append("CPE: `{c}`{n}".format(c=cpe, n=" ({x})".format(x="; ".join(notes))
                                         if notes else ""))
    lines.append("")
    if product.get("status") != "ok":
        lines.append(CVE_FAILED.format(s=product.get("status") or "unknown"))
        lines.append("")
        return
    lines.append("NVD data fetched: {f}{c}".format(
        f=product.get("fetched_at") or "unknown",
        c=" (from cache)" if product.get("from_cache") else ""))
    lines.append("")
    cves = product.get("cves") or []
    if not cves:
        lines.append(CVE_NONE)
        lines.append("")
        return
    lines.append(_cve_counts_line(cves))
    lines.append("")
    ordered = _ordered_cves(cves, confirmed)
    for cve in ordered[:CVE_SHOWN]:
        lines.append(_cve_line(cve, confirmed))
    if len(ordered) > CVE_SHOWN:
        lines.append(CVE_MORE.format(n=len(ordered) - CVE_SHOWN))
    lines.append("")


def _cve_section(lines, ports, nvd, nuclei):
    """Runs when cve_lookup ran, or when open ports carry CPEs it never looked up."""
    if not nvd:
        if any(p.get("cpe") for p in ports):
            lines.append(CVE_HEAD)
            lines.append("")
            lines.append(CVE_NOT_CHECKED)
            lines.append("")
        return
    lines.append(CVE_HEAD)
    lines.append("")
    lines.append(PATCH_NOTE + " " + RANGE_NOTE)
    lines.append("")
    if nvd.get("status") != "ok":
        lines.append(CVE_NO_CPE if nvd.get("status") == "no-cpe"
                     else CVE_FAILED.format(s=nvd.get("status") or "unknown"))
        lines.append("")
    confirmed = _nuclei_cve_ids(nuclei)
    for product in nvd.get("products") or []:
        _cve_product(lines, product, confirmed)
    skipped = nvd.get("skipped") or []
    for template, group in ((CVE_SKIPPED, [s for s in skipped if not s.get("candidates")]),
                            (CVE_AMBIGUOUS, [s for s in skipped if s.get("candidates")])):
        if not group:
            continue
        items = []
        for s in group:
            where = ", ".join(s.get("ports") or [])
            items.append("{c}{w} ({r})".format(c=s.get("cpe", ""),
                                                w=" on " + where if where else "",
                                                r=s.get("reason", "")))
        lines.append(template.format(items="; ".join(items)))
        lines.append("")


WEB_NOT_CHECKED = ("**Not checked:** these open web ports were not fingerprinted "
                   "with whatweb: {ports}.")
WEB_FAILED = "_whatweb did not complete (status {s}), so this port was not checked._"
WEB_NO_COMPONENTS = "_whatweb recognized no components._"


def _web_component_line(component):
    """One component: its versions first, then its strings, as whatweb gave them."""
    parts = ["version {v}".format(v=v) for v in component.get("versions") or []]
    parts += [str(s) for s in component.get("strings") or []]
    name = component.get("name", "")
    return "- {n}: {p}".format(n=name, p="; ".join(parts)) if parts else "- {n}".format(n=name)


def _web_section(lines, ports, web):
    """Only runs if at least one open port is an HTTP or HTTPS service."""
    web_ports = [p for p in ports if is_web_service(p)]
    if not web_ports:
        return
    web = web or {}
    lines.append("## Web technology (whatweb)")
    lines.append("")
    not_checked = []
    for p in web_ports:
        label = "{port}/{protocol}".format(port=p.get("port", ""),
                                           protocol=p.get("protocol") or "tcp")
        # int keys from the agent; str keys if the scan was reloaded from JSON
        result = web.get(p.get("port")) or web.get(str(p.get("port")))
        if not result:
            not_checked.append("{l} ({s})".format(l=label, s=p.get("service") or "unknown"))
            continue
        if result.get("status") != "ok":
            lines.append("**{l}** {u}".format(l=label, u=result.get("url") or "").strip())
            lines.append(WEB_FAILED.format(s=result.get("status") or "unknown"))
            lines.append("")
            continue
        http_status = result.get("http_status")
        lines.append("**{l}** {u} (HTTP status {h})".format(
            l=label, u=result.get("url", ""),
            h=http_status if http_status is not None else "unknown"))
        components = result.get("components") or []
        if not components:
            lines.append(WEB_NO_COMPONENTS)
        for c in components:
            lines.append(_web_component_line(c))
        lines.append("")
    if not_checked:
        lines.append(WEB_NOT_CHECKED.format(ports=", ".join(not_checked)))
        lines.append("")


DISCOVERY_HEAD = "## Web content discovery (ffuf)"
DISCOVERY_NOT_CHECKED = ("**Not checked:** these open web ports were not scanned for "
                         "content with ffuf: {ports}.")
DISCOVERY_FAILED = "_ffuf did not complete (status {s}), so this port was not checked._"
DISCOVERY_NO_RESULTS = "_ffuf found no matching paths._"
DISCOVERY_WORDLIST = "Wordlist: {n} ({c} lines)"


def _discovery_table(lines, results):
    """Every ffuf result, sorted by path, values as ffuf gave them."""
    lines.append("| Path | Status | Size | Redirect |")
    lines.append("|------|--------|------|----------|")
    for r in sorted(results, key=lambda r: str(r.get("path", ""))):
        size = r.get("length")
        lines.append("| {p} | {s} | {z} | {r} |".format(
            p=_cell(r.get("path")), s=_cell(r.get("status")),
            z=_cell(size if size is not None else ""), r=_cell(r.get("redirect"))))


def _discovery_section(lines, ports, discovery):
    """Only runs if at least one open port is an HTTP or HTTPS service."""
    web_ports = [p for p in ports if is_web_service(p)]
    if not web_ports:
        return
    discovery = discovery or {}
    lines.append(DISCOVERY_HEAD)
    lines.append("")
    not_checked = []
    for p in web_ports:
        label = "{port}/{protocol}".format(port=p.get("port", ""),
                                           protocol=p.get("protocol") or "tcp")
        # int keys from the agent; str keys if the scan was reloaded from JSON
        result = discovery.get(p.get("port")) or discovery.get(str(p.get("port")))
        if not result:
            not_checked.append("{l} ({s})".format(l=label, s=p.get("service") or "unknown"))
            continue
        lines.append("**{l}** {u}".format(l=label, u=result.get("url") or "").strip())
        if result.get("status") != "ok":
            lines.append(DISCOVERY_FAILED.format(s=result.get("status") or "unknown"))
            lines.append("")
            continue
        count = result.get("wordlist_lines")
        lines.append(DISCOVERY_WORDLIST.format(
            n=os.path.basename(result.get("wordlist") or "") or "unknown",
            c=count if count is not None else "unknown"))
        lines.append("")
        # raw_json is evidence only and is never printed.
        results = result.get("results") or []
        if results:
            _discovery_table(lines, results)
        else:
            lines.append(DISCOVERY_NO_RESULTS)
        lines.append("")
    if not_checked:
        lines.append(DISCOVERY_NOT_CHECKED.format(ports=", ".join(not_checked)))
        lines.append("")


NUCLEI_HEAD = "## Template checks (nuclei)"
NUCLEI_NOT_CHECKED = ("**Not checked:** these open web ports were not checked with "
                      "nuclei templates: {ports}.")
NUCLEI_FAILED = "_nuclei did not complete (status {s}), so this port was not checked._"
NUCLEI_NO_FINDINGS = "_nuclei found nothing at low severity or above._"
NUCLEI_TEMPLATES = "Templates version: {v}"
NUCLEI_EXCLUDED = ("Excluded: denial of service, fuzzing, intrusive, default login and "
                   "brute force templates. No outside callbacks (interactsh off).")


def _nuclei_finding_line(f):
    """One finding: severity, name, template id, where it matched, any CVE."""
    line = "- [{s}] {n}, template {t}, matched at {m}".format(
        s=f.get("severity", ""), n=f.get("name", ""), t=f.get("template_id", ""),
        m=f.get("matched_at", ""))
    cves = [str(c) for c in f.get("cve") or [] if c]
    if cves:
        line += ", {c}".format(c=", ".join(cves))
    return line


def _nuclei_section(lines, ports, nuclei):
    """Only runs if at least one open port is an HTTP or HTTPS service."""
    web_ports = [p for p in ports if is_web_service(p)]
    if not web_ports:
        return
    nuclei = nuclei or {}
    lines.append(NUCLEI_HEAD)
    lines.append("")
    not_checked = []
    for p in web_ports:
        label = "{port}/{protocol}".format(port=p.get("port", ""),
                                           protocol=p.get("protocol") or "tcp")
        # int keys from the agent; str keys if the scan was reloaded from JSON
        result = nuclei.get(p.get("port")) or nuclei.get(str(p.get("port")))
        if not result:
            not_checked.append("{l} ({s})".format(l=label, s=p.get("service") or "unknown"))
            continue
        lines.append("**{l}** {u}".format(l=label, u=result.get("url") or "").strip())
        if result.get("status") != "ok":
            lines.append(NUCLEI_FAILED.format(s=result.get("status") or "unknown"))
            lines.append("")
            continue
        lines.append(NUCLEI_TEMPLATES.format(v=result.get("templates_version") or "unknown"))
        lines.append("")
        lines.append(NUCLEI_EXCLUDED)
        lines.append("")
        # raw_jsonl is evidence only and is never printed.
        findings = sorted(result.get("findings") or [],
                          key=lambda f: nuclei_severity_rank(f.get("severity")))
        if not findings:
            lines.append(NUCLEI_NO_FINDINGS)
        for f in findings:
            lines.append(_nuclei_finding_line(f))
        lines.append("")
    if not_checked:
        lines.append(NUCLEI_NOT_CHECKED.format(ports=", ".join(not_checked)))
        lines.append("")


TLS_HEAD = "## TLS checks (testssl.sh)"
TLS_NOT_CHECKED = ("**Not checked:** these TLS or STARTTLS capable ports were not "
                   "checked with testssl.sh: {ports}.")
TLS_FAILED = "_testssl.sh did not complete (status {s}), so this port was not checked._"
TLS_NOT_TLS = "_testssl.sh reports this port does not speak TLS._"
TLS_NO_FINDINGS = "_No findings of LOW severity or higher._"
TLS_NO_CERT = "_No certificate findings._"
TLS_CIPHERS_KEPT = "{n} individual cipher entries kept in the stored scan data."

# testssl.sh protocol ids and how the report names them.
PROTOCOL_NAMES = {"SSLv2": "SSLv2", "SSLv3": "SSLv3", "TLS1": "TLS 1.0",
                  "TLS1_1": "TLS 1.1", "TLS1_2": "TLS 1.2", "TLS1_3": "TLS 1.3"}


def _tls_finding_line(f):
    line = "- [{s}] {i}: {t}".format(s=f.get("severity", ""), i=f.get("id", ""),
                                    t=f.get("finding", ""))
    if f.get("cve"):
        line += " ({c})".format(c=f["cve"])
    return line


def _tls_port_result(lines, result):
    findings = result.get("findings") or []
    offered = [PROTOCOL_NAMES[f.get("id")] for f in findings
               if f.get("id") in PROTOCOL_IDS
               and str(f.get("finding", "")).lower().startswith("offered")]
    lines.append("Protocols offered: {p}".format(p=", ".join(offered) or "none reported"))
    lines.append("")
    lines.append("Certificate:")
    cert = [f for f in findings if str(f.get("id", "")).startswith(CERT_PREFIX)]
    if not cert:
        lines.append(TLS_NO_CERT)
    for f in cert:
        lines.append("- {i}: {t} ({s})".format(i=f.get("id", ""), t=f.get("finding", ""),
                                               s=f.get("severity", "")))
    lines.append("")
    lines.append("Findings, most severe first:")
    rated = sorted((f for f in findings
                    if str(f.get("severity", "")).upper() in SEVERITY_ORDER),
                   key=lambda f: severity_rank(f.get("severity")))
    if not rated:
        lines.append(TLS_NO_FINDINGS)
    for f in rated:
        lines.append(_tls_finding_line(f))
    # Per cipher rows are evidence: counted here, never listed. raw_json is
    # never printed.
    lines.append("")
    lines.append(TLS_CIPHERS_KEPT.format(n=len(result.get("ciphers") or [])))


def _tls_section(lines, ports, tls):
    """Only runs if at least one open port is TLS or STARTTLS capable."""
    tls_ports = [p for p in ports if is_tls_capable(p)]
    if not tls_ports:
        return
    tls = tls or {}
    lines.append(TLS_HEAD)
    lines.append("")
    not_checked = []
    for p in tls_ports:
        label = "{port}/{protocol}".format(port=p.get("port", ""),
                                           protocol=p.get("protocol") or "tcp")
        proto = starttls_protocol(p)
        how = "STARTTLS {s}".format(s=proto) if proto else "direct TLS"
        # int keys from the agent; str keys if the scan was reloaded from JSON
        result = tls.get(p.get("port")) or tls.get(str(p.get("port")))
        if not result:
            not_checked.append("{l} ({s}, {h})".format(
                l=label, s=p.get("service") or "unknown", h=how))
            continue
        lines.append("**{l}** ({h})".format(l=label, h=how))
        status = result.get("status")
        if status == "not-tls":
            lines.append(TLS_NOT_TLS)
        elif status != "ok":
            lines.append(TLS_FAILED.format(s=status or "unknown"))
        else:
            _tls_port_result(lines, result)
        lines.append("")
    if not_checked:
        lines.append(TLS_NOT_CHECKED.format(ports=", ".join(not_checked)))
        lines.append("")


SMB_HEAD = "## SMB enumeration (enum4linux-ng)"
SMB_NOT_CHECKED = ("**Not checked:** SMB port(s) {ports} are open but SMB was not "
                   "enumerated with enum4linux-ng.")
SMB_FAILED = "_enum4linux-ng did not complete (status {s}), so SMB was not checked._"
SMB_NULL_SESSION = "**Null session allowed:** {v}"
SMB_DOMAIN = "**Domain or workgroup:** {v}"
SMB_OS = "**OS:** {v}"
SMB_USERS = "**Users ({n}):** {v}"
SMB_NO_SHARES = "_No shares reported._"
SMB_NO_POLICY = "_No password policy reported._"
SMB_UNKNOWN = "not reported"
SMB_ANONYMOUS_NOTE = "_Anonymous (null session) checks only. No credentials were used._"


def _null_session_text(value):
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return SMB_UNKNOWN


def _smb_result(lines, result):
    users = result.get("users") or []
    lines.append(SMB_NULL_SESSION.format(v=_null_session_text(result.get("null_session"))))
    lines.append("")
    lines.append(SMB_DOMAIN.format(v=result.get("domain") or SMB_UNKNOWN))
    lines.append("")
    lines.append(SMB_OS.format(v=os_summary(result.get("os")) or SMB_UNKNOWN))
    lines.append("")
    lines.append(SMB_USERS.format(
        n=len(users), v=", ".join(u.get("username", "") for u in users) or "none"))
    lines.append("")
    lines.append("Shares:")
    lines.append("")
    shares = result.get("shares") or []
    if not shares:
        lines.append(SMB_NO_SHARES)
    else:
        lines.append("| Name | Type | Comment | Mapping | Listing |")
        lines.append("|------|------|---------|---------|---------|")
        for s in shares:
            lines.append("| {n} | {t} | {c} | {m} | {l} |".format(
                n=_cell(s.get("name")), t=_cell(s.get("type")), c=_cell(s.get("comment")),
                m=_cell(s.get("mapping")), l=_cell(s.get("listing"))))
    lines.append("")
    lines.append("Password policy:")
    fields = policy_fields(result.get("policy"))
    if not fields:
        lines.append(SMB_NO_POLICY)
    for field, value in fields:
        lines.append("- {f}: {v}".format(f=field, v=format_value(value)))
    lines.append("")
    # raw_json is evidence only and is never printed.
    lines.append(SMB_ANONYMOUS_NOTE)


def _smb_section(lines, ports, smb):
    """Only runs if port 139 or 445 is open."""
    open_smb = smb_ports(ports)
    if not open_smb:
        return
    lines.append(SMB_HEAD)
    lines.append("")
    labels = ", ".join("{port}/{protocol}".format(port=p.get("port", ""),
                                                 protocol=p.get("protocol") or "tcp")
                       for p in open_smb)
    if not smb:
        lines.append(SMB_NOT_CHECKED.format(ports=labels))
    elif smb.get("status") != "ok":
        lines.append(SMB_FAILED.format(s=smb.get("status") or "unknown"))
    else:
        _smb_result(lines, smb)
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
    unconfirmed = scan.get("unconfirmed_ports") or []

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

    if status not in ("refused", "nmap-not-found"):
        _scan_details_section(lines, scan.get("scan_info"))

    if status == "refused":
        lines.append("The target was refused by the authorization gate. "
                      "It is not on the allowlist, so no scan was run.")
    elif status == "nmap-not-found":
        lines.append("nmap is not installed on this machine, so no scan was run. "
                     "Run this on the Kali box where nmap is present.")
    elif not ports:
        if unconfirmed:
            lines.append("The scan ran but no port was confirmed open. See the "
                         "unconfirmed ports warning below.")
        else:
            lines.append("The scan ran but found no open ports.")
        if scan.get("port_states") or unconfirmed:
            lines.append("")
            _port_states_section(lines, scan.get("port_states"), unconfirmed)
    else:
        _ports_table(lines, ports)
        _port_states_section(lines, scan.get("port_states"), unconfirmed)
        _risky_section(lines, ports)
        _exploits_section(lines, ports)
        _cve_section(lines, ports, scan.get("nvd"), scan.get("nuclei"))
        _web_section(lines, ports, scan.get("web"))
        _discovery_section(lines, ports, scan.get("discovery"))
        _nuclei_section(lines, ports, scan.get("nuclei"))
        _tls_section(lines, ports, scan.get("tls"))
        _smb_section(lines, ports, scan.get("smb"))
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
        if unconfirmed:
            note += (" {k} more port(s) answered as open in discovery only and "
                     "were not confirmed, so they are not counted here.".format(
                         k=len(unconfirmed)))
        note += " Next stage: map each finding to its MITRE ATT&CK technique."
        lines.append(note)

    text = "\n".join(lines) + "\n"
    with open(path, "w") as fh:
        fh.write(text)
    return path
