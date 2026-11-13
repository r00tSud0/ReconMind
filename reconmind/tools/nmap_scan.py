"""
ReconMind nmap tool.

A thin wrapper around nmap. The only entry point is run_nmap(target_ip), and
its very first action is to ask the authorization gate whether the target is
allowed. If the gate says no, nmap is never launched. This is how the safety
interlock is enforced for every scan: the tool cannot run against a target the
allowlist did not approve.

Output is a plain dict so the agent and the report builder can read it without
knowing anything about nmap. Besides the open ports it records how every
scanned port answered (port_states) and how the scan was run (scan_info).
"""

import re
import shlex
import shutil
import socket
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime

from reconmind.core.authorization import is_authorized
from reconmind.core.scan_plan import (
    PORTS_ALL, PORTS_TOP, PortsSpecError, parse_ports, port_count)

# Service and version detection, reasonable speed. No exploit scripts.
# Both scripts are in the default, discovery and safe categories only.
# smb-os-discovery reads the real Samba version that -sV reports as a vague
# range ("3.X - 4.X"); irc-info reads the IRC server's version line
# ("Unreal3.2.8.1"), which -sV usually leaves empty.
NMAP_FLAGS = ["-Pn", "-sV", "--script", "smb-os-discovery,irc-info", "-T4"]

# Added to every pass: nmap records why it gave each port its state
# (syn-ack, reset, no-response, admin-prohibited and so on).
REASON_FLAG = "--reason"

# Pass 1 of an all ports scan: find the open TCP ports across all 65535.
# No version detection and no scripts; pass 2 does the detail work on the
# open ports only. No --min-rate or --max-retries: a forced rate flooded the
# state tables of firewalls on the path and lost packets, while nmap's own
# adaptive timing slows down when it sees drops.
DISCOVERY_FLAGS = ["-Pn", "-p-", "-T4"]

DEFAULT_TIMEOUT = 300     # the single default pass, and pass 2 (detail)
DISCOVERY_TIMEOUT = 1800  # pass 1 (discovery) over every TCP port

MODE_DEFAULT = "top 1000 ports"
MODE_ALL_PORTS = "all 65535 ports, two pass"
MODE_PORT_LIST = "port list {ports}"

# An explicit port list longer than this gets the long timeout.
PORT_LIST_SHORT = 1000

STATUS_BAD_PORTS = "bad-ports"

SMB_PORTS = (139, 445)


def _samba_version(host):
    """Samba version from the host's smb-os-discovery output, or ""."""
    script = host.find("./hostscript/script[@id='smb-os-discovery']")
    if script is None:
        return ""
    lanman = script.find("elem[@key='lanmanager']")
    text = (lanman.text or "") if lanman is not None else ""
    if not text:
        # Older nmap only gives the text form: "OS: Unix (Samba 3.0.20-Debian)"
        found = re.search(r"\((Samba [^)]+)\)", script.get("output", ""))
        text = found.group(1) if found else ""
    found = re.match(r"Samba\s+(\S+)", text.strip())
    return found.group(1) if found else ""


def _unreal_version(port):
    """UnrealIRCd version from the port's irc-info output, or ""."""
    script = port.find("script[@id='irc-info']")
    if script is None:
        return ""
    elem = script.find("elem[@key='version']")
    text = (elem.text or "") if elem is not None else ""
    if not text:
        # Text form: "  version: Unreal3.2.8.1. irc.Metasploitable.LAN"
        found = re.search(r"version:\s*(.+)", script.get("output", ""))
        text = found.group(1) if found else ""
    found = re.search(r"Unreal(?:IRCd)?\s*v?(\d+(?:\.\d+)+)", text, re.IGNORECASE)
    return found.group(1) if found else ""


def _parse_nmap_xml(xml_text):
    """Turn nmap -oX output into a list of open-port dicts."""
    ports = []
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        host_ports = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            entry = {
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "service": (svc.get("name") if svc is not None else "unknown"),
                "product": (svc.get("product") if svc is not None else ""),
                "version": (svc.get("version") if svc is not None else ""),
                # "ssl" when nmap saw the service inside TLS (HTTPS shows as
                # name="http" tunnel="ssl"). Empty otherwise.
                "tunnel": (svc.get("tunnel", "") if svc is not None else ""),
                "reason": state.get("reason", ""),
                # CPE strings exactly as nmap wrote them (CPE 2.2, e.g.
                # cpe:/a:apache:http_server:2.2.8). Empty list if none.
                "cpe": ([c.text.strip() for c in svc.findall("cpe")
                         if c.text and c.text.strip()] if svc is not None else []),
            }
            # Fill the real UnrealIRCd version in when irc-info found one.
            unreal = _unreal_version(port)
            if unreal:
                entry["product"] = "UnrealIRCd"
                entry["version"] = unreal
            host_ports.append(entry)

        # Fill the real Samba version into the SMB ports. Leave other
        # products (a Windows host, say) untouched.
        samba = _samba_version(host)
        if samba:
            for p in host_ports:
                product = p["product"] or ""
                if p["port"] in SMB_PORTS and (not product or "samba" in product.lower()):
                    p["product"] = "Samba smbd"
                    p["version"] = samba
        ports.extend(host_ports)
    return ports


def _open_tcp_ports(xml_text):
    """Sorted open TCP port numbers from one nmap XML run."""
    root = ET.fromstring(xml_text)
    found = set()
    for port in root.findall("./host/ports/port"):
        state = port.find("state")
        if (port.get("protocol") == "tcp" and state is not None
                and state.get("state") == "open"):
            found.add(int(port.get("portid")))
    return sorted(found)


def _unconfirmed_ports(open_ports, detail_xml):
    """
    Ports pass 1 found open that pass 2 did not return as open, as a list of
    {"port", "protocol", "pass2_state", "pass2_reason"} in port order.

    A port pass 2 listed one by one carries its own state and reason. A port
    pass 2 folded into an <extraports> summary is not named in the XML; it
    takes the summary's state when there is exactly one summary (and its
    reason when that summary gives exactly one), otherwise "unknown".
    """
    root = ET.fromstring(detail_xml)
    listed = {}
    for port in root.findall("./host/ports/port"):
        if port.get("protocol") != "tcp":
            continue
        state = port.find("state")
        if state is None:
            listed[int(port.get("portid"))] = ("unknown", "")
        else:
            listed[int(port.get("portid"))] = (state.get("state", "unknown"),
                                               state.get("reason", ""))

    folded = ("unknown", "")
    extras = root.findall("./host/ports/extraports")
    if len(extras) == 1:
        reasons = extras[0].findall("extrareasons")
        folded = (extras[0].get("state", "unknown"),
                  reasons[0].get("reason", "") if len(reasons) == 1 else "")

    unconfirmed = []
    for number in open_ports:
        state, reason = listed.get(number, folded)
        if state != "open":
            unconfirmed.append({"port": number, "protocol": "tcp",
                                "pass2_state": state, "pass2_reason": reason})
    return unconfirmed


def _parse_port_states(xml_text):
    """
    Count every scanned port by state. nmap lists some ports one by one and
    folds the rest into <extraports> summaries; both are counted, so closed
    and filtered ports are not dropped. Returns a list of
    {"state", "count", "reasons": {reason: count}}, largest count first. An
    "open" entry is always present, even when its count is 0.
    """
    root = ET.fromstring(xml_text)
    states = {}

    def entry(state):
        return states.setdefault(state, {"state": state, "count": 0, "reasons": {}})

    def add_reason(item, reason, count):
        if reason:
            item["reasons"][reason] = item["reasons"].get(reason, 0) + count

    entry("open")
    for ports in root.findall("./host/ports"):
        for extra in ports.findall("extraports"):
            item = entry(extra.get("state", "unknown"))
            item["count"] += int(extra.get("count", "0"))
            for why in extra.findall("extrareasons"):
                add_reason(item, why.get("reason", ""), int(why.get("count", "0")))
        for port in ports.findall("port"):
            state = port.find("state")
            if state is None:
                continue
            item = entry(state.get("state", "unknown"))
            item["count"] += 1
            add_reason(item, state.get("reason", ""), 1)
    return sorted(states.values(), key=lambda s: -s["count"])


def _run_info(xml_text):
    """nmap version, start time and elapsed seconds from one XML run."""
    root = ET.fromstring(xml_text)
    start = root.get("start", "")
    if start.isdigit():
        started = datetime.fromtimestamp(int(start)).strftime("%Y-%m-%d %H:%M:%S")
    else:
        started = root.get("startstr", "")
    finished = root.find("./runstats/finished")
    try:
        elapsed = float(finished.get("elapsed")) if finished is not None else 0.0
    except (TypeError, ValueError):
        elapsed = 0.0
    return {"nmap_version": root.get("version", "unknown"),
            "started": started, "elapsed": elapsed}


def _source_ip(target_ip):
    """
    The local address this machine would use to reach the target. connect()
    on a UDP socket sends no packet; it only asks the OS routing table which
    source address it would pick. Returns "unknown" if that fails.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((str(target_ip), 9))
            return sock.getsockname()[0]
    except (OSError, ValueError):
        return "unknown"


def _run_pass(flags, target_ip, timeout):
    """Run one nmap pass with XML output. Return (command line, xml text)."""
    with tempfile.NamedTemporaryFile(suffix=".xml") as tmp:
        cmd = ["nmap"] + flags + ["-oX", tmp.name, str(target_ip)]
        subprocess.run(cmd, check=True, capture_output=True, text=True,
                       timeout=timeout)
        with open(tmp.name) as fh:
            xml_text = fh.read()
    return shlex.join(cmd), xml_text


def run_nmap(target_ip, all_ports=False, ports=None):
    """
    Scan one authorized target and return a dict:
        {"target", "status", "ports": [...], "unconfirmed_ports": [...],
         "port_states": [...], "scan_info": {...}, "raw_xml": [...]}
    If the gate refuses the target, status is "refused" and nmap never runs.

    ports is an optional ports spec ("top", "all" or a list such as
    "21,22,80,8000-8100"). When given it wins over all_ports. It is checked
    with parse_ports right after the gate; a spec that fails gives status
    "bad-ports" with an "error" and nmap never runs. "top" and "all" behave
    exactly like all_ports=False and all_ports=True.

    Explicit list: one pass, NMAP_FLAGS plus --reason plus -p with the
    validated list, 300 second timeout (1800 above 1000 ports).

    Default (all_ports=False): one pass, NMAP_FLAGS plus --reason on nmap's
    default top 1000 ports, 300 second timeout.

    all_ports=True: two passes.
      Pass 1 (discovery): DISCOVERY_FLAGS plus --reason over all 65535 TCP
      ports, no -sV and no scripts, 1800 second timeout.
      Pass 2 (detail): NMAP_FLAGS plus --reason plus -p with only the ports
      pass 1 found open, 300 second timeout. Skipped if none were open.
    port_states always comes from the pass that covered the whole port range
    (the single default pass, or pass 1).

    ports holds only confirmed open ports: in two pass mode, the ones pass 2
    returned as open. A port pass 1 found open but pass 2 did not goes into
    unconfirmed_ports instead, with its pass 2 state and reason; this usually
    means packet loss on the network path. unconfirmed_ports is always
    present and is empty in default mode. raw_xml is the XML of every pass
    that ran, in pass order, kept as evidence.
    """
    # The gate decides first. Nothing happens if it says no.
    if not is_authorized(target_ip):
        return {"target": target_ip, "status": "refused", "ports": [],
                "unconfirmed_ports": [], "raw_xml": []}

    # Checked again here, whatever the caller already did, so no text that
    # is not a clean port list can reach the command line. The list that goes
    # after -p is the one parse_ports rebuilt from integers.
    port_list = None
    if ports is not None:
        try:
            spec = parse_ports(ports)
        except PortsSpecError as exc:
            return {"target": target_ip, "status": STATUS_BAD_PORTS, "ports": [],
                    "unconfirmed_ports": [], "raw_xml": [], "error": str(exc)}
        all_ports = spec == PORTS_ALL
        if spec not in (PORTS_TOP, PORTS_ALL):
            port_list = spec

    # Make sure nmap is actually present before trying to call it.
    if shutil.which("nmap") is None:
        return {"target": target_ip, "status": "nmap-not-found", "ports": [],
                "unconfirmed_ports": [], "raw_xml": []}

    commands = []
    unconfirmed = []
    if port_list:
        mode = MODE_PORT_LIST.format(ports=port_list)
        timeout = (DEFAULT_TIMEOUT if port_count(port_list) <= PORT_LIST_SHORT
                   else DISCOVERY_TIMEOUT)
        cmd, state_xml = _run_pass(NMAP_FLAGS + [REASON_FLAG, "-p", port_list], target_ip,
                                   timeout)
        commands.append(cmd)
        runs = [state_xml]
        ports = _parse_nmap_xml(state_xml)
    elif all_ports:
        mode = MODE_ALL_PORTS
        cmd, state_xml = _run_pass(DISCOVERY_FLAGS + [REASON_FLAG], target_ip,
                                   DISCOVERY_TIMEOUT)
        commands.append(cmd)
        runs = [state_xml]
        ports = []
        open_ports = _open_tcp_ports(state_xml)
        if open_ports:
            detail_flags = NMAP_FLAGS + [REASON_FLAG, "-p",
                                         ",".join(str(p) for p in open_ports)]
            cmd, detail_xml = _run_pass(detail_flags, target_ip, DEFAULT_TIMEOUT)
            commands.append(cmd)
            runs.append(detail_xml)
            ports = _parse_nmap_xml(detail_xml)
            unconfirmed = _unconfirmed_ports(open_ports, detail_xml)
    else:
        mode = MODE_DEFAULT
        cmd, state_xml = _run_pass(NMAP_FLAGS + [REASON_FLAG], target_ip,
                                   DEFAULT_TIMEOUT)
        commands.append(cmd)
        runs = [state_xml]
        ports = _parse_nmap_xml(state_xml)

    infos = [_run_info(xml_text) for xml_text in runs]
    scan_info = {
        "source_ip": _source_ip(target_ip),
        "nmap_version": infos[0]["nmap_version"],
        "mode": mode,
        "commands": commands,
        "started": infos[0]["started"],
        "elapsed_seconds": round(sum(i["elapsed"] for i in infos), 2),
    }
    return {"target": str(target_ip), "status": "ok", "ports": ports,
            "unconfirmed_ports": unconfirmed,
            "port_states": _parse_port_states(state_xml), "scan_info": scan_info,
            "raw_xml": runs}


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("usage: python3 -m reconmind.tools.nmap_scan <target_ip>")
        sys.exit(1)
    result = run_nmap(sys.argv[1])
    print("target:", result["target"], " status:", result["status"])
    for p in result["ports"]:
        print("  {port}/{protocol}  {service}  {product} {version}".format(**p))
