"""
ReconMind nmap tool.

A thin wrapper around nmap. The only entry point is run_nmap(target_ip), and
its very first action is to ask the authorization gate whether the target is
allowed. If the gate says no, nmap is never launched. This is how the safety
interlock is enforced for every scan: the tool cannot run against a target the
allowlist did not approve.

Output is a plain dict so the agent and the report builder can read it without
knowing anything about nmap.
"""

import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from reconmind.core.authorization import is_authorized

# Service and version detection, reasonable speed. No exploit scripts.
# smb-os-discovery is in the default, discovery and safe categories only; it
# reads the real Samba version that -sV reports as a vague range ("3.X - 4.X").
NMAP_FLAGS = ["-Pn", "-sV", "--script", "smb-os-discovery", "-T4"]

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
            host_ports.append({
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "service": (svc.get("name") if svc is not None else "unknown"),
                "product": (svc.get("product") if svc is not None else ""),
                "version": (svc.get("version") if svc is not None else ""),
            })

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


def run_nmap(target_ip):
    """
    Scan one authorized target and return a dict:
        {"target", "status", "ports": [...]}
    If the gate refuses the target, status is "refused" and nmap never runs.
    """
    # The gate decides first. Nothing happens if it says no.
    if not is_authorized(target_ip):
        return {"target": target_ip, "status": "refused", "ports": []}

    # Make sure nmap is actually present before trying to call it.
    if shutil.which("nmap") is None:
        return {"target": target_ip, "status": "nmap-not-found", "ports": []}

    # Write XML to a temp file, then read and parse it.
    with tempfile.NamedTemporaryFile(suffix=".xml") as tmp:
        cmd = ["nmap"] + NMAP_FLAGS + ["-oX", tmp.name, str(target_ip)]
        subprocess.run(cmd, check=True, capture_output=True, text=True,
                       timeout=300)
        tmp.seek(0)
        xml_text = open(tmp.name).read()

    ports = _parse_nmap_xml(xml_text)
    return {"target": str(target_ip), "status": "ok", "ports": ports}


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("usage: python3 -m reconmind.tools.nmap_scan <target_ip>")
        sys.exit(1)
    result = run_nmap(sys.argv[1])
    print("target:", result["target"], " status:", result["status"])
    for p in result["ports"]:
        print("  {port}/{protocol}  {service}  {product} {version}".format(**p))
