"""
Which scanning tools are ready, using the engine's own lookup rules. Shared
by the System check page and the installer's final verification.
"""

import re
import shutil
import subprocess

from reconmind.tools import httpx_scan

# (label, engine check, version command, check category).
TOOLS = (
    ("nmap", "nmap", ("--version",), "Surface Map"),
    # searchsploit prints no version of its own; () means do not ask.
    ("searchsploit", "searchsploit", (), "Exploit Hunt"),
    ("httpx", "httpx", ("-version",), "Web Fingerprint"),
    ("ffuf", "ffuf", ("-V",), "Hidden Paths"),
    ("nuclei", "nuclei", ("-version",), "Vuln Probe"),
    ("testssl.sh", "testssl", ("--version",), "Crypto Check"),
    ("enum4linux-ng", "enum4linux-ng", ("-h",), "SMB Recon"),
    ("Semgrep", "semgrep", ("--version",), "Code scan"),
    ("Bandit", "bandit", ("--version",), "Code scan"),
)


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_VERSION = re.compile(r"\d+\.\d+")


def tool_path(name):
    """Exact engine selection for ProjectDiscovery httpx and testssl variants."""
    if name == "httpx":
        return shutil.which(httpx_scan.find_binary() or "")
    if name == "testssl":
        return shutil.which("testssl") or shutil.which("testssl.sh")
    return shutil.which(name)


def tool_version(binary, flags):
    """Best-effort version, never fail if a tool hangs or prints junk."""
    if not flags:
        return ""
    try:
        result = subprocess.run([binary, *flags], capture_output=True, text=True,
                                stdin=subprocess.DEVNULL, timeout=2, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    text = _ANSI.sub("", (result.stdout or "") + "\n" + (result.stderr or ""))
    # Banners and usage text are skipped: only a line with a version number counts.
    return next((line.strip()[:120] for line in text.splitlines()
                 if _VERSION.search(line)), "")


def tools():
    """[{"name", "action", "status": "ready"|"missing", "version"}] for every tool."""
    result = []
    for label, executable, flags, action in TOOLS:
        binary = tool_path(executable)
        result.append({
            "name": label,
            "action": action,
            "status": "ready" if binary else "missing",
            "version": tool_version(binary, flags) if binary else "",
        })
    return result
