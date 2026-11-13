"""
ReconMind testssl.sh tool (Stage 2, TLS checks).

A thin wrapper around testssl.sh. The only entry point is
run_testssl(target_ip, port, starttls=None), and like run_nmap and
run_httpx its very first action is to ask the authorization gate whether the
target is allowed. If the gate says no, testssl.sh is never launched.

testssl.sh runs with its default checks only. Results are read from its flat
JSON file. Finding text, CVE and CWE values are kept exactly as testssl.sh
wrote them; nothing is rewritten or guessed. Rows for one individual cipher or
one protocol's cipher order are evidence, not findings, and are kept apart in
"ciphers". The whole JSON file is kept as evidence in "raw_json".

Output is a plain dict so the agent and the report builder can read it
without knowing anything about testssl.sh.
"""

import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile

from reconmind.core.authorization import is_authorized

# Installed as "testssl" by the Kali package and as "testssl.sh" from git.
BINARY_NAMES = ("testssl", "testssl.sh")
TESTSSL_FLAGS = ["--quiet", "--color", "0", "--warnings", "off"]
TESTSSL_TIMEOUT = 600

# nmap service name to testssl.sh --starttls protocol.
STARTTLS_SERVICES = {
    "smtp": "smtp",
    "ftp": "ftp",
    "imap": "imap",
    "pop3": "pop3",
    "postgresql": "postgres",
}
STARTTLS_PROTOCOLS = tuple(sorted(set(STARTTLS_SERVICES.values())))

# Severities kept for every finding, most severe first.
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
# Kept whatever their severity: which protocols are offered and the
# certificate details.
PROTOCOL_IDS = ("SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3")
CERT_PREFIX = "cert_"
# One row per individual cipher (cipher-tls1_2_xc030) or per protocol cipher
# order (cipher_order-tls1_2). Evidence, not findings. cipherlist_* and plain
# cipher_order stay findings.
CIPHER_PREFIXES = ("cipher-", "cipher_order-")

# What testssl.sh says when the port does not speak TLS. A STARTTLS port that
# never offers STARTTLS gives "Fatal error: No STARTTLS found in handshake"
# (exit code 246).
NOT_TLS_PATTERN = re.compile(
    r"doesn.t seem to be a TLS/SSL enabled server|not a TLS/SSL enabled server"
    r"|No STARTTLS found in handshake",
    re.IGNORECASE)

STATUS_OK = "ok"
STATUS_REFUSED = "refused"
STATUS_BAD_PORT = "bad-port"
STATUS_BAD_STARTTLS = "bad-starttls"
STATUS_NOT_FOUND = "testssl-not-found"
STATUS_TIMEOUT = "timeout"
STATUS_FAILED = "failed"
STATUS_EMPTY_JSON = "empty-json"
STATUS_BAD_JSON = "bad-json"
STATUS_NOT_TLS = "not-tls"


def direct_tls(port):
    """True if nmap saw the port wrapped in SSL/TLS: tunnel ssl, or a service
    named https, ssl or ssl/anything."""
    service = (port.get("service") or "").lower()
    tunnel = (port.get("tunnel") or "").lower()
    return (tunnel == "ssl" or service in ("https", "ssl")
            or service.startswith("ssl/"))


def starttls_protocol(port):
    """The testssl.sh --starttls protocol for a plain text service that can
    upgrade to TLS, or None. Ports already wrapped in TLS never use STARTTLS."""
    if direct_tls(port):
        return None
    return STARTTLS_SERVICES.get((port.get("service") or "").lower())


def is_tls_capable(port):
    """True if tls_check is allowed on this port."""
    return direct_tls(port) or starttls_protocol(port) is not None


def build_target(target_ip, port):
    """host:port as testssl.sh expects it, e.g. 10.10.1.100:443."""
    host = str(target_ip).strip()
    if ":" in host:  # IPv6 literal
        host = "[{h}]".format(h=host)
    return "{h}:{p}".format(h=host, p=int(port))


def severity_rank(severity):
    """0 for CRITICAL up to 3 for LOW; anything else sorts after them."""
    severity = str(severity or "").upper()
    return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER)


def is_cipher_row(entry):
    """True for a per cipher or per protocol cipher order row."""
    return str(entry.get("id", "")).startswith(CIPHER_PREFIXES)


def _keep(entry):
    entry_id = str(entry.get("id", ""))
    if str(entry.get("severity", "")).upper() in SEVERITY_ORDER:
        return True
    return entry_id.startswith(PROTOCOL_IDS) or entry_id.startswith(CERT_PREFIX)


def _finding(entry):
    return {"id": entry.get("id", ""), "severity": entry.get("severity", ""),
            "finding": entry.get("finding", ""), "cve": entry.get("cve", ""),
            "cwe": entry.get("cwe", "")}


def _result(status, target="", port=None, starttls=None, command="", findings=None,
            error="", ciphers=None, raw_json=""):
    result = {"status": status, "target": target, "port": port, "starttls": starttls,
              "command": command, "findings": findings or [], "ciphers": ciphers or [],
              "raw_json": raw_json or ""}
    if error:
        result["error"] = error
    return result


def _parse_json(text, output=""):
    """
    Read testssl.sh's flat JSON file. Return (status, findings, ciphers, error).
    ciphers holds every per cipher and per protocol cipher order row,
    whatever its severity; findings never holds one. output is testssl.sh's
    stdout and stderr, used only to spot the not TLS message when the JSON
    does not carry it.
    """
    not_tls = "testssl.sh reports the service does not speak TLS."
    if NOT_TLS_PATTERN.search(output or ""):
        return STATUS_NOT_TLS, [], [], not_tls
    if not text.strip():
        return STATUS_EMPTY_JSON, [], [], "testssl.sh wrote an empty JSON file."
    try:
        data = json.loads(text)
    except ValueError as exc:
        return STATUS_BAD_JSON, [], [], "testssl.sh JSON is not valid: {e}".format(e=exc)
    if isinstance(data, dict) and isinstance(data.get("scanResult"), list):
        return STATUS_BAD_JSON, [], [], "testssl.sh wrote pretty JSON, not the flat format."
    if not isinstance(data, list):
        return STATUS_BAD_JSON, [], [], "testssl.sh JSON is not a list."

    entries = [e for e in data if isinstance(e, dict) and e.get("id")]
    if any(NOT_TLS_PATTERN.search(str(e.get("finding", ""))) for e in entries):
        return STATUS_NOT_TLS, [], [], not_tls
    ciphers = [_finding(e) for e in entries if is_cipher_row(e)]
    findings = [_finding(e) for e in entries if not is_cipher_row(e) and _keep(e)]
    fatal = [e for e in entries if str(e.get("severity", "")).upper() == "FATAL"]
    if fatal and not findings and not ciphers:
        return STATUS_FAILED, [], [], "testssl.sh stopped: {f}".format(
            f=fatal[0].get("finding", "no reason given"))
    if not entries:
        return STATUS_EMPTY_JSON, [], [], "testssl.sh JSON has no findings."
    return STATUS_OK, findings, ciphers, ""


def run_testssl(target_ip, port, starttls=None):
    """
    Check TLS on one port of one authorized target and return a dict:
        {"status", "target", "port", "starttls", "command",
         "findings": [{"id", "severity", "finding", "cve", "cwe"}],
         "ciphers": [same shape], "raw_json": "..."}
    plus "error" when status is not "ok". ciphers holds the per cipher and per
    protocol cipher order rows, kept as evidence apart from findings. raw_json
    is testssl.sh's whole JSON file, kept as evidence like nmap's raw_xml; it
    is never sent to the model or printed in the report. If the gate refuses the target,
    status is "refused" and testssl.sh never runs. If testssl.sh is not
    installed, status is "testssl-not-found". If testssl.sh says the port does
    not speak TLS, status is "not-tls".
    """
    # The gate decides first. Nothing happens if it says no.
    if not is_authorized(target_ip):
        return _result(STATUS_REFUSED, starttls=starttls)

    try:
        port = int(port)
    except (TypeError, ValueError):
        return _result(STATUS_BAD_PORT, str(target_ip), starttls=starttls,
                       error="Port {p} is not a number.".format(p=port))
    if not 1 <= port <= 65535:
        return _result(STATUS_BAD_PORT, str(target_ip), port, starttls,
                       error="Port {p} is out of range.".format(p=port))
    if starttls is not None and starttls not in STARTTLS_PROTOCOLS:
        return _result(STATUS_BAD_STARTTLS, str(target_ip), port, starttls,
                       error="STARTTLS protocol {s} is not one of {a}.".format(
                           s=starttls, a=", ".join(STARTTLS_PROTOCOLS)))
    target = build_target(target_ip, port)

    # Make sure testssl.sh is actually present before trying to call it.
    binary = next((name for name in BINARY_NAMES if shutil.which(name)), None)
    if binary is None:
        return _result(STATUS_NOT_FOUND, str(target_ip), port, starttls,
                       error="testssl.sh is not installed on this machine.")

    # testssl.sh refuses to write over an existing file, so the JSON path is
    # a new name inside a fresh temp directory.
    temp_dir = tempfile.mkdtemp(prefix="reconmind_testssl_")
    json_path = os.path.join(temp_dir, "testssl.json")
    cmd = [binary] + TESTSSL_FLAGS + ["--jsonfile", json_path]
    if starttls:
        cmd += ["--starttls", starttls]
    cmd.append(target)
    command = shlex.join(cmd)
    try:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  stdin=subprocess.DEVNULL, timeout=TESTSSL_TIMEOUT)
        except subprocess.TimeoutExpired:
            return _result(STATUS_TIMEOUT, str(target_ip), port, starttls, command,
                           error="testssl.sh did not finish within {s} seconds.".format(
                               s=TESTSSL_TIMEOUT))
        except OSError as exc:
            return _result(STATUS_FAILED, str(target_ip), port, starttls, command,
                           error="testssl.sh could not be started: {e}".format(e=exc))
        output = (getattr(proc, "stdout", "") or "") + "\n" + (getattr(proc, "stderr", "") or "")
        text = ""
        if os.path.exists(json_path):
            try:
                with open(json_path) as fh:
                    text = fh.read()
            except OSError as exc:
                return _result(STATUS_BAD_JSON, str(target_ip), port, starttls, command,
                               error="testssl.sh JSON could not be read: {e}".format(e=exc))
    finally:
        try:
            os.remove(json_path)
        except OSError:
            pass
        try:
            os.rmdir(temp_dir)
        except OSError:
            pass

    status, findings, ciphers, error = _parse_json(text, output)
    if status not in (STATUS_OK, STATUS_NOT_TLS) and getattr(proc, "returncode", 0):
        stderr = (getattr(proc, "stderr", "") or "").strip().splitlines()
        error += " testssl.sh exited with code {c}".format(c=proc.returncode)
        error += (": {s}".format(s=stderr[0]) if stderr else ".")
    return _result(status, str(target_ip), port, starttls, command, findings, error,
                   ciphers=ciphers, raw_json=text)


if __name__ == "__main__":
    import sys
    args = [a for a in sys.argv[1:] if not a.startswith("--starttls=")]
    proto = next((a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--starttls=")), None)
    if len(args) != 2:
        print("usage: python3 -m reconmind.tools.testssl_scan <target_ip> <port> "
              "[--starttls=smtp|ftp|imap|pop3|postgres]")
        sys.exit(1)
    result = run_testssl(args[0], args[1], starttls=proto)
    print("target:", result["target"], " port:", result["port"],
          " status:", result["status"])
    if result.get("error"):
        print("error:", result["error"])
    for f in sorted(result["findings"], key=lambda f: severity_rank(f["severity"])):
        print("  [{s}] {i}: {t}{c}".format(
            s=f["severity"], i=f["id"], t=f["finding"],
            c=" ({c})".format(c=f["cve"]) if f["cve"] else ""))
    print("  {n} individual cipher entries kept apart.".format(n=len(result["ciphers"])))
