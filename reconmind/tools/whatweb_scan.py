"""
ReconMind whatweb tool (Stage 2, web technology fingerprinting).

A thin wrapper around whatweb. The only entry point is
run_whatweb(target_ip, port, use_https=False), and like run_nmap its very
first action is to ask the authorization gate whether the target is allowed.
If the gate says no, whatweb is never launched.

whatweb runs at aggression level 1: one normal HTTP request to the URL, plus
any redirects the server sends, nothing intrusive. Results are read from whatweb's JSON log. Versions and
strings are kept exactly as whatweb reports them; nothing is guessed.

Output is a plain dict so the agent and the report builder can read it
without knowing anything about whatweb.
"""

import json
import os
import shlex
import shutil
import subprocess
import tempfile

from reconmind.core.authorization import is_authorized

# Aggression 1 (stealthy) sends one normal request, plus any redirects the
# server sends. No URL guessing, no brute force. --no-errors keeps connection errors out of the output.
WHATWEB_FLAGS = ["--color=never", "--no-errors", "-a", "1",
                 "--open-timeout", "10", "--read-timeout", "20"]
LOG_FLAG = "--log-json="
WHATWEB_TIMEOUT = 120

# Kept even when whatweb found no version and no string for them: knowing the
# server or language is present is useful on its own.
ALWAYS_KEEP = ("HTTPServer", "PHP", "Apache", "nginx")

# Never kept: IP only repeats the target address and Country is a GeoIP
# guess, so neither says anything about the web technology.
NEVER_KEEP = ("Country", "IP")

STATUS_OK = "ok"
STATUS_REFUSED = "refused"
STATUS_BAD_PORT = "bad-port"
STATUS_NOT_FOUND = "whatweb-not-found"
STATUS_TIMEOUT = "timeout"
STATUS_FAILED = "failed"
STATUS_EMPTY_LOG = "empty-log"
STATUS_BAD_LOG = "bad-log"


def is_web_service(port):
    """True if nmap named the port's service as some kind of HTTP or HTTPS
    (http, https, ssl/http, http-proxy, http-alt and similar)."""
    return "http" in (port.get("service") or "").lower()


def wants_https(port):
    """True if the service name or nmap's tunnel field says SSL/TLS or HTTPS."""
    service = (port.get("service") or "").lower()
    tunnel = (port.get("tunnel") or "").lower()
    return tunnel in ("ssl", "tls") or "ssl" in service or "https" in service


def build_url(target_ip, port, use_https=False):
    """http:// or https:// plus target and port, e.g. http://10.10.1.100:80."""
    host = str(target_ip).strip()
    if ":" in host:  # IPv6 literal
        host = "[{h}]".format(h=host)
    return "{s}://{h}:{p}".format(s="https" if use_https else "http", h=host, p=int(port))


def _result(status, url="", command="", http_status=None, components=None, error=""):
    result = {"status": status, "url": url, "http_status": http_status,
              "components": components or [], "command": command}
    if error:
        result["error"] = error
    return result


def _as_list(value):
    """whatweb gives lists; wrap a lone value, keep everything else as is."""
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    return [value]


def _components(plugins):
    """
    Turn whatweb's plugins dict into a list of
    {"name", "versions", "strings"}, in whatweb's order. Plugins with no
    version and no string are skipped unless they are in ALWAYS_KEEP.
    Plugins in NEVER_KEEP are always skipped.
    """
    components = []
    for name, info in plugins.items():
        if name in NEVER_KEEP:
            continue
        info = info if isinstance(info, dict) else {}
        versions = _as_list(info.get("version"))
        strings = _as_list(info.get("string"))
        if versions or strings or name in ALWAYS_KEEP:
            components.append({"name": name, "versions": versions, "strings": strings})
    return components


def _same_url(a, b):
    return str(a or "").rstrip("/") == str(b or "").rstrip("/")


def _parse_log(text, url):
    """
    Read whatweb's JSON log. Return (status, http_status, components, error).
    The log is a JSON array with one entry per URL fetched (a redirect adds
    more) and often a trailing empty {}. The entry for the requested URL is
    used; if none matches, the first entry is used.
    """
    if not text.strip():
        return STATUS_EMPTY_LOG, None, [], "whatweb wrote an empty log."
    try:
        data = json.loads(text)
    except ValueError as exc:
        return STATUS_BAD_LOG, None, [], "whatweb log is not valid JSON: {e}".format(e=exc)
    if not isinstance(data, list):
        return STATUS_BAD_LOG, None, [], "whatweb log is not a JSON list."

    entries = [e for e in data if isinstance(e, dict) and isinstance(e.get("plugins"), dict)]
    if not entries:
        if any(isinstance(e, dict) and e for e in data):
            return STATUS_BAD_LOG, None, [], "whatweb log has no plugin results."
        return STATUS_EMPTY_LOG, None, [], "whatweb log has no results for the URL."

    entry = next((e for e in entries if _same_url(e.get("target"), url)), entries[0])
    return STATUS_OK, entry.get("http_status"), _components(entry["plugins"]), ""


def run_whatweb(target_ip, port, use_https=False):
    """
    Fingerprint one web port on one authorized target and return a dict:
        {"status", "url", "http_status",
         "components": [{"name", "versions", "strings"}], "command"}
    plus "error" when status is not "ok". If the gate refuses the target,
    status is "refused" and whatweb never runs. If whatweb is not installed,
    status is "whatweb-not-found".
    """
    # The gate decides first. Nothing happens if it says no.
    if not is_authorized(target_ip):
        return _result(STATUS_REFUSED)

    try:
        port = int(port)
    except (TypeError, ValueError):
        return _result(STATUS_BAD_PORT, error="Port {p} is not a number.".format(p=port))
    if not 1 <= port <= 65535:
        return _result(STATUS_BAD_PORT, error="Port {p} is out of range.".format(p=port))
    url = build_url(target_ip, port, use_https)

    # Make sure whatweb is actually present before trying to call it.
    if shutil.which("whatweb") is None:
        return _result(STATUS_NOT_FOUND, url=url,
                       error="whatweb is not installed on this machine.")

    fd, log_path = tempfile.mkstemp(prefix="reconmind_whatweb_", suffix=".json")
    os.close(fd)
    cmd = ["whatweb"] + WHATWEB_FLAGS + [LOG_FLAG + log_path, url]
    command = shlex.join(cmd)
    try:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=WHATWEB_TIMEOUT)
        except subprocess.TimeoutExpired:
            return _result(STATUS_TIMEOUT, url, command,
                           error="whatweb did not finish within {s} seconds.".format(
                               s=WHATWEB_TIMEOUT))
        except OSError as exc:
            return _result(STATUS_FAILED, url, command,
                           error="whatweb could not be started: {e}".format(e=exc))
        try:
            with open(log_path) as fh:
                text = fh.read()
        except OSError as exc:
            return _result(STATUS_BAD_LOG, url, command,
                           error="whatweb log could not be read: {e}".format(e=exc))
    finally:
        try:
            os.remove(log_path)
        except OSError:
            pass

    status, http_status, components, error = _parse_log(text, url)
    if status != STATUS_OK and getattr(proc, "returncode", 0):
        stderr = (getattr(proc, "stderr", "") or "").strip().splitlines()
        error += " whatweb exited with code {c}".format(c=proc.returncode)
        error += (": {s}".format(s=stderr[0]) if stderr else ".")
    return _result(status, url, command, http_status, components, error)


if __name__ == "__main__":
    import sys
    args = [a for a in sys.argv[1:] if a != "--https"]
    if len(args) != 2:
        print("usage: python3 -m reconmind.tools.whatweb_scan <target_ip> <port> [--https]")
        sys.exit(1)
    result = run_whatweb(args[0], args[1], use_https="--https" in sys.argv[1:])
    print("url:", result["url"], " status:", result["status"],
          " http status:", result["http_status"])
    if result.get("error"):
        print("error:", result["error"])
    for c in result["components"]:
        print("  {n}  versions: {v}  strings: {s}".format(
            n=c["name"], v=", ".join(map(str, c["versions"])) or "none",
            s="; ".join(map(str, c["strings"])) or "none"))
