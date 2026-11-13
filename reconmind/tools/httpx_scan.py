"""
ReconMind httpx tool (Stage 2, web technology fingerprinting).

A thin wrapper around ProjectDiscovery's httpx. The main entry point is
run_httpx(target_ip, port, use_https=False), and like run_nmap its very first
action is to ask the authorization gate whether the target is allowed. If the
gate says no, httpx is never launched.

httpx sends one request to the URL and does not follow redirects. Technologies
come from its Wappalyzer based tech detection, which can include false
matches. Every value (server, title, location, technology strings) is kept
exactly as httpx wrote it. A technology is only split into name and version
when httpx wrote "name:version" and the part after the last colon starts with
a digit; nothing is guessed.

Kali ships ProjectDiscovery's httpx as httpx-toolkit, because Python's httpx
library also installs a command named httpx. A plain httpx command is used
only when its -version output mentions projectdiscovery.

basic_http_fingerprint is a small fallback for when httpx times out or fails:
one GET with urllib, no redirects, and only the server's own Server and
X-Powered-By headers and page title are kept, exactly as sent.

Output is a plain dict so the agent and the report builder can read it
without knowing anything about httpx.
"""

import http.client
import json
import re
import shlex
import shutil
import ssl
import subprocess
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from reconmind.core.authorization import is_authorized
from reconmind.tools.web_common import build_url

BINARY_NAME = "httpx-toolkit"
ALT_BINARY_NAME = "httpx"
VENDOR_MARK = "projectdiscovery"
VERSION_CHECK_TIMEOUT = 10

# One request, no redirect following (httpx only follows with -fr), no
# update check, no colors so the JSON stays clean.
HTTPX_FLAGS = ["-tech-detect", "-title", "-server", "-status-code", "-location",
               "-json", "-silent", "-no-color", "-timeout", "10", "-retries", "1",
               "-disable-update-check"]
HTTPX_TIMEOUT = 60

BASIC_METHOD = "basic header check"
BASIC_TIMEOUT = 10
BASIC_MAX_BYTES = 64 * 1024
CERT_NOT_VERIFIED = ("Certificate not verified: self signed certificates are accepted "
                     "on lab targets.")

STATUS_OK = "ok"
STATUS_REFUSED = "refused"
STATUS_BAD_PORT = "bad-port"
STATUS_NOT_FOUND = "httpx-not-found"
STATUS_TIMEOUT = "timeout"
STATUS_FAILED = "failed"
STATUS_BAD_OUTPUT = "bad-output"

# httpx results that hand the port to basic_http_fingerprint.
FALLBACK_STATUSES = (STATUS_TIMEOUT, STATUS_FAILED)

_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _check_port(port):
    """Return (port as int, "") or (None, error)."""
    try:
        number = int(port)
    except (TypeError, ValueError):
        return None, "Port {p} is not a number.".format(p=port)
    if not 1 <= number <= 65535:
        return None, "Port {p} is out of range.".format(p=port)
    return number, ""


# ---- httpx --------------------------------------------------------------

def _is_projectdiscovery(binary):
    """True if `binary -version` mentions projectdiscovery."""
    try:
        proc = subprocess.run([binary, "-version"], capture_output=True, text=True,
                              timeout=VERSION_CHECK_TIMEOUT)
    except (subprocess.TimeoutExpired, OSError):
        return False
    text = "{o}\n{e}".format(o=proc.stdout or "", e=proc.stderr or "")
    return VENDOR_MARK in text.lower()


def find_binary():
    """
    The httpx command to run: httpx-toolkit if present, else httpx when it is
    ProjectDiscovery's httpx and not Python's. None if neither.
    """
    if shutil.which(BINARY_NAME) is not None:
        return BINARY_NAME
    if shutil.which(ALT_BINARY_NAME) is not None and _is_projectdiscovery(ALT_BINARY_NAME):
        return ALT_BINARY_NAME
    return None


def split_technology(raw):
    """
    One entry of httpx's "tech" list as {"name", "version", "raw"}. raw is
    exactly what httpx wrote. "PHP:5.2.4" splits on the last colon into PHP
    and 5.2.4; when the part after the last colon does not start with a digit
    (or there is no colon) the whole text is the name and version is "".
    """
    text = str(raw)
    name, sep, version = text.rpartition(":")
    if sep and name and version[:1].isdigit():
        return {"name": name, "version": version, "raw": text}
    return {"name": text, "version": "", "raw": text}


def _result(status, url="", command="", http_status=None, server="", title="",
            location="", technologies=None, raw_json="", error=""):
    result = {"status": status, "url": url, "http_status": http_status, "server": server,
              "title": title, "location": location, "technologies": technologies or [],
              "command": command, "raw_json": raw_json}
    if error:
        result["error"] = error
    return result


def _parse_output(text):
    """
    Read httpx's JSON lines output. Return (status, data, error) where data is
    the first JSON object httpx wrote. No output means httpx got no response.
    """
    lines = [line for line in (text or "").splitlines() if line.strip()]
    if not lines:
        return STATUS_FAILED, None, ("httpx returned no result for the URL (no response "
                                     "or the connection failed).")
    for line in lines:
        try:
            data = json.loads(line)
        except ValueError:
            continue
        if isinstance(data, dict):
            if data.get("failed") is True:
                return STATUS_FAILED, None, "httpx reports the request failed."
            return STATUS_OK, data, ""
    return STATUS_BAD_OUTPUT, None, "httpx output is not a JSON object."


def run_httpx(target_ip, port, use_https=False):
    """
    Fingerprint one web port on one authorized target and return a dict:
        {"status", "url", "http_status", "server", "title", "location",
         "technologies": [{"name", "version", "raw"}], "command", "raw_json"}
    plus "error" when status is not "ok". raw_json is httpx's stdout exactly
    as written. If the gate refuses the target, status is "refused" and
    nothing runs. If no ProjectDiscovery httpx is installed, status is
    "httpx-not-found".
    """
    # The gate decides first. Nothing happens if it says no.
    if not is_authorized(target_ip):
        return _result(STATUS_REFUSED)

    port, error = _check_port(port)
    if error:
        return _result(STATUS_BAD_PORT, error=error)
    url = build_url(target_ip, port, use_https)

    binary = find_binary()
    if binary is None:
        return _result(STATUS_NOT_FOUND, url=url,
                       error="ProjectDiscovery httpx (httpx-toolkit) is not installed on "
                             "this machine.")

    cmd = [binary, "-u", url] + HTTPX_FLAGS
    command = shlex.join(cmd)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=HTTPX_TIMEOUT)
    except subprocess.TimeoutExpired:
        return _result(STATUS_TIMEOUT, url, command,
                       error="httpx did not finish within {s} seconds.".format(s=HTTPX_TIMEOUT))
    except OSError as exc:
        return _result(STATUS_FAILED, url, command,
                       error="httpx could not be started: {e}".format(e=exc))

    raw = proc.stdout or ""
    status, data, error = _parse_output(raw)
    if status != STATUS_OK:
        if proc.returncode:
            stderr = (proc.stderr or "").strip().splitlines()
            error += " httpx exited with code {c}".format(c=proc.returncode)
            error += (": {s}".format(s=stderr[0]) if stderr else ".")
        return _result(status, url, command, raw_json=raw, error=error)

    return _result(STATUS_OK, url, command,
                   http_status=data.get("status_code"),
                   server=data.get("webserver") or "",
                   title=data.get("title") or "",
                   location=data.get("location") or "",
                   technologies=[split_technology(t) for t in data.get("tech") or []],
                   raw_json=raw)


# ---- basic header check fallback ----------------------------------------

class _NoRedirect(HTTPRedirectHandler):
    """Never follow a redirect: the 3xx answer itself comes back as HTTPError."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _basic_result(status, url="", http_status=None, server="", x_powered_by="", title="",
                  use_https=False, error=""):
    result = {"status": status, "url": url, "method": BASIC_METHOD, "http_status": http_status,
              "server": server, "x_powered_by": x_powered_by, "title": title}
    if use_https:
        result["certificate_check"] = CERT_NOT_VERIFIED
    if error:
        result["error"] = error
    return result


def _first_title(body):
    """The text inside the first <title> tag, exactly as sent, or ""."""
    match = _TITLE.search(body or b"")
    if not match:
        return ""
    raw = match.group(1)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _is_timeout(exc):
    reason = getattr(exc, "reason", None)
    return isinstance(exc, TimeoutError) or isinstance(reason, TimeoutError)


def basic_http_fingerprint(target_ip, port, use_https=False):
    """
    One GET to the port with urllib, no redirects followed, at most 64 KB of
    body read. Return {"status", "url", "method", "http_status", "server",
    "x_powered_by", "title"} with header values and title exactly as sent,
    plus "certificate_check" for https (certificates are not verified, so
    self signed lab certificates are accepted) and "error" when status is not
    "ok". If the gate refuses the target, status is "refused" and nothing is
    sent.
    """
    # The gate decides first. Nothing happens if it says no.
    if not is_authorized(target_ip):
        return _basic_result(STATUS_REFUSED)

    port, error = _check_port(port)
    if error:
        return _basic_result(STATUS_BAD_PORT, error=error)
    url = build_url(target_ip, port, use_https)

    handlers = [_NoRedirect()]
    if use_https:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        handlers.append(HTTPSHandler(context=context))
    opener = build_opener(*handlers)

    try:
        response = opener.open(Request(url, method="GET"), timeout=BASIC_TIMEOUT)
    except HTTPError as exc:
        response = exc  # 3xx, 4xx and 5xx answers still carry headers and a body
    except (URLError, OSError, http.client.HTTPException) as exc:
        if _is_timeout(exc):
            return _basic_result(STATUS_TIMEOUT, url, use_https=use_https,
                                 error="No answer within {s} seconds.".format(s=BASIC_TIMEOUT))
        reason = getattr(exc, "reason", None) or exc
        return _basic_result(STATUS_FAILED, url, use_https=use_https,
                             error="The request failed: {e}".format(e=reason))

    try:
        headers = response.headers
        code = response.getcode()
        try:
            body = response.read(BASIC_MAX_BYTES)
        except (OSError, http.client.HTTPException):
            body = b""  # headers were received; a broken body only loses the title
    finally:
        response.close()

    return _basic_result(STATUS_OK, url, http_status=code,
                         server=headers.get("Server") or "",
                         x_powered_by=headers.get("X-Powered-By") or "",
                         title=_first_title(body), use_https=use_https)


if __name__ == "__main__":
    import sys
    args = [a for a in sys.argv[1:] if a != "--https"]
    if len(args) != 2:
        print("usage: python3 -m reconmind.tools.httpx_scan <target_ip> <port> [--https]")
        sys.exit(1)
    result = run_httpx(args[0], args[1], use_https="--https" in sys.argv[1:])
    print("url:", result["url"], " status:", result["status"],
          " http status:", result["http_status"])
    if result.get("error"):
        print("error:", result["error"])
    print("server:", result["server"] or "none", " title:", result["title"] or "none")
    for t in result["technologies"]:
        print("  {n}  version: {v}".format(n=t["name"], v=t["version"] or "none"))
