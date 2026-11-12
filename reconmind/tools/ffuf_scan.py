"""
ReconMind ffuf tool (Stage 2, web content discovery).

A thin wrapper around ffuf. The only entry point is
run_ffuf(target_ip, port, use_https=False, wordlist=None), and like run_nmap
its very first action is to ask the authorization gate whether the target is
allowed. If the gate says no, ffuf is never launched.

Discovery only: ffuf sends one GET request per word in the wordlist, with the
word as the path. No parameter fuzzing, no POST bodies, no credentials, no
recursion. The rate is capped at 50 requests per second, and auto calibration
(-ac) drops the catch all responses some servers send for every path.

Results are read from ffuf's JSON output. Paths and values are kept exactly as
ffuf reports them. The whole JSON file is kept as "raw_json", which is
evidence only: it is never sent to the model or printed in the report.
"""

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import tempfile

from reconmind.core.authorization import is_authorized
from reconmind.tools.whatweb_scan import build_url

BINARY_NAME = "ffuf"

# Tried in this order when no wordlist is given.
DEFAULT_WORDLISTS = (
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
)

# Response codes ffuf keeps. Everything else is dropped.
MATCH_CODES = "200,204,301,302,307,401,403,405"

# GET only (ffuf's default method), no -X, -d, -H, -b or -recursion.
FFUF_FLAGS = ["-rate", "50", "-t", "10", "-timeout", "10", "-maxtime", "300",
              "-ac", "-mc", MATCH_CODES, "-noninteractive", "-s", "-of", "json"]
FFUF_TIMEOUT = 360
JSON_BASENAME = "ffuf.json"

STATUS_OK = "ok"
STATUS_REFUSED = "refused"
STATUS_BAD_PORT = "bad-port"
STATUS_NOT_FOUND = "ffuf-not-found"
STATUS_NO_WORDLIST = "wordlist-not-found"
STATUS_TIMEOUT = "timeout"
STATUS_FAILED = "failed"
STATUS_EMPTY_OUTPUT = "empty-output"
STATUS_BAD_JSON = "bad-json"


def _result(status, url="", wordlist="", wordlist_lines=None, wordlist_sha256="",
            command="", results=None, dropped_empty=0, raw_json="", error=""):
    result = {"status": status, "url": url, "wordlist": wordlist,
              "wordlist_lines": wordlist_lines, "wordlist_sha256": wordlist_sha256,
              "command": command, "results": results or [],
              "dropped_empty": dropped_empty, "raw_json": raw_json or ""}
    if error:
        result["error"] = error
    return result


def pick_wordlist(wordlist=None):
    """The given wordlist if it exists, else the first default that exists.
    None if there is none. A given wordlist that is missing is never
    swapped for a default."""
    if wordlist:
        return wordlist if os.path.isfile(wordlist) else None
    return next((w for w in DEFAULT_WORDLISTS if os.path.isfile(w)), None)


def wordlist_facts(path):
    """(line count, SHA-256 hex) of the wordlist file, read in binary."""
    digest = hashlib.sha256()
    lines = 0
    last = b""
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
            lines += chunk.count(b"\n")
            last = chunk
    if last and not last.endswith(b"\n"):
        lines += 1  # last line has no newline
    return lines, digest.hexdigest()


def _results(data):
    """ffuf's results list as ([{"path", "status", "length", "words", "lines",
    "redirect"}], dropped_empty), in ffuf's order, values exactly as ffuf gave
    them. A result with an empty or whitespace-only path is dropped and
    counted: it comes from a blank wordlist line (or a lone "\\r" in a CRLF
    wordlist), so ffuf requested the base URL itself, which is not a
    discovery."""
    items = []
    dropped_empty = 0
    for r in data.get("results") or []:
        if not isinstance(r, dict):
            continue
        given = r.get("input") if isinstance(r.get("input"), dict) else {}
        path = given.get("FUZZ", "")
        if isinstance(path, str) and not path.strip():
            dropped_empty += 1
            continue
        items.append({"path": path, "status": r.get("status"),
                      "length": r.get("length"), "words": r.get("words"),
                      "lines": r.get("lines"), "redirect": r.get("redirectlocation", "")})
    return items, dropped_empty


def _parse_json(text):
    """Return (status, results, dropped_empty, error) for ffuf's JSON output."""
    if not text.strip():
        return STATUS_EMPTY_OUTPUT, [], 0, "ffuf wrote no JSON output."
    try:
        data = json.loads(text)
    except ValueError as exc:
        return STATUS_BAD_JSON, [], 0, "ffuf JSON is not valid: {e}".format(e=exc)
    if not isinstance(data, dict) or not isinstance(data.get("results", []), list):
        return STATUS_BAD_JSON, [], 0, "ffuf JSON does not have a results list."
    results, dropped_empty = _results(data)
    return STATUS_OK, results, dropped_empty, ""


def run_ffuf(target_ip, port, use_https=False, wordlist=None):
    """
    Discover content on one web port of one authorized target and return:
        {"status", "url", "wordlist", "wordlist_lines", "wordlist_sha256",
         "command", "results": [{"path", "status", "length", "words",
         "lines", "redirect"}], "dropped_empty", "raw_json"}
    plus "error" when status is not "ok". dropped_empty counts results
    dropped for an empty path (a blank wordlist line hits the base URL). raw_json is ffuf's whole JSON file,
    kept as evidence; it is never sent to the model or printed in the report.
    If the gate refuses the target, status is "refused" and ffuf never runs.
    If ffuf is not installed, status is "ffuf-not-found". If no wordlist is
    found, status is "wordlist-not-found".
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

    # Make sure ffuf is actually present before trying to call it.
    if shutil.which(BINARY_NAME) is None:
        return _result(STATUS_NOT_FOUND, url=url, error="ffuf is not installed on this machine.")

    chosen = pick_wordlist(wordlist)
    if chosen is None:
        tried = [wordlist] if wordlist else list(DEFAULT_WORDLISTS)
        return _result(STATUS_NO_WORDLIST, url=url, wordlist=wordlist or "",
                       error="No wordlist found. Tried: {t}.".format(t=", ".join(tried)))
    try:
        lines, sha256 = wordlist_facts(chosen)
    except OSError as exc:
        return _result(STATUS_NO_WORDLIST, url=url, wordlist=chosen,
                       error="Wordlist could not be read: {e}".format(e=exc))
    facts = {"url": url, "wordlist": chosen, "wordlist_lines": lines,
             "wordlist_sha256": sha256}

    # A fresh temp directory, so the output name is always new.
    temp_dir = tempfile.mkdtemp(prefix="reconmind_ffuf_")
    json_path = os.path.join(temp_dir, JSON_BASENAME)
    cmd = ([BINARY_NAME, "-u", url + "/FUZZ", "-w", chosen] + FFUF_FLAGS
           + ["-o", json_path])
    command = shlex.join(cmd)
    try:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  stdin=subprocess.DEVNULL, timeout=FFUF_TIMEOUT)
        except subprocess.TimeoutExpired:
            return _result(STATUS_TIMEOUT, command=command,
                           error="ffuf did not finish within {s} seconds.".format(
                               s=FFUF_TIMEOUT), **facts)
        except OSError as exc:
            return _result(STATUS_FAILED, command=command,
                           error="ffuf could not be started: {e}".format(e=exc), **facts)
        text = ""
        if os.path.exists(json_path):
            try:
                with open(json_path) as fh:
                    text = fh.read()
            except OSError as exc:
                return _result(STATUS_BAD_JSON, command=command,
                               error="ffuf JSON could not be read: {e}".format(e=exc),
                               **facts)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    status, results, dropped_empty, error = _parse_json(text)
    if status != STATUS_OK and getattr(proc, "returncode", 0):
        stderr = (getattr(proc, "stderr", "") or "").strip().splitlines()
        error += " ffuf exited with code {c}".format(c=proc.returncode)
        error += (": {s}".format(s=stderr[0]) if stderr else ".")
    return _result(status, command=command, results=results,
                   dropped_empty=dropped_empty, raw_json=text, error=error, **facts)


if __name__ == "__main__":
    import sys
    args = [a for a in sys.argv[1:] if a != "--https"]
    if len(args) not in (2, 3):
        print("usage: python3 -m reconmind.tools.ffuf_scan <target_ip> <port> "
              "[wordlist] [--https]")
        sys.exit(1)
    result = run_ffuf(args[0], args[1], use_https="--https" in sys.argv[1:],
                      wordlist=args[2] if len(args) == 3 else None)
    print("url:", result["url"], " status:", result["status"])
    print("wordlist:", result["wordlist"] or "none",
          " lines:", result["wordlist_lines"], " sha256:", result["wordlist_sha256"])
    if result.get("error"):
        print("error:", result["error"])
    for r in sorted(result["results"], key=lambda r: str(r["path"])):
        print("  /{p}  status {s}  size {l}{r}".format(
            p=r["path"], s=r["status"], l=r["length"],
            r="  redirect " + r["redirect"] if r["redirect"] else ""))
