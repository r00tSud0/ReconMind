"""
ReconMind enum4linux-ng tool (Stage 2, SMB enumeration).

A thin wrapper around enum4linux-ng. The only entry point is
run_enum4linux(target_ip), and like run_nmap, run_whatweb and run_testssl its
very first action is to ask the authorization gate whether the target is
allowed. If the gate says no, enum4linux-ng is never launched.

Anonymous (null session) enumeration only. enum4linux-ng runs with -A, its
standard anonymous checks, and is never given a username, a password, a hash,
a ticket or a word list. No password guessing of any kind.

Results are read from its JSON file. The JSON shape differs between
enum4linux-ng versions, so every section is read defensively: a missing or
oddly shaped section becomes an empty value, never a crash. Text is kept
exactly as enum4linux-ng wrote it. The whole JSON file is kept as evidence in
"raw_json", which is never sent to the model or printed in the report.

Output is a plain dict so the agent and the report builder can read it
without knowing anything about enum4linux-ng.
"""

import json
import os
import shlex
import shutil
import subprocess
import tempfile

from reconmind.core.authorization import is_authorized

BINARY_NAME = "enum4linux-ng"
# -A: all simple anonymous checks. No credential options, ever.
ENUM_FLAGS = ["-A"]
ENUM_TIMEOUT = 600
# enum4linux-ng adds ".json" to the name given with -oJ.
JSON_BASENAME = "enum4linux_ng"

# The ports smb_enum is allowed on.
SMB_PORTS = (139, 445)

STATUS_OK = "ok"
STATUS_REFUSED = "refused"
STATUS_NOT_FOUND = "enum4linux-ng-not-found"
STATUS_TIMEOUT = "timeout"
STATUS_FAILED = "failed"
STATUS_EMPTY_JSON = "empty-json"
STATUS_BAD_JSON = "bad-json"


def smb_ports(ports):
    """The open ports from an nmap result that smb_enum may run for."""
    found = []
    for p in ports or []:
        try:
            number = int(p.get("port"))
        except (TypeError, ValueError):
            continue
        if number in SMB_PORTS:
            found.append(p)
    return found


# ---- defensive readers ----------------------------------------------------

def _dict(value):
    return value if isinstance(value, dict) else {}


def _text(value):
    """A plain string for a scalar value, "" for None or anything nested."""
    if value is None or isinstance(value, (dict, list)):
        return ""
    return str(value)


def _entries(section, id_key):
    """
    enum4linux-ng keeps users and groups as a dict keyed by RID (and shares
    keyed by name). Some versions or error paths give a list instead. Return
    a list of (key, dict) pairs either way; anything else gives [].
    """
    if isinstance(section, dict):
        return [(str(k), v) for k, v in section.items() if isinstance(v, dict)]
    if isinstance(section, list):
        return [(_text(v.get(id_key)), v) for v in section if isinstance(v, dict)]
    return []


def _null_session(data):
    """True or False when enum4linux-ng says whether a null session works,
    None when the JSON does not say."""
    sessions = data.get("sessions")
    if not isinstance(sessions, dict):
        return None
    for key in ("null", "null_session"):
        value = sessions.get(key)
        if isinstance(value, bool):
            return value
        if isinstance(value, dict) and isinstance(value.get("possible"), bool):
            return value["possible"]
    return None


def _domain(data):
    """Domain or workgroup name, from whichever section this version wrote."""
    candidates = [
        _dict(data.get("rpc_domain_info")).get("Domain"),
        data.get("domain"),
        data.get("workgroup"),
        _dict(data.get("smb_domain_info")).get("NetBIOS domain name"),
        _dict(data.get("target")).get("workgroup"),
    ]
    return next((_text(c).strip() for c in candidates if _text(c).strip()), "")


def _os(data):
    """The text fields of os_info, as enum4linux-ng wrote them."""
    info = data.get("os_info")
    if isinstance(info, str):
        return {"OS": info} if info.strip() else {}
    return {str(k): _text(v) for k, v in _dict(info).items()
            if _text(v).strip() and not isinstance(v, bool)}


def _users(data):
    users = []
    for key, entry in _entries(data.get("users"), "rid"):
        name = _text(entry.get("username")) or _text(entry.get("name"))
        if not name:
            continue
        user = {"username": name, "rid": _text(entry.get("rid")) or key}
        description = _text(entry.get("description")).strip()
        if description:
            user["description"] = _text(entry.get("description"))
        users.append(user)
    return users


def _groups(data):
    groups = []
    for key, entry in _entries(data.get("groups"), "rid"):
        name = _text(entry.get("groupname")) or _text(entry.get("name"))
        if not name:
            continue
        groups.append({"name": name, "rid": _text(entry.get("rid")) or key,
                       "type": _text(entry.get("type"))})
    return groups


def _shares(data):
    shares = []
    for key, entry in _entries(data.get("shares"), "name"):
        name = _text(entry.get("name")) or key
        if not name:
            continue
        access = _dict(entry.get("access"))
        shares.append({"name": name, "type": _text(entry.get("type")),
                       "comment": _text(entry.get("comment")),
                       "mapping": _text(access.get("mapping")),
                       "listing": _text(access.get("listing"))})
    return shares


def _policy(data):
    return _dict(data.get("policy"))


def policy_fields(policy):
    """
    Flatten the password policy into (field, value) pairs, in the order
    enum4linux-ng wrote them. Values are left as enum4linux-ng gave them.
    """
    fields = []
    for section, value in _dict(policy).items():
        if isinstance(value, dict):
            fields.extend((str(k), v) for k, v in value.items())
        else:
            fields.append((str(section), value))
    return fields


def format_value(value):
    """One line of text for a policy value, keeping enum4linux-ng's words."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, dict):
        return "; ".join("{k}: {v}".format(k=k, v=format_value(v)) for k, v in value.items())
    if isinstance(value, list):
        return ", ".join(format_value(v) for v in value)
    return str(value)


def os_summary(os_info):
    """One line naming the OS, built only from enum4linux-ng's own fields."""
    os_info = _dict(os_info)
    keys = ("OS", "OS version", "OS release", "OS build", "Native OS", "Native LAN manager")
    parts = ["{k}: {v}".format(k=k, v=os_info[k]) for k in keys if os_info.get(k)]
    return "; ".join(parts)


# ---- run ------------------------------------------------------------------

def _result(status, target="", command="", null_session=None, domain="", os_info=None,
            users=None, groups=None, shares=None, policy=None, raw_json="", error=""):
    result = {"status": status, "target": target, "command": command,
              "null_session": null_session, "domain": domain, "os": os_info or {},
              "users": users or [], "groups": groups or [], "shares": shares or [],
              "policy": policy or {}, "raw_json": raw_json or ""}
    if error:
        result["error"] = error
    return result


def _parse_json(text):
    """Return (status, data, error). data is the JSON dict when status is ok."""
    if not text.strip():
        return STATUS_EMPTY_JSON, {}, "enum4linux-ng wrote an empty JSON file."
    try:
        data = json.loads(text)
    except ValueError as exc:
        return STATUS_BAD_JSON, {}, "enum4linux-ng JSON is not valid: {e}".format(e=exc)
    if not isinstance(data, dict):
        return STATUS_BAD_JSON, {}, "enum4linux-ng JSON is not an object."
    return STATUS_OK, data, ""


def run_enum4linux(target_ip):
    """
    Enumerate SMB anonymously on one authorized target and return a dict:
        {"status", "target", "command", "null_session", "domain", "os",
         "users": [{"username", "rid", "description" (when present)}],
         "groups": [{"name", "rid", "type"}],
         "shares": [{"name", "type", "comment", "mapping", "listing"}],
         "policy": {...}, "raw_json": "..."}
    plus "error" when status is not "ok". null_session is True or False when
    enum4linux-ng says, None when it does not. raw_json is enum4linux-ng's
    whole JSON file, kept as evidence; it is never sent to the model or
    printed in the report. If the gate refuses the target, status is
    "refused" and enum4linux-ng never runs. If enum4linux-ng is not
    installed, status is "enum4linux-ng-not-found".
    """
    # The gate decides first. Nothing happens if it says no.
    if not is_authorized(target_ip):
        return _result(STATUS_REFUSED)

    target = str(target_ip).strip()

    # Make sure enum4linux-ng is actually present before trying to call it.
    binary = shutil.which(BINARY_NAME)
    if binary is None:
        return _result(STATUS_NOT_FOUND, target,
                       error="enum4linux-ng is not installed on this machine.")

    # A fresh temp directory, so the output name is always new.
    temp_dir = tempfile.mkdtemp(prefix="reconmind_enum4linux_")
    out_base = os.path.join(temp_dir, JSON_BASENAME)
    json_path = out_base + ".json"
    # Anonymous only: no -u, -p, -H, -K, -w or any other credential option.
    cmd = [BINARY_NAME] + ENUM_FLAGS + ["-oJ", out_base, target]
    command = shlex.join(cmd)
    try:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  stdin=subprocess.DEVNULL, timeout=ENUM_TIMEOUT)
        except subprocess.TimeoutExpired:
            return _result(STATUS_TIMEOUT, target, command,
                           error="enum4linux-ng did not finish within {s} seconds.".format(
                               s=ENUM_TIMEOUT))
        except OSError as exc:
            return _result(STATUS_FAILED, target, command,
                           error="enum4linux-ng could not be started: {e}".format(e=exc))
        text = ""
        if os.path.exists(json_path):
            try:
                with open(json_path) as fh:
                    text = fh.read()
            except OSError as exc:
                return _result(STATUS_BAD_JSON, target, command,
                               error="enum4linux-ng JSON could not be read: {e}".format(e=exc))
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    status, data, error = _parse_json(text)
    if status != STATUS_OK:
        if getattr(proc, "returncode", 0):
            stderr = (getattr(proc, "stderr", "") or "").strip().splitlines()
            error += " enum4linux-ng exited with code {c}".format(c=proc.returncode)
            error += (": {s}".format(s=stderr[0]) if stderr else ".")
        return _result(status, target, command, raw_json=text, error=error)

    return _result(STATUS_OK, target, command,
                   null_session=_null_session(data), domain=_domain(data),
                   os_info=_os(data), users=_users(data), groups=_groups(data),
                   shares=_shares(data), policy=_policy(data), raw_json=text)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("usage: python3 -m reconmind.tools.smb_enum <target_ip>")
        sys.exit(1)
    result = run_enum4linux(sys.argv[1])
    print("target:", result["target"], " status:", result["status"])
    if result.get("error"):
        print("error:", result["error"])
    print("null session:", result["null_session"])
    print("domain:", result["domain"] or "unknown")
    print("os:", os_summary(result["os"]) or "unknown")
    print("users ({n}):".format(n=len(result["users"])),
          ", ".join(u["username"] for u in result["users"]))
    for s in result["shares"]:
        print("  share {n} ({t}) mapping={m} listing={l}".format(
            n=s["name"], t=s["type"], m=s["mapping"], l=s["listing"]))
    for field, value in policy_fields(result["policy"]):
        print("  {f}: {v}".format(f=field, v=format_value(value)))
