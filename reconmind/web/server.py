"""
ReconMind web server.

create_app(report_dir=None, runner=None, port=None) returns the FastAPI app
that python3 -m reconmind.web serves on 127.0.0.1.

    GET  /                        the page (static/index.html)
    GET  /static/...              its stylesheet and JavaScript modules
    GET  /api/options             presets, actions, allowlist and denylist (read only)
    POST /api/check               check a scan request; nothing is launched
    POST /api/scans               the same checks, then start a job
    GET  /api/scans/<job id>      a job's status and its last output lines
    POST /api/scans/<job id>/stop stop that job
    GET  /api/history             report history entries, newest first

Every request passes the same guards before any route runs:

    the Host header must be 127.0.0.1:<port> or localhost:<port>, otherwise
    400, so a web page that rebinds its own DNS name to 127.0.0.1 is refused
    every POST needs the header "X-ReconMind: 1" and a JSON body, otherwise
    403; there is no CORS, so another site cannot send that header
    every response carries a strict Content-Security-Policy, nosniff and
    no-referrer

The server checks what it can before launching (IPv4, the authorization
gate, the scan plan, the code input) and the CLI runs the same checks again
inside the job. There is no route that changes the configuration.
"""

import os
import re

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from reconmind.__main__ import is_ipv4
from reconmind.code.inputs import InputError, validate_input
from reconmind.core import config, history
from reconmind.core import report as report_mod
from reconmind.core.authorization import is_authorized
from reconmind.core.scan_plan import (
    ACTIONS, DEFAULT_PRESET, PRESETS, PlanError, PortsSpecError, build_plan)
from reconmind.web.jobs import JOB_ID, Busy, JobManager

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
MAX_HOSTS = 8
HISTORY_WARNING = ("The report history ({p}) could not be read: {e}. "
                   "New scans still save their reports.")

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self'; connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}
LOCAL_HOSTS = ("127.0.0.1", "localhost")
_ANY_LOCAL_HOST = re.compile(r"(?:127\.0\.0\.1|localhost)(?::[0-9]{1,5})?")


class Refused(Exception):
    """The authorization gate refused the target."""


class Invalid(Exception):
    """The request is not valid. field names the input it is about, if any."""

    def __init__(self, message, field=None):
        super().__init__(message)
        self.field = field


def _join_networks(networks):
    items = list(networks)
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def refused_message(target):
    return ("{t} is not on the allowlist. The scan was refused and nothing was sent to "
            "that address. Choose a target inside one of these networks: {n}.").format(
                t=target, n=_join_networks(config.ALLOWLIST))


def _text(body, key, field, required=True):
    """A string field from the request body, or None when it may be left out."""
    value = body.get(key)
    if value is None and not required:
        return None
    if not isinstance(value, str):
        raise Invalid("{k} must be text.".format(k=key.capitalize()), field)
    return value


def _check_recon(body):
    """Return a ScanPlan for a recon request. Raises Refused or Invalid."""
    target = _text(body, "target", "target").strip()
    if not target:
        raise Invalid("Enter the IPv4 address of a lab target.", "target")
    if not is_ipv4(target):
        raise Invalid("{t!r} is not an IPv4 address. Enter one address, such as "
                      "10.10.1.20.".format(t=target[:100]), "target")
    # The gate comes before the plan, exactly as in the CLI.
    if not is_authorized(target):
        raise Refused(refused_message(target))

    preset = _text(body, "preset", "preset", required=False)
    ports = _text(body, "ports", "ports", required=False)
    actions = body.get("actions")
    if actions is not None and (not isinstance(actions, list)
                                or not all(isinstance(a, str) for a in actions)):
        raise Invalid("Actions must be a list of action ids.", "actions")
    try:
        return build_plan(target, preset=preset, ports=ports, actions=actions)
    except PortsSpecError as exc:
        raise Invalid(str(exc), "ports") from None
    except PlanError as exc:
        field = "preset" if "preset" in str(exc).lower() else "actions"
        raise Invalid(str(exc), field) from None


def _check_code(body, cwd):
    """Return (CodeInput, explain) for a code request. Raises Invalid."""
    path = _text(body, "path", "path").strip()
    if not path:
        raise Invalid("Enter the path of a source file or folder on this machine.", "path")
    # A leading "-" would read as an option to the CLI.
    if path.startswith("-"):
        raise Invalid("A path cannot start with \"-\". Give the full path, such as "
                      "/home/you/project.", "path")
    explain = body.get("explain", False)
    if not isinstance(explain, bool):
        raise Invalid("Explain must be true or false.", "explain")
    # Relative paths mean the repo root, where the CLI also runs.
    full = os.path.join(cwd, os.path.expanduser(path))
    try:
        code_input = validate_input(full)
    except InputError as exc:
        raise Invalid(str(exc), "path") from None
    return code_input, explain


def _check(body, cwd):
    """("recon", plan) or ("code", (CodeInput, explain)). Raises Refused or Invalid."""
    kind = body.get("kind")
    if kind == "recon":
        return kind, _check_recon(body)
    if kind == "code":
        return kind, _check_code(body, cwd)
    raise Invalid("Kind must be \"recon\" or \"code\".", "kind")


def _input_dict(code_input):
    return {"path": code_input.root, "is_dir": code_input.is_dir,
            "files": len(code_input.files), "languages": code_input.languages,
            "total_bytes": code_input.total_bytes}


def _failure(status, reason, message, **extra):
    return JSONResponse(dict({"ok": False, "reason": reason, "message": message}, **extra),
                        status_code=status)


def _refused(exc):
    return _failure(403, "refused", str(exc), networks=list(config.ALLOWLIST))


def _invalid(exc):
    return _failure(400, "invalid", str(exc), field=exc.field)


async def _json_body(request):
    """The request body as a JSON object, or None when it is not one."""
    try:
        body = await request.json()
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


def _host_ok(host, port):
    host = (host or "").strip().lower()
    if port is None:
        return bool(_ANY_LOCAL_HOST.fullmatch(host))
    return host in ("{h}:{p}".format(h=h, p=port) for h in LOCAL_HOSTS)


def create_app(report_dir=None, runner=None, port=None):
    """
    The FastAPI app. report_dir defaults to reports/ in the current folder
    (the repo root, as for the CLI); jobs keep their files in its .jobs
    folder. runner replaces subprocess.Popen (tests pass a fake). port is the
    port the Host header must name; None accepts any port on 127.0.0.1 or
    localhost.
    """
    cwd = os.getcwd()
    report_dir = os.path.abspath(report_dir or os.path.join(cwd, report_mod.REPORT_DIR))
    jobs = JobManager(report_dir, cwd=cwd, runner=runner)

    app = FastAPI(title="ReconMind", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.jobs = jobs
    app.state.report_dir = report_dir

    @app.middleware("http")
    async def guard(request, call_next):
        if not _host_ok(request.headers.get("host"), port):
            response = JSONResponse({"ok": False, "reason": "bad_host",
                                     "message": "Open ReconMind at http://127.0.0.1 only."},
                                    status_code=400)
        elif request.method == "POST" and (
                request.headers.get("x-reconmind") != "1"
                or request.headers.get("content-type", "").split(";")[0].strip().lower()
                != "application/json"):
            response = JSONResponse({"ok": False, "reason": "forbidden",
                                     "message": "Requests must come from the ReconMind page."},
                                    status_code=403)
        else:
            response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        return response

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/")
    def index():
        return FileResponse(os.path.join(STATIC_DIR, "index.html"),
                            headers={"Cache-Control": "no-store"})

    @app.get("/api/options")
    def options():
        return {
            "presets": [{"id": name, "actions": list(p.actions), "ports": p.ports,
                         "vuln_mode": p.vuln_mode} for name, p in PRESETS.items()],
            "actions": [{"id": a.id, "name": a.name, "tools": list(a.tools)} for a in ACTIONS],
            "default_preset": DEFAULT_PRESET,
            "allowlist": list(config.ALLOWLIST),
            "denylist": list(config.DENYLIST),
            "max_hosts": MAX_HOSTS,
        }

    @app.post("/api/check")
    async def check(request: Request):
        body = await _json_body(request)
        if body is None:
            return _failure(403, "forbidden", "The request body must be a JSON object.")
        try:
            kind, result = _check(body, cwd)
        except Refused as exc:
            # 200: the check itself worked; the answer is "refused".
            return {"ok": False, "reason": "refused", "message": str(exc),
                    "networks": list(config.ALLOWLIST)}
        except Invalid as exc:
            return {"ok": False, "reason": "invalid", "message": str(exc), "field": exc.field}
        if kind == "recon":
            return {"ok": True, "plan": result.to_dict(), "describe": result.describe()}
        return {"ok": True, "input": _input_dict(result[0]), "explain": result[1]}

    @app.post("/api/scans")
    async def start_scan(request: Request):
        body = await _json_body(request)
        if body is None:
            return _failure(403, "forbidden", "The request body must be a JSON object.")
        try:
            kind, result = _check(body, cwd)
        except Refused as exc:
            return _refused(exc)
        except Invalid as exc:
            return _invalid(exc)
        try:
            if kind == "recon":
                job_id = jobs.start_recon(result)
            else:
                code_input, explain = result
                job_id = jobs.start_code(code_input.root, explain)
        except Busy as exc:
            return _failure(409, "busy", str(exc), job_id=exc.running_id)
        return JSONResponse({"ok": True, "job_id": job_id}, status_code=201)

    @app.get("/api/scans/{job_id}")
    def get_scan(job_id: str):
        data = jobs.get(job_id) if JOB_ID.fullmatch(job_id) else None
        if data is None:
            return _failure(404, "not_found", "There is no scan with that id.")
        return data

    @app.post("/api/scans/{job_id}/stop")
    async def stop_scan(job_id: str, request: Request):
        if await _json_body(request) is None:
            return _failure(403, "forbidden", "The request body must be a JSON object.")
        if not JOB_ID.fullmatch(job_id) or jobs.get(job_id) is None:
            return _failure(404, "not_found", "There is no scan with that id.")
        # Waiting for the process can take seconds; keep it off the event loop.
        return await run_in_threadpool(jobs.stop, job_id)

    @app.get("/api/history")
    def get_history():
        try:
            entries = history.read_index(report_dir)
        except (OSError, ValueError) as exc:
            return {"entries": [], "warning": HISTORY_WARNING.format(
                p=os.path.join(report_dir, history.INDEX_NAME), e=exc)}
        return {"entries": [e for e in reversed(entries) if isinstance(e, dict)]}

    return app
