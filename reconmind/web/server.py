"""
ReconMind web server.

create_app(report_dir=None, runner=None, port=None) returns the FastAPI app
that python3 -m reconmind.web serves on 127.0.0.1.

    GET  /                        the page (static/index.html)
    GET  /static/...              its stylesheet and JavaScript modules, with
                                  "Cache-Control: no-cache" so the browser
                                  revalidates them (ETag) on every load
    GET  /api/options             presets, actions, allowlist and denylist, and
                                  whether AI analysis is available (read only;
                                  provider and model, never the key)
    POST /api/check               check a scan request; nothing is launched
    POST /api/scans               the same checks, then start a job; a recon
                                  request may carry "mode": "standard" or "ai"
    GET  /api/scans/latest        {"job": ...}: the running job, otherwise the
                                  most recently started one, otherwise null
    GET  /api/scans/<job id>      a job's status and its last output lines
    GET  /api/scans/<job id>/events?since=N
                                  the job's progress events after the first N
                                  lines of its events file: {"events", "next",
                                  "more"}; N defaults to 0
    POST /api/scans/<job id>/stop stop that job
    GET  /api/history             report history entries, newest first
    GET  /api/reports/<run id>    one saved run for the Report screen: its index
                                  entry, report.md, scan.json and the findings,
                                  port spectrum and AI summary derived from
                                  them (see runs.report_view); never
                                  evidence.json
    GET  /api/reports/<run id>/evidence
                                  evidence.json as a download (Raw evidence)
    GET  /api/reports/<run id>/report.md
                                  report.md as a download (Export .md)

Run ids must look like the ones history.new_run_id makes, and every run file
must resolve to exactly <report_dir>/<run id>/<name> (runs.run_file);
anything else is 404.

Every request passes the same guards before any route runs:

    the Host header must be 127.0.0.1:<port> or localhost:<port>, otherwise
    400, so a web page that rebinds its own DNS name to 127.0.0.1 is refused
    every POST needs the header "X-ReconMind: 1" and a JSON body, otherwise
    403; there is no CORS, so another site cannot send that header
    every response carries a strict Content-Security-Policy, nosniff and
    no-referrer

The server checks what it can before launching (IPv4, the authorization
gate, the scan plan, the code input) and the CLI runs the same checks again
inside the job. Only the local System settings route can update owned .env keys. It cannot
change lab authorization networks or scanning scope.
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
from reconmind.core.report import MODE_AI, MODE_STANDARD, MODES
from reconmind.agent.morvain import DECISIONS as AGENT_DECISIONS, FOLLOW_UP as AGENT_CHECKS, MODE_AGENT
from reconmind.core.scan_plan import (
    ACTIONS, DEFAULT_PRESET, PRESETS, PlanError, PortsSpecError, build_plan)
from reconmind.web import runs, system, settings
from reconmind.web.setup_runner import SetupBusy, SetupRunner
from reconmind.web import setup_runner
from reconmind.web.jobs import JOB_ID, Busy, JobManager

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
MAX_HOSTS = 8
# The "since" of the events route: a line count, digits only.
SINCE = re.compile(r"[0-9]{1,9}")
NO_REPORT = "There is no report with that id."
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


def ai_options():
    """{"available", "provider", "model"} for the configured LLM. Never the key."""
    from reconmind.agent.__main__ import ai_config
    config, _ = ai_config()
    if config is None:
        return {"available": False, "provider": None, "model": None}
    return {"available": True, "provider": config.name, "model": config.model}


def _check_mode(body):
    """The report mode for a recon request. Raises Invalid."""
    mode = body.get("mode")
    if mode is None:
        return MODE_AI if ai_options()["available"] else MODE_STANDARD
    if mode not in MODES and mode != MODE_AGENT:
        raise Invalid("Mode must be \"standard\", \"ai\" or \"agent\".", "mode")
    if mode in (MODE_AI, MODE_AGENT) and not ai_options()["available"]:
        raise Invalid(("The AI agent" if mode == MODE_AGENT else "AI analysis")
                      + " needs an LLM. Set a provider and key on the System page, or turn "
                      "AI off.", "mode")
    return mode


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


class RevalidatedStaticFiles(StaticFiles):
    """
    StaticFiles with "Cache-Control: no-cache" on every response, so the
    browser revalidates with the ETag on each load and never runs an old
    copy of a script after an update.
    """

    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache"
        return response


def _host_ok(host, port):
    host = (host or "").strip().lower()
    if port is None:
        return bool(_ANY_LOCAL_HOST.fullmatch(host))
    return host in ("{h}:{p}".format(h=h, p=port) for h in LOCAL_HOSTS)


def create_app(report_dir=None, runner=None, port=None, setup_popen=None):
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
    setup = SetupRunner(cwd, popen=setup_popen)
    app.state.setup = setup

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

    app.mount("/static", RevalidatedStaticFiles(directory=STATIC_DIR), name="static")

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
            "ai": ai_options(),
        }

    @app.get("/api/system")
    def system_check():
        # GET is read-only. A new request rechecks executable availability.
        return system.snapshot(report_dir)

    @app.get("/api/setup")
    async def setup_check():
        # Read only: preflight, tools, model files and the install plan.
        data = await run_in_threadpool(setup_runner.snapshot)
        data["job"] = setup.status()
        return data

    @app.get("/api/setup/status")
    def setup_status():
        return setup.status()

    @app.post("/api/setup/install")
    async def setup_install(request: Request):
        body = await _json_body(request)
        if body is None:
            return _failure(403, "forbidden", "The request body must be a JSON object.")
        try:
            setup.start(scan_running=bool(jobs.running_id))
        except SetupBusy as exc:
            return _failure(409, "busy", str(exc))
        return JSONResponse({"ok": True, "status": setup.status()}, status_code=202)

    @app.post("/api/system/save")
    async def save_settings(request: Request):
        body = await _json_body(request)
        if body is None:
            return _failure(403, "forbidden", "The request body must be a JSON object.")
        try:
            return await run_in_threadpool(settings.save, body, cwd)
        except settings.SettingsError as exc:
            return _failure(400, "invalid", str(exc))

    @app.post("/api/system/test")
    async def test_settings(request: Request):
        body = await _json_body(request)
        if body is None:
            return _failure(403, "forbidden", "The request body must be a JSON object.")
        try:
            return await run_in_threadpool(settings.test_connection, body, cwd)
        except settings.SettingsError as exc:
            return _failure(400, "invalid", str(exc))

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
            mode = _check_mode(body) if kind == "recon" else None
        except Refused as exc:
            return _refused(exc)
        except Invalid as exc:
            return _invalid(exc)
        if setup.running():
            return _failure(409, "busy", "Setup is running. Scans can start when it finishes.")
        try:
            if kind == "recon":
                job_id = jobs.start_recon(result, mode)
            else:
                code_input, explain = result
                job_id = jobs.start_code(code_input.root, explain)
        except Busy as exc:
            return _failure(409, "busy", str(exc), job_id=exc.running_id)
        return JSONResponse({"ok": True, "job_id": job_id}, status_code=201)

    @app.post("/api/scans/{job_id}/agent")
    async def agent_decision(job_id: str, request: Request):
        # The operator's answer to MORVAIN-X0's plan. It only says which of the
        # proposed checks to run; the agent drops anything it did not propose,
        # and every check still passes the gate inside the tools.
        body = await _json_body(request)
        if body is None:
            return _failure(403, "forbidden", "The request body must be a JSON object.")
        if not JOB_ID.fullmatch(job_id):
            return _failure(404, "not_found", "No such scan.")
        decision = body.get("decision")
        round_number = body.get("round")
        actions = body.get("actions", [])
        message = body.get("message", "")
        if (decision not in AGENT_DECISIONS or not isinstance(round_number, int)
                or isinstance(round_number, bool) or not 1 <= round_number <= 99
                or not isinstance(actions, list)
                or not all(isinstance(a, str) and a in AGENT_CHECKS for a in actions)
                or not isinstance(message, str) or len(message) > 500):
            return _failure(400, "invalid", "That is not a valid answer to the plan.")
        clean = {"round": round_number, "decision": decision, "actions": list(dict.fromkeys(actions)),
                 "message": " ".join(message.split())}
        if not await run_in_threadpool(jobs.decide, job_id, clean):
            return _failure(409, "not_running", "This scan is not running any more.")
        return {"ok": True}

    # Before /api/scans/{job_id}, so "latest" is never read as a job id.
    @app.get("/api/scans/latest")
    def latest_scan():
        return {"job": jobs.latest()}

    @app.get("/api/scans/{job_id}")
    def get_scan(job_id: str):
        data = jobs.get(job_id) if JOB_ID.fullmatch(job_id) else None
        if data is None:
            return _failure(404, "not_found", "There is no scan with that id.")
        return data

    @app.get("/api/scans/{job_id}/events")
    def scan_events(job_id: str, request: Request):
        if not jobs.exists(job_id):
            return _failure(404, "not_found", "There is no scan with that id.")
        since = request.query_params.get("since", "0")
        if not SINCE.fullmatch(since):
            return _failure(400, "invalid", "since must be a line count, such as 0 or 42.",
                            field="since")
        events, next_line, more = runs.read_events(jobs.events_path(job_id), int(since))
        return {"events": events, "next": next_line, "more": more}

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

    @app.get("/api/reports/{run_id}")
    def get_report(run_id: str):
        try:
            data = runs.report_view(report_dir, run_id)
        except OSError:
            return _failure(500, "unreadable", "This report could not be read.")
        if data is None:
            return _failure(404, "not_found", NO_REPORT)
        return data

    @app.get("/api/reports/{run_id}/evidence")
    def get_evidence(run_id: str):
        path = runs.run_file(report_dir, run_id, history.EVIDENCE_NAME)
        if path is None:
            return _failure(404, "not_found", "There is no raw evidence for that report.")
        # run_id passed valid_run_id, so it is safe in a file name.
        return FileResponse(path, media_type="application/json",
                            filename=run_id + "_evidence.json",
                            headers={"Cache-Control": "no-store"})

    @app.get("/api/reports/{run_id}/report.md")
    def get_report_markdown(run_id: str):
        path = runs.run_file(report_dir, run_id, history.REPORT_NAME)
        if path is None:
            return _failure(404, "not_found", NO_REPORT)
        return FileResponse(path, media_type="text/markdown; charset=utf-8",
                            filename=run_id + ".md", headers={"Cache-Control": "no-store"})

    return app
