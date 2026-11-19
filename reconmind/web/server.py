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
    POST /api/reports/<run id>/ask
                                  {"question", "turns"}: an answer from that
                                  report only (see ask.py); needs an LLM
    GET  /api/lists, /api/lists/<list id>
                                  host lists: up to 8 hosts scanned one after
                                  another ("kind": "hosts" on /api/scans)
    POST /api/lists/<list id>/stop
                                  stop after the current host
    GET  /api/workspace?folder=F  that target folder's notes and your reports
    POST /api/workspace/notes[/<note id>]
                                  add, edit or delete ("delete": true) a note
    POST /api/analyst             start one of your reports, blank or from a run
    GET|POST /api/analyst/<id>    read or save it ("delete": true deletes it)
    GET  /api/analyst/<id>/report.md
                                  your report as Markdown (Export .md)

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
from fastapi.responses import FileResponse, JSONResponse, Response
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
from reconmind.web.jobs import JOB_ID, LIST_ID, Busy, JobManager, recon_label
from reconmind.web import ask as ask_mod
from reconmind.web.workspace import Workspace, WorkspaceError, report_markdown

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


def _check_hosts(body):
    """A list of ScanPlans, one per host, each through the gate. Raises Refused or Invalid."""
    targets = body.get("targets")
    if not isinstance(targets, list) or not all(isinstance(t, str) for t in targets):
        raise Invalid("Hosts must be a list of IPv4 addresses.", "hosts")
    targets = [t.strip() for t in targets if t.strip()]
    if not targets:
        raise Invalid("Enter at least one lab host, one address per line.", "hosts")
    if len(targets) > MAX_HOSTS:
        raise Invalid("A host list holds up to {m} hosts. This one has {n}.".format(
            m=MAX_HOSTS, n=len(targets)), "hosts")
    seen = set()
    for t in targets:
        if not is_ipv4(t):
            raise Invalid("{t!r} is not an IPv4 address. Ranges like /24 are not accepted; "
                          "put one address on each line.".format(t=t[:100]), "hosts")
        if t in seen:
            raise Invalid("{t} is in the list twice.".format(t=t), "hosts")
        seen.add(t)
    # The gate checks every host before anything starts. One refused host
    # refuses the whole list, so nothing is ever sent to it.
    for t in targets:
        if not is_authorized(t):
            raise Refused(refused_message(t) + " Remove it from the list to scan the others.")
    if body.get("mode") == MODE_AGENT:
        raise Invalid("The AI agent works on one target at a time. Choose Off or AI analysis "
                      "for a host list.", "mode")
    plans = []
    for t in targets:
        plans.append(_check_recon(dict(body, target=t)))
    return plans


def _check(body, cwd):
    """("recon", plan), ("hosts", [plan, ...]) or ("code", (CodeInput, explain)).
    Raises Refused or Invalid."""
    kind = body.get("kind")
    if kind == "recon":
        return kind, _check_recon(body)
    if kind == "hosts":
        return kind, _check_hosts(body)
    if kind == "code":
        return kind, _check_code(body, cwd)
    raise Invalid("Kind must be \"recon\", \"hosts\" or \"code\".", "kind")


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


def ws_note_id(value):
    from reconmind.web.workspace import NOTE_ID
    return bool(NOTE_ID.fullmatch(value))


def _with_findings(report_dir, data):
    """Add each host's finding counts from the report history."""
    try:
        entries = {e.get("run_id"): e for e in history.read_index(report_dir) if isinstance(e, dict)}
    except (OSError, ValueError):
        entries = {}
    for host in data.get("hosts", []):
        entry = entries.get(host.get("run_id")) or {}
        host["findings"] = entry.get("findings") if isinstance(entry.get("findings"), dict) else None
        host["open_ports"] = entry.get("open_ports")
    return data


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
        if kind == "hosts":
            return {"ok": True, "plan": result[0].to_dict(), "describe": result[0].describe(),
                    "targets": [p.target for p in result]}
        return {"ok": True, "input": _input_dict(result[0]), "explain": result[1]}

    @app.post("/api/scans")
    async def start_scan(request: Request):
        body = await _json_body(request)
        if body is None:
            return _failure(403, "forbidden", "The request body must be a JSON object.")
        try:
            kind, result = _check(body, cwd)
            mode = _check_mode(body) if kind in ("recon", "hosts") else None
        except Refused as exc:
            return _refused(exc)
        except Invalid as exc:
            return _invalid(exc)
        if setup.running():
            return _failure(409, "busy", "Setup is running. Scans can start when it finishes.")
        try:
            if kind == "recon":
                job_id = jobs.start_recon(result, mode)
            elif kind == "hosts":
                label = "{n} hosts, {s}".format(n=len(result), s=recon_label(result[0]).split(",")[0])
                list_id = jobs.start_list(result, mode, label)
                data = jobs.get_list(list_id) or {}
                first = (data.get("hosts") or [{}])[0].get("job_id")
                return JSONResponse({"ok": True, "list_id": list_id, "job_id": first},
                                    status_code=201)
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
        # and every check still passes the gate inside the tools. "ask" is a
        # question at the checkpoint: it is answered and never runs anything.
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
        if decision == "ask" and not message.strip() and len(actions) != 1:
            return _failure(400, "invalid", "Type a question first.")
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

    # ---- host lists ----------------------------------------------------------

    @app.get("/api/lists")
    def get_lists():
        return {"lists": [_with_findings(report_dir, l) for l in jobs.lists()]}

    @app.get("/api/lists/{list_id}")
    def get_list(list_id: str):
        data = jobs.get_list(list_id) if LIST_ID.fullmatch(list_id) else None
        if data is None:
            return _failure(404, "not_found", "There is no host list with that id.")
        return _with_findings(report_dir, data)

    @app.post("/api/lists/{list_id}/stop")
    async def stop_list(list_id: str, request: Request):
        if await _json_body(request) is None:
            return _failure(403, "forbidden", "The request body must be a JSON object.")
        if not LIST_ID.fullmatch(list_id) or jobs.get_list(list_id) is None:
            return _failure(404, "not_found", "There is no host list with that id.")
        if not jobs.stop_list_after(list_id):
            return _failure(409, "not_running", "This host list is not running any more.")
        return {"ok": True}

    # ---- the analyst's notes and reports ------------------------------------

    workspace = Workspace(report_dir)

    def _ws(fn, *args):
        try:
            return fn(*args)
        except WorkspaceError as exc:
            return _failure(400, "invalid", str(exc))
        except OSError:
            return _failure(500, "unwritable", "The workspace folder could not be written.")

    @app.get("/api/workspace")
    def get_workspace(request: Request):
        folder = request.query_params.get("folder", "")
        return _ws(lambda: {"notes": workspace.notes(folder), "reports": workspace.reports(folder)})

    async def _ws_post(request, fn):
        body = await _json_body(request)
        if body is None:
            return _failure(403, "forbidden", "The request body must be a JSON object.")
        return await run_in_threadpool(_ws, fn, body)

    @app.post("/api/workspace/notes")
    async def add_note(request: Request):
        return await _ws_post(request, lambda b: {"ok": True, "note": workspace.save_note(
            b.get("folder"), b.get("text"), None)})

    @app.post("/api/workspace/notes/{note_id}")
    async def edit_note(note_id: str, request: Request):
        def run(b):
            if b.get("delete") is True:
                workspace.delete_note(b.get("folder"), note_id)
                return {"ok": True}
            if not ws_note_id(note_id):
                raise WorkspaceError("That note no longer exists.")
            return {"ok": True, "note": workspace.save_note(b.get("folder"), b.get("text"), note_id)}
        return await _ws_post(request, run)

    @app.post("/api/analyst")
    async def new_analyst_report(request: Request):
        return await _ws_post(request, lambda b: {"ok": True, "report": workspace.create_report(
            b.get("folder"), b.get("from_run"))})

    @app.get("/api/analyst/{report_id}")
    def get_analyst_report(report_id: str):
        data = workspace.report(report_id)
        if data is None:
            return _failure(404, "not_found", "There is no report of yours with that id.")
        return data

    @app.post("/api/analyst/{report_id}")
    async def save_analyst_report(report_id: str, request: Request):
        def run(b):
            if b.get("delete") is True:
                workspace.delete_report(report_id)
                return {"ok": True}
            return {"ok": True, "report": workspace.save_report(report_id, b)}
        return await _ws_post(request, run)

    @app.get("/api/analyst/{report_id}/report.md")
    def analyst_markdown(report_id: str):
        data = workspace.report(report_id)
        if data is None:
            return _failure(404, "not_found", "There is no report of yours with that id.")
        return Response(report_markdown(data), media_type="text/markdown; charset=utf-8",
                        headers={"Cache-Control": "no-store",
                                 "Content-Disposition": 'attachment; filename="report_'
                                 + report_id + '.md"'})

    # ---- ask about this report ----------------------------------------------

    @app.post("/api/reports/{run_id}/ask")
    async def ask_report(run_id: str, request: Request):
        body = await _json_body(request)
        if body is None:
            return _failure(403, "forbidden", "The request body must be a JSON object.")
        try:
            question, turns = ask_mod.check(body.get("question"), body.get("turns"))
        except ask_mod.AskError as exc:
            return _failure(400, "invalid", str(exc))
        try:
            view = await run_in_threadpool(runs.report_view, report_dir, run_id)
        except OSError:
            return _failure(500, "unreadable", "This report could not be read.")
        if view is None:
            return _failure(404, "not_found", NO_REPORT)
        from reconmind.agent.__main__ import ai_config
        from reconmind.agent import llm
        config, _ = ai_config()
        if config is None:
            return _failure(409, "no_ai", "Asking needs an LLM. Set a provider and key on the "
                                          "System page.")
        try:
            client = llm.make_client(config)
            text = await run_in_threadpool(ask_mod.answer, view, question, turns, client,
                                           config.model)
        except ask_mod.AskError as exc:
            return _failure(502, "empty", str(exc))
        except ImportError:
            return _failure(500, "no_package", "The LLM package is not installed. Run Setup.")
        except Exception as exc:  # the provider failed; the report is untouched
            return _failure(502, "llm_failed", "The model could not answer: " + str(exc)[:300])
        return {"ok": True, "answer": text, "model": config.model}

    return app
