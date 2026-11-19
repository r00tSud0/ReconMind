"""
ReconMind web jobs.

A job is one run of the existing CLI, python3 -m reconmind, started as a child
process for a scan the server has already checked. The server never imports
or runs the agent itself, so the CLI keeps doing everything it does on the
command line: the authorization gate, the scan plan check, the report and the
history entry.

    JobManager.start_recon(plan, mode)  [python, -u, -m, reconmind, target,
                                         --preset, P, --ports, S, --actions, A,
                                         --mode, M]
    JobManager.start_code(path, explain) [python, -u, -m, reconmind, path]
                                         plus --explain when asked

mode is "standard" or "ai". Left out, it is "ai" when an LLM is configured
and "standard" otherwise, the same default the CLI uses.

Each job gets RECONMIND_EVENTS=<report_dir>/.jobs/<job id>.events.jsonl in
its environment, so the CLI writes its progress events there (see
reconmind/core/events.py).

Every value on the command line comes from a validated ScanPlan or a validated
absolute path, never from request text, and the list is passed without a
shell. Only one job runs at a time; starting another raises Busy.

A daemon thread reads the child's output line by line into memory (the last
MAX_LINES lines), appends every line to <report_dir>/.jobs/<job id>.log and
picks up the "run id:" line the CLI prints at the end. The job's metadata,
without the lines, is kept in <report_dir>/.jobs/<job id>.json, written to a
temp file and renamed so a crash never leaves half a file. A job still marked
running when a new JobManager starts belonged to a server that stopped, so it
is marked interrupted.

Jobs belong to the server, not to the browser window: closing the page does
not stop a scan. stop() sends SIGTERM to the job's whole process group (the
CLI and any tool it started), waits up to STOP_GRACE seconds so the CLI can
write its partial report, then sends SIGKILL. The CLI exits 4 after a stop,
which is recorded as "stopped".

Exit 1 after the CLI printed its "run id:" line means the report was saved
without the AI summary (the model was busy or failed). That job is "done"
with a "warning" saying so. Exit 1 with no run id is "failed".
"""

import json
import os
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import threading
from collections import deque
from datetime import datetime

JOBS_FOLDER = ".jobs"
MAX_LINES = 5000
STOP_GRACE = 20  # seconds after SIGTERM, so the CLI can save its partial report
STOP_WAIT = 5    # seconds after SIGKILL
EVENTS_ENV = "RECONMIND_EVENTS"
EVENTS_SUFFIX = ".events.jsonl"
MODES = ("standard", "ai", "agent")
AGENT_SUFFIX = ".agent.json"
AGENT_ENV = "RECONMIND_AGENT_INBOX"
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
JOB_ID = re.compile(r"[0-9a-f]{12}")
RUN_ID_PREFIX = "run id:"

RUNNING = "running"
DONE = "done"
FAILED = "failed"
REFUSED = "refused"
STOPPED = "stopped"
INTERRUPTED = "interrupted"

# Exit codes of python3 -m reconmind: 0 finished, 2 refused by the gate,
# 4 stopped (a partial report was saved).
EXIT_OK = 0
EXIT_REFUSED = 2
EXIT_STOPPED = 4
# Exit 1 after a "run id:" line means the report was saved but the AI summary
# was not (the model was busy or failed), so the job counts as done.
EXIT_ERROR = 1
SUMMARY_WARNING = "The AI summary was unavailable, so the report has the tool results only."

PRESET_LABELS = {"quick": "Quick scan", "standard": "Standard scan", "full": "Full scan"}
CUSTOM_LABEL = "Custom scan"
META_KEYS = ("id", "kind", "label", "status", "exit_code", "started", "finished", "run_id",
             "warning", "list")
LIST_ID = re.compile(r"[0-9a-f]{10}")
LIST_SUFFIX = ".list.json"
MAX_LIST = 8


class Busy(RuntimeError):
    """Another job is still running. running_id names it."""

    def __init__(self, running_id):
        super().__init__("A scan is already running. Wait for it to finish or stop it first.")
        self.running_id = running_id


def write_json(path, data):
    """Write JSON to a temp file in the same folder, then rename it over path."""
    folder = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=folder, prefix="." + os.path.basename(path) + ".",
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _now():
    return datetime.now().strftime(TIME_FORMAT)


def default_mode():
    """"ai" when an LLM is configured (after reading .env), otherwise "standard"."""
    # Imported here so the jobs module never loads the LLM code on its own.
    from reconmind.agent.__main__ import default_mode as cli_default_mode
    return cli_default_mode()


def recon_command(plan, mode):
    """The CLI argument list for a validated ScanPlan and report mode."""
    if mode not in MODES:
        raise ValueError("Unknown report mode {m!r}.".format(m=mode))
    return [sys.executable, "-u", "-m", "reconmind", plan.target,
            "--preset", plan.preset, "--ports", plan.ports,
            "--actions", ",".join(plan.actions), "--mode", mode]


def code_command(path, explain):
    """The CLI argument list for a validated absolute path."""
    argv = [sys.executable, "-u", "-m", "reconmind", path]
    if explain:
        argv.append("--explain")
    return argv


def recon_label(plan):
    """"Quick scan, <target>"; a plan that differs from its preset is "Custom scan"."""
    name = CUSTOM_LABEL if plan.customized else PRESET_LABELS.get(plan.preset, "Scan")
    return "{n}, {t}".format(n=name, t=plan.target)


def code_label(path):
    return "Code scan, {n}".format(n=os.path.basename(path.rstrip(os.sep)) or path)


class _Job:
    """One job in memory: its metadata, its process and its recent lines."""

    def __init__(self, job_id, kind, label, host_list=None):
        self.meta = {"id": job_id, "kind": kind, "label": label, "status": RUNNING,
                     "exit_code": None, "started": _now(), "finished": None,
                     "run_id": None, "warning": None, "list": host_list}
        self.lines = deque(maxlen=MAX_LINES)
        self.proc = None
        self.thread = None


class JobManager:
    """
    Starts, follows and stops CLI jobs. runner is called like subprocess.Popen
    (argv plus keyword arguments) and must return a Popen like object with
    stdout, wait() and poll(); tests pass a fake so no process ever starts.
    """

    def __init__(self, report_dir, cwd=None, runner=None):
        self.jobs_dir = os.path.join(report_dir, JOBS_FOLDER)
        self.cwd = cwd or os.getcwd()
        self.runner = runner or subprocess.Popen
        self._lock = threading.Lock()
        self._jobs = {}
        self._running_id = None
        self._lists = {}
        self._mark_interrupted()

    # ---- saved jobs --------------------------------------------------------

    def _meta_path(self, job_id):
        return os.path.join(self.jobs_dir, job_id + ".json")

    def _log_path(self, job_id):
        return os.path.join(self.jobs_dir, job_id + ".log")

    def events_path(self, job_id):
        """Where the job's CLI writes its progress events."""
        return os.path.join(self.jobs_dir, job_id + EVENTS_SUFFIX)

    def agent_inbox(self, job_id):
        """Where the web app leaves the operator's plan decision for an agent job."""
        return os.path.join(self.jobs_dir, job_id + AGENT_SUFFIX)

    def decide(self, job_id, decision):
        """Write an agent decision for the running job. Returns False when
        job_id is not the running job. decision is already validated."""
        with self._lock:
            if self._running_id != job_id:
                return False
            path = self.agent_inbox(job_id)
            tmp = path + ".part"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(decision, f)
            os.replace(tmp, path)
            return True

    def _mark_interrupted(self):
        """A job saved as running was cut off when its server stopped."""
        if not os.path.isdir(self.jobs_dir):
            return
        for name in sorted(os.listdir(self.jobs_dir)):
            if not name.endswith(".json") or not JOB_ID.fullmatch(name[:-5]):
                continue
            meta = self._load_meta(name[:-5])
            if meta and meta.get("status") == RUNNING:
                meta["status"] = INTERRUPTED
                meta["finished"] = meta.get("finished") or _now()
                try:
                    write_json(self._meta_path(name[:-5]), meta)
                except OSError:
                    pass  # an unwritable file stays as it is; it is read as interrupted below

    def _load_meta(self, job_id):
        try:
            with open(self._meta_path(job_id)) as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        return {key: data.get(key) for key in META_KEYS}

    def _save(self, job):
        """Save the metadata. A failed write never stops the job itself."""
        try:
            write_json(self._meta_path(job.meta["id"]), dict(job.meta))
        except OSError:
            pass

    # ---- starting ----------------------------------------------------------

    def start_recon(self, plan, mode=None, host_list=None):
        mode = mode or default_mode()
        label = ("Agent scan, " + plan.target) if mode == "agent" else recon_label(plan)
        return self._start("recon", label, recon_command(plan, mode), host_list)

    def start_code(self, path, explain=False):
        return self._start("code", code_label(path), code_command(path, explain))

    def _start(self, kind, label, argv, host_list=None):
        with self._lock:
            if self._running_id is not None:
                raise Busy(self._running_id)
            job_id = secrets.token_hex(6)
            while job_id in self._jobs or os.path.exists(self._meta_path(job_id)):
                job_id = secrets.token_hex(6)
            os.makedirs(self.jobs_dir, exist_ok=True)
            job = _Job(job_id, kind, label, host_list)
            env = dict(os.environ, PYTHONUNBUFFERED="1")
            env[EVENTS_ENV] = self.events_path(job_id)
            # Only an agent job reads approvals; the path is set for every job
            # so the CLI never looks anywhere else.
            env[AGENT_ENV] = self.agent_inbox(job_id)
            try:
                # An argument list and no shell: nothing in it is ever parsed by a shell.
                # A new session gives the job its own process group, so stop() reaches
                # every tool the CLI starts.
                job.proc = self.runner(argv, cwd=self.cwd, env=env, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, bufsize=1,
                                       start_new_session=True)
            except OSError as exc:
                job.meta.update(status=FAILED, finished=_now())
                job.lines.append("Could not start python3 -m reconmind: {e}".format(e=exc))
                self._jobs[job_id] = job
                self._save(job)
                return job_id
            self._jobs[job_id] = job
            self._running_id = job_id
            self._save(job)
            job.thread = threading.Thread(target=self._follow, args=(job,), daemon=True,
                                          name="reconmind-job-" + job_id)
            job.thread.start()
            return job_id

    def _follow(self, job):
        """Read the child's output until it ends, then record how it ended."""
        job_id = job.meta["id"]
        list_id = None
        try:
            with open(self._log_path(job_id), "a", encoding="utf-8") as log:
                for raw in job.proc.stdout:
                    line = raw.rstrip("\r\n")
                    with self._lock:
                        job.lines.append(line)
                        if line.startswith(RUN_ID_PREFIX):
                            job.meta["run_id"] = line[len(RUN_ID_PREFIX):].strip() or None
                    log.write(line + "\n")
                    log.flush()
        except (OSError, ValueError) as exc:
            with self._lock:
                job.lines.append("Output could not be read: {e}".format(e=exc))
        finally:
            try:
                code = job.proc.wait()
            except Exception:  # a broken child still has to free the slot
                code = None
            with self._lock:
                job.meta["exit_code"] = code
                job.meta["finished"] = _now()
                if job.meta["status"] == RUNNING:
                    if code == EXIT_OK:
                        job.meta["status"] = DONE
                    elif code == EXIT_REFUSED:
                        job.meta["status"] = REFUSED
                    elif code == EXIT_STOPPED:
                        job.meta["status"] = STOPPED
                    elif code == EXIT_ERROR and job.meta["run_id"]:
                        # The report exists; only the AI summary is missing.
                        job.meta["status"] = DONE
                        job.meta["warning"] = SUMMARY_WARNING
                    else:
                        job.meta["status"] = FAILED
                if self._running_id == job_id:
                    self._running_id = None
                self._save(job)
                list_id = job.meta.get("list")
            if list_id:
                self._list_next(list_id)

    # ---- reading -----------------------------------------------------------

    @property
    def running_id(self):
        with self._lock:
            return self._running_id

    def exists(self, job_id):
        """True for a job of this server or one saved by an earlier server."""
        if not JOB_ID.fullmatch(str(job_id)):
            return False
        with self._lock:
            if job_id in self._jobs:
                return True
        return os.path.isfile(self._meta_path(job_id))

    def get(self, job_id, max_lines=400):
        """The job's metadata plus its last max_lines lines, or None."""
        if not JOB_ID.fullmatch(str(job_id)):
            return None
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                data = dict(job.meta)
                data["lines"] = list(job.lines)[-max_lines:]
                return data
        # A job from an earlier server: metadata and lines come from disk.
        meta = self._load_meta(job_id)
        if meta is None:
            return None
        if meta.get("status") == RUNNING:
            meta["status"] = INTERRUPTED
        try:
            with open(self._log_path(job_id), encoding="utf-8", errors="replace") as fh:
                meta["lines"] = [line.rstrip("\r\n") for line in deque(fh, maxlen=max_lines)]
        except OSError:
            meta["lines"] = []
        return meta

    def latest(self, max_lines=400):
        """
        The running job, otherwise the most recently started one (this
        server's or a saved one from an earlier server), with its last
        max_lines lines. None when there is no job at all.
        """
        with self._lock:
            running = self._running_id
            # Jobs of this server rank above saved ones with the same start
            # second, and among themselves by start order.
            ranked = [((job.meta.get("started") or "", 1, order), job_id)
                      for order, (job_id, job) in enumerate(self._jobs.items())]
            known = set(self._jobs)
        if running is not None:
            return self.get(running, max_lines)
        if os.path.isdir(self.jobs_dir):
            for name in os.listdir(self.jobs_dir):
                job_id = name[:-5]
                if not name.endswith(".json") or not JOB_ID.fullmatch(job_id) or job_id in known:
                    continue
                meta = self._load_meta(job_id)
                started = meta.get("started") if meta else None
                if isinstance(started, str):
                    ranked.append(((started, 0, 0), job_id))
        if not ranked:
            return None
        return self.get(max(ranked)[1], max_lines)

    # ---- stopping ----------------------------------------------------------

    def _signal(self, proc, sig):
        """Signal the job's whole process group; its pgid is its pid (new session)."""
        pid = getattr(proc, "pid", None)
        # Never a pid of 0 or 1 or below: those would name this server's own group or init.
        if not isinstance(pid, int) or pid <= 1:
            return
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError):
            pass

    def stop(self, job_id):
        """
        Stop a running job: SIGTERM, up to STOP_GRACE seconds (the CLI saves
        its partial report and exits 4), then SIGKILL.
        Return the job's data, or None when there is no such job. A job that
        is not running is returned unchanged.
        """
        stopping = False
        with self._lock:
            job = self._jobs.get(job_id)
            # A job that already ended is left to _follow, which records how it ended.
            if (job is not None and job.meta["status"] == RUNNING and job.proc is not None
                    and job.proc.poll() is None):
                job.meta["status"] = STOPPED
                job.lines.append("Stopped from the web app.")
                self._save(job)
                stopping = True
                lst = self._lists.get(job.meta.get("list"))
                if lst is not None:
                    lst["stop_after"] = True
        if stopping:
            self._signal(job.proc, signal.SIGTERM)
            try:
                job.proc.wait(timeout=STOP_GRACE)
            except subprocess.TimeoutExpired:
                self._signal(job.proc, signal.SIGKILL)
                try:
                    job.proc.wait(timeout=STOP_WAIT)
                except subprocess.TimeoutExpired:
                    pass
            if job.thread is not None:
                job.thread.join(timeout=2)
        return self.get(job_id)


    # ---- host lists ----------------------------------------------------------
    #
    # A host list is up to MAX_LIST checked scan plans run one after another,
    # each as an ordinary job (so each target passes the authorization gate
    # again inside the CLI and gets its own report). The list is saved as
    # <report_dir>/.jobs/<list id>.list.json. When a host's job ends, the next
    # one starts, unless the list was told to stop after the current host or
    # one of its hosts was stopped.

    def _list_path(self, list_id):
        return os.path.join(self.jobs_dir, list_id + LIST_SUFFIX)

    def _save_list(self, lst):
        record = {k: v for k, v in lst.items() if k != "plans"}
        try:
            write_json(self._list_path(lst["id"]), record)
        except OSError:
            pass

    def start_list(self, plans, mode, label):
        """Start the first host of a new list. Returns the list id. Raises Busy."""
        if not 1 <= len(plans) <= MAX_LIST:
            raise ValueError("A host list holds 1 to {m} hosts.".format(m=MAX_LIST))
        with self._lock:
            if self._running_id is not None:
                raise Busy(self._running_id)
            list_id = secrets.token_hex(5)
            while os.path.exists(self._list_path(list_id)):
                list_id = secrets.token_hex(5)
            lst = {"id": list_id, "label": label, "mode": mode, "status": RUNNING,
                   "started": _now(), "finished": None, "stop_after": False,
                   "hosts": [{"target": p.target, "job_id": None} for p in plans],
                   "plans": list(plans)}
            self._lists[list_id] = lst
            os.makedirs(self.jobs_dir, exist_ok=True)
            self._save_list(lst)
        self._list_next(list_id)
        return list_id

    def _list_next(self, list_id):
        """Start the list's next host, or close the list when none is left."""
        with self._lock:
            lst = self._lists.get(list_id)
            if lst is None or lst["status"] != RUNNING:
                return
            index = next((i for i, h in enumerate(lst["hosts"]) if h["job_id"] is None), None)
            if index is None or lst["stop_after"]:
                lst["status"] = DONE if index is None else STOPPED
                lst["finished"] = _now()
                self._save_list(lst)
                return
            plan = lst["plans"][index]
            mode = lst["mode"]
        try:
            job_id = self.start_recon(plan, mode, host_list=list_id)
        except Busy:
            with self._lock:
                lst["status"] = INTERRUPTED
                lst["finished"] = _now()
                lst["warning"] = "Another scan started first, so the list stopped at host {n}.".format(
                    n=index + 1)
                self._save_list(lst)
            return
        with self._lock:
            lst["hosts"][index]["job_id"] = job_id
            self._save_list(lst)

    def stop_list_after(self, list_id):
        """Let the current host finish, then start no more. False when not running."""
        with self._lock:
            lst = self._lists.get(list_id)
            if lst is None or lst["status"] != RUNNING:
                return False
            lst["stop_after"] = True
            self._save_list(lst)
            return True

    def _load_list(self, list_id):
        try:
            with open(self._list_path(list_id)) as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or not isinstance(data.get("hosts"), list):
            return None
        if data.get("status") == RUNNING:
            data["status"] = INTERRUPTED   # saved by a server that stopped
        return data

    def get_list(self, list_id):
        """The list with each host's job status and run id, or None."""
        if not LIST_ID.fullmatch(str(list_id)):
            return None
        with self._lock:
            lst = self._lists.get(list_id)
            data = {k: v for k, v in lst.items() if k != "plans"} if lst else None
            if data is not None:
                data["hosts"] = [dict(h) for h in lst["hosts"]]
        if data is None:
            data = self._load_list(list_id)
        if data is None:
            return None
        for host in data["hosts"]:
            job = self.get(host.get("job_id"), max_lines=1) if host.get("job_id") else None
            host["status"] = job["status"] if job else ("waiting" if data["status"] == RUNNING
                                                        else "skipped")
            host["run_id"] = job["run_id"] if job else None
            host["warning"] = job["warning"] if job else None
        return data

    def lists(self):
        """Every saved list, newest first."""
        ids = set()
        with self._lock:
            ids.update(self._lists)
        if os.path.isdir(self.jobs_dir):
            for name in os.listdir(self.jobs_dir):
                if name.endswith(LIST_SUFFIX) and LIST_ID.fullmatch(name[:-len(LIST_SUFFIX)]):
                    ids.add(name[:-len(LIST_SUFFIX)])
        found = [self.get_list(i) for i in ids]
        return sorted((f for f in found if f), key=lambda f: str(f.get("started")), reverse=True)
