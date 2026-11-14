"""
ReconMind web jobs.

A job is one run of the existing CLI, python3 -m reconmind, started as a child
process for a scan the server has already checked. The server never imports
or runs the agent itself, so the CLI keeps doing everything it does on the
command line: the authorization gate, the scan plan check, the report and the
history entry.

    JobManager.start_recon(plan)        [python, -u, -m, reconmind, target,
                                         --preset, P, --ports, S, --actions, A]
    JobManager.start_code(path, explain) [python, -u, -m, reconmind, path]
                                         plus --explain when asked

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
CLI and any tool it started), waits up to STOP_WAIT seconds, then sends
SIGKILL.
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
STOP_WAIT = 5
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
JOB_ID = re.compile(r"[0-9a-f]{12}")
RUN_ID_PREFIX = "run id:"

RUNNING = "running"
DONE = "done"
FAILED = "failed"
REFUSED = "refused"
STOPPED = "stopped"
INTERRUPTED = "interrupted"

# Exit codes of python3 -m reconmind: 0 finished, 2 refused by the gate.
EXIT_OK = 0
EXIT_REFUSED = 2

PRESET_LABELS = {"quick": "Quick scan", "standard": "Standard scan", "full": "Full report"}
META_KEYS = ("id", "kind", "label", "status", "exit_code", "started", "finished", "run_id")


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


def recon_command(plan):
    """The CLI argument list for a validated ScanPlan."""
    return [sys.executable, "-u", "-m", "reconmind", plan.target,
            "--preset", plan.preset, "--ports", plan.ports,
            "--actions", ",".join(plan.actions)]


def code_command(path, explain):
    """The CLI argument list for a validated absolute path."""
    argv = [sys.executable, "-u", "-m", "reconmind", path]
    if explain:
        argv.append("--explain")
    return argv


def recon_label(plan):
    name = "Custom scan" if plan.customized else PRESET_LABELS.get(plan.preset, "Scan")
    return "{n}, {t}".format(n=name, t=plan.target)


def code_label(path):
    return "Code scan, {n}".format(n=os.path.basename(path.rstrip(os.sep)) or path)


class _Job:
    """One job in memory: its metadata, its process and its recent lines."""

    def __init__(self, job_id, kind, label):
        self.meta = {"id": job_id, "kind": kind, "label": label, "status": RUNNING,
                     "exit_code": None, "started": _now(), "finished": None,
                     "run_id": None}
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
        self._mark_interrupted()

    # ---- saved jobs --------------------------------------------------------

    def _meta_path(self, job_id):
        return os.path.join(self.jobs_dir, job_id + ".json")

    def _log_path(self, job_id):
        return os.path.join(self.jobs_dir, job_id + ".log")

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

    def start_recon(self, plan):
        return self._start("recon", recon_label(plan), recon_command(plan))

    def start_code(self, path, explain=False):
        return self._start("code", code_label(path), code_command(path, explain))

    def _start(self, kind, label, argv):
        with self._lock:
            if self._running_id is not None:
                raise Busy(self._running_id)
            job_id = secrets.token_hex(6)
            while job_id in self._jobs or os.path.exists(self._meta_path(job_id)):
                job_id = secrets.token_hex(6)
            os.makedirs(self.jobs_dir, exist_ok=True)
            job = _Job(job_id, kind, label)
            env = dict(os.environ, PYTHONUNBUFFERED="1")
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
                    else:
                        job.meta["status"] = FAILED
                if self._running_id == job_id:
                    self._running_id = None
                self._save(job)

    # ---- reading -----------------------------------------------------------

    @property
    def running_id(self):
        with self._lock:
            return self._running_id

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
        Stop a running job: SIGTERM, up to STOP_WAIT seconds, then SIGKILL.
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
        if stopping:
            self._signal(job.proc, signal.SIGTERM)
            try:
                job.proc.wait(timeout=STOP_WAIT)
            except subprocess.TimeoutExpired:
                self._signal(job.proc, signal.SIGKILL)
                try:
                    job.proc.wait(timeout=STOP_WAIT)
                except subprocess.TimeoutExpired:
                    pass
            if job.thread is not None:
                job.thread.join(timeout=2)
        return self.get(job_id)
