"""
Runs the installer for the app's Setup screen.

The installer always runs as its own process, the same command a person can
type (python3 -m reconmind.setup --install --yes --events), so the web server
never installs anything itself. One setup run at a time, never while a scan
runs. Its JSON progress lines are kept in memory for the page to poll.
"""

import json
import os
import subprocess
import sys
import threading

from reconmind.setup import detect, install, preflight
from reconmind.ai import attack_mapper
from reconmind.setup import manifest

MAX_LOG = 400


class SetupBusy(RuntimeError):
    pass


def snapshot():
    """What the Setup screen shows before anything runs. Read only."""
    checks = preflight.run_checks()
    info = preflight.read_os_release()
    distro, arch = preflight.distro(info), preflight.arch()
    plan = []
    if distro and arch:
        plan = [{"title": t, "detail": d}
                for t, d in install.Installer(distro, arch, interactive=False).plan()]
    folder = attack_mapper.model_dir()
    files = all(os.path.isfile(os.path.join(folder, n)) for n in attack_mapper.REQUIRED_FILES)
    return {
        "preflight": [c._asdict() for c in checks],
        "blocked": bool(preflight.blocking_failures(checks)),
        "tools": detect.tools(),
        "model": {"folder": os.path.basename(folder), "files_present": files,
                  "labels": manifest.MODEL["labels"],
                  "source_set": bool(manifest.MODEL["url"])},
        "plan": plan,
    }


class SetupRunner:
    def __init__(self, cwd, popen=None):
        self.cwd = cwd
        self.popen = popen or subprocess.Popen
        self.lock = threading.Lock()
        self.proc = None
        self._reset("idle")

    def _reset(self, state):
        self.state = state          # idle, running, done, failed
        self.steps = {}             # index -> {"index", "title", "state", "message"}
        self.total = 0
        self.log = []
        self.result = None
        self.blocked = None

    def running(self):
        return self.state == "running"

    def start(self, scan_running=False):
        with self.lock:
            if self.state == "running":
                raise SetupBusy("Setup is already running.")
            if scan_running:
                raise SetupBusy("A scan is running. Setup can start when it finishes.")
            self._reset("running")
            argv = [sys.executable, "-u", "-m", "reconmind.setup", "--install", "--yes",
                    "--events"]
            try:
                self.proc = self.popen(argv, cwd=self.cwd, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                       text=True, start_new_session=True)
            except OSError as exc:
                self.state = "failed"
                self.log.append("Setup could not start: " + str(exc))
                return
        threading.Thread(target=self._follow, args=(self.proc,), daemon=True).start()

    def _follow(self, proc):
        for line in proc.stdout:
            self.feed(line)
        code = proc.wait()
        with self.lock:
            ok = code == 0
            self.state = "done" if ok else "failed"

    def feed(self, line):
        """One line from the installer: a JSON event, or plain text for the log."""
        line = line.rstrip("\n")
        if not line:
            return
        try:
            event = json.loads(line)
        except ValueError:
            event = {"type": "say", "text": line}
        if not isinstance(event, dict):
            event = {"type": "say", "text": line}
        with self.lock:
            kind = event.get("type")
            if kind == "step":
                index = int(event.get("index") or 0)
                self.total = int(event.get("total") or self.total)
                self.steps[index] = {"index": index, "title": str(event.get("title", "")),
                                     "state": str(event.get("state", "")),
                                     "message": str(event.get("message", ""))}
            elif kind == "result":
                self.result = {"ready": event.get("ready"), "total": event.get("total"),
                               "failed": event.get("failed") or []}
            elif kind == "blocked":
                self.blocked = event.get("checks") or []
            else:
                text = str(event.get("text") or event.get("message") or "")
                if text:
                    self.log.append(text[:500])
                    del self.log[:-MAX_LOG]

    def status(self):
        with self.lock:
            return {"state": self.state, "total": self.total,
                    "steps": [self.steps[i] for i in sorted(self.steps)],
                    "log": list(self.log[-200:]), "result": self.result,
                    "blocked": self.blocked}
