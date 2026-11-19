"""Setup screen API tests. The installer process is faked; nothing is installed."""
import io
import json
import os
import tempfile
import time
import unittest
from unittest import mock

try:
    from fastapi.testclient import TestClient
except ImportError:
    raise unittest.SkipTest("FastAPI test dependencies missing")

from reconmind.setup import __main__ as cli
from reconmind.setup import install
from reconmind.web import setup_runner
from reconmind.web.server import create_app

H = {"X-ReconMind": "1"}


class FakeProc:
    def __init__(self, lines, code=0):
        self.stdout = io.StringIO("".join(l + "\n" for l in lines))
        self.code = code

    def wait(self):
        return self.code


def events(*items):
    return [json.dumps(i) for i in items]


class RunnerTests(unittest.TestCase):
    def test_feed_builds_steps_log_and_result(self):
        r = setup_runner.SetupRunner("/tmp", popen=lambda *a, **k: FakeProc(events(
            {"type": "say", "text": "1/2 nmap"},
            {"type": "step", "index": 1, "total": 2, "title": "System packages", "state": "running"},
            {"type": "step", "index": 1, "total": 2, "title": "System packages", "state": "skipped",
             "message": "already installed"},
            {"type": "step", "index": 2, "total": 2, "title": "ffuf", "state": "failed",
             "message": "network down"},
            {"type": "result", "ready": 8, "total": 9, "failed": [{"title": "ffuf", "message": "x"}]},
        ) + ["not json at all"], code=1))
        r.start()
        for _ in range(100):
            if not r.running():
                break
            time.sleep(0.01)
        s = r.status()
        self.assertEqual(s["state"], "failed")
        self.assertEqual([x["state"] for x in s["steps"]], ["skipped", "failed"])
        self.assertEqual(s["result"]["ready"], 8)
        self.assertIn("not json at all", s["log"])

    def test_runs_the_real_installer_command_only(self):
        seen = []

        def popen(argv, **kw):
            seen.append((argv, kw))
            return FakeProc([], 0)
        r = setup_runner.SetupRunner("/repo", popen=popen)
        r.start()
        argv, kw = seen[0]
        self.assertEqual(argv[1:], ["-u", "-m", "reconmind.setup", "--install", "--yes", "--events"])
        self.assertEqual(kw["cwd"], "/repo")
        self.assertEqual(kw["stdin"], setup_runner.subprocess.DEVNULL)

    def test_refuses_during_scan_and_twice(self):
        r = setup_runner.SetupRunner("/tmp", popen=lambda *a, **k: FakeProc([]))
        with self.assertRaises(setup_runner.SetupBusy):
            r.start(scan_running=True)
        r.state = "running"
        with self.assertRaises(setup_runner.SetupBusy):
            r.start()


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.calls = []

        def popen(argv, **kw):
            self.calls.append(argv)
            return FakeProc(events({"type": "result", "ready": 9, "total": 9, "failed": []}))
        self.app = create_app(report_dir=os.path.join(self.tmp.name, "reports"), port=8777,
                              setup_popen=popen)
        self.client = TestClient(self.app, base_url="http://127.0.0.1:8777")

    def tearDown(self):
        self.tmp.cleanup()

    def test_install_needs_the_page_header(self):
        self.assertEqual(self.client.post("/api/setup/install", json={}).status_code, 403)
        self.assertEqual(self.calls, [])

    def test_install_starts_and_finishes(self):
        res = self.client.post("/api/setup/install", json={}, headers=H)
        self.assertEqual(res.status_code, 202)
        for _ in range(100):
            if self.client.get("/api/setup/status").json()["state"] != "running":
                break
            time.sleep(0.01)
        self.assertEqual(self.client.get("/api/setup/status").json()["state"], "done")
        self.assertEqual(len(self.calls), 1)

    def test_snapshot_is_read_only(self):
        fake = {"preflight": [], "blocked": False, "tools": [], "model": {}, "plan": []}
        with mock.patch.object(setup_runner, "snapshot", return_value=fake):
            data = self.client.get("/api/setup").json()
        self.assertEqual(data["job"]["state"], "idle")
        self.assertEqual(self.calls, [])

    def test_scan_refused_while_setup_runs(self):
        self.app.state.setup.state = "running"
        res = self.client.post("/api/scans", json={"kind": "recon", "target": "10.10.1.20", "preset": "quick"}, headers=H)
        self.assertEqual(res.status_code, 409)
        self.assertIn("Setup is running", res.json()["message"])


class PrivilegeTests(unittest.TestCase):
    def make(self, env, sudo_ok):
        class Proc:
            returncode = 0 if sudo_ok else 1
        return install.Installer("ubuntu", "amd64", data_dir=tempfile.mkdtemp(), root=False,
                                 interactive=False, env=env, log=lambda *a: None,
                                 run=lambda *a, **k: Proc())

    def test_passwordless_sudo_first(self):
        with mock.patch.object(install.shutil, "which", return_value="/usr/bin/x"):
            self.assertEqual(self.make({}, True).privilege()[0], "sudo-n")

    def test_pkexec_on_a_desktop(self):
        with mock.patch.object(install.shutil, "which", return_value="/usr/bin/x"):
            self.assertEqual(self.make({"DISPLAY": ":0"}, False).privilege()[0], "pkexec")

    def test_no_desktop_explains_terminal(self):
        with mock.patch.object(install.shutil, "which", return_value="/usr/bin/x"):
            with self.assertRaises(install.StepError) as err:
                self.make({}, False).privilege()
        self.assertIn("python3 -m reconmind.setup --install", str(err.exception))


class EventsModeTests(unittest.TestCase):
    def test_every_line_is_json_and_no_prompt(self):
        checks = [cli.preflight.Check("Operating system", True, "Ubuntu", True)]
        with mock.patch.object(cli.preflight, "run_checks", return_value=checks), \
                mock.patch.object(cli.preflight, "read_os_release", return_value={"ID": "ubuntu"}), \
                mock.patch.object(cli.install.Installer, "install",
                                  return_value=([("ffuf", install.DONE, "ok")], [])), \
                mock.patch("sys.stdout", new=io.StringIO()) as out:
            code = cli.main(["--install", "--yes", "--events"],
                            inp=lambda p: self.fail("no prompt in events mode"))
        lines = out.getvalue().strip().splitlines()
        self.assertEqual(code, 0)
        self.assertTrue(all(isinstance(json.loads(l), dict) for l in lines))
        self.assertEqual(json.loads(lines[-1])["type"], "result")

    def test_events_needs_install_yes(self):
        with mock.patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(cli.main(["--check", "--events"]), 2)


if __name__ == "__main__":
    unittest.main()
