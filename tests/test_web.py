"""
Offline tests for the web app (reconmind/web): /api/options against
scan_plan and config, /api/check for recon and code requests, /api/scans
starting a job through a fake runner (argument list, no shell, one job at a
time), the request guards (Host header, X-ReconMind header, JSON body, CSP),
/api/history, job ids, and saved running jobs becoming interrupted.

No real process is started and no network is used: every JobManager gets a
fake runner, and report_dir and logs/ live in a temp folder. The whole module
is skipped when the web packages are not installed.

    python3 -m unittest discover -s tests -v
"""

import json
import os
import tempfile
import threading
import time
import unittest
from unittest import mock

try:
    import fastapi  # noqa: F401
    import httpx  # noqa: F401
except ImportError:
    raise unittest.SkipTest("fastapi and httpx are not installed; "
                            "pip install -r requirements-web.txt to run the web tests")

from fastapi.testclient import TestClient

from reconmind.agent import llm
from reconmind.core import config
from reconmind.core.scan_plan import ACTIONS, DEFAULT_PRESET, PRESETS, build_plan
from reconmind.web import jobs as jobmod
from reconmind.web.server import CSP, create_app

PORT = 8000
BASE = "http://127.0.0.1:{p}".format(p=PORT)
HEADERS = {"X-ReconMind": "1"}
ALLOWED = "10.10.1.20"
DENIED = "10.0.3.5"
SECRET_KEY = "sk-or-test-0123456789-secret"
AI_CONFIG = llm.ProviderConfig("anthropic", "anthropic", None, "ANTHROPIC_API_KEY", SECRET_KEY,
                               "fake-model")


def no_llm():
    """llm.load_config as it behaves with no key set."""
    return mock.patch.object(llm, "load_config",
                             side_effect=llm.ConfigError("OPENROUTER_API_KEY is not set."))


def with_llm():
    return mock.patch.object(llm, "load_config", return_value=AI_CONFIG)


class FakeProc:
    """A Popen stand in. Prints its lines, then holds until released."""

    def __init__(self, lines=(), exit_code=0, hold=False):
        self.pid = None  # JobManager never signals a job without a real pid
        self.exit_code = exit_code
        self._lines = list(lines)
        self._released = threading.Event()
        if not hold:
            self._released.set()
        self.stdout = self._read()

    def _read(self):
        for line in self._lines:
            yield line + "\n"
        self._released.wait(5)

    def release(self):
        self._released.set()

    def wait(self, timeout=None):
        self._released.wait(5 if timeout is None else timeout)
        return self.exit_code

    def poll(self):
        return self.exit_code if self._released.is_set() else None


class FakeRunner:
    """Records every call; returns the next prepared FakeProc."""

    def __init__(self, **proc_kwargs):
        self.calls = []
        self.procs = []
        self.proc_kwargs = proc_kwargs

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        proc = FakeProc(**self.proc_kwargs)
        self.procs.append(proc)
        return proc


class WebTestCase(unittest.TestCase):
    """A fresh temp folder as cwd (logs/ lands there) and a temp report_dir."""

    runner_kwargs = {}

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)
        # No LLM settings from the developer's shell or from a .env that an
        # earlier test loaded into os.environ, and the temp cwd has no .env,
        # so AI is unavailable unless a test patches it in.
        self._env = mock.patch.dict(
            os.environ, {k: os.environ[k] for k in ("PATH", "HOME") if k in os.environ},
            clear=True)
        self._env.start()
        self.report_dir = os.path.join(self._tmp.name, "reports")
        self.runner = FakeRunner(**self.runner_kwargs)
        self.app = create_app(report_dir=self.report_dir, runner=self.runner, port=PORT)
        self.client = TestClient(self.app, base_url=BASE)

    def tearDown(self):
        for proc in self.runner.procs:
            proc.release()
        for job in list(self.app.state.jobs._jobs.values()):
            if job.thread is not None:
                job.thread.join(5)
        self._env.stop()
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def post(self, url, body, headers=HEADERS):
        return self.client.post(url, json=body, headers=headers)

    def recon(self, target=ALLOWED, **extra):
        return dict({"kind": "recon", "target": target, "preset": "standard",
                     "ports": "top", "actions": list(PRESETS["standard"].actions)}, **extra)

    def wait_finished(self, job_id, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            data = self.client.get("/api/scans/" + job_id).json()
            if data["status"] != "running":
                return data
            time.sleep(0.02)
        self.fail("job {j} did not finish".format(j=job_id))


# ---- options ---------------------------------------------------------------

class OptionsTests(WebTestCase):

    def test_options_match_scan_plan_and_config(self):
        response = self.client.get("/api/options")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual([p["id"] for p in data["presets"]], list(PRESETS))
        for item in data["presets"]:
            preset = PRESETS[item["id"]]
            self.assertEqual(item["actions"], list(preset.actions))
            self.assertEqual(item["ports"], preset.ports)
            self.assertEqual(item["vuln_mode"], preset.vuln_mode)
        self.assertEqual(data["actions"], [{"id": a.id, "name": a.name, "tools": list(a.tools)}
                                           for a in ACTIONS])
        self.assertEqual(data["default_preset"], DEFAULT_PRESET)
        self.assertEqual(data["allowlist"], list(config.ALLOWLIST))
        self.assertEqual(data["denylist"], list(config.DENYLIST))
        self.assertEqual(data["max_hosts"], 8)

    def test_options_say_whether_ai_is_available_and_never_show_the_key(self):
        with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": SECRET_KEY,
                                          "RECONMIND_PROVIDER": "openrouter",
                                          "RECONMIND_MODEL": "some/model"}):
            response = self.client.get("/api/options")
        self.assertEqual(response.json()["ai"],
                         {"available": True, "provider": "openrouter", "model": "some/model"})
        self.assertNotIn(SECRET_KEY, response.text)

        with with_llm():
            response = self.client.get("/api/options")
        self.assertEqual(response.json()["ai"],
                         {"available": True, "provider": "anthropic", "model": "fake-model"})
        self.assertNotIn(SECRET_KEY, response.text)

        with no_llm():
            data = self.client.get("/api/options").json()
        self.assertEqual(data["ai"], {"available": False, "provider": None, "model": None})

    def test_no_route_changes_config(self):
        for method in ("post", "put", "patch", "delete"):
            response = getattr(self.client, method)("/api/options", headers=HEADERS)
            self.assertIn(response.status_code, (403, 405), method)


# ---- /api/check ------------------------------------------------------------

class CheckTests(WebTestCase):

    def test_allowed_target_is_ok(self):
        data = self.post("/api/check", self.recon()).json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["plan"], build_plan(ALLOWED, preset="standard").to_dict())
        self.assertEqual(data["describe"], build_plan(ALLOWED, preset="standard").describe())
        self.assertEqual(self.runner.calls, [])

    def test_denied_target_is_refused_and_names_the_networks(self):
        data = self.post("/api/check", self.recon(DENIED)).json()
        self.assertFalse(data["ok"])
        self.assertEqual(data["reason"], "refused")
        for network in config.ALLOWLIST:
            self.assertIn(network, data["message"])
        self.assertEqual(self.runner.calls, [])

    def test_not_an_ip_is_invalid(self):
        data = self.post("/api/check", self.recon("not-an-ip")).json()
        self.assertFalse(data["ok"])
        self.assertEqual(data["reason"], "invalid")
        self.assertEqual(data["field"], "target")

    def test_ports_with_shell_text_are_invalid(self):
        data = self.post("/api/check", self.recon(ports="22;rm -rf /")).json()
        self.assertFalse(data["ok"])
        self.assertEqual(data["reason"], "invalid")
        self.assertEqual(data["field"], "ports")

    def test_unknown_action_is_invalid(self):
        data = self.post("/api/check", self.recon(actions=["surface", "nope"])).json()
        self.assertFalse(data["ok"])
        self.assertEqual(data["reason"], "invalid")
        self.assertEqual(data["field"], "actions")

    def test_code_input_is_ok(self):
        path = os.path.join(self._tmp.name, "app.py")
        with open(path, "w") as fh:
            fh.write("print('hi')\n")
        data = self.post("/api/check", {"kind": "code", "path": path, "explain": False}).json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["input"]["path"], os.path.realpath(path))
        self.assertEqual(data["input"]["languages"], {"python": 1})

    def test_unknown_kind_is_invalid(self):
        data = self.post("/api/check", {"kind": "shell", "target": ALLOWED}).json()
        self.assertEqual(data["reason"], "invalid")


# ---- /api/scans ------------------------------------------------------------

class ScanTests(WebTestCase):

    runner_kwargs = {"hold": True}

    def test_refused_target_never_calls_the_runner(self):
        response = self.post("/api/scans", self.recon(DENIED))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["reason"], "refused")
        self.assertEqual(self.runner.calls, [])

    def test_valid_target_runs_the_cli_with_the_plan(self):
        body = self.recon(preset="quick", ports="22,80,8000-8100", actions=["exploits"],
                          mode="standard")
        response = self.post("/api/scans", body)
        self.assertEqual(response.status_code, 201)
        job_id = response.json()["job_id"]
        self.assertRegex(job_id, r"^[0-9a-f]{12}$")

        self.assertEqual(len(self.runner.calls), 1)
        argv, kwargs = self.runner.calls[0]
        plan = build_plan(ALLOWED, preset="quick", ports="22,80,8000-8100",
                          actions=["exploits"])
        self.assertIsInstance(argv, list)
        self.assertEqual(argv, jobmod.recon_command(plan, "standard"))
        self.assertEqual(argv[1:], ["-u", "-m", "reconmind", ALLOWED, "--preset", "quick",
                                    "--ports", "22,80,8000-8100",
                                    "--actions", "surface,exploits", "--mode", "standard"])
        self.assertFalse(kwargs.get("shell", False))
        self.assertTrue(kwargs["start_new_session"])
        self.assertEqual(kwargs["cwd"], os.getcwd())
        self.assertEqual(kwargs["env"]["PYTHONUNBUFFERED"], "1")
        self.assertEqual(kwargs["env"]["RECONMIND_EVENTS"],
                         os.path.join(self.report_dir, ".jobs", job_id + ".events.jsonl"))

        job = self.client.get("/api/scans/" + job_id).json()
        self.assertEqual(job["status"], "running")
        self.assertEqual(job["kind"], "recon")
        self.assertTrue(os.path.exists(os.path.join(self.report_dir, ".jobs",
                                                    job_id + ".json")))

    def test_mode_is_passed_to_the_cli(self):
        with with_llm():
            self.assertEqual(self.post("/api/scans", self.recon(mode="ai")).status_code, 201)
        self.assertEqual(self.runner.calls[0][0][-2:], ["--mode", "ai"])

    def test_default_mode_is_ai_with_a_key(self):
        with with_llm():
            self.assertEqual(self.post("/api/scans", self.recon()).status_code, 201)
        self.assertEqual(self.runner.calls[0][0][-2:], ["--mode", "ai"])
        self.assertNotIn(SECRET_KEY, self.runner.calls[0][0])

    def test_default_mode_is_standard_without_a_key(self):
        with no_llm():
            self.assertEqual(self.post("/api/scans", self.recon()).status_code, 201)
        self.assertEqual(self.runner.calls[0][0][-2:], ["--mode", "standard"])

    def assert_mode_refused(self, modes):
        for mode in modes:
            response = self.post("/api/scans", self.recon(mode=mode))
            self.assertEqual(response.status_code, 400, mode)
            self.assertEqual(response.json()["field"], "mode")
        self.assertEqual(self.runner.calls, [])

    def test_bad_mode_is_400_with_ai_available(self):
        with with_llm():
            self.assert_mode_refused(("turbo", 1, ["ai"], ""))

    def test_bad_mode_is_400_without_ai(self):
        with no_llm():
            self.assert_mode_refused(("turbo", 1, ["ai"], ""))

    def test_ai_mode_without_ai_is_400(self):
        with no_llm():
            self.assert_mode_refused(("ai",))

    def test_second_start_while_running_is_409(self):
        first = self.post("/api/scans", self.recon())
        self.assertEqual(first.status_code, 201)
        second = self.post("/api/scans", self.recon())
        self.assertEqual(second.status_code, 409)
        self.assertEqual(second.json()["job_id"], first.json()["job_id"])
        self.assertEqual(len(self.runner.calls), 1)

    def test_missing_code_path_is_400(self):
        missing = os.path.join(self._tmp.name, "nothing_here")
        response = self.post("/api/scans", {"kind": "code", "path": missing})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["field"], "path")
        self.assertEqual(self.runner.calls, [])

    def test_path_starting_with_dash_is_400(self):
        response = self.post("/api/scans", {"kind": "code", "path": "--explain"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.runner.calls, [])

    def test_code_scan_uses_the_absolute_path(self):
        os.makedirs("src")
        with open(os.path.join("src", "app.py"), "w") as fh:
            fh.write("print('hi')\n")
        response = self.post("/api/scans", {"kind": "code", "path": "src", "explain": True})
        self.assertEqual(response.status_code, 201)
        argv, kwargs = self.runner.calls[0]
        self.assertEqual(argv[1:], ["-u", "-m", "reconmind",
                                    os.path.realpath(os.path.join(self._tmp.name, "src")),
                                    "--explain"])
        self.assertFalse(kwargs.get("shell", False))


class JobEndTests(WebTestCase):

    runner_kwargs = {"lines": ["ReconMind agent  target=10.10.1.20",
                               "run id:      20261114_101500_10.10.1.20",
                               "report:      reports/20261114_101500_10.10.1.20/report.md"]}

    def test_exit_0_is_done_with_the_run_id_and_a_log(self):
        job_id = self.post("/api/scans", self.recon()).json()["job_id"]
        job = self.wait_finished(job_id)
        self.assertEqual(job["status"], "done")
        self.assertEqual(job["exit_code"], 0)
        self.assertEqual(job["run_id"], "20261114_101500_10.10.1.20")
        self.assertEqual(job["lines"][0], "ReconMind agent  target=10.10.1.20")
        self.assertIsNotNone(job["finished"])
        with open(os.path.join(self.report_dir, ".jobs", job_id + ".log")) as fh:
            self.assertEqual(len(fh.read().splitlines()), 3)
        # The slot is free again.
        self.assertEqual(self.post("/api/scans", self.recon()).status_code, 201)


class RefusedExitTests(WebTestCase):

    runner_kwargs = {"exit_code": 2}

    def test_exit_2_is_refused(self):
        job_id = self.post("/api/scans", self.recon()).json()["job_id"]
        self.assertEqual(self.wait_finished(job_id)["status"], "refused")


class ExitOneWithReportTests(WebTestCase):

    runner_kwargs = {"exit_code": 1, "lines": ["Model busy (rate limited).",
                                               "run id:      20261115_110000_10.10.1.20",
                                               "report:      reports/x/report.md"]}

    def test_exit_1_after_a_run_id_is_done_with_a_warning(self):
        job_id = self.post("/api/scans", self.recon(mode="standard")).json()["job_id"]
        job = self.wait_finished(job_id)
        self.assertEqual(job["status"], "done")
        self.assertEqual(job["exit_code"], 1)
        self.assertEqual(job["run_id"], "20261115_110000_10.10.1.20")
        self.assertEqual(job["warning"], jobmod.SUMMARY_WARNING)
        # The warning is saved with the job, so it survives a server restart.
        with open(os.path.join(self.report_dir, ".jobs", job_id + ".json")) as fh:
            self.assertEqual(json.load(fh)["warning"], jobmod.SUMMARY_WARNING)


class ExitOneWithoutReportTests(WebTestCase):

    runner_kwargs = {"exit_code": 1, "lines": ["Bad scan plan: something"]}

    def test_exit_1_without_a_run_id_is_failed(self):
        job_id = self.post("/api/scans", self.recon(mode="standard")).json()["job_id"]
        job = self.wait_finished(job_id)
        self.assertEqual(job["status"], "failed")
        self.assertIsNone(job["run_id"])
        self.assertIsNone(job["warning"])


class StoppedExitTests(WebTestCase):

    runner_kwargs = {"exit_code": 4, "lines": ["status:      stopped",
                                               "run id:      20261115_101500_10.10.1.20",
                                               "report:      reports/x/report.md"]}

    def test_exit_4_is_stopped_with_the_partial_run_id(self):
        job_id = self.post("/api/scans", self.recon(mode="standard")).json()["job_id"]
        job = self.wait_finished(job_id)
        self.assertEqual(job["status"], "stopped")
        self.assertEqual(job["exit_code"], 4)
        self.assertEqual(job["run_id"], "20261115_101500_10.10.1.20")

    def test_stop_waits_for_the_partial_report(self):
        self.assertEqual(jobmod.STOP_GRACE, 20)


# ---- request guards --------------------------------------------------------

class SecurityTests(WebTestCase):

    def test_post_without_header_is_403(self):
        response = self.client.post("/api/scans", json=self.recon())
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.runner.calls, [])

    def test_post_without_json_body_is_403(self):
        response = self.client.post("/api/check", content="kind=recon",
                                    headers=dict(HEADERS, **{"Content-Type": "text/plain"}))
        self.assertEqual(response.status_code, 403)
        response = self.client.post("/api/check", content="[1, 2]",
                                    headers=dict(HEADERS, **{"Content-Type": "application/json"}))
        self.assertEqual(response.status_code, 403)

    def test_bad_host_is_400(self):
        for host in ("evil.example:8000", "127.0.0.1:9999", "127.0.0.1.evil.example:8000"):
            response = self.client.get("/api/options", headers={"Host": host})
            self.assertEqual(response.status_code, 400, host)
        self.assertEqual(self.client.get("/api/options",
                                         headers={"Host": "localhost:8000"}).status_code, 200)

    def test_csp_and_headers_on_index(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Content-Security-Policy"], CSP)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertNotIn("access-control-allow-origin", response.headers)

    def test_static_files_are_served(self):
        response = self.client.get("/static/js/app.js")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Content-Security-Policy", response.headers)


# ---- history and job ids ---------------------------------------------------

class HistoryTests(WebTestCase):

    def test_no_index_is_empty(self):
        data = self.client.get("/api/history").json()
        self.assertEqual(data["entries"], [])
        self.assertNotIn("warning", data)

    def test_entries_newest_first(self):
        os.makedirs(self.report_dir)
        with open(os.path.join(self.report_dir, "index.json"), "w") as fh:
            json.dump([{"run_id": "a"}, {"run_id": "b"}], fh)
        data = self.client.get("/api/history").json()
        self.assertEqual([e["run_id"] for e in data["entries"]], ["b", "a"])

    def test_unreadable_index_is_empty_with_a_warning(self):
        os.makedirs(self.report_dir)
        with open(os.path.join(self.report_dir, "index.json"), "w") as fh:
            fh.write("{not json")
        data = self.client.get("/api/history").json()
        self.assertEqual(data["entries"], [])
        self.assertIn("warning", data)

    def test_bad_job_id_is_404(self):
        for job_id in ("nothex", "ABCDEF123456", "0123456789abc", "0123456789a"):
            self.assertEqual(self.client.get("/api/scans/" + job_id).status_code, 404, job_id)
        self.assertEqual(self.client.get("/api/scans/0123456789ab").status_code, 404)


# ---- saved jobs ------------------------------------------------------------

class InterruptedTests(unittest.TestCase):

    def test_saved_running_job_becomes_interrupted(self):
        with tempfile.TemporaryDirectory() as report_dir:
            jobs_dir = os.path.join(report_dir, jobmod.JOBS_FOLDER)
            os.makedirs(jobs_dir)
            meta = {"id": "0123456789ab", "kind": "recon", "label": "Standard scan, 10.10.1.20",
                    "status": "running", "exit_code": None, "started": "2026-11-14T10:00:00",
                    "finished": None, "run_id": None}
            jobmod.write_json(os.path.join(jobs_dir, "0123456789ab.json"), meta)
            done = dict(meta, id="ba9876543210", status="done", exit_code=0,
                        finished="2026-11-14T10:05:00")
            jobmod.write_json(os.path.join(jobs_dir, "ba9876543210.json"), done)

            manager = jobmod.JobManager(report_dir, cwd=report_dir, runner=FakeRunner())
            with open(os.path.join(jobs_dir, "0123456789ab.json")) as fh:
                self.assertEqual(json.load(fh)["status"], "interrupted")
            self.assertEqual(manager.get("0123456789ab")["status"], "interrupted")
            self.assertEqual(manager.get("ba9876543210")["status"], "done")
            self.assertIsNone(manager.running_id)


if __name__ == "__main__":
    unittest.main()
