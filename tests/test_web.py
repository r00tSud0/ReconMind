"""
Offline tests for the web app (reconmind/web): /api/options against
scan_plan and config, /api/check for recon and code requests, /api/scans
starting a job through a fake runner (argument list, no shell, one job at a
time), the request guards (Host header, X-ReconMind header, JSON body, CSP),
/api/history, job ids, /api/scans/latest, saved running jobs becoming
interrupted, the job labels (Quick, Standard, Full and Custom scan), the
progress events route (since, 404s, 400s), and the report routes (the report
data without evidence, the evidence and report.md downloads, run id
validation, 404s and path containment).

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

    def test_static_files_are_revalidated(self):
        response = self.client.get("/static/js/app.js")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Cache-Control"], "no-cache")
        self.assertIn("etag", response.headers)

    def test_index_is_not_stored(self):
        self.assertEqual(self.client.get("/").headers["Cache-Control"], "no-store")


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


# ---- /api/scans/latest -----------------------------------------------------

def save_job(report_dir, job_id, started, status="done"):
    """A job saved by an earlier server."""
    jobs_dir = os.path.join(report_dir, jobmod.JOBS_FOLDER)
    os.makedirs(jobs_dir, exist_ok=True)
    jobmod.write_json(os.path.join(jobs_dir, job_id + ".json"),
                      {"id": job_id, "kind": "recon", "label": "Standard scan, 10.10.1.20",
                       "status": status, "exit_code": 0, "started": started,
                       "finished": started, "run_id": None, "warning": None})


class LatestEmptyTests(WebTestCase):

    def test_no_job_is_null(self):
        response = self.client.get("/api/scans/latest")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"job": None})


class LatestRunningTests(WebTestCase):

    runner_kwargs = {"hold": True, "lines": ["ReconMind agent  target=10.10.1.20"]}

    def test_running_job_comes_first(self):
        # A saved job that claims a later start still loses to the running one.
        save_job(self.report_dir, "fedcba987654", "2099-01-01T00:00:00")
        job_id = self.post("/api/scans", self.recon(mode="standard")).json()["job_id"]
        data = self.client.get("/api/scans/latest").json()
        self.assertEqual(data["job"]["id"], job_id)
        self.assertEqual(data["job"]["status"], "running")
        # Same fields as /api/scans/<id>; the lines may grow between the two calls.
        single = self.client.get("/api/scans/" + job_id).json()
        self.assertEqual(set(data["job"]), set(single))
        self.assertEqual({k: v for k, v in data["job"].items() if k != "lines"},
                         {k: v for k, v in single.items() if k != "lines"})


class LatestNewestTests(WebTestCase):

    def test_newest_job_when_none_runs(self):
        first = self.post("/api/scans", self.recon(mode="standard")).json()["job_id"]
        self.wait_finished(first)
        second = self.post("/api/scans", self.recon(mode="standard")).json()["job_id"]
        self.wait_finished(second)
        data = self.client.get("/api/scans/latest").json()
        self.assertEqual(data["job"]["id"], second)
        self.assertEqual(data["job"]["status"], "done")
        self.assertEqual(data["job"], self.client.get("/api/scans/" + second).json())

    def test_newest_saved_job_from_an_earlier_server(self):
        save_job(self.report_dir, "0123456789ab", "2026-11-14T10:00:00")
        save_job(self.report_dir, "ba9876543210", "2026-11-15T09:00:00")
        save_job(self.report_dir, "aaaaaaaaaaaa", "2026-11-13T23:00:00")
        manager = jobmod.JobManager(self.report_dir, cwd=self._tmp.name, runner=FakeRunner())
        self.assertEqual(manager.latest()["id"], "ba9876543210")


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


# ---- job labels ------------------------------------------------------------

class LabelTests(unittest.TestCase):

    def test_preset_labels(self):
        self.assertEqual(jobmod.recon_label(build_plan(ALLOWED, preset="quick")),
                         "Quick scan, 10.10.1.20")
        self.assertEqual(jobmod.recon_label(build_plan(ALLOWED, preset="standard")),
                         "Standard scan, 10.10.1.20")
        self.assertEqual(jobmod.recon_label(build_plan(ALLOWED, preset="full")),
                         "Full scan, 10.10.1.20")

    def test_customized_plan_is_a_custom_scan(self):
        # The page sends Custom as the standard preset with the user's ports and actions.
        plan = build_plan(ALLOWED, preset="standard", ports="22,80", actions=["exploits"])
        self.assertEqual(jobmod.recon_label(plan), "Custom scan, 10.10.1.20")
        plan = build_plan(ALLOWED, preset="quick", actions=["exploits", "cves"])
        self.assertEqual(jobmod.recon_label(plan), "Custom scan, 10.10.1.20")

    def test_no_label_says_report(self):
        for label in jobmod.PRESET_LABELS.values():
            self.assertNotIn("report", label.lower())


# ---- /api/scans/<job id>/events --------------------------------------------

JOB = "0123456789ab"


class EventsRouteTests(WebTestCase):

    def setUp(self):
        super().setUp()
        save_job(self.report_dir, JOB, "2026-11-12T21:36:00")
        self.path = self.app.state.jobs.events_path(JOB)

    def write_events(self, *kinds):
        with open(self.path, "a", encoding="utf-8") as fh:
            for kind in kinds:
                fh.write(json.dumps({"time": "2026-11-12T21:36:00", "kind": kind}) + "\n")

    def test_no_events_yet_is_empty(self):
        response = self.client.get("/api/scans/" + JOB + "/events")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"events": [], "next": 0, "more": False})

    def test_events_after_since(self):
        self.write_events("plan", "ports", "step")
        data = self.client.get("/api/scans/" + JOB + "/events").json()
        self.assertEqual([e["kind"] for e in data["events"]], ["plan", "ports", "step"])
        self.assertEqual(data["next"], 3)
        self.write_events("finished")
        data = self.client.get("/api/scans/" + JOB + "/events?since=3").json()
        self.assertEqual([e["kind"] for e in data["events"]], ["finished"])
        self.assertEqual(data["next"], 4)

    def test_events_of_a_running_job_of_this_server(self):
        runner = FakeRunner(hold=True)
        self.runner.procs = runner.procs  # released in tearDown
        self.app.state.jobs.runner = runner
        with no_llm():
            job_id = self.post("/api/scans", self.recon()).json()["job_id"]
        with open(self.app.state.jobs.events_path(job_id), "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"kind": "plan", "target": ALLOWED}) + "\n")
        data = self.client.get("/api/scans/" + job_id + "/events").json()
        self.assertEqual(data["events"], [{"kind": "plan", "target": ALLOWED}])

    def test_bad_since_is_400(self):
        for since in ("-1", "abc", "1.5", "1e3", "", "0x10", "1234567890"):
            response = self.client.get("/api/scans/" + JOB + "/events", params={"since": since})
            self.assertEqual(response.status_code, 400, since)
            self.assertEqual(response.json()["field"], "since")

    def test_unknown_or_bad_job_is_404(self):
        for job_id in ("ffffffffffff", "nothex", "ABCDEF123456", "0123456789abc", "..", "%2e%2e"):
            response = self.client.get("/api/scans/" + job_id + "/events")
            self.assertEqual(response.status_code, 404, job_id)


# ---- /api/reports/<run id> -------------------------------------------------

RUN = "20261112_213600_10.10.1.20"
SECRET_EVIDENCE = "SECRET-RAW-EVIDENCE-0123"
REPORT_MD = "# ReconMind Report\n\n**Target:** 10.10.1.20\n"
RECON_RESULTS = {
    "target": ALLOWED, "status": "ok",
    "ports": [{"port": 23, "protocol": "tcp", "service": "telnet", "product": "Linux telnetd"},
              {"port": 80, "protocol": "tcp", "service": "http", "product": "Apache httpd"}],
    "nuclei": {"80": {"status": "ok", "findings": [
        {"severity": "medium", "name": "phpMyAdmin panel", "template_id": "phpmyadmin-panel"}]}},
}


def save_run_files(report_dir, run_id, results, kind="recon", markdown=REPORT_MD,
                   evidence=True, index=True, entry_extra=None):
    """A saved run as history.save_run lays it out, written directly."""
    folder = os.path.join(report_dir, run_id)
    os.makedirs(folder)
    with open(os.path.join(folder, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(markdown)
    scan = {"run_id": run_id, "results": results}
    if kind == "code":
        scan["kind"] = "code"
    else:
        scan["plan"] = build_plan(ALLOWED).to_dict()
    jobmod.write_json(os.path.join(folder, "scan.json"), scan)
    if evidence:
        jobmod.write_json(os.path.join(folder, "evidence.json"),
                          {"run_id": run_id, "evidence": {"raw_xml": SECRET_EVIDENCE}})
    if index:
        entry = dict({"run_id": run_id, "kind": kind, "started": "2026-11-12T21:36:00",
                      "finished": "2026-11-12T21:49:04", "status": "ok"}, **(entry_extra or {}))
        path = os.path.join(report_dir, "index.json")
        entries = []
        if os.path.exists(path):
            with open(path) as fh:
                entries = json.load(fh)
        jobmod.write_json(path, entries + [entry])
    return folder


class ReportRouteTests(WebTestCase):

    def setUp(self):
        super().setUp()
        self.folder = save_run_files(self.report_dir, RUN, RECON_RESULTS,
                                     entry_extra={"target": ALLOWED, "preset": "standard"})

    def test_report_has_entry_markdown_and_scan(self):
        response = self.client.get("/api/reports/" + RUN)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["run_id"], RUN)
        self.assertEqual(data["kind"], "recon")
        self.assertEqual(data["entry"]["target"], ALLOWED)
        self.assertEqual(data["markdown"], REPORT_MD)
        self.assertEqual(data["scan"]["results"]["target"], ALLOWED)
        self.assertTrue(data["has_evidence"])
        self.assertEqual([(f["severity"], f["port"]) for f in data["findings"]],
                         [("high", 23), ("medium", 80)])
        self.assertEqual(data["spectrum"], [{"port": 23, "service": "telnet", "severity": "high"},
                                            {"port": 80, "service": "http", "severity": "medium"}])
        self.assertEqual(data["summary"]["state"], "none")

    def test_report_never_carries_raw_evidence_or_local_paths(self):
        text = self.client.get("/api/reports/" + RUN).text
        self.assertNotIn(SECRET_EVIDENCE, text)
        self.assertNotIn(self._tmp.name, text)
        self.assertNotIn("evidence.json", text)

    def test_security_headers_on_report_routes(self):
        for url in ("/api/reports/" + RUN, "/api/reports/" + RUN + "/evidence",
                    "/api/reports/" + RUN + "/report.md"):
            response = self.client.get(url)
            self.assertEqual(response.headers["content-security-policy"], CSP, url)
            self.assertEqual(response.headers["x-content-type-options"], "nosniff", url)

    def test_missing_run_is_404_on_every_route(self):
        missing = "20261112_213600_10.10.1.21"
        for suffix in ("", "/evidence", "/report.md"):
            response = self.client.get("/api/reports/" + missing + suffix)
            self.assertEqual(response.status_code, 404, suffix)
            self.assertEqual(response.json()["reason"], "not_found")

    def test_bad_run_ids_are_404_on_every_route(self):
        for run_id in ("..", "%2e%2e", "%2E%2E", "20261112_213600_..", "abc", "index.json",
                       ".jobs", "20261112_213600_x%2F..%2F..", "20261112_213600_x%00",
                       "20261112_213600_" + "a" * 161):
            for suffix in ("", "/evidence", "/report.md"):
                response = self.client.get("/api/reports/" + run_id + suffix)
                self.assertEqual(response.status_code, 404, run_id + suffix)
                self.assertNotIn(SECRET_EVIDENCE, response.text)

    @unittest.skipUnless(hasattr(os, "symlink"), "needs symlinks")
    def test_symlinked_run_folder_outside_reports_is_404(self):
        outside = os.path.join(self._tmp.name, "outside")
        os.makedirs(outside)
        for name in ("report.md", "scan.json", "evidence.json"):
            with open(os.path.join(outside, name), "w") as fh:
                fh.write('{"secret": "' + SECRET_EVIDENCE + '"}')
        link = "20261112_213600_linked"
        os.symlink(outside, os.path.join(self.report_dir, link))
        for suffix in ("", "/evidence", "/report.md"):
            response = self.client.get("/api/reports/" + link + suffix)
            self.assertEqual(response.status_code, 404, suffix)
            self.assertNotIn(SECRET_EVIDENCE, response.text)

    @unittest.skipUnless(hasattr(os, "symlink"), "needs symlinks")
    def test_symlinked_report_file_is_404(self):
        outside = os.path.join(self._tmp.name, "secret.md")
        with open(outside, "w") as fh:
            fh.write(SECRET_EVIDENCE)
        os.remove(os.path.join(self.folder, "report.md"))
        os.symlink(outside, os.path.join(self.folder, "report.md"))
        for suffix in ("", "/report.md"):
            response = self.client.get("/api/reports/" + RUN + suffix)
            self.assertEqual(response.status_code, 404, suffix)
            self.assertNotIn(SECRET_EVIDENCE, response.text)

    def test_unreadable_scan_json_still_shows_the_report(self):
        with open(os.path.join(self.folder, "scan.json"), "w") as fh:
            fh.write("{not json")
        data = self.client.get("/api/reports/" + RUN).json()
        self.assertIsNone(data["scan"])
        self.assertEqual(data["findings"], [])
        self.assertTrue(data["warnings"])

    def test_run_missing_from_the_index_has_no_entry(self):
        save_run_files(self.report_dir, RUN + "_2", RECON_RESULTS, index=False)
        data = self.client.get("/api/reports/" + RUN + "_2").json()
        self.assertIsNone(data["entry"])
        self.assertEqual(len(data["findings"]), 2)

    def test_unreadable_index_still_shows_the_report(self):
        with open(os.path.join(self.report_dir, "index.json"), "w") as fh:
            fh.write("{not json")
        data = self.client.get("/api/reports/" + RUN).json()
        self.assertIsNone(data["entry"])
        self.assertTrue(data["warnings"])

    def test_code_run_gives_names_never_paths(self):
        code_run = "20261112_220000_app.py"
        path = os.path.join(self._tmp.name, "project", "src", "app.py")
        results = {"kind": "code", "input": path, "status": "ok", "findings": [
            {"severity": "high", "file": "src/app.py", "line": 3, "cwe": ["CWE-78"],
             "sources": ["bandit"], "rule_ids": {"bandit": "B605"},
             "messages": {"bandit": "Shell call."}, "snippet": "os.system(x)"}]}
        save_run_files(self.report_dir, code_run, results, kind="code", evidence=False,
                       entry_extra={"input": path})
        data = self.client.get("/api/reports/" + code_run).json()
        self.assertEqual(data["kind"], "code")
        self.assertEqual(data["entry"]["input"], "app.py")
        self.assertEqual(data["scan"]["results"]["input"], "app.py")
        self.assertEqual(data["findings"][0]["where"], "app.py, line 3")
        self.assertEqual(data["spectrum"], [])
        self.assertFalse(data["has_evidence"])
        self.assertEqual(self.client.get("/api/reports/" + code_run + "/evidence").status_code, 404)


class ReportDownloadTests(WebTestCase):

    def setUp(self):
        super().setUp()
        save_run_files(self.report_dir, RUN, RECON_RESULTS)

    def test_raw_evidence_is_a_json_download(self):
        response = self.client.get("/api/reports/" + RUN + "/evidence")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers["content-type"].startswith("application/json"))
        disposition = response.headers["content-disposition"]
        self.assertIn("attachment", disposition)
        self.assertIn(RUN + "_evidence.json", disposition)
        self.assertEqual(response.json()["evidence"]["raw_xml"], SECRET_EVIDENCE)

    def test_export_md_is_a_markdown_download(self):
        response = self.client.get("/api/reports/" + RUN + "/report.md")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers["content-type"].startswith("text/markdown"))
        disposition = response.headers["content-disposition"]
        self.assertIn("attachment", disposition)
        self.assertIn(RUN + ".md", disposition)
        self.assertEqual(response.text, REPORT_MD)

    def test_downloads_are_not_cached(self):
        for suffix in ("/evidence", "/report.md"):
            response = self.client.get("/api/reports/" + RUN + suffix)
            self.assertEqual(response.headers["cache-control"], "no-store", suffix)


if __name__ == "__main__":
    unittest.main()
