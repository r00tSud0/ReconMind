"""
Offline tests for the features that finish the web app: host lists (up to 8
hosts, one after another, every host through the gate first), the analyst's
notes and own reports (kept apart from the tool reports, which never change),
and "Ask about this report" (the report only, IDs it does not contain
removed, nothing without an LLM).

No real process, network or model is used.

    python3 -m unittest tests.test_web_finish -v
"""

import json
import os
import time
import unittest
from types import SimpleNamespace
from unittest import mock

try:
    import fastapi  # noqa: F401
    import httpx  # noqa: F401
except ImportError:
    raise unittest.SkipTest("fastapi and httpx are not installed")

from reconmind.web import ask as ask_mod
from reconmind.web import workspace as ws
from tests.test_web import (ALLOWED, DENIED, RECON_RESULTS, RUN, WebTestCase, save_run_files,
                            with_llm)

HOSTS = ["10.10.1.20", "10.10.1.21", "10.10.2.15"]


def hosts_body(targets=HOSTS, **extra):
    return dict({"kind": "hosts", "targets": list(targets), "preset": "quick", "mode": "standard"},
                **extra)


class HostListTests(WebTestCase):

    def wait_list(self, list_id, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            data = self.client.get("/api/lists/" + list_id).json()
            if data["status"] != "running":
                return data
            time.sleep(0.02)
        self.fail("list did not finish")

    def test_runs_every_host_one_after_another(self):
        response = self.post("/api/scans", hosts_body())
        self.assertEqual(response.status_code, 201, response.text)
        list_id = response.json()["list_id"]
        data = self.wait_list(list_id)
        self.assertEqual(data["status"], "done")
        self.assertEqual([h["target"] for h in data["hosts"]], HOSTS)
        self.assertTrue(all(h["status"] == "done" for h in data["hosts"]))
        # One CLI run per host, each with its own target, never a shell.
        targets = [argv[4] for argv, _ in self.runner.calls]
        self.assertEqual(targets, HOSTS)
        for argv, kwargs in self.runner.calls:
            self.assertNotIn("shell", kwargs)
        job = self.client.get("/api/scans/" + data["hosts"][1]["job_id"]).json()
        self.assertEqual(job["list"], list_id)
        listed = self.client.get("/api/lists").json()["lists"]
        self.assertEqual(listed[0]["id"], list_id)

    def test_one_refused_host_refuses_the_whole_list(self):
        response = self.post("/api/scans", hosts_body(HOSTS + [DENIED]))
        self.assertEqual(response.status_code, 403)
        self.assertIn(DENIED, response.json()["message"])
        self.assertEqual(self.runner.calls, [], "Nothing starts when any host is refused")

    def test_limits_and_bad_input(self):
        nine = ["10.10.1.{n}".format(n=n) for n in range(1, 10)]
        for body, words in ((hosts_body(nine), "up to 8"), (hosts_body([]), "at least one"),
                            (hosts_body(["10.10.1.0/24"]), "not an IPv4"),
                            (hosts_body([ALLOWED, ALLOWED]), "twice"),
                            (dict(hosts_body(), targets="10.10.1.20"), "must be a list"),
                            (hosts_body(mode="agent"), "one target at a time")):
            response = self.post("/api/scans", body)
            self.assertEqual(response.status_code, 400, body)
            self.assertIn(words, response.json()["message"])
        self.assertEqual(self.runner.calls, [])

    def test_check_names_every_host(self):
        data = self.post("/api/check", hosts_body()).json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["targets"], HOSTS)


class HostListStopTests(WebTestCase):
    runner_kwargs = {"hold": True}

    def test_stop_after_this_host(self):
        list_id = self.post("/api/scans", hosts_body()).json()["list_id"]
        self.assertEqual(self.post("/api/lists/" + list_id + "/stop", {}).json(), {"ok": True})
        self.runner.procs[0].release()
        deadline = time.time() + 5
        while time.time() < deadline:
            data = self.client.get("/api/lists/" + list_id).json()
            if data["status"] != "running":
                break
            time.sleep(0.02)
        self.assertEqual(data["status"], "stopped")
        self.assertEqual(len(self.runner.calls), 1, "No host after the current one")
        self.assertEqual([h["status"] for h in data["hosts"]], ["done", "skipped", "skipped"])
        self.assertEqual(self.post("/api/lists/" + list_id + "/stop", {}).status_code, 409)

    def test_unknown_list(self):
        self.assertEqual(self.client.get("/api/lists/zzzz").status_code, 404)
        self.assertEqual(self.client.get("/api/lists/0123456789").status_code, 404)


class NotesTests(WebTestCase):

    def test_add_edit_delete(self):
        note = self.post("/api/workspace/notes", {"folder": ALLOWED, "text": " Port 21 is vsftpd "}).json()
        self.assertTrue(note["ok"])
        nid = note["note"]["id"]
        self.assertEqual(note["note"]["text"], "Port 21 is vsftpd")
        edited = self.post("/api/workspace/notes/" + nid, {"folder": ALLOWED, "text": "Changed"}).json()
        self.assertEqual(edited["note"]["text"], "Changed")
        data = self.client.get("/api/workspace", params={"folder": ALLOWED}).json()
        self.assertEqual([n["text"] for n in data["notes"]], ["Changed"])
        other = self.client.get("/api/workspace", params={"folder": "10.10.1.21"}).json()
        self.assertEqual(other["notes"], [], "Notes belong to one folder")
        self.assertEqual(self.post("/api/workspace/notes/" + nid,
                                   {"folder": ALLOWED, "delete": True}).json(), {"ok": True})
        self.assertEqual(self.client.get("/api/workspace", params={"folder": ALLOWED}).json()["notes"], [])

    def test_refuses_bad_notes(self):
        for body in ({"folder": ALLOWED, "text": ""}, {"folder": ALLOWED, "text": 5},
                     {"folder": "", "text": "x"}, {"folder": ALLOWED, "text": "x" * 5001}):
            self.assertEqual(self.post("/api/workspace/notes", body).status_code, 400, body)
        self.assertEqual(self.post("/api/workspace/notes/../../x", {"folder": ALLOWED, "text": "x"}).status_code, 404)

    def test_folder_name_never_becomes_a_path(self):
        self.post("/api/workspace/notes", {"folder": "../../etc", "text": "x"})
        names = os.listdir(os.path.join(self.report_dir, ".workspace", "notes"))
        self.assertEqual(len(names), 1)
        self.assertRegex(names[0], r"^[0-9a-f]{32}\.json$")


class AnalystReportTests(WebTestCase):

    def setUp(self):
        super().setUp()
        save_run_files(self.report_dir, RUN, RECON_RESULTS,
                       entry_extra={"target": ALLOWED, "preset": "standard"})

    def test_start_from_a_scan_copies_findings_and_never_changes_it(self):
        scan_file = os.path.join(self.report_dir, RUN, "scan.json")
        def read():
            with open(scan_file) as fh:
                return fh.read()
        before = read()
        report = self.post("/api/analyst", {"folder": ALLOWED, "from_run": RUN}).json()["report"]
        self.assertEqual(report["from_run"], RUN)
        self.assertEqual([(f["severity"], f["port"]) for f in report["findings"]],
                         [("high", "23"), ("medium", "80")])
        self.assertEqual(report["fields"]["overall_risk"], "high")
        self.assertEqual(read(), before, "The tool report is never changed")
        listed = self.client.get("/api/workspace", params={"folder": ALLOWED}).json()["reports"]
        self.assertEqual([r["id"] for r in listed], [report["id"]])

    def test_save_validates_and_exports(self):
        report = self.post("/api/analyst", {"folder": ALLOWED}).json()["report"]
        url = "/api/analyst/" + report["id"]
        fields = dict(report["fields"], summary="Two backdoors.", status="final", confirmed=True)
        findings = [{"title": "vsftpd backdoor", "severity": "critical", "status": "open",
                     "evidence": "220 (vsFTPd 2.3.4)"}]
        saved = self.post(url, {"fields": fields, "findings": findings}).json()["report"]
        self.assertEqual(saved["fields"]["status"], "final")
        self.assertEqual(saved["findings"][0]["severity"], "critical")
        md = self.client.get(url + "/report.md")
        self.assertEqual(md.status_code, 200)
        self.assertIn("### F01 vsftpd backdoor", md.text)
        self.assertIn("Two backdoors.", md.text)
        for bad in ({"fields": dict(fields, status="done"), "findings": []},
                    {"fields": fields, "findings": [{"severity": "huge"}]},
                    {"fields": fields, "findings": [{}] * 201},
                    {"fields": dict(fields, title=7), "findings": []}):
            self.assertEqual(self.post(url, bad).status_code, 400)
        self.assertEqual(self.post(url, {"delete": True}).json(), {"ok": True})
        self.assertEqual(self.client.get(url).status_code, 404)

    def test_bad_ids(self):
        self.assertEqual(self.client.get("/api/analyst/xyz").status_code, 404)
        self.assertEqual(self.post("/api/analyst", {"folder": ALLOWED, "from_run": "../x"}).status_code, 400)


class AgentLabelTests(unittest.TestCase):

    def test_agent_runs_are_marked_in_the_index(self):
        import tempfile
        from reconmind.core import history
        from reconmind.core.scan_plan import build_plan
        with tempfile.TemporaryDirectory() as d:
            plan = build_plan(ALLOWED, preset="standard", actions=["surface", "exploits"])
            agent = history.save_run({"target": ALLOWED, "status": "ok", "ports": [],
                                      "agent": {"name": "MORVAIN-X0", "transcript": []}},
                                     plan=plan, report_dir=d, mode="ai")
            plain = history.save_run({"target": ALLOWED, "status": "ok", "ports": []},
                                     plan=plan, report_dir=d, mode="standard")
            entries = {e["run_id"]: e for e in history.read_index(d)}
            self.assertIs(entries[agent.run_id]["agent"], True)
            self.assertIs(entries[plain.run_id]["agent"], False)


class RepairBudgetTests(unittest.TestCase):

    def test_a_cut_off_summary_gets_a_bigger_repair_budget(self):
        from reconmind.agent import __main__ as runner
        model = FakeModel("### Key findings\n- still cut off")
        with mock.patch("builtins.print"):
            text, refs = runner._final_summary(model, "m", ALLOWED, {"ports": []},
                                               "### Key findings\n- cut off")
        self.assertIsNone(text, "A summary that still fails is never published")
        self.assertEqual(model.calls[0]["max_tokens"], runner.REPAIR_MAX_TOKENS)
        self.assertGreaterEqual(runner.REPAIR_MAX_TOKENS, 16000)


class FakeModel:
    def __init__(self, text):
        self.text = text
        self.calls = []
        self.messages = self

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=self.text)])


class AskTests(WebTestCase):

    def setUp(self):
        super().setUp()
        save_run_files(self.report_dir, RUN, RECON_RESULTS,
                       entry_extra={"target": ALLOWED, "preset": "standard"})

    def test_needs_an_llm(self):
        response = self.post("/api/reports/" + RUN + "/ask", {"question": "What is open?"})
        self.assertEqual(response.status_code, 409)

    def test_answers_from_the_report_only(self):
        model = FakeModel("Telnet on 23 is open. See CVE-1999-0619 and CVE-2099-0001.")
        with with_llm(), mock.patch("reconmind.agent.llm.make_client", return_value=model):
            response = self.post("/api/reports/" + RUN + "/ask",
                                 {"question": "Why is 23 high?", "turns": [{"q": "hi", "a": "hello"}]})
        self.assertEqual(response.status_code, 200, response.text)
        answer = response.json()["answer"]
        self.assertIn("[ID removed]", answer, "An ID the report does not contain is removed")
        call = model.calls[0]
        self.assertIn("Use only the report below", call["system"])
        self.assertIn("telnet", call["system"].lower(), "The report is sent as context")
        self.assertEqual(call["messages"][-1], {"role": "user", "content": "Why is 23 high?"})
        self.assertNotIn("tools", call)

    def test_bad_questions(self):
        for body in ({"question": ""}, {"question": "x" * 1001}, {"question": 3},
                     {"question": "ok", "turns": "no"}):
            self.assertEqual(self.post("/api/reports/" + RUN + "/ask", body).status_code, 400)
        self.assertEqual(self.post("/api/reports/20990101_000000_x/ask", {"question": "hi"}).status_code, 404)

    def test_context_is_capped(self):
        view = {"markdown": "x" * 200000, "findings": [], "entry": {}}
        self.assertLessEqual(len(ask_mod.context(view)), ask_mod.MAX_REPORT * 2)


if __name__ == "__main__":
    unittest.main()
