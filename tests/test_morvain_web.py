"""MORVAIN-X0 web routes: starting an agent scan and sending plan decisions."""
import json
import os
import unittest

import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_web import HEADERS as H, WebTestCase, no_llm as without_llm, with_llm  # noqa: E402


class AgentRouteTests(WebTestCase):
    runner_kwargs = {"hold": True}

    def start(self):
        with with_llm():
            res = self.client.post("/api/scans", json={"kind": "recon", "target": "10.10.1.20",
                                                       "preset": "quick", "mode": "agent"},
                                   headers=H)
        self.assertEqual(res.status_code, 201, res.text)
        return res.json()["job_id"]

    def test_agent_scan_runs_the_cli_in_agent_mode(self):
        job_id = self.start()
        argv, kwargs = self.runner.calls[0]
        self.assertEqual(argv[argv.index("--mode") + 1], "agent")
        self.assertTrue(kwargs["env"]["RECONMIND_AGENT_INBOX"].endswith(job_id + ".agent.json"))
        self.assertTrue(self.client.get("/api/scans/" + job_id).json()["label"]
                        .startswith("Agent scan"))

    def test_agent_needs_an_llm(self):
        with without_llm():
            res = self.client.post("/api/scans", json={"kind": "recon", "target": "10.10.1.20",
                                                       "mode": "agent"}, headers=H)
        self.assertIn("AI agent", res.json()["message"])
        self.assertEqual(self.runner.calls, [])

    def test_decision_is_written_for_the_running_job(self):
        job_id = self.start()
        res = self.client.post("/api/scans/{j}/agent".format(j=job_id), headers=H,
                               json={"round": 1, "decision": "approve",
                                     "actions": ["web", "web", "smb"], "message": "  go  "})
        self.assertEqual(res.status_code, 200, res.text)
        path = self.app.state.jobs.agent_inbox(job_id)
        with open(path) as f:
            self.assertEqual(json.load(f), {"round": 1, "decision": "approve",
                                            "actions": ["web", "smb"], "message": "go"})

    def test_bad_decisions_rejected(self):
        job_id = self.start()
        url = "/api/scans/{j}/agent".format(j=job_id)
        bad = [{"round": 1, "decision": "launch"},
               {"round": "1", "decision": "approve"},
               {"round": True, "decision": "approve"},
               {"round": 1, "decision": "approve", "actions": ["surface"]},
               {"round": 1, "decision": "approve", "actions": ["web; rm -rf /"]},
               {"round": 1, "decision": "redirect", "message": "x" * 501},
               {"round": 1, "decision": "ask", "message": "   "},
               {"round": 1, "decision": "ask", "message": "", "actions": ["web", "smb"]}]
        for body in bad:
            with self.subTest(body=body):
                self.assertEqual(self.client.post(url, json=body, headers=H).status_code, 400)
        self.assertFalse(os.path.exists(self.app.state.jobs.agent_inbox(job_id)))
        self.assertEqual(self.client.post(url, json={"round": 1, "decision": "finish"})
                         .status_code, 403)

    def test_question_is_written_for_the_running_job(self):
        job_id = self.start()
        url = "/api/scans/{j}/agent".format(j=job_id)
        res = self.client.post(url, headers=H, json={"round": 2, "decision": "ask",
                                                      "message": " Why  port 21? "})
        self.assertEqual(res.status_code, 200, res.text)
        with open(self.app.state.jobs.agent_inbox(job_id)) as f:
            self.assertEqual(json.load(f)["message"], "Why port 21?")
        res = self.client.post(url, headers=H, json={"round": 2, "decision": "ask",
                                                      "actions": ["web"]})
        self.assertEqual(res.status_code, 200, res.text)

    def test_decision_for_a_job_that_is_not_running(self):
        res = self.client.post("/api/scans/0123456789ab/agent", headers=H,
                               json={"round": 1, "decision": "finish"})
        self.assertEqual(res.status_code, 409)


if __name__ == "__main__":
    unittest.main()
