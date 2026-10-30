"""
Offline tests for the ReconMind agent brain.

A scripted fake LLM drives the real ReAct loop, so these run with no API key,
no network, no nmap and no searchsploit:

    python3 -m unittest discover -s tests -v
"""

import os
import tempfile
import unittest
from types import SimpleNamespace as NS
from unittest import mock

from reconmind.agent import brain, tools as toolmod
from reconmind.agent.__main__ import main
from reconmind.core.report import build_report

TARGET = "10.10.1.100"

FAKE_SCAN = {
    "target": TARGET, "status": "ok",
    "ports": [
        {"port": 21, "protocol": "tcp", "service": "ftp", "product": "vsftpd", "version": "2.3.4"},
        {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "4.7p1"},
    ],
}
FAKE_EXPLOITS = [{"title": "vsftpd 2.3.4 - Backdoor Command Execution", "edb_id": "49757"}]


def tool_call(name, args, call_id):
    return NS(type="tool_use", id=call_id, name=name, input=args)


def text(t):
    return NS(type="text", text=t)


class FakeClient:
    """Plays back a fixed list of model turns and records what it was sent."""

    def __init__(self, turns):
        self.turns = list(turns)
        self.requests = []
        self.messages = NS(create=self._create)

    def _create(self, **kwargs):
        # snapshot the history, the loop keeps appending to the same list
        self.requests.append(dict(kwargs, messages=list(kwargs["messages"])))
        content = self.turns.pop(0)
        stop = "tool_use" if any(b.type == "tool_use" for b in content) else "end_turn"
        return NS(content=content, stop_reason=stop)


class AgentTests(unittest.TestCase):

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)  # logs/ and reports/ land here

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def test_full_react_loop_builds_report(self):
        client = FakeClient([
            [text("Start with a service scan."), tool_call("nmap_scan", {"target": TARGET}, "t1")],
            [text("vsftpd 2.3.4 is a known backdoored version."),
             tool_call("exploit_lookup", {"port": 21, "product": "vsftpd", "version": "2.3.4"}, "t2")],
            [text("### Key findings\n1. vsftpd 2.3.4 backdoor on 21/tcp")],
        ])
        with mock.patch.object(toolmod, "run_nmap", return_value=dict(FAKE_SCAN, ports=[dict(p) for p in FAKE_SCAN["ports"]])), \
             mock.patch.object(toolmod, "search_exploits", return_value=FAKE_EXPLOITS):
            tb, summary = brain.run_agent(TARGET, client=client, model="fake", trace=False)

        self.assertEqual([c[0] for c in tb.calls], ["nmap_scan", "exploit_lookup"])
        self.assertIn("vsftpd 2.3.4 backdoor", summary)
        self.assertEqual(tb.scan["ports"][0]["exploits"], FAKE_EXPLOITS)

        # tool results were fed back to the model with matching ids
        last_user = client.requests[2]["messages"][-1]
        self.assertEqual(last_user["content"][0]["tool_use_id"], "t2")
        self.assertFalse(last_user["content"][0]["is_error"])

        report = open(build_report(tb.scan, analyst_summary=summary)).read()
        self.assertIn("## Analyst summary", report)
        self.assertIn("EDB-49757", report)

    def test_scope_lock_blocks_other_targets(self):
        client = FakeClient([
            [tool_call("nmap_scan", {"target": "10.10.1.200"}, "t1")],
            [text("Out of scope, stopping.")],
        ])
        with mock.patch.object(toolmod, "run_nmap") as fake_nmap:
            tb, _ = brain.run_agent(TARGET, client=client, model="fake", trace=False)
        fake_nmap.assert_not_called()
        result = client.requests[1]["messages"][-1]["content"][0]
        self.assertTrue(result["is_error"])
        self.assertIn("outside this run's scope", result["content"])

    def test_gate_refuses_inside_the_tool(self):
        # Real run_nmap: the gate refuses a public IP before nmap is looked up.
        tb = toolmod.ToolBox("8.8.8.8")
        obs, is_error = tb.call("nmap_scan", {"target": "8.8.8.8"})
        self.assertTrue(is_error)
        self.assertIn("authorization gate", obs)
        self.assertEqual(tb.scan["status"], "refused")

    def test_runner_refuses_before_calling_the_model(self):
        with mock.patch.object(brain, "run_agent") as fake_agent:
            code = main(["reconmind.agent", "10.0.3.15"])  # real home network
        self.assertEqual(code, 2)
        fake_agent.assert_not_called()

    def test_bad_tool_requests_become_observations(self):
        tb = toolmod.ToolBox(TARGET)
        obs, err = tb.call("rm_rf", {})
        self.assertTrue(err)
        obs, err = tb.call("exploit_lookup", {"port": 21, "product": "vsftpd"})
        self.assertTrue(err)
        self.assertIn("nmap_scan first", obs)

    def test_step_limit_stops_a_looping_model(self):
        looping = [[tool_call("exploit_lookup", {"port": 1, "product": "x"}, "t%d" % i)]
                   for i in range(brain.MAX_STEPS)]
        tb, summary = brain.run_agent(TARGET, client=FakeClient(looping), model="fake", trace=False)
        self.assertEqual(len(tb.calls), brain.MAX_STEPS)
        self.assertIn("step limit", summary)


if __name__ == "__main__":
    unittest.main()
