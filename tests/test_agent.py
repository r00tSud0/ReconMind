"""
Offline tests for the ReconMind agent brain.

A scripted fake LLM drives the real ReAct loop, so these run with no API key,
no network, no nmap and no searchsploit:

    python3 -m unittest discover -s tests -v
"""

import contextlib
from functools import partial
import io
import os
import tempfile
import unittest
from types import SimpleNamespace as NS
from unittest import mock

from reconmind.agent import brain, llm, tools as toolmod
from reconmind.agent import __main__ as runner
from reconmind.agent.__main__ import main
from reconmind.core.attack_check import check_attack
from reconmind.core.report import build_report

TARGET = "10.10.1.100"
ATTACK_FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "fixtures", "attack_techniques.json")

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


VALID_SUMMARY = (
    "### Key findings\n1. vsftpd 2.3.4 backdoor on 21/tcp (EDB-49757), confirmed. "
    "See also EDB-99999 and CVE-2007-2447.\n"
    "### Likely attack path\nBackdoor shell on 21/tcp.\n"
    "### MITRE ATT&CK (preliminary)\nT1190 Exploit Public-Facing Application\n"
    "### Recommended fixes\nUpgrade vsftpd.\nEND OF SUMMARY\n")
class RateLimitError(Exception):
    status_code = 429


THINKING_TRUNCATED = ("Let me think about this. Port 21 looks bad.\n"
                      "### Key findings\n- vsftpd backdoor\n### Likely attack")


class SummaryValidationRunnerTests(unittest.TestCase):
    """main() validates the model's summary and repairs it at most once."""

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def run_main(self, draft, repair_turns, target=TARGET, client=None, attack_path=None):
        client = client or FakeClient(repair_turns)
        tb = toolmod.ToolBox(TARGET)
        tb.scan = dict(FAKE_SCAN, ports=[dict(FAKE_SCAN["ports"][0], exploits=FAKE_EXPLOITS),
                                         dict(FAKE_SCAN["ports"][1], exploits=[])])
        config = llm.ProviderConfig("anthropic", "anthropic", None, "ANTHROPIC_API_KEY",
                                    "k", "fake-model")
        out = io.StringIO()
        with mock.patch.object(llm, "load_config", return_value=config) as load, \
             mock.patch.object(llm, "make_client", return_value=client) as make, \
             mock.patch.object(brain, "run_agent", return_value=(tb, draft)) as agent, \
             mock.patch.object(runner, "check_attack", partial(
                 check_attack, path=attack_path or ATTACK_FIXTURE)), \
             mock.patch.object(llm.time, "sleep") as self.sleep, \
             contextlib.redirect_stdout(out):
            code = main(["reconmind.agent", target])
        report = ""
        if os.path.isdir("reports"):
            name = sorted(os.listdir("reports"))[-1]
            with open(os.path.join("reports", name)) as fh:
                report = fh.read()
        return code, client, report, out.getvalue(), (load, make, agent)

    def test_thinking_then_truncated_draft_is_repaired_once(self):
        code, client, report, out, _ = self.run_main(THINKING_TRUNCATED, [[text(VALID_SUMMARY)]])
        self.assertEqual(code, 0)
        self.assertEqual(len(client.requests), 1)
        repair = client.requests[0]
        self.assertNotIn("tools", repair)
        self.assertEqual(repair["model"], "fake-model")
        self.assertIn("49757", repair["messages"][0]["content"])  # scan facts were sent
        self.assertIn("AI interpretation. The tables below are the verified tool results.",
                      report)
        self.assertIn("Upgrade vsftpd.", report)
        self.assertNotIn("Let me think", report)
        refs = report.split("**Unverified references**", 1)[1].split("## Open ports", 1)[0]
        self.assertIn("- EDB-99999", refs)
        self.assertIn("- CVE-2007-2447", refs)
        self.assertNotIn("EDB-49757", refs)
        self.assertIn("repaired", out)

    def test_two_failures_publish_no_model_text(self):
        code, client, report, out, _ = self.run_main(
            THINKING_TRUNCATED, [[text("Sorry, here is my thinking again.\n### Key findings\nx")]])
        self.assertEqual(code, 0)
        self.assertEqual(len(client.requests), 1)
        self.assertIn("Analyst summary unavailable: the model output failed validation.", report)
        self.assertNotIn("Let me think", report)
        self.assertNotIn("vsftpd backdoor", report)
        self.assertNotIn("Sorry", report)
        self.assertNotIn("AI interpretation", report)
        self.assertIn("## Open ports", report)
        self.assertIn("EDB-49757", report)  # fact sections still render

    def test_repair_call_error_publishes_no_model_text(self):
        code, client, report, _, _ = self.run_main(THINKING_TRUNCATED, [])  # no turns: raises
        self.assertEqual(code, 0)
        self.assertIn("Analyst summary unavailable", report)

    def test_valid_summary_needs_no_repair(self):
        code, client, report, _, _ = self.run_main("Preamble.\n" + VALID_SUMMARY, [])
        self.assertEqual(code, 0)
        self.assertEqual(client.requests, [])
        self.assertIn("Upgrade vsftpd.", report)
        self.assertNotIn("Preamble.", report)

    def test_attack_check_table_in_report(self):
        draft = VALID_SUMMARY.replace("T1190 Exploit Public-Facing Application",
                                      "T1190 Exploit Public-Facing Application\n"
                                      "T1021.004 Pass the Hash")
        code, _, report, out, _ = self.run_main(draft, [])
        self.assertEqual(code, 0)
        self.assertIn("| T1190 | Exploit Public-Facing Application | "
                      "Exploit Public-Facing Application | verified |", report)
        self.assertIn("| T1021.004 | Pass the Hash | Remote Services: SSH | name_mismatch |",
                      report)
        self.assertIn("attack:      1 verified, 1 flagged", out)

    def test_attack_check_skipped_without_data_file(self):
        code, _, report, out, _ = self.run_main(VALID_SUMMARY, [],
                                                attack_path=os.path.join("nope", "x.json"))
        self.assertEqual(code, 0)
        self.assertIn("ATT&CK check skipped: MITRE data file missing", report)
        self.assertIn("ATT&CK check skipped: MITRE data file missing", out)

    def test_end_marker_is_not_published(self):
        _, _, report, _, _ = self.run_main(VALID_SUMMARY, [])
        self.assertNotIn("END OF SUMMARY", report)

    def test_repair_rate_limited_still_writes_fact_report(self):
        def rate_limited(**_):
            raise RateLimitError()
        client = llm.AnthropicClient(NS(messages=NS(create=rate_limited)))
        code, _, report, out, _ = self.run_main(THINKING_TRUNCATED, [], client=client)
        self.assertEqual(code, 1)
        self.sleep.assert_called_once_with(20)
        self.assertIn("Analyst summary unavailable: the model was busy (rate limited).", report)
        self.assertNotIn("failed validation", report)
        self.assertNotIn("vsftpd backdoor", report)  # the bad draft is never published
        self.assertIn("## Open ports", report)
        self.assertIn("## Known exploits (Exploit-DB)", report)
        self.assertIn("EDB-49757", report)
        self.assertIn("## Notes", report)
        self.assertIn("Model busy (rate limited). Try again in a minute or use --model "
                      "with another model.", out)
        self.assertNotIn("Traceback", out)

    def test_gate_runs_before_config_client_or_model(self):
        code, client, report, _, (load, make, agent) = self.run_main(
            VALID_SUMMARY, [], target="10.0.3.15")
        self.assertEqual(code, 2)
        load.assert_not_called()
        make.assert_not_called()
        agent.assert_not_called()
        self.assertEqual(client.requests, [])


if __name__ == "__main__":
    unittest.main()
