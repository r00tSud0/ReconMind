"""MORVAIN-X0 agent tests. Offline: the model, the tools and the operator are fakes."""
import json
import os
import tempfile
import unittest

from reconmind.agent import morvain
from reconmind.agent.llm import Response, TextBlock
from reconmind.core.pipeline import StopRequested

PORTS = [
    {"port": 21, "service": "ftp", "product": "vsftpd", "version": "2.3.4",
     "exploits": [{"title": "vsftpd 2.3.4 Backdoor"}]},
    {"port": 80, "service": "http", "product": "Apache httpd", "version": "2.2.8"},
    {"port": 445, "service": "netbios-ssn", "product": "Samba smbd", "version": "3.0.20"},
]


class FakeToolBox:
    def __init__(self, target, ports=PORTS, status="ok"):
        self.target = target
        self.plan = None
        self.scan = {"target": target, "status": status, "ports": [dict(p) for p in ports]}
        self.steps = []
        self.calls = []
        self.fail = set()

    def call(self, name, args):
        self.calls.append((name, dict(args)))
        allowed = self.plan is None or self.plan.allows_tool(name) or name == "attack_map"
        if not allowed:
            return json.dumps({"error": "not in plan"}), True
        if name in self.fail:
            return json.dumps({"error": name + " timed out"}), True
        return json.dumps({"ok": True}), False


class FakeRun:
    """Stands in for run_plan: returns the surface toolbox and records the plan."""
    def __init__(self, box):
        self.box, self.plans = box, []

    def __call__(self, target, plan, events=None, mode=None, trace=True):
        self.plans.append(plan)
        self.box.plan = plan
        self.box.steps.append({"action": "surface", "tool": "nmap_scan", "port": None,
                               "status": "done"})
        return self.box


class FakeModel:
    def __init__(self, answers):
        self.answers = list(answers)
        self.requests = []
        self.messages = self

    def create(self, **kw):
        self.requests.append(kw)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return Response(content=[TextBlock(answer)], stop_reason="end_turn")


def plan_json(*actions, message="Plan."):
    return json.dumps({"message": message,
                       "plan": [{"action": a, "why": "Port 80 runs Apache 2.2.8."} for a in actions]})


class Operator:
    """A fake sleep that answers each waiting plan with the next decision."""
    def __init__(self, inbox, decisions):
        self.inbox, self.decisions, self.round = inbox, list(decisions), 0

    def __call__(self, seconds):
        decision = self.decisions.pop(0)
        if isinstance(decision, BaseException):
            raise decision
        with open(self.inbox, "w") as f:
            json.dump(decision, f)


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.inbox = os.path.join(self.tmp.name, "a.agent.json")
        self.events = []
        self.box = FakeToolBox("10.10.1.20")

    def tearDown(self):
        self.tmp.cleanup()

    def session(self, model, decisions):
        return morvain.Session("10.10.1.20", "top", client=model, model="m", inbox=self.inbox,
                               emit=lambda kind, **kw: self.events.append((kind, kw)),
                               trace=False, sleep=Operator(self.inbox, decisions),
                               run=FakeRun(self.box))

    def agent(self, state=None):
        return [kw for kind, kw in self.events if kind == "agent"
                and (state is None or kw.get("state") == state)]

    def test_approve_runs_only_the_ticked_checks_then_finishes(self):
        model = FakeModel([plan_json("web", "smb", "cves"), json.dumps({"message": "", "plan": []})])
        box = self.session(model, [{"round": 1, "decision": "approve", "actions": ["web", "smb"]}]).run()
        tools = [name for name, _ in box.calls]
        self.assertIn("web_fingerprint", tools)
        self.assertIn("smb_enum", tools)
        self.assertNotIn("cve_lookup", tools)
        self.assertNotIn("nmap_scan", tools)  # the surface ran once, through run_plan
        self.assertEqual(box.scan["agent"]["checks"], ["surface", "exploits", "web", "smb"])
        self.assertEqual(sorted(box.plan.actions), sorted(["surface", "exploits", "web", "smb"]))
        awaiting = self.agent("awaiting")[0]
        self.assertEqual([s["action"] for s in awaiting["plan"]], ["web", "smb", "cves"])
        self.assertEqual(self.agent("done")[-1]["state"], "done")

    def test_nothing_runs_before_approval(self):
        model = FakeModel([plan_json("web")])
        self.session(model, [{"round": 1, "decision": "finish"}]).run()
        self.assertEqual(self.box.calls, [])

    def test_model_cannot_add_checks_outside_the_list(self):
        model = FakeModel([json.dumps({"message": "x", "plan": [
            {"action": "surface", "why": "again"}, {"action": "rm -rf", "why": "x"},
            {"action": "web", "why": "ok"}, {"action": "web", "why": "dupe"}]}),
            json.dumps({"plan": []})])
        self.session(model, [{"round": 1, "decision": "approve",
                              "actions": ["web", "paths", "surface"]}]).run()
        awaiting = self.agent("awaiting")[0]
        self.assertEqual([s["action"] for s in awaiting["plan"]], ["web"])
        tools = {name for name, _ in self.box.calls}
        self.assertNotIn("web_discover", tools)  # "paths" was never proposed

    def test_redirect_replans_with_the_operator_text(self):
        model = FakeModel([plan_json("cves", "web"), plan_json("web"), json.dumps({"plan": []})])
        self.session(model, [
            {"round": 1, "decision": "redirect", "message": "Do the web servers first."},
            {"round": 1, "decision": "approve", "actions": ["web"]}]).run()
        second = model.requests[1]["messages"][0]["content"]
        self.assertIn("Do the web servers first.", second)
        self.assertIn("a preference only", second)
        mine = [e for e in self.agent() if e.get("from") == "operator"]
        self.assertEqual(mine[0]["decision"], "redirect")

    def test_questions_are_answered_and_the_plan_stays_open(self):
        model = FakeModel([plan_json("web", "cves"),
                           "Port 21 runs vsftpd 2.3.4 with a public exploit. CVE-1999-0001 too.",
                           json.dumps({"plan": []})])
        self.session(model, [
            {"round": 1, "decision": "ask", "message": "Why is port 21 risky?"},
            {"round": 1, "decision": "approve", "actions": ["web"]}]).run()
        answers = self.agent("answer")
        self.assertEqual(len(answers), 1)
        self.assertIn("vsftpd", answers[0]["text"])
        self.assertIn("[ID removed]", answers[0]["text"])   # never an invented ID
        ask = model.requests[1]
        self.assertIn("only answer questions about this scan", ask["system"])
        self.assertIn("Why is port 21 risky?", ask["messages"][0]["content"])
        self.assertIn("web_fingerprint", [n for n, _ in self.box.calls])  # the approval still ran
        self.assertEqual(len(self.agent("awaiting")), 1)                   # no new plan for a question
        mine = [e for e in self.agent() if e.get("from") == "operator"]
        self.assertEqual([e["decision"] for e in mine], ["ask", "approve"])

    def test_tell_me_more_without_a_model_uses_the_check_description(self):
        model = FakeModel([plan_json("web"), RuntimeError("model down"), json.dumps({"plan": []})])
        self.session(model, [
            {"round": 1, "decision": "ask", "message": "", "actions": ["web"]},
            {"round": 1, "decision": "finish"}]).run()
        text = self.agent("answer")[0]["text"]
        self.assertIn("httpx", text)
        self.assertIn("Port 80 runs Apache", text)
        self.assertEqual(self.box.calls, [])  # asking never runs anything

    def test_question_limit_per_checkpoint(self):
        model = FakeModel([plan_json("web")] + ["Answer."] * morvain.MAX_ASKS)
        asks = [{"round": 1, "decision": "ask", "message": "q"}] * (morvain.MAX_ASKS + 1)
        self.session(model, asks + [{"round": 1, "decision": "finish"}]).run()
        answers = self.agent("answer")
        self.assertEqual(len(answers), morvain.MAX_ASKS + 1)
        self.assertIn("the limit", answers[-1]["text"])

    def test_every_plan_comes_with_a_brief(self):
        model = FakeModel([plan_json("web")])
        self.session(model, [{"round": 1, "decision": "finish"}]).run()
        items = self.agent("awaiting")[0]["brief"]["items"]
        self.assertTrue(items)
        self.assertIn("Port 21", items[0]["text"])
        self.assertIn("exploit match", items[0]["text"])

    def test_brief_orders_by_severity(self):
        scan = {"ports": [
            {"port": 23, "service": "telnet", "product": "Linux telnetd"},
            {"port": 1524, "service": "bindshell", "product": "Metasploitable root shell"},
            {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "4.7p1"}]}
        b = morvain.brief(scan)
        self.assertEqual([i["severity"] for i in b["items"]], ["critical", "high"])
        self.assertEqual(b["more"], 0)
        self.assertEqual(morvain.brief({"ports": []}), {"items": [], "more": 0})

    def test_model_failure_falls_back_to_rules_and_says_so(self):
        model = FakeModel([RuntimeError("rate limited"), RuntimeError("down")])
        self.session(model, [{"round": 1, "decision": "finish"}]).run()
        errors = self.agent("error")
        self.assertIn("fixed rules", errors[0]["text"])
        awaiting = self.agent("awaiting")[0]
        self.assertEqual(awaiting["source"], "rules")
        self.assertIn("smb", [s["action"] for s in awaiting["plan"]])

    def test_failed_step_is_reported_and_can_be_retried(self):
        self.box.fail.add("smb_enum")
        model = FakeModel([plan_json("smb"), plan_json("smb", message="Retry it."),
                           json.dumps({"plan": []})])
        self.session(model, [{"round": 1, "decision": "approve", "actions": ["smb"]},
                             {"round": 2, "decision": "approve", "actions": ["smb"]}]).run()
        self.assertIn("failed", self.agent("error")[0]["text"])
        facts = json.loads(model.requests[1]["messages"][0]["content"].split("\n", 1)[1])
        self.assertEqual(facts["failed_steps"][0]["tool"], "smb_enum")
        self.assertEqual([n for n, _ in self.box.calls].count("smb_enum"), 2)

    def test_stop_while_waiting_is_not_swallowed(self):
        model = FakeModel([plan_json("web")])
        with self.assertRaises(StopRequested):
            self.session(model, [StopRequested()]).run()

    def test_surface_failure_ends_without_planning(self):
        self.box.scan["status"] = "error"
        model = FakeModel([])
        box = self.session(model, []).run()
        self.assertEqual(model.requests, [])
        self.assertIn("did not complete", self.agent("error")[0]["text"])
        self.assertIn("agent", box.scan)

    def test_unapproved_everything_means_finish(self):
        model = FakeModel([plan_json("web")])
        self.session(model, [{"round": 1, "decision": "approve", "actions": []}]).run()
        self.assertEqual(self.box.calls, [])


class HelperTests(unittest.TestCase):
    def test_rule_plan_from_ports(self):
        scan = {"ports": PORTS + [{"port": 443, "service": "https", "tunnel": "ssl"}]}
        actions = [s["action"] for s in morvain.rule_plan(scan, set(morvain.SURFACE_ACTIONS))]
        for a in ("web", "paths", "vulns", "smb", "cves"):
            self.assertIn(a, actions)
        self.assertEqual(morvain.rule_plan({"ports": []}, set()), [])

    def test_scrub_ids_keeps_only_tool_ids(self):
        scan = {"nvd": {"cves": ["CVE-2011-2523"]}}
        text = morvain.scrub_ids("CVE-2011-2523 and CVE-2099-0001 and T1190", scan)
        self.assertIn("CVE-2011-2523", text)
        self.assertNotIn("CVE-2099-0001", text)
        self.assertNotIn("T1190", text)

    def test_parse_plan_needs_json(self):
        with self.assertRaises(morvain.AgentError):
            morvain.parse_plan("I think you should scan everything.", ["web"])
        message, steps = morvain.parse_plan('Sure: {"message": "m", "plan": '
                                            '[{"action": "WEB", "why": "  a\\n b "}]}', ["web"])
        self.assertEqual(steps, [{"action": "web", "why": "a b"}])

    def test_old_or_broken_decisions_are_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.json")
            for content in ('{"round": 1, "decision": "approve"}', "not json",
                            '{"round": 2, "decision": "launch"}'):
                with open(path, "w") as f:
                    f.write(content)
                self.assertIsNone(morvain.read_decision(path, 2))
                self.assertFalse(os.path.exists(path))

    def test_lab_network(self):
        self.assertEqual(morvain.lab_network("10.10.1.20"), "10.10.1.0/24")
        self.assertIsNone(morvain.lab_network("8.8.8.8"))


if __name__ == "__main__":
    unittest.main()
