"""
Offline tests for the standard pipeline (reconmind/core/pipeline.py): the
fixed order, web tools only on web ports, tls_check only on TLS capable
ports, smb_enum only when 139 or 445 is open, cve_lookup after the web steps,
attack_map always last, actions outside the plan never running, a tool error
not stopping the run, a failed or refused nmap stopping after nmap, and a
StopRequested mid run giving a stopped partial scan. One test runs the real
ToolBox with every runner replaced by a fake.

No tool, model or network is used.

    python3 -m unittest discover -s tests -v
"""

import contextlib
import copy
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from reconmind.agent import tools as toolmod
from reconmind.ai import attack_mapper
from reconmind.core import history, pipeline
from reconmind.core.pipeline import StopRequested, run_plan
from reconmind.core.scan_plan import build_plan

TARGET = "10.10.1.100"

FTP = {"port": 21, "protocol": "tcp", "service": "ftp", "product": "vsftpd", "version": "2.3.4"}
SSH = {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "4.7p1"}
HTTP = {"port": 80, "protocol": "tcp", "service": "http", "product": "Apache httpd",
        "version": "2.2.8"}
HTTPS = {"port": 443, "protocol": "tcp", "service": "https", "product": "Apache httpd",
         "version": "2.2.8"}
SMB = {"port": 445, "protocol": "tcp", "service": "netbios-ssn", "product": "Samba smbd",
       "version": "3.X"}

ALL_PORTS = (FTP, SSH, HTTP, HTTPS, SMB)

FULL_ORDER = [
    ("nmap_scan", None),
    ("web_fingerprint", 80), ("web_fingerprint", 443),
    ("web_discover", 80), ("web_discover", 443),
    ("vuln_templates", 80), ("vuln_templates", 443),
    ("tls_check", 21), ("tls_check", 443),
    ("smb_enum", None),
    ("cve_lookup", None),
    ("attack_map", None),
]


def nmap_result(*ports, status="ok"):
    result = {"target": TARGET, "status": status, "ports": [dict(p) for p in ports]}
    if status == "ok":
        result["scan_info"] = {"commands": ["nmap -sV -oX /tmp/x.xml " + TARGET]}
    return result


class FakeToolBox:
    """
    Stands in for ToolBox: records every call, sets the nmap result, fails
    the tools in errors and raises StopRequested at stop_at (tool, port).
    """

    def __init__(self, result, errors=(), stop_at=None):
        self.scan = {"target": TARGET, "status": "not-run", "ports": []}
        self.result = result
        self.errors = set(errors)
        self.stop_at = stop_at
        self.calls = []

    def call(self, name, args):
        self.calls.append((name, dict(args or {})))
        port = (args or {}).get("port")
        if self.stop_at == (name, port):
            raise StopRequested()
        if name == "nmap_scan":
            self.scan = copy.deepcopy(self.result)
            if self.scan["status"] != "ok":
                return json.dumps({"error": "Scan did not run"}), True
        if name in self.errors:
            return json.dumps({"error": "{n} broke".format(n=name)}), True
        if name == "attack_map":
            self.scan["attack_map"] = {"status": "ok", "ports": []}
        return "{}", False

    def order(self):
        return [(name, args.get("port")) for name, args in self.calls]


class Recorder:
    """Records events instead of writing them."""

    def __init__(self):
        self.events = []

    def __call__(self, kind, **data):
        self.events.append(dict(data, kind=kind))

    def of(self, kind, **match):
        return [e for e in self.events if e["kind"] == kind
                and all(e.get(k) == v for k, v in match.items())]


def run(plan, toolbox):
    events = Recorder()
    with contextlib.redirect_stdout(io.StringIO()):
        result = run_plan(TARGET, plan, toolbox=toolbox, events=events, mode="standard")
    return result, events


class OrderTests(unittest.TestCase):

    def test_fixed_order_with_every_action(self):
        tb = FakeToolBox(nmap_result(*ALL_PORTS))
        result, events = run(build_plan(TARGET, "standard"), tb)
        self.assertIs(result, tb)
        self.assertEqual(tb.order(), FULL_ORDER)
        self.assertEqual(tb.calls[0], ("nmap_scan", {"target": TARGET}))
        self.assertEqual([s["status"] for s in tb.steps], ["done"] * len(FULL_ORDER))

    def test_web_tools_only_on_web_ports(self):
        tb = FakeToolBox(nmap_result(*ALL_PORTS))
        run(build_plan(TARGET, actions="web,paths,vulns"), tb)
        web_calls = [(n, p) for n, p in tb.order()
                     if n in ("web_fingerprint", "web_discover", "vuln_templates")]
        self.assertEqual({p for _, p in web_calls}, {80, 443})
        self.assertEqual(len(web_calls), 6)

    def test_tls_only_on_tls_capable_ports(self):
        tb = FakeToolBox(nmap_result(*ALL_PORTS))
        run(build_plan(TARGET, actions="crypto"), tb)
        self.assertEqual([p for n, p in tb.order() if n == "tls_check"], [21, 443])
        self.assertNotIn(("tls_check", 22), tb.order())
        self.assertNotIn(("tls_check", 80), tb.order())

    def test_smb_only_when_139_or_445_is_open(self):
        tb = FakeToolBox(nmap_result(FTP, HTTP))
        _, events = run(build_plan(TARGET, actions="smb"), tb)
        self.assertNotIn("smb_enum", [n for n, _ in tb.order()])
        skipped = events.of("step", tool="smb_enum", status="skipped")
        self.assertEqual(skipped[0]["reason"], pipeline.NO_SMB_PORT)

        tb = FakeToolBox(nmap_result(FTP, dict(SMB, port=139)))
        run(build_plan(TARGET, actions="smb"), tb)
        self.assertIn(("smb_enum", None), tb.order())

    def test_cve_lookup_after_the_web_steps(self):
        tb = FakeToolBox(nmap_result(*ALL_PORTS))
        run(build_plan(TARGET, actions="cves,web,paths,vulns"), tb)
        order = [n for n, _ in tb.order()]
        last_web = max(i for i, n in enumerate(order)
                       if n in ("web_fingerprint", "web_discover", "vuln_templates"))
        self.assertGreater(order.index("cve_lookup"), last_web)

    def test_attack_map_always_last(self):
        for actions in ("", "web", "exploits,cves", "smb,crypto",
                        "exploits,cves,web,paths,vulns,crypto,smb"):
            with self.subTest(actions=actions):
                tb = FakeToolBox(nmap_result(*ALL_PORTS))
                run(build_plan(TARGET, actions=actions), tb)
                self.assertEqual(tb.order()[-1], ("attack_map", None))
                self.assertEqual([n for n, _ in tb.order()].count("attack_map"), 1)

    def test_actions_not_in_the_plan_never_run(self):
        tb = FakeToolBox(nmap_result(*ALL_PORTS))
        _, events = run(build_plan(TARGET, actions="exploits"), tb)
        self.assertEqual(tb.order(), [("nmap_scan", None), ("attack_map", None)])
        # Unselected actions are not even reported as skipped.
        self.assertEqual(events.of("step", status="skipped"), [])

    def test_no_web_port_is_skipped_with_a_reason(self):
        tb = FakeToolBox(nmap_result(SSH))
        _, events = run(build_plan(TARGET, actions="web"), tb)
        self.assertEqual(tb.order(), [("nmap_scan", None), ("attack_map", None)])
        skipped = events.of("step", tool="web_fingerprint", status="skipped")
        self.assertEqual(skipped[0]["reason"], pipeline.NO_WEB_PORT)

    def test_ports_come_from_nmap_only(self):
        # The plan asks for 8080, but nmap found only 80 open.
        tb = FakeToolBox(nmap_result(HTTP))
        run(build_plan(TARGET, ports="80,8080", actions="web"), tb)
        self.assertEqual([p for n, p in tb.order() if n == "web_fingerprint"], [80])


class ErrorTests(unittest.TestCase):

    def test_tool_error_does_not_stop_the_pipeline(self):
        tb = FakeToolBox(nmap_result(*ALL_PORTS), errors=("web_fingerprint", "smb_enum"))
        _, events = run(build_plan(TARGET, "standard"), tb)
        self.assertEqual(tb.order(), FULL_ORDER)
        errors = [s for s in tb.steps if s["status"] == "error"]
        self.assertEqual([(s["tool"], s["port"]) for s in errors],
                         [("web_fingerprint", 80), ("web_fingerprint", 443),
                          ("smb_enum", None)])
        self.assertEqual(errors[0]["message"], "web_fingerprint broke")
        self.assertEqual(len(events.of("step", status="error")), 3)

    def test_nmap_failure_stops_after_nmap(self):
        for status in ("refused", "nmap-not-found", "error"):
            with self.subTest(status=status):
                tb = FakeToolBox(nmap_result(*ALL_PORTS, status=status))
                _, events = run(build_plan(TARGET, "standard"), tb)
                self.assertEqual(tb.order(), [("nmap_scan", None)])
                self.assertEqual(tb.scan["status"], status)
                self.assertEqual(events.of("ports"), [])
                skipped = events.of("step", status="skipped")
                self.assertIn("attack_map", [e["tool"] for e in skipped])
                self.assertIn("status " + status, skipped[0]["reason"])


class StopTests(unittest.TestCase):

    def test_stop_mid_run_gives_a_stopped_partial_scan(self):
        tb = FakeToolBox(nmap_result(*ALL_PORTS), stop_at=("web_discover", 443))
        _, events = run(build_plan(TARGET, "standard"), tb)
        scan = tb.scan
        self.assertEqual(scan["status"], "stopped")
        self.assertEqual(scan["stop"]["finished"],
                         ["nmap_scan", "web_fingerprint port 80", "web_fingerprint port 443",
                          "web_discover port 80"])
        self.assertEqual(scan["stop"]["not_run"],
                         ["web_discover port 443 (stopped while running)",
                          "vuln_templates port 80", "vuln_templates port 443",
                          "tls_check port 21", "tls_check port 443", "smb_enum",
                          "cve_lookup", "attack_map"])
        # Nothing ran after the stop.
        self.assertEqual(tb.order()[-1], ("web_discover", 443))
        self.assertEqual(len(events.of("stopped")), 1)

    def test_stop_during_nmap(self):
        tb = FakeToolBox(nmap_result(*ALL_PORTS), stop_at=("nmap_scan", None))
        run(build_plan(TARGET, actions="web,smb"), tb)
        self.assertEqual(tb.scan["status"], "stopped")
        self.assertEqual(tb.scan["stop"]["finished"], [])
        self.assertEqual(tb.scan["stop"]["not_run"][0], "nmap_scan (stopped while running)")
        self.assertIn("smb_enum (needed the nmap results)", tb.scan["stop"]["not_run"])
        self.assertIn("attack_map (needed the nmap results)", tb.scan["stop"]["not_run"])

    def test_stop_requested_is_not_an_exception(self):
        # ToolBox.call catches Exception, so a stop must not be one.
        self.assertFalse(issubclass(StopRequested, Exception))
        self.assertTrue(issubclass(StopRequested, BaseException))

    def test_real_toolbox_lets_the_stop_through(self):
        tb = toolmod.ToolBox(TARGET, plan=build_plan(TARGET, actions="web"))
        with mock.patch.object(toolmod, "run_nmap", side_effect=StopRequested()):
            with self.assertRaises(StopRequested):
                tb.call("nmap_scan", {"target": TARGET})

    def test_stopped_partial_report_and_index(self):
        tb = FakeToolBox(nmap_result(*ALL_PORTS), stop_at=("tls_check", 21))
        plan = build_plan(TARGET, "standard")
        run(plan, tb)
        with tempfile.TemporaryDirectory() as report_dir:
            record = history.save_run(tb.scan, plan=plan, report_dir=report_dir,
                                      mode="standard")
            with open(record.report_path) as fh:
                report = fh.read()
            entry = history.read_index(report_dir)[-1]
        self.assertTrue(report.startswith("# ReconMind Report\n\n**Stopped.**"))
        self.assertIn("- Finished: nmap_scan, web_fingerprint port 80", report)
        self.assertIn("- Did not run: tls_check port 21 (stopped while running), "
                      "tls_check port 443, smb_enum, cve_lookup, attack_map", report)
        self.assertIn("**Scan status:** stopped", report)
        self.assertIn("| surface | Surface Map | Ran |", report)
        self.assertIn("## Open ports", report)
        self.assertTrue(entry["stopped"])
        self.assertEqual(entry["status"], "stopped")
        self.assertEqual(entry["mode"], "standard")


class EventTests(unittest.TestCase):

    def test_plan_ports_and_step_events(self):
        tb = FakeToolBox(nmap_result(HTTP, SSH))
        _, events = run(build_plan(TARGET, actions="web"), tb)
        plan_event = events.of("plan")[0]
        self.assertEqual((plan_event["preset"], plan_event["ports"], plan_event["actions"],
                          plan_event["mode"]),
                         ("standard", "top", ["surface", "web"], "standard"))
        self.assertEqual(events.of("ports")[0]["ports"],
                         [{"port": 80, "service": "http", "product": "Apache httpd",
                           "version": "2.2.8"},
                          {"port": 22, "service": "ssh", "product": "OpenSSH",
                           "version": "4.7p1"}])
        starts = events.of("step", status="start")
        self.assertEqual([(e["action"], e["tool"], e["port"]) for e in starts],
                         [("surface", "nmap_scan", None), ("web", "web_fingerprint", 80),
                          ("attack_map", "attack_map", None)])
        self.assertEqual(events.of("command", tool="nmap_scan")[0]["command"],
                         "nmap -sV -oX /tmp/x.xml " + TARGET)


class RealToolBoxTests(unittest.TestCase):
    """The pipeline through the real ToolBox, every runner replaced by a fake."""

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)  # logs/ lands here
        no_model = os.path.join(self._tmp.name, "no_model")
        os.makedirs(no_model)
        self._env = mock.patch.dict(os.environ, {attack_mapper.DIR_ENV: no_model})
        self._env.start()
        attack_mapper.clear_cache()

    def tearDown(self):
        attack_mapper.clear_cache()
        self._env.stop()
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def test_every_tool_goes_through_toolbox_call(self):
        def web_result(name):
            def fake(target, port, **kwargs):
                return {"status": "ok", "url": "http://{t}:{p}".format(t=target, p=port),
                        "command": "{n} {t}:{p}".format(n=name, t=target, p=port)}
            return fake

        patches = [
            mock.patch.object(toolmod, "run_nmap", return_value=nmap_result(FTP, HTTP, SMB)),
            mock.patch.object(toolmod, "search_exploits", return_value=[]),
            mock.patch.object(toolmod, "run_httpx", side_effect=web_result("httpx")),
            mock.patch.object(toolmod, "run_ffuf", side_effect=web_result("ffuf")),
            mock.patch.object(toolmod, "run_nuclei", side_effect=web_result("nuclei")),
            mock.patch.object(toolmod, "run_testssl", side_effect=web_result("testssl")),
            mock.patch.object(toolmod, "run_enum4linux",
                              return_value={"status": "ok", "command": "enum4linux-ng -A x"}),
            mock.patch.object(toolmod.nvd_lookup, "run_cve_lookup",
                              return_value={"status": "ok", "products": [], "skipped": []}),
            mock.patch.object(attack_mapper, "load",
                              return_value=attack_mapper.Predictor("not-installed", "x")),
        ]
        plan = build_plan(TARGET, "standard")
        events = Recorder()
        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            tb = run_plan(TARGET, plan, events=events)
        self.assertIsInstance(tb, toolmod.ToolBox)
        self.assertEqual([c[0] for c in tb.calls],
                         ["nmap_scan", "web_fingerprint", "web_discover", "vuln_templates",
                          "tls_check", "smb_enum", "cve_lookup", "attack_map"])
        self.assertEqual([s["status"] for s in tb.steps], ["done"] * 8)
        self.assertIn(80, tb.scan["web"])
        self.assertIn("attack_map", tb.scan)
        commands = [e["command"] for e in events.of("command")]
        self.assertIn("httpx {t}:80".format(t=TARGET), commands)
        self.assertIn("testssl {t}:21".format(t=TARGET), commands)
        self.assertIn("enum4linux-ng -A x", commands)

    def test_gate_still_refuses_inside_the_tool(self):
        # Real run_nmap: the gate refuses an address outside the allowlist.
        outside = "8.8.8.8"
        plan = build_plan(outside, "standard")
        with contextlib.redirect_stdout(io.StringIO()):
            tb = run_plan(outside, plan, events=Recorder())
        self.assertEqual(tb.scan["status"], "refused")
        self.assertEqual([c[0] for c in tb.calls], ["nmap_scan"])


if __name__ == "__main__":
    unittest.main()
