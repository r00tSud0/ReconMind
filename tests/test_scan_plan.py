"""
Offline tests for scan plans and the report history: ports spec validation
(including injection attempts), presets and overrides, the nmap -p command,
the nuclei auto and deep commands, ToolBox refusing tools outside the plan,
filtered specs and the plan's system prompt reaching the model through
brain.run_agent, brain's unchanged defaults, the CLI options, the report's
Scan plan section, and the history folder, scan.json, evidence.json and
index.json. Nothing here runs nmap, nuclei or any other tool, and no model
or network is used.

    python3 -m unittest discover -s tests -v
"""

import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime
from types import SimpleNamespace as NS
from unittest import mock

from reconmind.agent import brain, llm, tools as toolmod
from reconmind.agent import __main__ as runner
from reconmind.agent.prompts import FORMAT_RULES, SYSTEM_PROMPT, build_system_prompt
from reconmind.core import history
from reconmind.core.report import build_report
from reconmind.core.scan_plan import (
    ACTION_IDS, PlanError, PortsSpecError, ScanPlan, build_plan, parse_ports, port_count)
from reconmind.tools import nmap_scan, nuclei_scan

TARGET = "10.10.1.100"

FTP_PORT = {"port": 21, "protocol": "tcp", "service": "ftp", "product": "vsftpd",
            "version": "2.3.4", "cpe": ["cpe:/a:beasts:vsftpd:2.3.4"]}
TELNET_PORT = {"port": 23, "protocol": "tcp", "service": "telnet", "product": "Linux telnetd",
               "version": ""}
HTTP_PORT = {"port": 80, "protocol": "tcp", "service": "http", "product": "Apache httpd",
             "version": "2.2.8"}
HTTPS_PORT = {"port": 443, "protocol": "tcp", "service": "https", "product": "Apache httpd",
              "version": "2.2.8"}
FAKE_EXPLOITS = [{"title": "vsftpd 2.3.4 - Backdoor Command Execution", "edb_id": "49757"}]

VALID_SUMMARY = (
    "### Key findings\n1. vsftpd 2.3.4 backdoor on 21/tcp (EDB-49757), confirmed.\n"
    "### Likely attack path\nBackdoor shell on 21/tcp.\n"
    "### MITRE ATT&CK (preliminary)\nT1190 Exploit Public-Facing Application\n"
    "### Recommended fixes\nUpgrade vsftpd.\nEND OF SUMMARY\n")


def scan_with(*ports, **extra):
    return dict({"target": TARGET, "status": "ok", "ports": [dict(p) for p in ports]}, **extra)


class InTempDir(unittest.TestCase):
    """reports/ lands in a fresh temp folder for every test."""

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()


# ---- ports spec ----------------------------------------------------------

class PortsSpecTests(unittest.TestCase):

    def test_keywords(self):
        self.assertEqual(parse_ports("top"), "top")
        self.assertEqual(parse_ports("all"), "all")
        self.assertEqual(parse_ports(" TOP "), "top")

    def test_lists_and_ranges(self):
        self.assertEqual(parse_ports("21,22,80,8000-8100"), "21,22,80,8000-8100")
        self.assertEqual(parse_ports("80"), "80")
        self.assertEqual(parse_ports("1-65535"), "1-65535")
        self.assertEqual(parse_ports("080,0443"), "80,443")  # rebuilt from integers
        self.assertEqual(parse_ports("22-22"), "22-22")

    def test_port_count(self):
        self.assertEqual(port_count("21,22,8000-8100"), 103)
        self.assertIsNone(port_count("top"))
        self.assertIsNone(port_count("all"))

    def test_injection_attempts_are_rejected(self):
        for spec in ("80;rm", "80;rm -rf /", "-oN", "-oN /tmp/x", "-p-", "-iL /etc/passwd",
                     "80 81", "80|id", "80&&id", "$(id)", "`id`", "80\nid", "80,-sC",
                     "--script=vuln", "22,80 -oX x", "٨٠", "8 0"):
            with self.subTest(spec=spec):
                with self.assertRaises(PortsSpecError):
                    parse_ports(spec)

    def test_malformed_lists_are_rejected(self):
        for spec in ("", "   ", "80,", ",80", "80,,81", "1-2-3", "80-", "-80", "a",
                     "80.0", "top,80", "all-ports"):
            with self.subTest(spec=spec):
                with self.assertRaises(PortsSpecError):
                    parse_ports(spec)

    def test_range_limits(self):
        for spec in ("0", "65536", "1-65536", "0-80", "99999999999999999999"):
            with self.subTest(spec=spec):
                with self.assertRaises(PortsSpecError) as ctx:
                    parse_ports(spec)
                self.assertIn("1 to 65535", str(ctx.exception))

    def test_start_above_end(self):
        with self.assertRaises(PortsSpecError) as ctx:
            parse_ports("100-90")
        self.assertIn("starts above", str(ctx.exception))

    def test_at_most_100_entries(self):
        parse_ports(",".join(str(p) for p in range(1, 101)))
        with self.assertRaises(PortsSpecError) as ctx:
            parse_ports(",".join(str(p) for p in range(1, 102)))
        self.assertIn("at most 100", str(ctx.exception))

    def test_not_text(self):
        for spec in (None, 80, ["80"]):
            with self.assertRaises(PortsSpecError):
                parse_ports(spec)

    def test_message_is_clear_and_has_no_dash_separators(self):
        with self.assertRaises(PortsSpecError) as ctx:
            parse_ports("80;rm")
        message = str(ctx.exception)
        self.assertIn("is not valid", message)
        self.assertIn("21,22,80,8000-8100", message)
        self.assertNotIn("—", message)
        self.assertNotIn(" - ", message)


# ---- presets and overrides -----------------------------------------------

class PresetTests(unittest.TestCase):

    def test_quick(self):
        plan = build_plan(TARGET, "quick")
        self.assertEqual(plan.actions, ("surface", "exploits", "cves"))
        self.assertEqual(plan.ports, "top")
        self.assertFalse(plan.customized)

    def test_standard_is_the_default(self):
        plan = build_plan(TARGET)
        self.assertEqual(plan.preset, "standard")
        self.assertEqual(plan.actions, ACTION_IDS)
        self.assertEqual(plan.ports, "top")
        self.assertEqual(plan.vuln_mode, "auto")
        self.assertEqual(ScanPlan(TARGET), plan)

    def test_full(self):
        plan = build_plan(TARGET, "full")
        self.assertEqual(plan.actions, ACTION_IDS)
        self.assertEqual(plan.ports, "all")
        self.assertEqual(plan.vuln_mode, "deep")

    def test_every_action(self):
        self.assertEqual(ACTION_IDS, ("surface", "exploits", "cves", "web", "paths", "vulns",
                                      "crypto", "smb"))

    def test_unknown_preset(self):
        with self.assertRaises(PlanError):
            build_plan(TARGET, "everything")

    def test_tools_per_action(self):
        plan = build_plan(TARGET, "full")
        self.assertEqual(plan.tools, ["nmap_scan", "exploit_lookup", "cve_lookup",
                                      "web_fingerprint", "web_discover", "vuln_templates",
                                      "tls_check", "smb_enum"])


class OverrideTests(unittest.TestCase):

    def test_actions_override_keeps_surface(self):
        self.assertEqual(build_plan(TARGET, actions=["web"]).actions, ("surface", "web"))
        self.assertEqual(build_plan(TARGET, actions="smb,web").actions,
                         ("surface", "web", "smb"))  # ACTIONS order
        self.assertEqual(build_plan(TARGET, actions="").actions, ("surface",))
        self.assertEqual(build_plan(TARGET, actions=[]).actions, ("surface",))

    def test_surface_cannot_be_removed(self):
        plan = build_plan(TARGET, "quick", actions="cves")
        self.assertTrue(plan.has("surface"))

    def test_unknown_action(self):
        with self.assertRaises(PlanError) as ctx:
            build_plan(TARGET, actions="web,pwn")
        self.assertIn("pwn", str(ctx.exception))

    def test_ports_override(self):
        plan = build_plan(TARGET, "full", ports="22,80")
        self.assertEqual(plan.ports, "22,80")
        self.assertTrue(plan.customized)
        with self.assertRaises(PortsSpecError):
            build_plan(TARGET, ports="80;rm")

    def test_bad_vuln_mode(self):
        with self.assertRaises(PlanError):
            build_plan(TARGET, vuln_mode="aggressive")

    def test_direct_construction_is_validated_too(self):
        with self.assertRaises(PortsSpecError):
            ScanPlan(TARGET, ports="-oN")

    def test_to_dict(self):
        self.assertEqual(build_plan(TARGET, "quick", ports="21").to_dict(), {
            "target": TARGET, "preset": "quick", "customized": True, "ports": "21",
            "actions": ["surface", "exploits", "cves"], "vuln_mode": "auto"})


# ---- nmap ----------------------------------------------------------------

LIST_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94" start="1762250000">
  <host>
    <ports>
      <extraports state="closed" count="2">
        <extrareasons reason="reset" count="2"/>
      </extraports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="4.7p1"/>
      </port>
    </ports>
  </host>
  <runstats><finished elapsed="3.00"/></runstats>
</nmaprun>
"""


def fake_nmap(*xml_runs):
    outputs = list(xml_runs)

    def run(cmd, **kwargs):
        with open(cmd[cmd.index("-oX") + 1], "w") as fh:
            fh.write(outputs.pop(0))
        return mock.Mock(returncode=0)

    return mock.Mock(side_effect=run)


class NmapPortsTests(unittest.TestCase):

    def _run(self, ports, *xml_runs):
        run = fake_nmap(*xml_runs)
        with mock.patch.object(nmap_scan, "is_authorized", return_value=True), \
             mock.patch.object(nmap_scan.shutil, "which", return_value="/usr/bin/nmap"), \
             mock.patch.object(nmap_scan, "_source_ip", return_value="10.10.1.5"), \
             mock.patch.object(nmap_scan.subprocess, "run", run):
            result = nmap_scan.run_nmap(TARGET, ports=ports)
        return run, result

    def test_explicit_list_is_one_pass_with_p(self):
        run, result = self._run("21,22,80,8000-8100", LIST_XML)
        self.assertEqual(run.call_count, 1)
        cmd = run.call_args.args[0]
        tmp = cmd[cmd.index("-oX") + 1]
        self.assertEqual(cmd, ["nmap"] + nmap_scan.NMAP_FLAGS
                         + ["--reason", "-p", "21,22,80,8000-8100", "-oX", tmp, TARGET])
        self.assertEqual(run.call_args.kwargs["timeout"], 300)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["scan_info"]["mode"], "port list 21,22,80,8000-8100")
        self.assertEqual([p["port"] for p in result["ports"]], [22])

    def test_list_is_the_normalized_one(self):
        run, _ = self._run("080,0443", LIST_XML)
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[cmd.index("-p") + 1], "80,443")

    def test_long_list_gets_long_timeout(self):
        run, _ = self._run("1-65535", LIST_XML)
        self.assertEqual(run.call_args.kwargs["timeout"], 1800)

    def test_top_keeps_todays_command(self):
        run, result = self._run("top", LIST_XML)
        cmd = run.call_args.args[0]
        tmp = cmd[cmd.index("-oX") + 1]
        self.assertEqual(cmd, ["nmap"] + nmap_scan.NMAP_FLAGS + ["--reason", "-oX", tmp, TARGET])
        self.assertEqual(result["scan_info"]["mode"], "top 1000 ports")

    def test_all_keeps_two_pass(self):
        run, result = self._run("all", LIST_XML, LIST_XML)
        self.assertEqual(run.call_count, 2)
        self.assertIn("-p-", run.call_args_list[0].args[0])
        self.assertEqual(result["scan_info"]["mode"], "all 65535 ports, two pass")

    def test_bad_ports_never_reach_nmap(self):
        for spec in ("80;rm", "-oN", "80 81", "$(id)", "0", "65536", "100-90"):
            with self.subTest(spec=spec):
                with mock.patch.object(nmap_scan, "is_authorized", return_value=True), \
                     mock.patch.object(nmap_scan.shutil, "which") as which, \
                     mock.patch.object(nmap_scan.subprocess, "run") as run:
                    result = nmap_scan.run_nmap(TARGET, ports=spec)
                run.assert_not_called()
                which.assert_not_called()
                self.assertEqual(result["status"], "bad-ports")
                self.assertTrue(result["error"])

    def test_gate_runs_before_the_ports_check(self):
        with mock.patch.object(nmap_scan, "is_authorized", return_value=False) as gate, \
             mock.patch.object(nmap_scan, "parse_ports") as parse, \
             mock.patch.object(nmap_scan.subprocess, "run") as run:
            result = nmap_scan.run_nmap("8.8.8.8", ports="80;rm")
        gate.assert_called_once_with("8.8.8.8")
        parse.assert_not_called()
        run.assert_not_called()
        self.assertEqual(result["status"], "refused")


# ---- nuclei --------------------------------------------------------------

VERSION_OUTPUT = "[INF] Public nuclei-templates version: v10.5.2 (/root/nuclei-templates)\n"
DEEP_FLAGS = ["-type", "http", "-severity", "low,medium,high,critical",
              "-exclude-tags", "dos,fuzz,intrusive,default-login,bruteforce,brute-force",
              "-no-interactsh", "-disable-update-check", "-rate-limit", "50",
              "-concurrency", "10", "-timeout", "10", "-retries", "1", "-omit-raw",
              "-no-color", "-silent", "-jsonl"]


def fake_nuclei():
    def run(cmd, **kwargs):
        if "-templates-version" in cmd:
            return mock.Mock(returncode=0, stdout="", stderr=VERSION_OUTPUT)
        return mock.Mock(returncode=0, stdout="", stderr="")  # no findings, no file
    return mock.Mock(side_effect=run)


def nuclei_scan_cmd(run):
    return [c.args[0] for c in run.call_args_list if "-templates-version" not in c.args[0]][0]


class NucleiModeTests(unittest.TestCase):

    def _run(self, **kwargs):
        run = fake_nuclei()
        with mock.patch.object(nuclei_scan, "is_authorized", return_value=True), \
             mock.patch.object(nuclei_scan.shutil, "which", return_value="/usr/bin/nuclei"), \
             mock.patch.object(nuclei_scan.subprocess, "run", run):
            result = nuclei_scan.run_nuclei(TARGET, 80, **kwargs)
        return run, result

    def test_deep_is_the_default_and_todays_command(self):
        for kwargs in ({}, {"mode": "deep"}):
            run, result = self._run(**kwargs)
            cmd = nuclei_scan_cmd(run)
            out = cmd[cmd.index("-o") + 1]
            self.assertEqual(cmd, ["nuclei", "-u", "http://10.10.1.100:80"] + DEEP_FLAGS
                             + ["-o", out])
            self.assertNotIn("-automatic-scan", cmd)
            self.assertEqual(result["mode"], "deep")
            self.assertEqual(result["status"], "ok")

    def test_auto_adds_automatic_scan_and_keeps_every_safety_flag(self):
        run, result = self._run(mode="auto")
        cmd = nuclei_scan_cmd(run)
        out = cmd[cmd.index("-o") + 1]
        self.assertEqual(cmd, ["nuclei", "-u", "http://10.10.1.100:80"] + DEEP_FLAGS
                         + ["-automatic-scan", "-o", out])
        self.assertIn("-no-interactsh", cmd)
        self.assertIn("-disable-update-check", cmd)
        self.assertEqual(cmd[cmd.index("-exclude-tags") + 1],
                         "dos,fuzz,intrusive,default-login,bruteforce,brute-force")
        self.assertEqual(cmd[cmd.index("-severity") + 1], "low,medium,high,critical")
        self.assertEqual(cmd[cmd.index("-type") + 1], "http")
        self.assertEqual(cmd[cmd.index("-rate-limit") + 1], "50")
        self.assertNotIn("-update-templates", cmd)
        self.assertEqual(result["mode"], "auto")

    def test_bad_mode_never_runs_nuclei(self):
        for mode in ("all", "", None, "-as"):
            run, result = self._run(mode=mode)
            run.assert_not_called()
            self.assertEqual(result["status"], "bad-mode")

    def test_gate_runs_before_the_mode_check(self):
        with mock.patch.object(nuclei_scan, "is_authorized", return_value=False) as gate, \
             mock.patch.object(nuclei_scan.subprocess, "run") as run:
            result = nuclei_scan.run_nuclei("8.8.8.8", 80, mode="bogus")
        gate.assert_called_once_with("8.8.8.8")
        run.assert_not_called()
        self.assertEqual(result["status"], "refused")


# ---- ToolBox -------------------------------------------------------------

class ToolBoxPlanTests(unittest.TestCase):

    def test_tools_outside_the_plan_are_refused(self):
        tb = toolmod.ToolBox(TARGET, plan=build_plan(TARGET, "quick"))
        tb.scan = scan_with(HTTP_PORT, HTTPS_PORT, dict(FTP_PORT, port=445, service="smb"))
        with mock.patch.object(toolmod, "run_httpx") as httpx, \
             mock.patch.object(toolmod, "run_ffuf") as ffuf, \
             mock.patch.object(toolmod, "run_nuclei") as nuclei, \
             mock.patch.object(toolmod, "run_testssl") as testssl, \
             mock.patch.object(toolmod, "run_enum4linux") as enum:
            for name, args in (("web_fingerprint", {"port": 80}), ("web_discover", {"port": 80}),
                               ("vuln_templates", {"port": 80}), ("tls_check", {"port": 443}),
                               ("smb_enum", {})):
                obs, is_error = tb.call(name, args)
                self.assertTrue(is_error, name)
                self.assertIn("{n} is not part of this scan".format(n=name), obs)
                self.assertIn("nmap_scan, exploit_lookup, cve_lookup", obs)
        for fake in (httpx, ffuf, nuclei, testssl, enum):
            fake.assert_not_called()
        self.assertEqual(len(tb.calls), 5)

    def test_exploit_lookup_refused_without_exploit_hunt(self):
        tb = toolmod.ToolBox(TARGET, plan=build_plan(TARGET, actions="web"))
        tb.scan = scan_with(FTP_PORT)
        obs, is_error = tb.call("exploit_lookup", {"port": 21})
        self.assertTrue(is_error)
        self.assertIn("not part of this scan", obs)
        self.assertIn("Exploit Hunt", obs)

    def test_unknown_tool_is_still_unknown(self):
        tb = toolmod.ToolBox(TARGET, plan=build_plan(TARGET, "quick"))
        obs, is_error = tb.call("rm_rf", {})
        self.assertTrue(is_error)
        self.assertIn("Unknown tool", obs)

    def test_nmap_uses_the_plan_ports_and_lookups_run_with_exploits(self):
        tb = toolmod.ToolBox(TARGET, plan=build_plan(TARGET, "quick", ports="21,23"))
        with mock.patch.object(toolmod, "run_nmap",
                               return_value=scan_with(FTP_PORT, TELNET_PORT)) as nmap, \
             mock.patch.object(toolmod, "search_exploits", return_value=FAKE_EXPLOITS) as search:
            obs, is_error = tb.call("nmap_scan", {"target": TARGET})
        self.assertFalse(is_error)
        nmap.assert_called_once_with(TARGET, ports="21,23")
        self.assertTrue(search.called)
        ports = {p["port"]: p for p in json.loads(obs)["open_ports"]}
        self.assertIn("exploit_label", ports[21])
        self.assertEqual(ports[23]["risk"]["severity"], "high")

    def test_no_lookup_or_risk_flags_without_exploit_hunt(self):
        tb = toolmod.ToolBox(TARGET, plan=build_plan(TARGET, actions="web"))
        with mock.patch.object(toolmod, "run_nmap",
                               return_value=scan_with(FTP_PORT, TELNET_PORT)), \
             mock.patch.object(toolmod, "search_exploits") as search:
            obs, is_error = tb.call("nmap_scan", {"target": TARGET})
        self.assertFalse(is_error)
        search.assert_not_called()
        for port in json.loads(obs)["open_ports"]:
            for key in ("exploit_label", "match_count", "top_matches", "risk"):
                self.assertNotIn(key, port)
        for port in tb.scan["ports"]:
            self.assertNotIn("exploit_status", port)

    def test_nuclei_gets_the_plan_mode(self):
        for preset, mode in (("standard", "auto"), ("full", "deep")):
            tb = toolmod.ToolBox(TARGET, plan=build_plan(TARGET, preset))
            tb.scan = scan_with(HTTP_PORT)
            result = {"status": "ok", "url": "http://10.10.1.100:80", "templates_version": "v1",
                      "mode": mode, "findings": []}
            with mock.patch.object(toolmod, "run_nuclei", return_value=result) as nuclei:
                obs, is_error = tb.call("vuln_templates", {"port": 80})
            self.assertFalse(is_error)
            nuclei.assert_called_once_with(TARGET, 80, use_https=False, mode=mode)
            self.assertEqual(json.loads(obs)["mode"], mode)

    def test_no_plan_calls_tools_as_before(self):
        tb = toolmod.ToolBox(TARGET)
        self.assertIsNone(tb.plan)
        with mock.patch.object(toolmod, "run_nmap", return_value=scan_with(HTTP_PORT)) as nmap, \
             mock.patch.object(toolmod, "search_exploits", return_value=[]):
            tb.call("nmap_scan", {"target": TARGET})
        nmap.assert_called_once_with(TARGET, all_ports=False)
        result = {"status": "ok", "url": "http://10.10.1.100:80", "templates_version": "v1",
                  "findings": []}
        with mock.patch.object(toolmod, "run_nuclei", return_value=result) as nuclei:
            tb.call("vuln_templates", {"port": 80})
        nuclei.assert_called_once_with(TARGET, 80, use_https=False)

    def test_plan_for_another_target_is_refused(self):
        with self.assertRaises(ValueError):
            toolmod.ToolBox(TARGET, plan=build_plan("10.10.1.200"))

    def test_spec_filter(self):
        quick = toolmod.plan_tool_specs(build_plan(TARGET, "quick"))
        self.assertEqual([s["name"] for s in quick], ["nmap_scan", "exploit_lookup", "cve_lookup"])
        self.assertEqual(toolmod.plan_tool_specs(build_plan(TARGET, "full")), toolmod.TOOL_SPECS)
        self.assertIs(toolmod.plan_tool_specs(None), toolmod.TOOL_SPECS)

    def test_nmap_spec_without_exploit_hunt(self):
        specs = toolmod.plan_tool_specs(build_plan(TARGET, actions="web"))
        self.assertEqual([s["name"] for s in specs], ["nmap_scan", "web_fingerprint"])
        self.assertNotIn("Exploit-DB", specs[0]["description"])
        self.assertIn("Exploit-DB", toolmod.TOOL_SPECS[0]["description"])  # not changed in place


# ---- brain ---------------------------------------------------------------

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
        self.requests.append(dict(kwargs, messages=list(kwargs["messages"])))
        content = self.turns.pop(0)
        stop = "tool_use" if any(b.type == "tool_use" for b in content) else "end_turn"
        return NS(content=content, stop_reason=stop)


class BrainPlanTests(unittest.TestCase):

    def test_filtered_specs_and_plan_prompt_reach_the_model(self):
        plan = build_plan(TARGET, "quick")
        specs = toolmod.plan_tool_specs(plan)
        client = FakeClient([[tool_call("web_fingerprint", {"port": 80}, "t1")],
                             [text("done")]])
        tb, _ = brain.run_agent(TARGET, client=client, model="fake", trace=False,
                                tool_specs=specs, system_prompt=build_system_prompt(plan),
                                plan=plan)
        for request in client.requests:
            self.assertEqual([s["name"] for s in request["tools"]],
                             ["nmap_scan", "exploit_lookup", "cve_lookup"])
            self.assertEqual(request["system"], build_system_prompt(plan))
        self.assertIs(tb.plan, plan)
        result = client.requests[1]["messages"][-1]["content"][0]
        self.assertTrue(result["is_error"])
        self.assertIn("not part of this scan", result["content"])

    def test_defaults_are_unchanged(self):
        client = FakeClient([[text("done")]])
        tb, summary = brain.run_agent(TARGET, client=client, model="fake", trace=False)
        self.assertIs(client.requests[0]["tools"], toolmod.TOOL_SPECS)
        self.assertEqual(client.requests[0]["system"], SYSTEM_PROMPT)
        self.assertIsNone(tb.plan)
        self.assertEqual(summary, "done")


# ---- system prompt -------------------------------------------------------

# A verbatim copy of SYSTEM_PROMPT from before scan plans. The built prompt
# with every action must match it exactly.
ORIGINAL_SYSTEM_PROMPT = """You are ReconMind, a security analyst agent working inside an \
isolated, authorized penetration testing lab. The operator has given you exactly \
one target that they own and are authorized to test.

You work in a ReAct loop: think briefly about what you know and what you need \
next, call one tool, read the observation, and repeat until you have enough to \
write the report.

Rules:
- Only the operator's target is in scope. Never try to scan any other address.
- If a tool says the target was refused or is out of scope, stop and report that. \
Do not retry or look for a way around it.
- Start with nmap_scan. It also runs the Exploit-DB lookup for every port with a \
product and returns a compact summary per port (exploit_label, match_count, top 3 \
titles with EDB-IDs) plus risk flags for services that are dangerous just by being \
exposed. Call exploit_lookup only when you need the full list for one port.
- After nmap_scan, call web_fingerprint once for every open HTTP or HTTPS port \
(any service name containing http, such as http, https, ssl/http or http-proxy).
- After web_fingerprint, call web_discover once for each open HTTP or HTTPS port.
- After web_discover, call vuln_templates once for each open HTTP or HTTPS port.
- After nmap_scan, call tls_check once for every TLS or STARTTLS capable port it \
allows: ports where nmap saw an SSL tunnel or a service named https or ssl/something, \
and smtp, ftp, imap, pop3 or postgresql ports.
- After nmap_scan, if port 139 or 445 is open, call smb_enum once.
- Call cve_lookup once, after the web tools (web_fingerprint, web_discover and \
vuln_templates). It takes no inputs. NVD matches the upstream version only, so a \
CVE it lists may already be patched by the distribution.
- You are doing reconnaissance and analysis only. Do not write exploit code or \
step by step exploitation commands.
- Use only facts, exploit titles and EDB-IDs that appear in tool observations. \
Never invent CVE numbers, EDB-IDs, versions or services.
- Match labels: exact_version is the only confirmed label. version_family (patch \
level not confirmed), product_only (version unknown) and unverified (version range \
could not be checked) are unconfirmed and must be described as unconfirmed, never \
as confirmed vulnerabilities.
- exploit_label lookup_failed means the service was not checked. Say the lookup \
failed. Never report it as having no exploits.
- Include every risk flag from nmap_scan as a finding, with its severity and reason.
- Rank findings by real severity, never by the number of exploits. Unauthenticated \
remote code execution and open shells come first. Cleartext or trust based logins \
come next. Flaws that need credentials or local access, and denial of service, \
come lower. A confirmed match ranks above an unconfirmed one of similar impact.

When you are done, reply with no tool call and write only the analyst summary in \
Markdown with exactly these sections. No introduction before them and no closing \
remarks, offers or questions after them.
### Key findings
Most severe first. For each: port and service, what is wrong, why it matters, \
and whether it is confirmed or unconfirmed.
### Likely attack path
How an attacker could chain these findings, at a high level.
### MITRE ATT&CK (preliminary)
One technique per line: the ID followed by its official ATT&CK name, e.g. \
T1190 Exploit Public-Facing Application, or T1021.004 Remote Services: SSH.
### Recommended fixes
Concrete remediation for each finding.
END OF SUMMARY

""" + FORMAT_RULES

OTHER_RULES = (
    "- Only the operator's target is in scope.",
    "Do not retry or look for a way around it.",
    "- You are doing reconnaissance and analysis only.",
    "Never invent CVE numbers, EDB-IDs, versions or services.",
    "- Rank findings by real severity",
    "### Key findings", "### Recommended fixes", "\nEND OF SUMMARY\n",
)


class PromptTests(unittest.TestCase):

    def test_every_action_gives_the_original_prompt(self):
        self.assertEqual(SYSTEM_PROMPT, ORIGINAL_SYSTEM_PROMPT)
        self.assertEqual(build_system_prompt(), ORIGINAL_SYSTEM_PROMPT)
        for preset in ("standard", "full"):
            self.assertEqual(build_system_prompt(build_plan(TARGET, preset)),
                             ORIGINAL_SYSTEM_PROMPT)

    def test_quick_names_only_its_tools(self):
        prompt = build_system_prompt(build_plan(TARGET, "quick"))
        for tool in ("web_fingerprint", "web_discover", "vuln_templates", "tls_check",
                     "smb_enum"):
            self.assertNotIn(tool, prompt)
        self.assertIn("Call exploit_lookup only when", prompt)
        self.assertIn("- Call cve_lookup once, after nmap_scan. It takes no inputs.", prompt)
        self.assertIn("- Match labels:", prompt)
        for rule in OTHER_RULES:
            self.assertIn(rule, prompt)
        self.assertTrue(prompt.endswith(FORMAT_RULES))

    def test_surface_only(self):
        prompt = build_system_prompt(build_plan(TARGET, actions=""))
        for word in ("exploit_lookup", "cve_lookup", "web_", "tls_check", "smb_enum",
                     "Match labels", "lookup_failed", "risk flag"):
            self.assertNotIn(word, prompt)
        self.assertIn("- Start with nmap_scan. It returns every open port with its service, "
                      "product and version.\n", prompt)
        for rule in OTHER_RULES:
            self.assertIn(rule, prompt)

    def test_web_chain_without_fingerprint(self):
        prompt = build_system_prompt(build_plan(TARGET, actions="paths,cves"))
        self.assertIn("- After nmap_scan, call web_discover once for each open HTTP or HTTPS "
                      "port (any service name containing http", prompt)
        self.assertIn("after the web tool (web_discover).", prompt)
        self.assertNotIn("web_fingerprint", prompt)


# ---- CLI -----------------------------------------------------------------

class CliTests(InTempDir):

    def run_main(self, argv):
        config = llm.ProviderConfig("anthropic", "anthropic", None, "ANTHROPIC_API_KEY",
                                    "k", "fake-model")
        captured = {}

        def fake_agent(target, **kwargs):
            captured.update(kwargs, target=target)
            tb = toolmod.ToolBox(target, plan=kwargs.get("plan"))
            tb.scan = scan_with(dict(FTP_PORT, exploits=FAKE_EXPLOITS))
            return tb, VALID_SUMMARY

        out = io.StringIO()
        with mock.patch.object(llm, "load_config", return_value=config) as load, \
             mock.patch.object(llm, "make_client", return_value=NS()) as make, \
             mock.patch.object(brain, "run_agent", side_effect=fake_agent) as agent, \
             mock.patch.object(runner, "check_attack",
                               return_value=NS(skipped="ATT&CK check skipped", rows=[])), \
             contextlib.redirect_stdout(out):
            code = runner.main(["reconmind.agent"] + argv)
        return code, captured, out.getvalue(), (load, make, agent)

    def test_parse_options(self):
        args = runner._parse_args([TARGET, "--preset", "quick", "--ports", "80,443",
                                   "--actions", "web,paths"])
        self.assertEqual((args.preset, args.ports, args.actions), ("quick", "80,443", "web,paths"))
        args = runner._parse_args([TARGET])
        self.assertEqual((args.preset, args.ports, args.actions), (None, None, None))

    def test_options_build_the_plan_and_reach_the_agent(self):
        code, captured, out, _ = self.run_main([TARGET, "--preset", "quick", "--ports", "21,22",
                                                "--actions", "web"])
        self.assertEqual(code, 0)
        plan = captured["plan"]
        self.assertEqual((plan.preset, plan.ports, plan.actions),
                         ("quick", "21,22", ("surface", "web")))
        self.assertEqual([s["name"] for s in captured["tool_specs"]],
                         ["nmap_scan", "web_fingerprint"])
        self.assertEqual(captured["system_prompt"], build_system_prompt(plan))
        self.assertIn("Scan plan: preset quick (customized), ports 21,22 (2 ports)", out)
        self.assertIn("[x] web", out)
        self.assertIn("[ ] smb", out)
        self.assertIn("exploits:    Not run (not selected)", out)

    def test_default_plan_is_standard(self):
        code, captured, out, _ = self.run_main([TARGET])
        self.assertEqual(code, 0)
        plan = captured["plan"]
        self.assertEqual((plan.preset, plan.ports, plan.actions, plan.vuln_mode),
                         ("standard", "top", ACTION_IDS, "auto"))
        self.assertIn("Vuln Probe mode: auto", out)

    def test_plan_is_printed_before_the_scan_starts(self):
        _, _, out, _ = self.run_main([TARGET])
        self.assertLess(out.index("Scan plan:"), out.index("-" * 60))

    def test_bad_ports_stop_before_config_or_model(self):
        for argv in ([TARGET, "--ports=80;rm"], [TARGET, "--ports=-oN"],
                     [TARGET, "--ports", "-oN"], [TARGET, "--ports=0"]):
            code, _, out, (load, make, agent) = self.run_main(argv)
            self.assertEqual(code, 1, argv)
            load.assert_not_called()
            make.assert_not_called()
            agent.assert_not_called()

    def test_bad_ports_message(self):
        code, _, out, _ = self.run_main([TARGET, "--ports=80;rm"])
        self.assertEqual(code, 1)
        self.assertIn("Bad scan plan: Ports spec '80;rm' is not valid.", out)

    def test_unknown_action_or_preset(self):
        code, _, out, (_, _, agent) = self.run_main([TARGET, "--actions", "web,pwn"])
        self.assertEqual(code, 1)
        self.assertIn("Unknown action 'pwn'", out)
        agent.assert_not_called()
        with contextlib.redirect_stderr(io.StringIO()):
            code, _, _, (_, _, agent) = self.run_main([TARGET, "--preset", "everything"])
        self.assertEqual(code, 1)
        agent.assert_not_called()

    def test_gate_still_runs_first(self):
        code, _, out, (load, make, agent) = self.run_main(["10.0.3.15", "--ports=80;rm"])
        self.assertEqual(code, 2)
        load.assert_not_called()
        make.assert_not_called()
        agent.assert_not_called()
        self.assertIn("REFUSED", out)
        entry = history.read_index()[-1]
        self.assertEqual(entry["status"], "refused")
        self.assertIsNone(entry["preset"])  # the plan was not valid either

    def test_run_is_saved_to_history(self):
        code, _, out, _ = self.run_main([TARGET, "--preset", "quick"])
        self.assertEqual(code, 0)
        entry = history.read_index()[-1]
        self.assertEqual(entry["preset"], "quick")
        self.assertEqual(entry["actions"], ["surface", "exploits", "cves"])
        report_path = os.path.join("reports", entry["run_id"], "report.md")
        self.assertIn(report_path, out)
        with open(report_path) as fh:
            self.assertIn("## Scan plan", fh.read())


# ---- report --------------------------------------------------------------

class ReportPlanTests(InTempDir):

    def read(self, scan, **kwargs):
        with open(build_report(scan, **kwargs)) as fh:
            return fh.read()

    def test_plan_section_and_not_run_lines(self):
        scan = scan_with(dict(FTP_PORT, exploits=FAKE_EXPLOITS), HTTP_PORT)
        report = self.read(scan, plan=build_plan(TARGET, "quick"))
        self.assertIn("## Scan plan", report)
        self.assertLess(report.index("## Scan plan"), report.index("## Open ports"))
        self.assertIn("- Preset: quick\n", report)
        self.assertIn("- Ports: top (nmap's default top 1000 ports)", report)
        self.assertIn("| surface | Surface Map | Ran |", report)
        self.assertIn("| exploits | Exploit Hunt | Ran |", report)
        self.assertIn("| cves | CVE Intel | Selected, did not run |", report)
        for action_id, name in (("web", "Web Fingerprint"), ("paths", "Hidden Paths"),
                                ("vulns", "Vuln Probe"), ("crypto", "Crypto Check"),
                                ("smb", "SMB Recon")):
            self.assertIn("| {i} | {n} | Not run (not selected) |".format(i=action_id, n=name),
                          report)
        self.assertNotIn("Vuln Probe mode", report)

    def test_unselected_sections_are_left_out(self):
        scan = scan_with(dict(FTP_PORT, exploits=FAKE_EXPLOITS), HTTP_PORT)
        report = self.read(scan, plan=build_plan(TARGET, "quick"))
        self.assertIn("## Known exploits (Exploit-DB)", report)
        for head in ("## Web technology (httpx)", "## Web content discovery (ffuf)",
                     "## Template checks (nuclei)"):
            self.assertNotIn(head, report)
        # Selected but not run still gets its own "not checked" line.
        self.assertIn("## Known CVEs (NVD)", report)
        self.assertIn("**Not checked:** open ports carry CPEs, but cve_lookup did not run", report)

    def test_without_exploit_hunt(self):
        report = self.read(scan_with(FTP_PORT, TELNET_PORT),
                           plan=build_plan(TARGET, actions="web"))
        self.assertNotIn("## Known exploits", report)
        self.assertNotIn("## Exposed risky services", report)
        self.assertIn("2 open port(s) found. Exploit lookup and risk flags: Not run (not "
                      "selected).", report)
        self.assertIn("| exploits | Exploit Hunt | Not run (not selected) |", report)

    def test_no_plan_renders_as_before(self):
        scan = scan_with(dict(FTP_PORT, exploits=FAKE_EXPLOITS), HTTP_PORT)
        report = self.read(scan)
        self.assertNotIn("## Scan plan", report)
        self.assertIn("## Web technology (httpx)", report)
        self.assertIn("**Not checked:** these open web ports were not fingerprinted", report)
        self.assertTrue(os.path.basename(build_report(scan)).startswith("recon_"))

    def test_nuclei_mode_and_customized_preset(self):
        scan = scan_with(HTTP_PORT, nuclei={80: {
            "status": "ok", "url": "http://10.10.1.100:80", "templates_version": "v1",
            "mode": "auto", "findings": []}})
        report = self.read(scan, plan=build_plan(TARGET, "standard", ports="80"))
        self.assertIn("- Preset: standard (customized)", report)
        self.assertIn("- Ports: 80 (1 port)", report)
        self.assertIn("- Vuln Probe mode: auto (nuclei picks templates", report)
        self.assertIn("Mode: auto (nuclei picks templates for the detected technology)", report)
        self.assertIn("| vulns | Vuln Probe | Ran |", report)


# ---- history -------------------------------------------------------------

STARTED = datetime(2026, 11, 12, 10, 0, 0)
FINISHED = datetime(2026, 11, 12, 10, 5, 30)


def history_scan():
    return scan_with(
        TELNET_PORT, HTTP_PORT, HTTPS_PORT,
        raw_xml=["<nmaprun/>"],
        nuclei={80: {"status": "ok", "url": "http://10.10.1.100:80", "mode": "auto",
                     "findings": [{"template_id": "x", "severity": "high"}],
                     "raw_jsonl": "{\"template-id\": \"x\"}\n"}},
        tls={443: {"status": "ok", "findings": [{"id": "BEAST", "severity": "MEDIUM"},
                                               {"id": "cert_x", "severity": "OK"}],
                   "ciphers": [], "raw_json": [{"id": "BEAST"}]}},
        discovery={80: {"status": "ok", "results": [], "raw_json": {"results": []}}})


class HistoryTests(InTempDir):

    def save(self, scan=None, plan=None, **kwargs):
        return history.save_run(scan or history_scan(),
                                plan=plan or build_plan(TARGET, "standard"),
                                started=STARTED, finished=FINISHED, **kwargs)

    def test_run_folder_files(self):
        record = self.save()
        self.assertEqual(record.run_id, "20261112_100000_10.10.1.100")
        folder = os.path.join("reports", record.run_id)
        self.assertEqual(sorted(os.listdir(folder)), ["evidence.json", "report.md", "scan.json"])
        self.assertEqual(record.report_path, os.path.join(folder, "report.md"))
        with open(record.report_path) as fh:
            self.assertIn("## Scan plan", fh.read())

    def test_scan_json_has_plan_and_results_without_evidence(self):
        record = self.save()
        with open(os.path.join(record.folder, "scan.json")) as fh:
            text_ = fh.read()
        data = json.loads(text_)
        self.assertEqual(data["plan"], build_plan(TARGET, "standard").to_dict())
        self.assertEqual(data["results"]["status"], "ok")
        self.assertEqual(data["results"]["nuclei"]["80"]["findings"][0]["template_id"], "x")
        for key in ("raw_xml", "raw_json", "raw_jsonl"):
            self.assertNotIn(key, text_)

    def test_evidence_json_holds_the_raw_output(self):
        record = self.save()
        with open(os.path.join(record.folder, "evidence.json")) as fh:
            evidence = json.load(fh)["evidence"]
        self.assertEqual(evidence["raw_xml"], ["<nmaprun/>"])
        self.assertEqual(evidence["nuclei"]["80"]["raw_jsonl"], "{\"template-id\": \"x\"}\n")
        self.assertEqual(evidence["tls"]["443"]["raw_json"], [{"id": "BEAST"}])
        self.assertEqual(evidence["discovery"]["80"]["raw_json"], {"results": []})

    def test_input_scan_is_not_changed(self):
        scan = history_scan()
        self.save(scan)
        self.assertEqual(scan["raw_xml"], ["<nmaprun/>"])
        self.assertIn("raw_json", scan["tls"][443])

    def test_index_entry(self):
        self.save()
        entries = history.read_index()
        self.assertEqual(entries, [{
            "run_id": "20261112_100000_10.10.1.100", "target": TARGET, "preset": "standard",
            "actions": list(ACTION_IDS), "ports_spec": "top",
            "started": "2026-11-12T10:00:00", "finished": "2026-11-12T10:05:30",
            "status": "ok", "open_ports": 3,
            # telnet risk flag high, nuclei high, testssl MEDIUM; "OK" is not counted
            "findings": {"critical": 0, "high": 2, "medium": 1, "low": 0},
        }])

    def test_risk_flags_not_counted_without_exploit_hunt(self):
        self.save(plan=build_plan(TARGET, actions="vulns,crypto,paths"))
        self.assertEqual(history.read_index()[-1]["findings"],
                         {"critical": 0, "high": 1, "medium": 1, "low": 0})

    def test_runs_append_and_never_collide(self):
        first = self.save()
        second = self.save()
        self.assertEqual(second.run_id, first.run_id + "_2")
        self.assertEqual([e["run_id"] for e in history.read_index()],
                         [first.run_id, second.run_id])

    def test_index_is_written_through_a_temp_file_and_rename(self):
        real_replace = os.replace
        calls = []

        def spy(src, dst):
            calls.append((src, dst))
            return real_replace(src, dst)

        with mock.patch.object(history.os, "replace", side_effect=spy):
            self.save()
        index_path = os.path.join("reports", "index.json")
        index_calls = [c for c in calls if c[1] == index_path]
        self.assertEqual(len(index_calls), 1)
        src = index_calls[0][0]
        self.assertEqual(os.path.abspath(os.path.dirname(src)), os.path.abspath("reports"))
        self.assertTrue(src.endswith(".tmp"))
        self.assertFalse(os.path.exists(src))
        leftovers = [n for n in os.listdir("reports") if n.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_failed_write_leaves_the_old_index(self):
        self.save()
        with open(os.path.join("reports", "index.json")) as fh:
            before = fh.read()
        real_replace = os.replace

        def fail_on_index(src, dst):
            if dst.endswith("index.json"):
                raise OSError("disk full")
            return real_replace(src, dst)

        with mock.patch.object(history.os, "replace", side_effect=fail_on_index):
            with self.assertRaises(OSError):
                self.save()
        with open(os.path.join("reports", "index.json")) as fh:
            self.assertEqual(fh.read(), before)
        self.assertEqual([n for n in os.listdir("reports") if n.endswith(".tmp")], [])

    def test_corrupt_index_is_kept_aside(self):
        os.makedirs("reports")
        with open(os.path.join("reports", "index.json"), "w") as fh:
            fh.write("not json")
        record = self.save()
        self.assertEqual(len(history.read_index()), 1)
        with open(os.path.join("reports", "index.json.bad-" + record.run_id)) as fh:
            self.assertEqual(fh.read(), "not json")

    def test_old_flat_reports_keep_working(self):
        os.makedirs("reports")
        old = os.path.join("reports", "recon_10.10.1.100_20250101_000000.md")
        with open(old, "w") as fh:
            fh.write("# old report\n")
        self.save()
        with open(old) as fh:
            self.assertEqual(fh.read(), "# old report\n")
        flat = build_report(scan_with(FTP_PORT))  # the fixed pipeline still writes flat
        self.assertEqual(os.path.dirname(flat), "reports")
        self.assertEqual(len(history.read_index()), 1)

    def test_refused_run_without_plan(self):
        record = history.save_run({"target": "8.8.8.8", "status": "refused", "ports": []},
                                  started=STARTED, finished=STARTED)
        entry = history.read_index()[-1]
        self.assertEqual(entry["run_id"], record.run_id)
        self.assertEqual((entry["status"], entry["preset"], entry["actions"],
                          entry["ports_spec"], entry["open_ports"]),
                         ("refused", None, [], None, 0))

    def test_run_id_is_safe(self):
        self.assertEqual(history.new_run_id("../../etc/x", STARTED),
                         "20261112_100000_.._.._etc_x")


if __name__ == "__main__":
    unittest.main()
