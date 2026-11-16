"""
Offline tests for the AI analyst and the report modes: ReadOnlyTools never
imports or calls a scanner and never changes the scan, the AI flow runs the
pipeline exactly once and then the analyst, an LLM failure still saves the
full tool report with the notice, brain.run_agent's defaults are unchanged,
the Standard report, stopping, and the CLI's --mode option (parsing, the
default with and without a configured key, and the gate still refusing
before anything else).

A scripted fake model drives the real brain loop where one is needed. No
tool, model or network is used.

    python3 -m unittest discover -s tests -v
"""

import ast
import contextlib
import copy
import io
import json
import os
import signal
import tempfile
import unittest
from functools import partial
from types import SimpleNamespace as NS
from unittest import mock

from reconmind import __main__ as router
from reconmind.agent import analyst_tools, brain, llm, tools as toolmod
from reconmind.agent import __main__ as runner
from reconmind.agent.analyst_tools import ANALYST_TOOL_SPECS, ReadOnlyTools
from reconmind.agent.prompts import (
    SYSTEM_PROMPT, analyst_first_message, build_analyst_system_prompt, first_user_message)
from reconmind.ai import attack_mapper
from reconmind.core import history, pipeline
from reconmind.core.attack_check import check_attack
from reconmind.core.report import (
    STANDARD_NOTE, SUMMARY_RATE_LIMITED, SUMMARY_UNAVAILABLE)
from reconmind.core.scan_plan import build_plan
from reconmind.tools import risky_services

TARGET = "10.10.1.100"
ATTACK_FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "fixtures", "attack_techniques.json")

FAKE_EXPLOITS = [{"title": "vsftpd 2.3.4 - Backdoor Command Execution", "edb_id": "49757",
                  "match": "exact_version"}]
FTP = {"port": 21, "protocol": "tcp", "service": "ftp", "product": "vsftpd", "version": "2.3.4",
       "exploit_status": "ok", "exploits": FAKE_EXPLOITS}
HTTP = {"port": 80, "protocol": "tcp", "service": "http", "product": "Apache httpd",
        "version": "2.2.8", "exploit_status": "ok", "exploits": []}
TELNET = {"port": 23, "protocol": "tcp", "service": "telnet", "product": "Linux telnetd",
          "version": ""}


def finished_scan():
    """A finished scan as the pipeline leaves it, raw evidence included."""
    return {
        "target": TARGET, "status": "ok",
        "ports": [copy.deepcopy(FTP), copy.deepcopy(HTTP), dict(TELNET)],
        "port_states": [{"state": "open", "count": 3}, {"state": "closed", "count": 997}],
        "unconfirmed_ports": [],
        "scan_info": {"commands": ["nmap -sV " + TARGET], "mode": "default"},
        "raw_xml": ["<nmaprun/>"],
        "web": {80: {"status": "ok", "url": "http://10.10.1.100:80", "server": "Apache",
                     "technologies": [{"name": "PHP", "version": "5.2.4"}],
                     "raw_json": {"secret": "evidence"}}},
        "discovery": {80: {"status": "ok", "url": "http://10.10.1.100:80",
                           "results": [{"path": "phpinfo.php", "status": 200, "length": 10}]}},
        "nuclei": {80: {"status": "ok", "findings": [
            {"template_id": "phpinfo-files", "name": "phpinfo Disclosure", "severity": "low",
             "matched_at": "http://10.10.1.100/phpinfo.php", "cve": []}]}},
        "tls": {21: {"status": "ok", "findings": [
            {"id": "SSLv3", "severity": "HIGH", "finding": "offered", "cve": "CVE-2014-3566"}],
            "ciphers": [{"id": "cipher-1"}]}},
        "nvd": {"status": "ok", "products": [{
            "product": "vsftpd", "cpe": "cpe:2.3:a:beasts:vsftpd:2.3.4", "ports": ["21/tcp"],
            "status": "ok", "cves": [
                {"id": "CVE-2011-2523", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
                 "kev": True, "kev_added": "2021-11-03", "description": "Backdoor."},
                {"id": "CVE-2015-1419", "cvss_score": 5.0, "cvss_severity": "MEDIUM",
                 "kev": False, "description": "Deny list bypass."}]}], "skipped": []},
        "attack_map": {"status": "ok", "ports": [
            {"port": 21, "protocol": "tcp", "text": "mapper text",
             "techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application",
                             "sources": ["model"], "confidence": 0.95}],
             "lower_confidence": [], "dropped": []}]},
    }


VALID_SUMMARY = (
    "### Key findings\n1. vsftpd 2.3.4 backdoor on 21/tcp (EDB-49757), confirmed.\n"
    "### Likely attack path\nBackdoor shell on 21/tcp.\n"
    "### MITRE ATT&CK (preliminary)\nT1190 Exploit Public-Facing Application\n"
    "### Recommended fixes\n1. Upgrade vsftpd.\nEND OF SUMMARY\n")

CONFIG = llm.ProviderConfig("anthropic", "anthropic", None, "ANTHROPIC_API_KEY", "k",
                            "fake-model")

# Every scanner runner the analyst must never reach.
RUNNERS = ("run_nmap", "search_exploits", "run_httpx", "basic_http_fingerprint", "run_ffuf",
           "run_nuclei", "run_testssl", "run_enum4linux")


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


@contextlib.contextmanager
def runners_that_fail():
    """Every scanner runner raises if anything calls it."""
    def boom(*args, **kwargs):
        raise AssertionError("a scanner was called")
    with contextlib.ExitStack() as stack:
        for name in RUNNERS:
            stack.enter_context(mock.patch.object(toolmod, name, side_effect=boom))
        stack.enter_context(mock.patch.object(toolmod.nvd_lookup, "run_cve_lookup",
                                              side_effect=boom))
        yield


# ---- ReadOnlyTools ---------------------------------------------------------

class ReadOnlyToolsTests(unittest.TestCase):

    def setUp(self):
        self.scan = finished_scan()
        self.before = copy.deepcopy(self.scan)
        self.plan = build_plan(TARGET, "standard")
        self.tools = ReadOnlyTools(self.scan, self.plan)

    def read(self, name, args=None):
        observation, is_error = self.tools.call(name, args or {})
        return json.loads(observation), is_error

    def test_imports_no_scanner_module(self):
        with open(analyst_tools.__file__) as fh:
            tree = ast.parse(fh.read())
        imported, names = set(), set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module)
                names.update(a.name for a in node.names)
            elif isinstance(node, ast.Name):
                names.add(node.id)
        ours = {m for m in imported if m and m.startswith("reconmind")}
        self.assertEqual(ours, {"reconmind.tools.risky_services"})
        self.assertFalse(imported & {"subprocess", "socket", "shutil", "urllib.request",
                                     "http.client", "requests"})
        self.assertFalse(names & set(RUNNERS + ("run_cve_lookup", "ToolBox")))

    def test_risky_services_is_a_plain_rule_table(self):
        with open(risky_services.__file__) as fh:
            tree = ast.parse(fh.read())
        imports = [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]
        self.assertEqual(imports, [])

    def test_no_tool_ever_calls_a_runner_or_changes_the_scan(self):
        with runners_that_fail():
            for name, args in (("list_findings", {}), ("get_port", {"port": 21}),
                               ("get_port", {"port": 80}), ("get_port", {"port": 23}),
                               ("get_section", {"name": "nvd"}),
                               ("get_section", {"name": "smb"}),
                               ("get_section", {"name": "attack_map"}),
                               ("get_section", {"name": "port_states"}),
                               ("get_section", {"name": "unconfirmed_ports"}),
                               ("nmap_scan", {"target": TARGET}),
                               ("web_fingerprint", {"port": 80})):
                with self.subTest(name=name, args=args):
                    observation, _ = self.tools.call(name, args)
                    json.loads(observation)
        self.assertEqual(self.scan, self.before)

    def test_scanner_tools_are_unknown(self):
        for name in ("nmap_scan", "exploit_lookup", "web_fingerprint", "tls_check",
                     "smb_enum", "cve_lookup", "attack_map", "shell"):
            data, is_error = self.read(name, {"target": "10.10.1.200"})
            self.assertTrue(is_error, name)
            self.assertIn("No scanner can be run from here", data["error"])

    def test_specs_are_the_three_read_tools(self):
        self.assertEqual([s["name"] for s in ANALYST_TOOL_SPECS],
                         ["list_findings", "get_port", "get_section"])
        for spec in ANALYST_TOOL_SPECS:
            self.assertEqual(set(spec), {"name", "description", "input_schema"})
            self.assertEqual(spec["input_schema"]["type"], "object")

    def test_get_port_returns_everything_for_the_port(self):
        data, is_error = self.read("get_port", {"port": 80})
        self.assertFalse(is_error)
        self.assertEqual(data["nmap"]["product"], "Apache httpd")
        self.assertEqual(data["web_fingerprint"]["technologies"],
                         [{"name": "PHP", "version": "5.2.4"}])
        self.assertEqual(data["web_discover"]["results"][0]["path"], "phpinfo.php")
        self.assertEqual(data["vuln_templates"]["findings"][0]["template_id"], "phpinfo-files")
        self.assertNotIn("raw_json", data["web_fingerprint"])  # evidence is never sent

        data, _ = self.read("get_port", {"port": 21})
        self.assertEqual(data["exploit_lookup"]["matches"][0]["edb_id"], "49757")
        self.assertEqual(data["tls_check"]["findings"][0]["cve"], "CVE-2014-3566")
        self.assertNotIn("ciphers", data["tls_check"])
        self.assertEqual(data["attack_map"]["techniques"][0]["id"], "T1190")

        data, _ = self.read("get_port", {"port": 23})
        self.assertEqual(data["risk"]["severity"], risky_services.flag_port(TELNET)["severity"])

    def test_get_port_rejects_ports_not_open(self):
        for port in (8080, "abc", None):
            data, is_error = self.read("get_port", {"port": port})
            self.assertTrue(is_error, port)
            self.assertIn("21, 80, 23", data["error"])

    def test_get_section(self):
        data, _ = self.read("get_section", {"name": "nvd"})
        product = data["nvd"]["products"][0]
        self.assertEqual(product["cve_count"], 2)
        self.assertEqual(product["cisa_kev"], ["CVE-2011-2523"])
        self.assertEqual(product["cves_shown"][0]["id"], "CVE-2011-2523")
        self.assertNotIn("cves", product)
        data, _ = self.read("get_section", {"name": "attack_map"})
        self.assertNotIn("text", data["attack_map"]["ports"][0])
        data, _ = self.read("get_section", {"name": "smb"})
        self.assertIn("did not run", data["status"])
        data, is_error = self.read("get_section", {"name": "evidence"})
        self.assertTrue(is_error)

    def test_actions_outside_the_plan_say_not_selected(self):
        plan = build_plan(TARGET, actions="web")
        tools = ReadOnlyTools(finished_scan(), plan)
        data = json.loads(tools.call("get_section", {"name": "nvd"})[0])
        self.assertIn("not selected", data["status"])
        data = json.loads(tools.call("get_port", {"port": 23})[0])
        self.assertIn("not selected", data["exploit_lookup"])
        self.assertNotIn("risk", data)

    def test_list_findings_names_each_source(self):
        data, is_error = self.read("list_findings")
        self.assertFalse(is_error)
        sources = {f["source"] for f in data["findings"]}
        self.assertEqual(sources, {"risk_flags", "exploit_lookup", "web_fingerprint",
                                   "web_discover", "vuln_templates", "tls_check", "cve_lookup",
                                   "attack_map"})
        self.assertEqual(data["finding_count"], len(data["findings"]))

    def test_bad_arguments_become_observations(self):
        for args in ({"port": 21, "extra": 1}, {"_invalid_arguments": "x"}, "not a dict"):
            observation, is_error = self.tools.call("get_port", args)
            self.assertTrue(is_error)
            self.assertIn("Bad arguments", json.loads(observation)["error"])

    def test_overview(self):
        facts = ReadOnlyTools(self.scan, self.plan,
                              steps=[{"tool": "nmap_scan", "port": None, "status": "done"}]
                              ).overview()
        self.assertEqual([p["port"] for p in facts["open_ports"]], [21, 80, 23])
        self.assertEqual(facts["results_stored"]["web_fingerprint"], [80])
        self.assertTrue(facts["results_stored"]["attack_map"])
        self.assertEqual(facts["steps"], [{"tool": "nmap_scan", "status": "done"}])
        message = analyst_first_message(TARGET, facts)
        self.assertIn("Authorized target: " + TARGET, message)
        self.assertIn('"scan_status": "ok"', message)


class AnalystPromptTests(unittest.TestCase):

    def test_prompt_keeps_the_summary_format_and_read_only_rules(self):
        prompt = build_analyst_system_prompt(build_plan(TARGET, "standard"))
        for heading in ("### Key findings", "### Likely attack path",
                        "### MITRE ATT&CK (preliminary)", "### Recommended fixes"):
            self.assertIn(heading, prompt)
        self.assertIn("The last line must be exactly END OF SUMMARY", prompt)
        self.assertIn("You cannot run any scanner", prompt)
        self.assertIn("most urgent first", prompt)
        self.assertIn("Match labels", prompt)

    def test_technique_ids_carry_their_official_name_and_stay_in_the_attack_section(self):
        # attack_check flags an ID whose name does not match MITRE's, so the
        # prompt asks for the exact name every time and no bare IDs elsewhere.
        for plan in (None, build_plan(TARGET, "standard"), build_plan(TARGET, actions="web")):
            prompt = build_analyst_system_prompt(plan)
            self.assertIn("Every time you write a technique ID, follow it right away with its "
                          "exact official name as attack_map gave it, e.g. T1190 Exploit "
                          "Public-Facing Application.", prompt)
            self.assertIn("Technique IDs appear only in the MITRE ATT&CK section. Never write "
                          "a technique ID in any other section", prompt)

    def test_exploit_rules_only_with_exploit_hunt(self):
        prompt = build_analyst_system_prompt(build_plan(TARGET, actions="web"))
        self.assertNotIn("Match labels", prompt)
        self.assertNotIn("NVD matches", prompt)


# ---- brain -----------------------------------------------------------------

class BrainTests(unittest.TestCase):

    def test_defaults_are_unchanged(self):
        client = FakeClient([[text("done")]])
        tb, summary = brain.run_agent(TARGET, client=client, model="fake", trace=False)
        request = client.requests[0]
        self.assertIs(request["tools"], toolmod.TOOL_SPECS)
        self.assertEqual(request["system"], SYSTEM_PROMPT)
        self.assertEqual(request["messages"][0],
                         {"role": "user", "content": first_user_message(TARGET)})
        self.assertIsInstance(tb, toolmod.ToolBox)
        self.assertIsNone(tb.plan)
        self.assertEqual(summary, "done")

    def test_toolbox_and_first_message_are_used(self):
        reader = ReadOnlyTools(finished_scan())
        client = FakeClient([[tool_call("get_port", {"port": 21}, "r1")], [text("done")]])
        tb, summary = brain.run_agent(TARGET, client=client, model="fake", trace=False,
                                      tool_specs=ANALYST_TOOL_SPECS, toolbox=reader,
                                      first_message="read the results")
        self.assertIs(tb, reader)
        self.assertEqual(reader.calls, [("get_port", {"port": 21})])
        self.assertEqual(client.requests[0]["messages"][0]["content"], "read the results")
        result = client.requests[1]["messages"][-1]["content"][0]
        self.assertFalse(result["is_error"])
        self.assertIn("vsftpd", result["content"])


# ---- the runner ------------------------------------------------------------

class RunnerCase(unittest.TestCase):
    """Each test in an empty folder and environment; the mapper never loads a model."""

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)
        no_model = os.path.join(self._tmp.name, "no_model")
        os.makedirs(no_model)
        self._env = mock.patch.dict(os.environ, {attack_mapper.DIR_ENV: no_model}, clear=True)
        self._env.start()
        attack_mapper.clear_cache()
        self.order = []

    def tearDown(self):
        attack_mapper.clear_cache()
        self._env.stop()
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def fake_pipeline(self, scan=None):
        def fake(target, plan, **kwargs):
            self.order.append("pipeline")
            self.pipeline_kwargs = kwargs
            tb = self.tb = toolmod.ToolBox(target, plan=plan)
            tb.scan = scan if scan is not None else finished_scan()
            tb.steps = [{"action": "surface", "tool": "nmap_scan", "port": None,
                         "status": "done"}]
            return tb
        return fake

    def run_main(self, argv, config=CONFIG, agent=None, client=None, scan=None):
        """argv after the program name. agent replaces brain.run_agent's behavior."""
        client = client if client is not None else FakeClient([])

        def fake_agent(target, **kwargs):
            self.order.append("analyst")
            self.agent_kwargs = kwargs
            if agent is not None:
                return agent(target, **kwargs)
            return kwargs.get("toolbox"), VALID_SUMMARY

        if config is None:
            load = mock.patch.object(llm, "load_config", side_effect=llm.ConfigError(
                "OPENROUTER_API_KEY is not set. Put it in .env in the repo root:\n"
                "    OPENROUTER_API_KEY=..."))
        else:
            load = mock.patch.object(llm, "load_config", return_value=config)
        out = io.StringIO()
        with load as self.load, \
             mock.patch.object(llm, "make_client", return_value=client) as self.make, \
             mock.patch.object(runner, "run_plan",
                               side_effect=self.fake_pipeline(scan)) as self.pipeline, \
             mock.patch.object(brain, "run_agent", side_effect=fake_agent) as self.agent, \
             mock.patch.object(runner, "check_attack", partial(check_attack,
                                                               path=ATTACK_FIXTURE)), \
             mock.patch.object(attack_mapper, "load",
                               return_value=attack_mapper.Predictor("not-installed", "x")), \
             mock.patch.object(llm.time, "sleep"), \
             contextlib.redirect_stdout(out):
            code = runner.main(["reconmind.agent"] + list(argv))
        self.out = out.getvalue()
        return code

    def report(self):
        entry = history.read_index()[-1]
        with open(os.path.join("reports", entry["run_id"], "report.md")) as fh:
            return entry, fh.read()


class AiFlowTests(RunnerCase):

    def test_pipeline_runs_once_then_the_analyst(self):
        code = self.run_main([TARGET, "--mode", "ai"])
        self.assertEqual(code, 0)
        self.assertEqual(self.order, ["pipeline", "analyst"])
        self.assertEqual(self.pipeline.call_count, 1)
        self.assertEqual(self.pipeline_kwargs["mode"], "ai")
        kwargs = self.agent_kwargs
        self.assertIsInstance(kwargs["toolbox"], ReadOnlyTools)
        self.assertIs(kwargs["toolbox"].scan, self.tb.scan)
        self.assertIs(kwargs["tool_specs"], ANALYST_TOOL_SPECS)
        plan = build_plan(TARGET, "standard")
        self.assertEqual(kwargs["system_prompt"], build_analyst_system_prompt(plan))
        self.assertIn("The scan has finished", kwargs["first_message"])
        entry, report = self.report()
        self.assertEqual(entry["mode"], "ai")
        self.assertFalse(entry["stopped"])
        self.assertIn("AI interpretation", report)
        self.assertIn("1. Upgrade vsftpd.", report)
        self.assertNotIn(STANDARD_NOTE, report)
        self.assertIn("run id:", self.out)
        self.assertIn("report:", self.out)

    def test_real_brain_reads_only(self):
        client = FakeClient([
            [tool_call("list_findings", {}, "a1"), tool_call("get_port", {"port": 21}, "a2")],
            [tool_call("nmap_scan", {"target": "10.10.1.200"}, "a3")],
            [text(VALID_SUMMARY)],
        ])
        real_agent = brain.run_agent  # taken before run_main replaces it

        def agent(target, **kwargs):
            return real_agent(target, trace=False, **kwargs)

        with runners_that_fail():
            code = self.run_main([TARGET], agent=agent, client=client)
        self.assertEqual(code, 0)
        self.assertEqual([s["name"] for s in client.requests[0]["tools"]],
                         ["list_findings", "get_port", "get_section"])
        first_results = client.requests[1]["messages"][-1]["content"]
        self.assertEqual([r["is_error"] for r in first_results], [False, False])
        refused = client.requests[2]["messages"][-1]["content"][0]
        self.assertTrue(refused["is_error"])
        self.assertIn("No scanner can be run from here", refused["content"])
        _, report = self.report()
        self.assertIn("1. Upgrade vsftpd.", report)
        self.assertIn("analyst reads: 3", self.out)

    def test_llm_error_still_saves_the_full_tool_report(self):
        def broken(target, **kwargs):
            raise RuntimeError("provider down")
        client = FakeClient([])
        code = self.run_main([TARGET], agent=broken, client=client)
        self.assertEqual(code, 0)
        self.assertIn("analysis:    failed: provider down", self.out)
        self.assertEqual(client.requests, [])  # no repair call after an error
        entry, report = self.report()
        self.assertEqual(entry["mode"], "ai")
        self.assertIn(SUMMARY_UNAVAILABLE, report)
        for section in ("## Open ports", "## Known exploits (Exploit-DB)", "EDB-49757",
                        "## Known CVEs (NVD)", "## Web technology (httpx)",
                        "## TLS checks (testssl.sh)", "## MITRE ATT&CK mapping"):
            self.assertIn(section, report)
        self.assertNotIn("Traceback", self.out)

    def test_rate_limit_still_saves_the_full_tool_report(self):
        def busy(target, **kwargs):
            raise llm.RateLimited(llm.RATE_LIMIT_MESSAGE)
        code = self.run_main([TARGET], agent=busy)
        self.assertEqual(code, 1)
        entry, report = self.report()
        self.assertIn(SUMMARY_RATE_LIMITED, report)
        self.assertIn("## Open ports", report)
        self.assertIn("EDB-49757", report)
        self.assertIn(llm.RATE_LIMIT_MESSAGE, self.out)
        self.assertIn("run id:", self.out)

    def test_summary_failing_after_repair_saves_the_notice(self):
        client = FakeClient([[text("still not a summary")]])
        code = self.run_main([TARGET], agent=lambda t, **k: (k["toolbox"], "no headings"),
                             client=client)
        self.assertEqual(code, 0)
        self.assertEqual(len(client.requests), 1)  # exactly one repair
        _, report = self.report()
        self.assertIn(SUMMARY_UNAVAILABLE, report)
        self.assertIn("## Open ports", report)

    def test_no_analysis_when_the_scan_did_not_run(self):
        scan = {"target": TARGET, "status": "nmap-not-found", "ports": []}
        code = self.run_main([TARGET], scan=scan)
        self.assertEqual(code, 0)
        self.assertEqual(self.order, ["pipeline"])
        self.assertIn("analysis:    skipped", self.out)


class StandardModeTests(RunnerCase):

    def test_standard_uses_no_llm(self):
        code = self.run_main([TARGET, "--mode", "standard"])
        self.assertEqual(code, 0)
        self.load.assert_not_called()
        self.make.assert_not_called()
        self.agent.assert_not_called()
        self.assertEqual(self.order, ["pipeline"])
        self.assertEqual(self.pipeline_kwargs["mode"], "standard")
        entry, report = self.report()
        self.assertEqual(entry["mode"], "standard")
        self.assertIn(STANDARD_NOTE, report)
        self.assertNotIn("Analyst summary", report)
        self.assertNotIn("unavailable", report)
        self.assertIn("## MITRE ATT&CK mapping", report)
        self.assertIn("mode=standard", self.out)


class ModeOptionTests(RunnerCase):

    def test_parse_mode(self):
        self.assertEqual(runner._parse_args([TARGET, "--mode", "ai"]).mode, "ai")
        self.assertEqual(runner._parse_args([TARGET, "--mode", "standard"]).mode, "standard")
        self.assertIsNone(runner._parse_args([TARGET]).mode)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.run_main([TARGET, "--mode", "turbo"]), 1)
        self.pipeline.assert_not_called()

    def test_default_is_ai_with_a_configured_key(self):
        code = self.run_main([TARGET])
        self.assertEqual(code, 0)
        self.assertEqual(self.order, ["pipeline", "analyst"])
        self.assertEqual(history.read_index()[-1]["mode"], "ai")
        self.assertIn("mode=ai", self.out)

    def test_default_is_standard_without_a_key(self):
        code = self.run_main([TARGET], config=None)
        self.assertEqual(code, 0)
        self.assertIn(runner.NO_KEY_STANDARD, self.out)
        self.make.assert_not_called()
        self.agent.assert_not_called()
        self.assertEqual(self.order, ["pipeline"])
        self.assertEqual(history.read_index()[-1]["mode"], "standard")

    def test_ai_without_a_key_exits_1(self):
        code = self.run_main([TARGET, "--mode", "ai"], config=None)
        self.assertEqual(code, 1)
        self.assertIn("OPENROUTER_API_KEY is not set", self.out)
        self.pipeline.assert_not_called()
        self.agent.assert_not_called()
        self.assertFalse(os.path.exists(os.path.join("reports", "index.json")))

    def test_provider_or_model_flag_asks_for_ai(self):
        for flags in (["--provider", "ollama"], ["--model", "some/model"],
                      ["--provider", "anthropic", "--model", "m"]):
            with self.subTest(flags=flags):
                code = self.run_main([TARGET] + flags, config=None)
                self.assertEqual(code, 1)
                self.assertIn("OPENROUTER_API_KEY is not set", self.out)
                self.assertNotIn(runner.NO_KEY_STANDARD, self.out)
                self.pipeline.assert_not_called()
                self.agent.assert_not_called()
        self.assertFalse(os.path.exists(os.path.join("reports", "index.json")))

    def test_provider_flag_with_a_working_config_runs_ai(self):
        code = self.run_main([TARGET, "--provider", "anthropic"])
        self.assertEqual(code, 0)
        self.assertEqual(self.order, ["pipeline", "analyst"])
        self.load.assert_called_with(provider="anthropic", model=None)

    def test_standard_mode_ignores_model_flags(self):
        code = self.run_main([TARGET, "--mode", "standard", "--model", "m"], config=None)
        self.assertEqual(code, 0)
        self.load.assert_not_called()
        self.assertEqual(self.order, ["pipeline"])

    def test_gate_refuses_before_anything_else(self):
        for argv in (["10.0.3.15", "--mode", "ai"], ["10.0.3.15", "--mode", "standard"],
                     ["10.0.3.15"]):
            with self.subTest(argv=argv):
                code = self.run_main(argv)
                self.assertEqual(code, 2)
                self.load.assert_not_called()
                self.make.assert_not_called()
                self.pipeline.assert_not_called()
                self.agent.assert_not_called()
                self.assertIn("REFUSED", self.out)

    def test_router_passes_mode_to_recon_only(self):
        with mock.patch.object(runner, "main", return_value=0) as agent_main, \
             contextlib.redirect_stdout(io.StringIO()):
            code = router.main(["python3 -m reconmind", TARGET, "--mode", "standard"])
        self.assertEqual(code, 0)
        agent_main.assert_called_once_with(["python3 -m reconmind.agent", TARGET,
                                            "--mode", "standard"])
        with open("app.py", "w") as fh:
            fh.write("print('hi')\n")
        out = io.StringIO()
        with mock.patch.object(runner, "main") as agent_main, contextlib.redirect_stdout(out):
            code = router.main(["python3 -m reconmind", "app.py", "--mode", "ai"])
        self.assertEqual(code, 1)
        agent_main.assert_not_called()
        self.assertIn("--mode only apply to an IPv4 target", out.getvalue())


class StopTests(RunnerCase):

    def test_stopped_pipeline_saves_a_partial_report_and_exits_4(self):
        scan = finished_scan()
        scan["status"] = "stopped"
        scan["stop"] = {"finished": ["nmap_scan"], "not_run": ["web_fingerprint port 80"]}
        code = self.run_main([TARGET], scan=scan)
        self.assertEqual(code, runner.EXIT_STOPPED)
        self.assertEqual(code, 4)
        self.agent.assert_not_called()
        entry, report = self.report()
        self.assertTrue(entry["stopped"])
        self.assertEqual(entry["status"], "stopped")
        self.assertTrue(report.startswith("# ReconMind Report\n\n**Stopped.**"))
        self.assertIn("- Did not run: web_fingerprint port 80", report)
        self.assertIn("run id:", self.out)
        self.assertIn("report:", self.out)

    def test_stop_during_the_analysis(self):
        def stopped(target, **kwargs):
            raise pipeline.StopRequested()
        code = self.run_main([TARGET], agent=stopped)
        self.assertEqual(code, 4)
        entry, report = self.report()
        self.assertTrue(entry["stopped"])
        self.assertIn("- Finished: nmap_scan", report)
        self.assertIn("- Did not run: AI analysis (stopped while running)", report)
        self.assertIn("## Open ports", report)  # every tool result is kept

    def test_sigterm_during_the_final_save_does_nothing(self):
        real_save = history.save_run
        handler_results = []

        def save_with_a_sigterm(scan, **kwargs):
            # A SIGTERM arrives while the final report is being saved.
            self.assertTrue(runner._saving["started"])
            handler_results.append(runner._on_sigterm(signal.SIGTERM, None))
            return real_save(scan, **kwargs)

        with mock.patch.object(runner, "save_run", side_effect=save_with_a_sigterm) as save:
            code = self.run_main([TARGET])
        self.assertEqual(code, 0)  # the save finished and the run exited normally
        self.assertEqual(save.call_count, 1)
        self.assertEqual(handler_results, [None])
        entries = history.read_index()
        self.assertEqual(len(entries), 1)
        self.assertFalse(entries[0]["stopped"])
        self.assertIn("run id:", self.out)
        self.assertFalse(runner._saving["started"])  # reset when the run ends

    def test_sigterm_before_the_save_still_stops(self):
        with runner._stop_on_sigterm():
            self.assertFalse(runner._saving["started"])
            with self.assertRaises(pipeline.StopRequested):
                runner._on_sigterm(signal.SIGTERM, None)

    def test_sigterm_handler_raises_once_and_is_restored(self):
        before = signal.getsignal(signal.SIGTERM)
        with runner._stop_on_sigterm():
            self.assertIs(signal.getsignal(signal.SIGTERM), runner._on_sigterm)
            with self.assertRaises(pipeline.StopRequested):
                runner._on_sigterm(signal.SIGTERM, None)
            # A second SIGTERM is ignored while the partial report is saved.
            self.assertEqual(signal.getsignal(signal.SIGTERM), signal.SIG_IGN)
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)


class HistoryModeTests(unittest.TestCase):

    def test_old_entries_read_fine(self):
        old = {"run_id": "old", "kind": "recon", "status": "ok"}
        self.assertEqual(history.entry_mode(old), "ai")
        self.assertFalse(history.entry_stopped(old))
        self.assertEqual(history.entry_mode({"run_id": "older"}), "ai")
        self.assertIsNone(history.entry_mode({"run_id": "c", "kind": "code"}))
        self.assertEqual(history.entry_mode({"kind": "recon", "mode": "standard"}), "standard")
        self.assertTrue(history.entry_stopped({"stopped": True}))


if __name__ == "__main__":
    unittest.main()
