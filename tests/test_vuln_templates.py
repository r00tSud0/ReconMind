"""
Offline tests for the vuln_templates agent tool, its prompt rule and the
report's nuclei template checks section. run_nuclei is replaced by a mock, so
nuclei never runs. raw_jsonl must never reach the observation or the report.
"""

import copy
import json
import os
import tempfile
import unittest
from unittest import mock

from reconmind.agent import prompts, tools as toolmod
from reconmind.core.report import build_report
from reconmind.tools import nuclei_scan

TARGET = "10.10.1.100"
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "nuclei_output.jsonl")
with open(FIXTURE) as _fh:
    RAW_JSONL = _fh.read()

SCAN = {
    "target": TARGET, "status": "ok",
    "ports": [
        {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH",
         "version": "4.7p1", "tunnel": ""},
        {"port": 80, "protocol": "tcp", "service": "http", "product": "Apache httpd",
         "version": "2.2.8", "tunnel": ""},
        {"port": 443, "protocol": "tcp", "service": "http", "product": "Apache httpd",
         "version": "2.2.8", "tunnel": "ssl"},
        {"port": 8443, "protocol": "tcp", "service": "https", "product": "", "version": ""},
        {"port": 8080, "protocol": "tcp", "service": "http-proxy", "product": "",
         "version": ""},
    ],
}

COMMAND = ("nuclei -u http://10.10.1.100:80 -type http -severity low,medium,high,critical "
           "-exclude-tags dos,fuzz,intrusive,default-login,bruteforce,brute-force "
           "-no-interactsh -disable-update-check -rate-limit 50")

# Strings that only exist in the raw JSONL or the command, never in our output.
RAW_MARKERS = ("curl-command", "template-path", "cvss-metrics", "matcher-status",
               "/root/nuclei-templates", "allow_url_include%3don'", "-rate-limit",
               "-no-interactsh", "pikpikcu", "epss-score")


def ok_result():
    """What run_nuclei returns for the fixture, built by the real parser."""
    _, findings, _ = nuclei_scan.parse_jsonl(RAW_JSONL)
    return {"status": "ok", "url": "http://10.10.1.100:80", "templates_version": "v10.5.2",
            "command": COMMAND, "findings": findings, "raw_jsonl": RAW_JSONL}


def toolbox():
    tb = toolmod.ToolBox(TARGET)
    tb.scan = copy.deepcopy(SCAN)
    return tb


class VulnTemplatesTests(unittest.TestCase):

    def test_requires_nmap_scan_first(self):
        tb = toolmod.ToolBox(TARGET)
        with mock.patch.object(toolmod, "run_nuclei") as run:
            obs, is_error = tb.call("vuln_templates", {"port": 80})
        self.assertTrue(is_error)
        self.assertIn("Run nmap_scan first", obs)
        run.assert_not_called()

    def test_refuses_non_web_port(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_nuclei") as run:
            obs, is_error = tb.call("vuln_templates", {"port": 22})
        self.assertTrue(is_error)
        message = json.loads(obs)["error"]
        self.assertIn("Port 22 (ssh) is not an HTTP or HTTPS service", message)
        self.assertIn("Web ports you can run templates against: 80, 443, 8443, 8080.", message)
        run.assert_not_called()
        self.assertNotIn("nuclei", tb.scan)

    def test_refuses_port_not_in_scan(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_nuclei") as run:
            obs, is_error = tb.call("vuln_templates", {"port": 8180})
        self.assertTrue(is_error)
        self.assertIn("Port 8180 was not found open in the scan", json.loads(obs)["error"])
        run.assert_not_called()

    def test_refuses_non_number_port(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_nuclei") as run:
            obs, is_error = tb.call("vuln_templates", {"port": "eighty"})
        self.assertTrue(is_error)
        self.assertIn("Port must be a number", obs)
        run.assert_not_called()

    def test_picks_https_like_web_fingerprint(self):
        expected = {80: False, 443: True, 8443: True, 8080: False}
        for port, https in expected.items():
            tb = toolbox()
            with mock.patch.object(toolmod, "run_nuclei", return_value=ok_result()) as run:
                tb.call("vuln_templates", {"port": port})
            run.assert_called_once_with(TARGET, port, use_https=https)

    def test_only_this_runs_target_is_used(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_nuclei", return_value=ok_result()) as run:
            obs, is_error = tb.call("vuln_templates", {"port": 80, "target": "10.10.1.200"})
        self.assertTrue(is_error)  # no target argument accepted
        run.assert_not_called()

    def test_stores_full_result(self):
        tb = toolbox()
        result = ok_result()
        with mock.patch.object(toolmod, "run_nuclei", return_value=result):
            tb.call("vuln_templates", {"port": 80})
            tb.call("vuln_templates", {"port": 8080})
        self.assertEqual(sorted(tb.scan["nuclei"]), [80, 8080])
        self.assertEqual(tb.scan["nuclei"][80], result)
        self.assertEqual(tb.scan["nuclei"][80]["raw_jsonl"], RAW_JSONL)

    def test_compact_observation(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_nuclei", return_value=ok_result()):
            obs, is_error = tb.call("vuln_templates", {"port": 80})
        self.assertFalse(is_error)
        data = json.loads(obs)
        self.assertEqual(data["port"], 80)
        self.assertEqual(data["url"], "http://10.10.1.100:80")
        self.assertEqual(data["templates_version"], "v10.5.2")
        self.assertEqual(data["severity_counts"],
                         {"critical": 1, "high": 1, "medium": 0, "low": 2})
        self.assertEqual(data["finding_count"], 4)
        self.assertEqual([f["template_id"] for f in data["findings"]], [
            "CVE-2009-1151", "CVE-2012-1823", "phpinfo-files",
            "apache-mod-negotiation-listing"])  # most severe first
        self.assertEqual(data["findings"][1], {
            "template_id": "CVE-2012-1823",
            "name": "PHP CGI v5.3.12/5.4.2 Remote Code Execution", "severity": "high",
            "matched_at": "http://10.10.1.100:80/index.php?-d+allow_url_include%3don+-d+"
                          "auto_prepend_file%3dphp%3a//input",
            "cve": ["CVE-2012-1823"]})
        self.assertEqual(data["findings"][2]["cve"], [])
        for f in data["findings"]:
            self.assertEqual(set(f), {"template_id", "name", "severity", "matched_at", "cve"})

    def test_raw_jsonl_and_command_never_sent(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_nuclei", return_value=ok_result()):
            obs, _ = tb.call("vuln_templates", {"port": 80})
        data = json.loads(obs)
        for key in ("raw_jsonl", "command"):
            self.assertNotIn(key, data)
        for marker in RAW_MARKERS:
            self.assertNotIn(marker, obs)

    def test_no_findings(self):
        tb = toolbox()
        result = dict(ok_result(), findings=[], raw_jsonl="")
        with mock.patch.object(toolmod, "run_nuclei", return_value=result):
            obs, is_error = tb.call("vuln_templates", {"port": 80})
        self.assertFalse(is_error)
        data = json.loads(obs)
        self.assertEqual(data["finding_count"], 0)
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["severity_counts"],
                         {"critical": 0, "high": 0, "medium": 0, "low": 0})

    def test_error_statuses(self):
        cases = {
            "refused": "authorization gate",
            "nuclei-not-found": "nuclei is not installed",
            "templates-not-found": "nuclei -update-templates once",
            "timeout": "This port was not checked.",
        }
        for status, text in cases.items():
            tb = toolbox()
            result = dict(ok_result(), status=status, findings=[], raw_jsonl="",
                          error="nuclei did not finish within 1800 seconds.")
            with mock.patch.object(toolmod, "run_nuclei", return_value=result):
                obs, is_error = tb.call("vuln_templates", {"port": 80})
            self.assertTrue(is_error, status)
            message = json.loads(obs)["error"]
            self.assertIn(text, message)
            self.assertIn("Do not retry" if status != "timeout" else "status=timeout", message)
            self.assertNotIn(" - ", message)
            self.assertNotIn("—", message)
            self.assertEqual(tb.scan["nuclei"][80]["status"], status)


class SpecAndPromptTests(unittest.TestCase):

    def spec(self):
        return next(s for s in toolmod.TOOL_SPECS if s["name"] == "vuln_templates")

    def test_tool_spec(self):
        spec = self.spec()
        for text in ("nuclei", "Denial of service", "interactsh", "never updated"):
            self.assertIn(text, spec["description"])
        schema = spec["input_schema"]
        self.assertEqual(list(schema["properties"]), ["port"])
        self.assertEqual(schema["properties"]["port"]["type"], "integer")
        self.assertEqual(schema["required"], ["port"])

    def test_prompt_rule(self):
        self.assertIn("After web_discover, call vuln_templates once for each open HTTP or "
                      "HTTPS port.", prompts.SYSTEM_PROMPT)
        self.assertLess(prompts.SYSTEM_PROMPT.index("call web_discover once"),
                        prompts.SYSTEM_PROMPT.index("call vuln_templates once"))

    def test_new_text_has_no_dash_separators(self):
        for text in (self.spec()["description"], prompts.SYSTEM_PROMPT):
            self.assertNotIn("—", text)
            self.assertNotIn(" - ", text)


REPORT_SCAN = {
    "target": TARGET, "status": "ok",
    "ports": [
        {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH",
         "version": "4.7p1", "exploits": []},
        {"port": 80, "protocol": "tcp", "service": "http", "product": "Apache httpd",
         "version": "2.2.8", "exploits": []},
        {"port": 443, "protocol": "tcp", "service": "http", "tunnel": "ssl",
         "product": "Apache httpd", "version": "2.2.8", "exploits": []},
        {"port": 8080, "protocol": "tcp", "service": "http-proxy", "product": "",
         "version": "", "exploits": []},
        {"port": 8180, "protocol": "tcp", "service": "http", "product": "Apache Tomcat",
         "version": "5.5", "exploits": []},
    ],
    "discovery": {80: {"status": "ok", "url": "http://10.10.1.100:80",
                       "wordlist": "/usr/share/wordlists/dirb/common.txt",
                       "wordlist_lines": 4614, "results": [], "raw_json": ""}},
    "nuclei": {
        80: ok_result(),
        443: dict(ok_result(), status="timeout", url="https://10.10.1.100:443",
                  findings=[], raw_jsonl="", error="nuclei did not finish within 1800 seconds."),
        8080: dict(ok_result(), url="http://10.10.1.100:8080", findings=[], raw_jsonl=""),
    },
}
NUCLEI_HEAD = "## Template checks (nuclei)"
EXCLUDED_LINE = ("Excluded: denial of service, fuzzing, intrusive, default login and brute "
                 "force templates. No outside callbacks (interactsh off).")


class NucleiReportTests(unittest.TestCase):

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def read(self, scan):
        with open(build_report(scan)) as fh:
            return fh.read()

    def section(self, report):
        return report.split(NUCLEI_HEAD)[1].split("\n## ")[0]

    def test_section_after_content_discovery(self):
        report = self.read(REPORT_SCAN)
        self.assertIn(NUCLEI_HEAD, report)
        self.assertLess(report.index("## Web content discovery (ffuf)"),
                        report.index(NUCLEI_HEAD))
        self.assertLess(report.index(NUCLEI_HEAD), report.index("## Notes"))

    def test_url_version_exclusions_and_findings(self):
        section = self.section(self.read(REPORT_SCAN))
        lines = section.splitlines()
        self.assertIn("**80/tcp** http://10.10.1.100:80", lines)
        self.assertIn("Templates version: v10.5.2", lines)
        self.assertIn(EXCLUDED_LINE, lines)
        findings = [l for l in lines if l.startswith("- [")]
        self.assertEqual(findings, [
            "- [critical] PhpMyAdmin Scripts - Remote Code Execution, template "
            "CVE-2009-1151, matched at http://10.10.1.100:80/phpMyAdmin/scripts/setup.php, "
            "CVE-2009-1151",
            "- [high] PHP CGI v5.3.12/5.4.2 Remote Code Execution, template CVE-2012-1823, "
            "matched at http://10.10.1.100:80/index.php?-d+allow_url_include%3don+-d+"
            "auto_prepend_file%3dphp%3a//input, CVE-2012-1823",
            "- [low] PHPInfo Page - Detect, template phpinfo-files, matched at "
            "http://10.10.1.100:80/phpinfo.php",
            "- [low] Apache mod_negotiation Pseudo Directory Listing, template "
            "apache-mod-negotiation-listing, matched at http://10.10.1.100:80/index",
        ])

    def test_failed_and_empty_ports(self):
        section = self.section(self.read(REPORT_SCAN))
        self.assertIn("**443/tcp** https://10.10.1.100:443", section)
        self.assertIn("_nuclei did not complete (status timeout), so this port was not "
                      "checked._", section)
        self.assertIn("**8080/tcp** http://10.10.1.100:8080", section)
        self.assertIn("_nuclei found nothing at low severity or above._", section)
        self.assertEqual(section.count(EXCLUDED_LINE), 2)  # only ports that ran

    def test_not_checked_line(self):
        section = self.section(self.read(REPORT_SCAN))
        self.assertIn("**Not checked:** these open web ports were not checked with nuclei "
                      "templates: 8180/tcp (http).", section)
        self.assertNotIn("22/tcp", section)

    def test_all_not_checked_without_nuclei(self):
        scan = {k: v for k, v in REPORT_SCAN.items() if k != "nuclei"}
        section = self.section(self.read(scan))
        self.assertIn("nuclei templates: 80/tcp (http), 443/tcp (http), 8080/tcp "
                      "(http-proxy), 8180/tcp (http).", section)

    def test_string_port_keys_from_json(self):
        scan = dict(REPORT_SCAN, nuclei={str(k): v for k, v in REPORT_SCAN["nuclei"].items()})
        section = self.section(self.read(scan))
        self.assertIn("template CVE-2012-1823", section)
        self.assertIn("nuclei templates: 8180/tcp (http).", section)

    def test_no_section_without_web_ports(self):
        scan = {"target": TARGET, "status": "ok",
                "ports": [{"port": 22, "protocol": "tcp", "service": "ssh",
                           "product": "OpenSSH", "version": "4.7p1", "exploits": []}]}
        self.assertNotIn(NUCLEI_HEAD, self.read(scan))

    def test_raw_jsonl_never_printed(self):
        report = self.read(REPORT_SCAN)
        for marker in RAW_MARKERS + ("5.2.4-2ubuntu5.10", "CWE-94", "cwe-200"):
            self.assertNotIn(marker, report)

    def test_our_text_has_no_em_dashes_or_dash_separators(self):
        report = self.read(REPORT_SCAN)
        report += self.read({k: v for k, v in REPORT_SCAN.items() if k != "nuclei"})
        for p in REPORT_SCAN["ports"]:
            report = report.replace(p["version"], "")  # nmap data, not our text
        for result in REPORT_SCAN["nuclei"].values():
            for f in result["findings"]:  # nuclei data, not our text
                for v in [f["name"], f["template_id"], f["matched_at"]] + f["cve"]:
                    if v:
                        report = report.replace(v, "")
        self.assertIn(NUCLEI_HEAD, report)
        self.assertNotIn("—", report)
        self.assertNotIn(" - ", report)


if __name__ == "__main__":
    unittest.main()
