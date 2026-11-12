"""
Offline tests for the web_discover agent tool, its prompt rule and the
report's web content discovery section. run_ffuf is replaced by a mock, so
ffuf never runs. raw_json must never reach the observation or the report.
"""

import copy
import json
import os
import tempfile
import unittest
from unittest import mock

from reconmind.agent import prompts, tools as toolmod
from reconmind.core.report import build_report
from reconmind.tools import ffuf_scan

TARGET = "10.10.1.100"
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "ffuf_output.json")
with open(FIXTURE) as _fh:
    RAW_JSON = _fh.read()

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


def ok_result():
    """What run_ffuf returns for the fixture, built by the real parser."""
    _, results, _, _ = ffuf_scan._parse_json(RAW_JSON)
    return {"status": "ok", "url": "http://10.10.1.100:80",
            "wordlist": "/usr/share/wordlists/dirb/common.txt", "wordlist_lines": 4614,
            "wordlist_sha256": "a" * 64,
            "command": "ffuf -u http://10.10.1.100:80/FUZZ -w "
                       "/usr/share/wordlists/dirb/common.txt -rate 50",
            "results": results, "raw_json": RAW_JSON}


def toolbox():
    tb = toolmod.ToolBox(TARGET)
    tb.scan = copy.deepcopy(SCAN)
    return tb


class WebDiscoverTests(unittest.TestCase):

    def test_requires_nmap_scan_first(self):
        tb = toolmod.ToolBox(TARGET)
        with mock.patch.object(toolmod, "run_ffuf") as run:
            obs, is_error = tb.call("web_discover", {"port": 80})
        self.assertTrue(is_error)
        self.assertIn("Run nmap_scan first", obs)
        run.assert_not_called()

    def test_refuses_non_web_port(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_ffuf") as run:
            obs, is_error = tb.call("web_discover", {"port": 22})
        self.assertTrue(is_error)
        message = json.loads(obs)["error"]
        self.assertIn("Port 22 (ssh) is not an HTTP or HTTPS service", message)
        self.assertIn("Web ports you can discover content on: 80, 443, 8443, 8080.", message)
        run.assert_not_called()
        self.assertNotIn("discovery", tb.scan)

    def test_refuses_port_not_in_scan(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_ffuf") as run:
            obs, is_error = tb.call("web_discover", {"port": 8180})
        self.assertTrue(is_error)
        self.assertIn("Port 8180 was not found open in the scan", json.loads(obs)["error"])
        run.assert_not_called()

    def test_refuses_non_number_port(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_ffuf") as run:
            obs, is_error = tb.call("web_discover", {"port": "eighty"})
        self.assertTrue(is_error)
        self.assertIn("Port must be a number", obs)
        run.assert_not_called()

    def test_web_fingerprint_messages_unchanged(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_whatweb") as run:
            obs, _ = tb.call("web_fingerprint", {"port": 22})
        self.assertIn("Web ports you can fingerprint: 80, 443, 8443, 8080.",
                      json.loads(obs)["error"])
        run.assert_not_called()

    def test_picks_https_like_web_fingerprint(self):
        expected = {80: False, 443: True, 8443: True, 8080: False}
        for port, https in expected.items():
            tb = toolbox()
            with mock.patch.object(toolmod, "run_ffuf", return_value=ok_result()) as run:
                tb.call("web_discover", {"port": port})
            run.assert_called_once_with(TARGET, port, use_https=https)

    def test_only_this_runs_target_is_used(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_ffuf", return_value=ok_result()) as run:
            obs, is_error = tb.call("web_discover", {"port": 80, "target": "10.10.1.200"})
        self.assertTrue(is_error)  # no target argument accepted
        run.assert_not_called()

    def test_stores_full_result(self):
        tb = toolbox()
        result = ok_result()
        with mock.patch.object(toolmod, "run_ffuf", return_value=result):
            tb.call("web_discover", {"port": 80})
            tb.call("web_discover", {"port": 8080})
        self.assertEqual(sorted(tb.scan["discovery"]), [80, 8080])
        self.assertEqual(tb.scan["discovery"][80], result)
        self.assertEqual(tb.scan["discovery"][80]["raw_json"], RAW_JSON)

    def test_compact_observation(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_ffuf", return_value=ok_result()):
            obs, is_error = tb.call("web_discover", {"port": 80})
        self.assertFalse(is_error)
        data = json.loads(obs)
        self.assertEqual(data["port"], 80)
        self.assertEqual(data["url"], "http://10.10.1.100:80")
        self.assertEqual(data["wordlist"], "common.txt")
        self.assertEqual(data["wordlist_lines"], 4614)
        self.assertEqual(data["result_count"], 12)
        paths = [r["path"] for r in data["results"]]
        self.assertEqual(paths, sorted(paths))
        self.assertEqual(paths[0], ".htaccess")
        dav = next(r for r in data["results"] if r["path"] == "dav")
        self.assertEqual(dav, {"path": "dav", "status": 301, "length": 321,
                               "redirect": "http://10.10.1.100/dav/"})
        index = next(r for r in data["results"] if r["path"] == "index")
        self.assertNotIn("redirect", index)

    def test_raw_json_and_command_never_sent(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_ffuf", return_value=ok_result()):
            obs, _ = tb.call("web_discover", {"port": 80})
        data = json.loads(obs)
        for key in ("raw_json", "command", "wordlist_sha256"):
            self.assertNotIn(key, data)
        for marker in ("FFUFHASH", "commandline", "content-type", "autocalibration", "a" * 64):
            self.assertNotIn(marker, obs)

    def test_only_first_40_sorted_by_path(self):
        result = ok_result()
        result["results"] = [{"path": "p{n:03d}".format(n=n), "status": 200, "length": n,
                              "words": 1, "lines": 1, "redirect": ""}
                             for n in range(99, -1, -1)]
        tb = toolbox()
        with mock.patch.object(toolmod, "run_ffuf", return_value=result):
            obs, _ = tb.call("web_discover", {"port": 80})
        data = json.loads(obs)
        self.assertEqual(data["result_count"], 100)
        self.assertEqual(len(data["results"]), 40)
        self.assertEqual(data["results"][0]["path"], "p000")
        self.assertEqual(data["results"][-1]["path"], "p039")
        self.assertEqual(len(tb.scan["discovery"][80]["results"]), 100)

    def test_error_statuses(self):
        cases = {
            "refused": "authorization gate",
            "ffuf-not-found": "ffuf is not installed",
            "wordlist-not-found": "No wordlist was found",
            "timeout": "This port was not checked.",
        }
        for status, text in cases.items():
            tb = toolbox()
            result = dict(ok_result(), status=status, results=[], raw_json="",
                          error="ffuf did not finish within 360 seconds.")
            with mock.patch.object(toolmod, "run_ffuf", return_value=result):
                obs, is_error = tb.call("web_discover", {"port": 80})
            self.assertTrue(is_error, status)
            message = json.loads(obs)["error"]
            self.assertIn(text, message)
            self.assertNotIn(" - ", message)
            self.assertNotIn("—", message)
            self.assertEqual(tb.scan["discovery"][80]["status"], status)


class SpecAndPromptTests(unittest.TestCase):

    def spec(self):
        return next(s for s in toolmod.TOOL_SPECS if s["name"] == "web_discover")

    def test_tool_spec(self):
        spec = self.spec()
        self.assertIn("ffuf", spec["description"])
        self.assertIn("no recursion", spec["description"])
        schema = spec["input_schema"]
        self.assertEqual(list(schema["properties"]), ["port"])
        self.assertEqual(schema["properties"]["port"]["type"], "integer")
        self.assertEqual(schema["required"], ["port"])

    def test_prompt_rule(self):
        self.assertIn("After web_fingerprint, call web_discover once for each open HTTP or "
                      "HTTPS port.", prompts.SYSTEM_PROMPT)
        self.assertLess(prompts.SYSTEM_PROMPT.index("call web_fingerprint once"),
                        prompts.SYSTEM_PROMPT.index("call web_discover once"))

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
    "web": {80: {"status": "ok", "url": "http://10.10.1.100:80", "http_status": 200,
                 "command": "whatweb ...",
                 "components": [{"name": "Apache", "versions": ["2.2.8"], "strings": []}]}},
    "discovery": {
        80: ok_result(),
        443: dict(ok_result(), status="timeout", url="https://10.10.1.100:443",
                  results=[], raw_json="", error="ffuf did not finish within 360 seconds."),
        8080: dict(ok_result(), url="http://10.10.1.100:8080", results=[],
                   raw_json='{"results": []}'),
    },
}
DISCOVERY_HEAD = "## Web content discovery (ffuf)"


class DiscoveryReportTests(unittest.TestCase):

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
        return report.split(DISCOVERY_HEAD)[1].split("\n## ")[0]

    def test_section_after_web_technology(self):
        report = self.read(REPORT_SCAN)
        self.assertIn(DISCOVERY_HEAD, report)
        self.assertLess(report.index("## Web technology (whatweb)"),
                        report.index(DISCOVERY_HEAD))
        self.assertLess(report.index(DISCOVERY_HEAD), report.index("## Notes"))

    def test_url_wordlist_and_every_result(self):
        section = self.section(self.read(REPORT_SCAN))
        self.assertIn("**80/tcp** http://10.10.1.100:80", section)
        self.assertIn("Wordlist: common.txt (4614 lines)", section)
        self.assertIn("| Path | Status | Size | Redirect |", section)
        self.assertIn("| dav | 301 | 321 | http://10.10.1.100/dav/ |", section)
        self.assertIn("| phpinfo.php | 200 | 48083 |  |", section)
        self.assertIn("| cgi-bin/ | 403 | 295 |  |", section)
        rows = [l for l in section.splitlines()
                if l.startswith("| ") and not l.startswith("| Path")]
        self.assertEqual(len(rows), 12)
        paths = [r.split(" | ")[0][2:] for r in rows]
        self.assertEqual(paths, sorted(paths))

    def test_failed_and_empty_ports(self):
        section = self.section(self.read(REPORT_SCAN))
        self.assertIn("**443/tcp** https://10.10.1.100:443", section)
        self.assertIn("_ffuf did not complete (status timeout), so this port was not "
                      "checked._", section)
        self.assertIn("**8080/tcp** http://10.10.1.100:8080", section)
        self.assertIn("_ffuf found no matching paths._", section)

    def test_not_checked_line(self):
        section = self.section(self.read(REPORT_SCAN))
        self.assertIn("**Not checked:** these open web ports were not scanned for content "
                      "with ffuf: 8180/tcp (http).", section)
        self.assertNotIn("22/tcp", section)

    def test_all_not_checked_without_discovery(self):
        scan = {k: v for k, v in REPORT_SCAN.items() if k != "discovery"}
        section = self.section(self.read(scan))
        self.assertIn("ffuf: 80/tcp (http), 443/tcp (http), 8080/tcp (http-proxy), "
                      "8180/tcp (http).", section)

    def test_string_port_keys_from_json(self):
        scan = dict(REPORT_SCAN,
                    discovery={str(k): v for k, v in REPORT_SCAN["discovery"].items()})
        section = self.section(self.read(scan))
        self.assertIn("| dav | 301 | 321 | http://10.10.1.100/dav/ |", section)
        self.assertIn("ffuf: 8180/tcp (http).", section)

    def test_no_section_without_web_ports(self):
        scan = {"target": TARGET, "status": "ok",
                "ports": [{"port": 22, "protocol": "tcp", "service": "ssh",
                           "product": "OpenSSH", "version": "4.7p1", "exploits": []}]}
        self.assertNotIn(DISCOVERY_HEAD, self.read(scan))
        self.assertNotIn(DISCOVERY_HEAD, self.read({"target": TARGET, "status": "ok",
                                                    "ports": []}))

    def test_raw_json_never_printed(self):
        report = self.read(REPORT_SCAN)
        for marker in ("FFUFHASH", "commandline", "content-type", "autocalibration",
                       "a" * 64, "-rate 50"):
            self.assertNotIn(marker, report)

    def test_our_text_has_no_em_dashes_or_dash_separators(self):
        report = self.read(REPORT_SCAN)
        report += self.read({k: v for k, v in REPORT_SCAN.items() if k != "discovery"})
        for p in REPORT_SCAN["ports"]:
            report = report.replace(p["version"], "")  # nmap data, not our text
        for result in REPORT_SCAN["discovery"].values():
            for r in result["results"]:  # ffuf data, not our text
                for v in (r["path"], r["redirect"]):
                    if v:
                        report = report.replace(v, "")
        self.assertIn(DISCOVERY_HEAD, report)
        self.assertNotIn("—", report)
        self.assertNotIn(" - ", report)


if __name__ == "__main__":
    unittest.main()
