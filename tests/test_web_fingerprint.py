"""
Offline tests for the web_fingerprint agent tool: it needs nmap_scan first,
refuses ports that are not open web ports, stores results in scan["web"],
and picks HTTPS for SSL services. run_whatweb is replaced by a mock, so
whatweb never runs.
"""

import copy
import json
import unittest
from unittest import mock

from reconmind.agent import prompts, tools as toolmod

TARGET = "10.10.1.100"

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

OK_RESULT = {
    "status": "ok", "url": "http://10.10.1.100:80", "http_status": 200,
    "components": [
        {"name": "Apache", "versions": ["2.2.8"], "strings": []},
        {"name": "HTTPServer", "versions": [], "strings": ["Apache/2.2.8 (Ubuntu) DAV/2"]},
        {"name": "nginx", "versions": [], "strings": []},
    ],
    "command": "whatweb --color=never --no-errors -a 1 --open-timeout 10 "
               "--read-timeout 20 --log-json=/tmp/x.json http://10.10.1.100:80",
}


def toolbox():
    tb = toolmod.ToolBox(TARGET)
    tb.scan = copy.deepcopy(SCAN)
    return tb


class WebFingerprintTests(unittest.TestCase):

    def test_requires_nmap_scan_first(self):
        tb = toolmod.ToolBox(TARGET)
        with mock.patch.object(toolmod, "run_whatweb") as run:
            obs, is_error = tb.call("web_fingerprint", {"port": 80})
        self.assertTrue(is_error)
        self.assertIn("Run nmap_scan first", obs)
        run.assert_not_called()

    def test_refuses_non_web_port(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_whatweb") as run:
            obs, is_error = tb.call("web_fingerprint", {"port": 22})
        self.assertTrue(is_error)
        message = json.loads(obs)["error"]
        self.assertIn("Port 22 (ssh) is not an HTTP or HTTPS service", message)
        self.assertIn("Web ports you can fingerprint: 80, 443, 8443, 8080.", message)
        run.assert_not_called()
        self.assertNotIn("web", tb.scan)

    def test_refuses_port_not_in_scan(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_whatweb") as run:
            obs, is_error = tb.call("web_fingerprint", {"port": 8180})
        self.assertTrue(is_error)
        message = json.loads(obs)["error"]
        self.assertIn("Port 8180 was not found open in the scan", message)
        self.assertIn("80, 443, 8443, 8080", message)
        run.assert_not_called()

    def test_stores_result_and_returns_compact_observation(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_whatweb", return_value=OK_RESULT) as run:
            obs, is_error = tb.call("web_fingerprint", {"port": 80})
        self.assertFalse(is_error)
        run.assert_called_once_with(TARGET, 80, use_https=False)
        self.assertEqual(tb.scan["web"][80], OK_RESULT)
        data = json.loads(obs)
        self.assertEqual(data["port"], 80)
        self.assertEqual(data["url"], "http://10.10.1.100:80")
        self.assertEqual(data["http_status"], 200)
        self.assertNotIn("command", data)
        self.assertEqual(data["components"], [
            {"name": "Apache", "versions": ["2.2.8"]},
            {"name": "HTTPServer", "strings": ["Apache/2.2.8 (Ubuntu) DAV/2"]},
            {"name": "nginx"},
        ])

    def test_several_ports_are_all_stored(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_whatweb", return_value=OK_RESULT):
            tb.call("web_fingerprint", {"port": 80})
            tb.call("web_fingerprint", {"port": 8080})
        self.assertEqual(sorted(tb.scan["web"]), [80, 8080])

    def test_picks_https_for_ssl_services(self):
        expected = {80: False, 443: True, 8443: True, 8080: False}
        for port, https in expected.items():
            tb = toolbox()
            with mock.patch.object(toolmod, "run_whatweb", return_value=OK_RESULT) as run:
                tb.call("web_fingerprint", {"port": port})
            run.assert_called_once_with(TARGET, port, use_https=https)

    def test_ssl_slash_http_service_name_uses_https(self):
        tb = toolbox()
        tb.scan["ports"].append({"port": 9443, "protocol": "tcp", "service": "ssl/http"})
        with mock.patch.object(toolmod, "run_whatweb", return_value=OK_RESULT) as run:
            tb.call("web_fingerprint", {"port": 9443})
        run.assert_called_once_with(TARGET, 9443, use_https=True)

    def test_only_this_runs_target_is_used(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_whatweb", return_value=OK_RESULT) as run:
            obs, is_error = tb.call("web_fingerprint", {"port": 80, "target": "10.10.1.200"})
        self.assertTrue(is_error)  # no target argument accepted
        run.assert_not_called()

    def test_missing_whatweb_is_an_error_observation(self):
        tb = toolbox()
        result = {"status": "whatweb-not-found", "url": "http://10.10.1.100:80",
                  "http_status": None, "components": [], "command": "",
                  "error": "whatweb is not installed on this machine."}
        with mock.patch.object(toolmod, "run_whatweb", return_value=result):
            obs, is_error = tb.call("web_fingerprint", {"port": 80})
        self.assertTrue(is_error)
        self.assertIn("whatweb is not installed", obs)
        self.assertEqual(tb.scan["web"][80]["status"], "whatweb-not-found")

    def test_failed_run_says_not_checked(self):
        tb = toolbox()
        result = {"status": "timeout", "url": "http://10.10.1.100:80", "http_status": None,
                  "components": [], "command": "whatweb ...",
                  "error": "whatweb did not finish within 120 seconds."}
        with mock.patch.object(toolmod, "run_whatweb", return_value=result):
            obs, is_error = tb.call("web_fingerprint", {"port": 80})
        self.assertTrue(is_error)
        message = json.loads(obs)["error"]
        self.assertIn("status=timeout", message)
        self.assertIn("This port was not checked.", message)
        self.assertNotIn(" - ", message)

    def test_gate_refusal_is_reported(self):
        tb = toolbox()
        result = {"status": "refused", "url": "", "http_status": None,
                  "components": [], "command": ""}
        with mock.patch.object(toolmod, "run_whatweb", return_value=result):
            obs, is_error = tb.call("web_fingerprint", {"port": 80})
        self.assertTrue(is_error)
        self.assertIn("authorization gate", obs)


class SpecAndPromptTests(unittest.TestCase):

    def test_tool_spec(self):
        spec = next(s for s in toolmod.TOOL_SPECS if s["name"] == "web_fingerprint")
        self.assertIn("whatweb", spec["description"])
        self.assertIn("one normal request, plus any redirects the server sends",
                      spec["description"])
        schema = spec["input_schema"]
        self.assertEqual(list(schema["properties"]), ["port"])
        self.assertEqual(schema["properties"]["port"]["type"], "integer")
        self.assertEqual(schema["required"], ["port"])

    def test_prompt_rule_and_end_marker(self):
        self.assertIn("After nmap_scan, call web_fingerprint once for every open HTTP or "
                      "HTTPS port", prompts.SYSTEM_PROMPT)
        self.assertIn("END OF SUMMARY", prompts.SYSTEM_PROMPT)
        self.assertIn("Start with nmap_scan", prompts.SYSTEM_PROMPT)

    def test_new_text_has_no_dash_separators(self):
        spec = next(s for s in toolmod.TOOL_SPECS if s["name"] == "web_fingerprint")
        for text in (spec["description"], prompts.SYSTEM_PROMPT):
            self.assertNotIn("—", text)
            self.assertNotIn(" - ", text)


if __name__ == "__main__":
    unittest.main()
