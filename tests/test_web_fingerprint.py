"""
Offline tests for the web_fingerprint agent tool: it needs nmap_scan first,
refuses ports that are not open web ports, stores results in scan["web"],
picks HTTPS for SSL services, and falls back to the basic header check only
when httpx times out or fails. run_httpx and basic_http_fingerprint are
replaced by mocks, so nothing runs.
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

RAW_JSON = ('{"url":"http://10.10.1.100:80","title":"Metasploitable2 - Linux",'
            '"webserver":"Apache/2.2.8 (Ubuntu) DAV/2","status_code":200}\n')

OK_RESULT = {
    "status": "ok", "url": "http://10.10.1.100:80", "http_status": 200,
    "server": "Apache/2.2.8 (Ubuntu) DAV/2", "title": "Metasploitable2 - Linux",
    "location": "",
    "technologies": [
        {"name": "Apache HTTP Server", "version": "2.2.8", "raw": "Apache HTTP Server:2.2.8"},
        {"name": "PHP", "version": "5.2.4", "raw": "PHP:5.2.4"},
        {"name": "Ubuntu", "version": "", "raw": "Ubuntu"},
    ],
    "command": "httpx-toolkit -u http://10.10.1.100:80 -tech-detect -title -server "
               "-status-code -location -json -silent -no-color -timeout 10 -retries 1 "
               "-disable-update-check",
    "raw_json": RAW_JSON,
}

BASIC_RESULT = {
    "status": "ok", "url": "http://10.10.1.100:80", "method": "basic header check",
    "http_status": 200, "server": "Apache/2.2.8 (Ubuntu) DAV/2",
    "x_powered_by": "PHP/5.2.4-2ubuntu5.10", "title": "Metasploitable2 - Linux",
}


def httpx_result(status, error="httpx went wrong."):
    return {"status": status, "url": "http://10.10.1.100:80", "http_status": None,
            "server": "", "title": "", "location": "", "technologies": [],
            "command": "httpx-toolkit ...", "raw_json": "", "error": error}


def toolbox():
    tb = toolmod.ToolBox(TARGET)
    tb.scan = copy.deepcopy(SCAN)
    return tb


def patched(httpx=OK_RESULT, basic=BASIC_RESULT):
    """Patch both engines; each call gets its own copy of the canned result."""
    return (mock.patch.object(toolmod, "run_httpx",
                              side_effect=lambda *a, **k: copy.deepcopy(httpx)),
            mock.patch.object(toolmod, "basic_http_fingerprint",
                              side_effect=lambda *a, **k: copy.deepcopy(basic)))


class WebFingerprintTests(unittest.TestCase):

    def call(self, tb, args, httpx=OK_RESULT, basic=BASIC_RESULT):
        run_patch, basic_patch = patched(httpx, basic)
        with run_patch as run, basic_patch as fallback:
            obs, is_error = tb.call("web_fingerprint", args)
        return obs, is_error, run, fallback

    def test_requires_nmap_scan_first(self):
        obs, is_error, run, fallback = self.call(toolmod.ToolBox(TARGET), {"port": 80})
        self.assertTrue(is_error)
        self.assertIn("Run nmap_scan first", obs)
        run.assert_not_called()
        fallback.assert_not_called()

    def test_refuses_non_web_port(self):
        tb = toolbox()
        obs, is_error, run, _ = self.call(tb, {"port": 22})
        self.assertTrue(is_error)
        message = json.loads(obs)["error"]
        self.assertIn("Port 22 (ssh) is not an HTTP or HTTPS service", message)
        self.assertIn("Web ports you can fingerprint: 80, 443, 8443, 8080.", message)
        run.assert_not_called()
        self.assertNotIn("web", tb.scan)

    def test_refuses_port_not_in_scan(self):
        obs, is_error, run, _ = self.call(toolbox(), {"port": 8180})
        self.assertTrue(is_error)
        message = json.loads(obs)["error"]
        self.assertIn("Port 8180 was not found open in the scan", message)
        self.assertIn("80, 443, 8443, 8080", message)
        run.assert_not_called()

    def test_stores_result_and_returns_compact_observation(self):
        tb = toolbox()
        obs, is_error, run, fallback = self.call(tb, {"port": 80})
        self.assertFalse(is_error)
        run.assert_called_once_with(TARGET, 80, use_https=False)
        fallback.assert_not_called()
        self.assertEqual(tb.scan["web"][80], OK_RESULT)
        data = json.loads(obs)
        self.assertEqual(data, {
            "port": 80, "url": "http://10.10.1.100:80", "http_status": 200,
            "server": "Apache/2.2.8 (Ubuntu) DAV/2", "title": "Metasploitable2 - Linux",
            "technologies": [{"name": "Apache HTTP Server", "version": "2.2.8"},
                             {"name": "PHP", "version": "5.2.4"},
                             {"name": "Ubuntu"}]})
        self.assertNotIn("raw_json", obs)
        self.assertNotIn("command", data)

    def test_location_is_shown_when_present(self):
        result = dict(OK_RESULT, http_status=302, location="/admin/")
        data = json.loads(self.call(toolbox(), {"port": 80}, httpx=result)[0])
        self.assertEqual(data["location"], "/admin/")

    def test_several_ports_are_all_stored(self):
        tb = toolbox()
        run_patch, basic_patch = patched()
        with run_patch, basic_patch:
            tb.call("web_fingerprint", {"port": 80})
            tb.call("web_fingerprint", {"port": 8080})
        self.assertEqual(sorted(tb.scan["web"]), [80, 8080])

    def test_picks_https_for_ssl_services(self):
        expected = {80: False, 443: True, 8443: True, 8080: False}
        for port, https in expected.items():
            _, _, run, _ = self.call(toolbox(), {"port": port})
            run.assert_called_once_with(TARGET, port, use_https=https)

    def test_ssl_slash_http_service_name_uses_https(self):
        tb = toolbox()
        tb.scan["ports"].append({"port": 9443, "protocol": "tcp", "service": "ssl/http"})
        _, _, run, _ = self.call(tb, {"port": 9443})
        run.assert_called_once_with(TARGET, 9443, use_https=True)

    def test_only_this_runs_target_is_used(self):
        obs, is_error, run, _ = self.call(toolbox(), {"port": 80, "target": "10.10.1.200"})
        self.assertTrue(is_error)  # no target argument accepted
        run.assert_not_called()

    def test_missing_httpx_is_an_error_observation_without_fallback(self):
        tb = toolbox()
        result = httpx_result("httpx-not-found", "httpx is not installed on this machine.")
        obs, is_error, _, fallback = self.call(tb, {"port": 80}, httpx=result)
        self.assertTrue(is_error)
        self.assertIn("httpx is not installed", obs)
        fallback.assert_not_called()
        self.assertEqual(tb.scan["web"][80]["status"], "httpx-not-found")

    def test_gate_refusal_is_reported_without_fallback(self):
        result = httpx_result("refused", "")
        obs, is_error, _, fallback = self.call(toolbox(), {"port": 80}, httpx=result)
        self.assertTrue(is_error)
        self.assertIn("authorization gate", obs)
        fallback.assert_not_called()


class FallbackTests(unittest.TestCase):

    def call(self, httpx, basic=BASIC_RESULT, port=80):
        tb = toolbox()
        run_patch, basic_patch = patched(httpx, basic)
        with run_patch, basic_patch as fallback:
            obs, is_error = tb.call("web_fingerprint", {"port": port})
        return tb, obs, is_error, fallback

    def test_fallback_runs_on_timeout_and_failed(self):
        for status in ("timeout", "failed"):
            tb, obs, is_error, fallback = self.call(httpx_result(status))
            self.assertFalse(is_error, status)
            fallback.assert_called_once_with(TARGET, 80, use_https=False)
            stored = tb.scan["web"][80]
            self.assertEqual(stored["fallback_reason"], status)
            self.assertEqual(stored["httpx_error"], "httpx went wrong.")
            self.assertEqual(stored["method"], "basic header check")
            data = json.loads(obs)
            self.assertEqual(data["fallback_reason"], status)
            self.assertEqual(data["x_powered_by"], "PHP/5.2.4-2ubuntu5.10")
            self.assertNotIn("technologies", data)

    def test_fallback_keeps_https(self):
        _, _, _, fallback = self.call(httpx_result("timeout"), port=443)
        fallback.assert_called_once_with(TARGET, 443, use_https=True)

    def test_no_fallback_for_other_statuses(self):
        for status in ("ok", "refused", "bad-port", "httpx-not-found", "bad-output"):
            httpx = OK_RESULT if status == "ok" else httpx_result(status)
            tb, _, _, fallback = self.call(httpx)
            fallback.assert_not_called()
            self.assertNotIn("fallback_reason", tb.scan["web"][80])

    def test_bad_output_says_not_checked(self):
        tb, obs, is_error, _ = self.call(httpx_result("bad-output", "httpx output is not "
                                                      "a JSON object."))
        self.assertTrue(is_error)
        message = json.loads(obs)["error"]
        self.assertIn("status=bad-output", message)
        self.assertIn("This port was not checked.", message)
        self.assertNotIn(" - ", message)

    def test_failed_fallback_says_not_checked(self):
        basic = dict(BASIC_RESULT, status="failed", http_status=None, server="",
                     x_powered_by="", title="", error="The request failed: refused")
        tb, obs, is_error, _ = self.call(httpx_result("timeout"), basic=basic)
        self.assertTrue(is_error)
        message = json.loads(obs)["error"]
        self.assertIn("(status timeout)", message)
        self.assertIn("status=failed", message)
        self.assertIn("This port was not checked.", message)
        self.assertNotIn(" - ", message)
        self.assertEqual(tb.scan["web"][80]["fallback_reason"], "timeout")


class SpecAndPromptTests(unittest.TestCase):

    def test_tool_spec(self):
        spec = next(s for s in toolmod.TOOL_SPECS if s["name"] == "web_fingerprint")
        self.assertIn("httpx", spec["description"])
        self.assertIn("no redirect following", spec["description"])
        self.assertIn("basic header check", spec["description"])
        self.assertNotIn("whatweb", spec["description"])
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
