"""
Offline tests for the whatweb wrapper: the authorization gate running before
whatweb, a missing whatweb, the command flags and URL for http and https, JSON
log parsing into components, and clean error statuses for empty and broken
logs. subprocess.run is replaced by a fake that writes a canned JSON log, so
whatweb never runs.
"""

import json
import os
import shlex
import subprocess
import unittest
from unittest import mock

from reconmind.tools import whatweb_scan

TARGET = "10.10.1.100"
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "whatweb_log.json")
with open(FIXTURE) as _fh:
    LOG_TEXT = _fh.read()

EXPECTED_FLAGS = ["--color=never", "--no-errors", "-a", "1",
                  "--open-timeout", "10", "--read-timeout", "20"]


def log_path_of(cmd):
    arg = next(a for a in cmd if a.startswith("--log-json="))
    return arg[len("--log-json="):]


def fake_whatweb(log_text, returncode=0, stderr=""):
    """Stand in for subprocess.run: writes log_text into the --log-json file."""
    seen = []

    def run(cmd, **kwargs):
        path = log_path_of(cmd)
        seen.append(path)
        with open(path, "w") as fh:
            fh.write(log_text)
        return mock.Mock(returncode=returncode, stdout="", stderr=stderr)

    fake = mock.Mock(side_effect=run)
    fake.log_paths = seen
    return fake


class Base(unittest.TestCase):

    def _run(self, run, port=80, use_https=False, target=TARGET):
        with mock.patch.object(whatweb_scan, "is_authorized", return_value=True), \
             mock.patch.object(whatweb_scan.shutil, "which", return_value="/usr/bin/whatweb"), \
             mock.patch.object(whatweb_scan.subprocess, "run", run):
            return whatweb_scan.run_whatweb(target, port, use_https=use_https)


class GateTests(unittest.TestCase):

    def test_refusal_never_reaches_subprocess(self):
        with mock.patch.object(whatweb_scan, "is_authorized", return_value=False) as gate, \
             mock.patch.object(whatweb_scan.shutil, "which") as which, \
             mock.patch.object(whatweb_scan.tempfile, "mkstemp") as mkstemp, \
             mock.patch.object(whatweb_scan.subprocess, "run") as run:
            result = whatweb_scan.run_whatweb("8.8.8.8", 80)
        gate.assert_called_once_with("8.8.8.8")
        run.assert_not_called()
        which.assert_not_called()
        mkstemp.assert_not_called()
        self.assertEqual(result["status"], "refused")
        self.assertEqual(result["components"], [])
        self.assertEqual(result["command"], "")

    def test_gate_runs_before_port_check(self):
        with mock.patch.object(whatweb_scan, "is_authorized", return_value=False) as gate, \
             mock.patch.object(whatweb_scan.subprocess, "run") as run:
            result = whatweb_scan.run_whatweb(TARGET, "not a port")
        gate.assert_called_once()
        run.assert_not_called()
        self.assertEqual(result["status"], "refused")


class MissingWhatwebTests(unittest.TestCase):

    def test_missing_whatweb_does_not_crash(self):
        with mock.patch.object(whatweb_scan, "is_authorized", return_value=True), \
             mock.patch.object(whatweb_scan.shutil, "which", return_value=None), \
             mock.patch.object(whatweb_scan.subprocess, "run") as run:
            result = whatweb_scan.run_whatweb(TARGET, 80)
        run.assert_not_called()
        self.assertEqual(result["status"], "whatweb-not-found")
        self.assertEqual(result["url"], "http://10.10.1.100:80")
        self.assertEqual(result["components"], [])
        self.assertIsNone(result["http_status"])


class CommandTests(Base):

    def test_http_command_flags_url_and_timeout(self):
        run = fake_whatweb(LOG_TEXT)
        result = self._run(run, port=80)
        self.assertEqual(run.call_count, 1)
        cmd = run.call_args.args[0]
        path = log_path_of(cmd)
        self.assertEqual(cmd, ["whatweb"] + EXPECTED_FLAGS
                         + ["--log-json=" + path, "http://10.10.1.100:80"])
        self.assertEqual(run.call_args.kwargs["timeout"], 120)
        self.assertEqual(result["url"], "http://10.10.1.100:80")
        self.assertEqual(result["command"], shlex.join(cmd))

    def test_https_url(self):
        run = fake_whatweb(LOG_TEXT)
        result = self._run(run, port=8443, use_https=True)
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[-1], "https://10.10.1.100:8443")
        self.assertEqual(result["url"], "https://10.10.1.100:8443")

    def test_aggression_is_one_and_nothing_intrusive(self):
        run = fake_whatweb(LOG_TEXT)
        self._run(run)
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[cmd.index("-a") + 1], "1")
        self.assertEqual(cmd.count("-a"), 1)
        for banned in ("--aggression", "-a 3", "-a 4", "--user-agent", "--proxy"):
            self.assertNotIn(banned, " ".join(cmd))

    def test_temp_log_is_deleted(self):
        run = fake_whatweb(LOG_TEXT)
        self._run(run)
        self.assertEqual(len(run.log_paths), 1)
        self.assertFalse(os.path.exists(run.log_paths[0]))

    def test_bad_port_never_runs_whatweb(self):
        run = fake_whatweb(LOG_TEXT)
        for port in (0, 70000, "abc"):
            result = self._run(run, port=port)
            self.assertEqual(result["status"], "bad-port")
        run.assert_not_called()


class ParseTests(Base):

    def test_components_from_fixture(self):
        result = self._run(fake_whatweb(LOG_TEXT))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["http_status"], 200)
        self.assertNotIn("error", result)
        names = [c["name"] for c in result["components"]]
        # HTML5 and Script carry no version and no string: skipped.
        # Country and IP are never kept.
        self.assertEqual(names, ["Apache", "HTTPServer", "PHP",
                                 "Title", "WebDAV", "X-Powered-By"])
        by_name = {c["name"]: c for c in result["components"]}
        self.assertEqual(by_name["Apache"], {"name": "Apache", "versions": ["2.2.8"],
                                             "strings": []})
        self.assertEqual(by_name["HTTPServer"]["strings"], ["Apache/2.2.8 (Ubuntu) DAV/2"])
        self.assertEqual(by_name["HTTPServer"]["versions"], [])
        self.assertEqual(by_name["PHP"]["versions"], ["5.2.4-2ubuntu5.10"])  # exactly as given
        self.assertEqual(by_name["Title"]["strings"], ["Metasploitable2 - Linux"])

    def test_always_kept_plugins_survive_without_data(self):
        log = json.dumps([{"target": "http://10.10.1.100:80", "http_status": 403,
                           "plugins": {"HTTPServer": {}, "nginx": {}, "PHP": {},
                                       "Apache": {"os": ["Linux"]}, "Script": {},
                                       "JQuery": {"version": ["1.4.2"]}}}, {}])
        result = self._run(fake_whatweb(log))
        self.assertEqual([c["name"] for c in result["components"]],
                         ["HTTPServer", "nginx", "PHP", "Apache", "JQuery"])
        self.assertEqual(result["http_status"], 403)

    def test_country_and_ip_are_never_components(self):
        log = json.dumps([{"target": "http://10.10.1.100:80", "http_status": 200,
                           "plugins": {"Country": {"string": ["RESERVED"], "module": ["ZZ"]},
                                       "IP": {"string": ["10.10.1.100"]},
                                       "Apache": {"version": ["2.2.8"]}}}, {}])
        result = self._run(fake_whatweb(log))
        self.assertEqual(result["status"], "ok")
        self.assertEqual([c["name"] for c in result["components"]], ["Apache"])
        fixture_names = [c["name"] for c in self._run(fake_whatweb(LOG_TEXT))["components"]]
        self.assertNotIn("Country", fixture_names)
        self.assertNotIn("IP", fixture_names)

    def test_redirect_keeps_status_of_requested_url(self):
        log = json.dumps([
            {"target": "http://10.10.1.100:80", "http_status": 302,
             "plugins": {"RedirectLocation": {"string": ["/login"]}}},
            {"target": "http://10.10.1.100/login", "http_status": 200,
             "plugins": {"Title": {"string": ["Login"]}}},
            {}])
        result = self._run(fake_whatweb(log))
        self.assertEqual(result["http_status"], 302)
        self.assertEqual([c["name"] for c in result["components"]], ["RedirectLocation"])

    def test_versions_are_never_guessed(self):
        log = json.dumps([{"target": "http://10.10.1.100:80", "http_status": 200,
                           "plugins": {"HTTPServer": {"string": ["Apache/2.2.8 (Ubuntu)"]}}}])
        result = self._run(fake_whatweb(log))
        self.assertEqual(result["components"],
                         [{"name": "HTTPServer", "versions": [],
                           "strings": ["Apache/2.2.8 (Ubuntu)"]}])


class BadLogTests(Base):

    def assert_clean_error(self, result, status):
        self.assertEqual(result["status"], status)
        self.assertEqual(result["components"], [])
        self.assertIsNone(result["http_status"])
        self.assertTrue(result["error"])
        self.assertNotIn("—", result["error"])
        self.assertNotIn(" - ", result["error"])

    def test_empty_log(self):
        run = fake_whatweb("")
        self.assert_clean_error(self._run(run), "empty-log")
        self.assertFalse(os.path.exists(run.log_paths[0]))

    def test_log_with_only_empty_entry(self):
        self.assert_clean_error(self._run(fake_whatweb("[\n{}\n]\n")), "empty-log")

    def test_broken_json(self):
        run = fake_whatweb('[\n{"target":"http://10.10.1.100:80","http_status":2')
        self.assert_clean_error(self._run(run), "bad-log")
        self.assertFalse(os.path.exists(run.log_paths[0]))

    def test_wrong_shape(self):
        self.assert_clean_error(self._run(fake_whatweb('{"plugins": {}}')), "bad-log")
        self.assert_clean_error(self._run(fake_whatweb('[{"target": "x"}]')), "bad-log")

    def test_nonzero_exit_is_reported_in_error(self):
        result = self._run(fake_whatweb("", returncode=1, stderr="ERROR Opening: refused"))
        self.assert_clean_error(result, "empty-log")
        self.assertIn("exited with code 1", result["error"])

    def test_timeout(self):
        seen = []

        def run(cmd, **kwargs):
            seen.append(log_path_of(cmd))
            raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

        result = self._run(mock.Mock(side_effect=run))
        self.assert_clean_error(result, "timeout")
        self.assertTrue(result["command"].startswith("whatweb "))
        self.assertFalse(os.path.exists(seen[0]))


class HelperTests(unittest.TestCase):

    def test_is_web_service(self):
        for name in ("http", "https", "ssl/http", "http-proxy", "http-alt", "HTTP"):
            self.assertTrue(whatweb_scan.is_web_service({"service": name}), name)
        for name in ("ssh", "ftp", "ssl", "", None):
            self.assertFalse(whatweb_scan.is_web_service({"service": name}), name)

    def test_wants_https(self):
        self.assertTrue(whatweb_scan.wants_https({"service": "http", "tunnel": "ssl"}))
        self.assertTrue(whatweb_scan.wants_https({"service": "ssl/http"}))
        self.assertTrue(whatweb_scan.wants_https({"service": "https"}))
        self.assertFalse(whatweb_scan.wants_https({"service": "http", "tunnel": ""}))
        self.assertFalse(whatweb_scan.wants_https({"service": "http-proxy"}))

    def test_nmap_records_tunnel(self):
        from reconmind.tools import nmap_scan
        xml = """<?xml version="1.0"?>
<nmaprun><host><ports>
  <port protocol="tcp" portid="443"><state state="open"/>
    <service name="http" product="Apache httpd" tunnel="ssl"/></port>
  <port protocol="tcp" portid="80"><state state="open"/>
    <service name="http" product="Apache httpd"/></port>
</ports></host></nmaprun>"""
        ports = {p["port"]: p for p in nmap_scan._parse_nmap_xml(xml)}
        self.assertEqual(ports[443]["tunnel"], "ssl")
        self.assertEqual(ports[80]["tunnel"], "")


if __name__ == "__main__":
    unittest.main()
