"""
Offline tests for the httpx wrapper and its basic header check fallback: the
authorization gate running first, the binary rules (httpx-toolkit, or httpx
only when it is ProjectDiscovery's and never Python's), the exact command
with no redirect following, parsing httpx's JSON line into technologies, and
clean error statuses. subprocess.run and urllib's build_opener are replaced
by fakes, so nothing is launched and nothing is sent.

The fixture is httpx's real output for Metasploitable's port 80 (title,
webserver, tech and status code as httpx wrote them).
"""

import io
import os
import shlex
import ssl
import subprocess
import unittest
from email.message import Message
from unittest import mock
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler

from reconmind.tools import httpx_scan

TARGET = "10.10.1.100"
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "httpx_metasploitable_80.jsonl")
with open(FIXTURE) as _fh:
    HTTPX_OUTPUT = _fh.read()

EXPECTED_FLAGS = ["-tech-detect", "-title", "-server", "-status-code", "-location",
                  "-json", "-silent", "-no-color", "-timeout", "10", "-retries", "1",
                  "-disable-update-check"]

PD_VERSION = ("\n    __    __  __       _  __\n   / /_  / /_/ /_____ | |/ /\n\n"
              "\t\tprojectdiscovery.io\n\n[INF] Current Version: v1.6.9\n")
PYTHON_VERSION = ("Usage: httpx [OPTIONS] URL\nTry 'httpx --help' for help.\n\n"
                  "Error: No such option: -v\n")


def which_for(*present):
    """Stand in for shutil.which: only the named commands exist."""
    return lambda name: "/usr/bin/" + name if name in present else None


def fake_run(stdout=HTTPX_OUTPUT, returncode=0, stderr="", version_text=PD_VERSION):
    """Stand in for subprocess.run: answers -version checks and httpx scans."""
    def run(cmd, **kwargs):
        if cmd[1:] == ["-version"]:
            return mock.Mock(returncode=0, stdout="", stderr=version_text)
        return mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)
    return mock.Mock(side_effect=run)


def scan_calls(run):
    return [c.args[0] for c in run.call_args_list if c.args[0][1:] != ["-version"]]


def no_dashes(test, text):
    test.assertNotIn("—", text)
    test.assertNotIn(" - ", text)


class Base(unittest.TestCase):

    def _run(self, run, port=80, use_https=False, present=("httpx-toolkit",)):
        with mock.patch.object(httpx_scan, "is_authorized", return_value=True), \
             mock.patch.object(httpx_scan.shutil, "which", side_effect=which_for(*present)), \
             mock.patch.object(httpx_scan.subprocess, "run", run):
            return httpx_scan.run_httpx(TARGET, port, use_https=use_https)


class GateTests(unittest.TestCase):

    def test_refusal_never_reaches_subprocess(self):
        with mock.patch.object(httpx_scan, "is_authorized", return_value=False) as gate, \
             mock.patch.object(httpx_scan.shutil, "which") as which, \
             mock.patch.object(httpx_scan.subprocess, "run") as run:
            result = httpx_scan.run_httpx("8.8.8.8", 80)
        gate.assert_called_once_with("8.8.8.8")
        which.assert_not_called()
        run.assert_not_called()
        self.assertEqual(result["status"], "refused")
        self.assertEqual(result["technologies"], [])
        self.assertEqual(result["command"], "")

    def test_gate_runs_before_port_check(self):
        with mock.patch.object(httpx_scan, "is_authorized", return_value=False) as gate, \
             mock.patch.object(httpx_scan.subprocess, "run") as run:
            result = httpx_scan.run_httpx(TARGET, "not a port")
        gate.assert_called_once()
        run.assert_not_called()
        self.assertEqual(result["status"], "refused")

    def test_basic_check_refusal_sends_nothing(self):
        with mock.patch.object(httpx_scan, "is_authorized", return_value=False) as gate, \
             mock.patch.object(httpx_scan, "build_opener") as opener:
            result = httpx_scan.basic_http_fingerprint("8.8.8.8", 80)
        gate.assert_called_once_with("8.8.8.8")
        opener.assert_not_called()
        self.assertEqual(result["status"], "refused")


class BinaryTests(Base):

    def test_httpx_toolkit_is_used_without_a_version_check(self):
        run = fake_run()
        result = self._run(run, present=("httpx-toolkit", "httpx"))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0][0], "httpx-toolkit")

    def test_projectdiscovery_httpx_is_accepted(self):
        run = fake_run(version_text=PD_VERSION)
        result = self._run(run, present=("httpx",))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(run.call_args_list[0].args[0], ["httpx", "-version"])
        self.assertEqual(scan_calls(run)[0][0], "httpx")
        self.assertTrue(result["command"].startswith("httpx -u "))

    def test_python_httpx_is_rejected(self):
        run = fake_run(version_text=PYTHON_VERSION)
        result = self._run(run, present=("httpx",))
        self.assertEqual(result["status"], "httpx-not-found")
        self.assertEqual(scan_calls(run), [])  # only the -version check ran
        self.assertEqual(result["url"], "http://10.10.1.100:80")
        self.assertIn("not installed", result["error"])
        no_dashes(self, result["error"])

    def test_version_check_that_cannot_run_is_rejected(self):
        for error in (OSError("exec format error"),
                      subprocess.TimeoutExpired(["httpx", "-version"], 10)):
            run = mock.Mock(side_effect=error)
            result = self._run(run, present=("httpx",))
            self.assertEqual(result["status"], "httpx-not-found")

    def test_nothing_installed(self):
        run = fake_run()
        result = self._run(run, present=())
        self.assertEqual(result["status"], "httpx-not-found")
        run.assert_not_called()


class CommandTests(Base):

    def test_exact_command_and_timeout(self):
        run = fake_run()
        result = self._run(run, port=80)
        cmd = run.call_args.args[0]
        self.assertEqual(cmd, ["httpx-toolkit", "-u", "http://10.10.1.100:80"] + EXPECTED_FLAGS)
        self.assertEqual(run.call_args.kwargs["timeout"], 60)
        self.assertEqual(result["command"], shlex.join(cmd))
        self.assertEqual(result["url"], "http://10.10.1.100:80")

    def test_no_redirect_following(self):
        run = fake_run()
        self._run(run)
        cmd = run.call_args.args[0]
        for flag in ("-fr", "-follow-redirects", "-fhr", "-follow-host-redirects",
                     "-maxr", "-max-redirects"):
            self.assertNotIn(flag, cmd)

    def test_https_url(self):
        run = fake_run()
        result = self._run(run, port=8443, use_https=True)
        self.assertEqual(run.call_args.args[0][2], "https://10.10.1.100:8443")
        self.assertEqual(result["url"], "https://10.10.1.100:8443")

    def test_bad_port_never_runs_httpx(self):
        run = fake_run()
        for port in (0, 70000, "abc"):
            self.assertEqual(self._run(run, port=port)["status"], "bad-port")
        run.assert_not_called()


class ParseTests(Base):

    def test_fixture_fields(self):
        result = self._run(fake_run())
        self.assertEqual(result["status"], "ok")
        self.assertNotIn("error", result)
        self.assertEqual(result["http_status"], 200)
        self.assertEqual(result["server"], "Apache/2.2.8 (Ubuntu) DAV/2")
        self.assertEqual(result["title"], "Metasploitable2 - Linux")
        self.assertEqual(result["location"], "")
        self.assertEqual(result["raw_json"], HTTPX_OUTPUT)  # exactly as httpx wrote it
        self.assertEqual(set(result), {"status", "url", "http_status", "server", "title",
                                       "location", "technologies", "command", "raw_json"})

    def test_fixture_technologies(self):
        result = self._run(fake_run())
        self.assertEqual(result["technologies"], [
            {"name": "Apache HTTP Server", "version": "2.2.8",
             "raw": "Apache HTTP Server:2.2.8"},
            {"name": "PHP", "version": "5.2.4", "raw": "PHP:5.2.4"},
            {"name": "Ubuntu", "version": "", "raw": "Ubuntu"},
            {"name": "bun", "version": "", "raw": "bun"},
            {"name": "mod_dav", "version": "2", "raw": "mod_dav:2"},
        ])

    def test_split_rules(self):
        split = httpx_scan.split_technology
        self.assertEqual(split("Apache HTTP Server:2.2.8"),
                         {"name": "Apache HTTP Server", "version": "2.2.8",
                          "raw": "Apache HTTP Server:2.2.8"})
        self.assertEqual(split("Ubuntu"), {"name": "Ubuntu", "version": "", "raw": "Ubuntu"})
        # Part after the last colon does not start with a digit: not split.
        self.assertEqual(split("Some CMS:beta"),
                         {"name": "Some CMS:beta", "version": "", "raw": "Some CMS:beta"})
        self.assertEqual(split(":1.0"), {"name": ":1.0", "version": "", "raw": ":1.0"})
        self.assertEqual(split("jQuery:")["version"], "")

    def test_location_is_kept(self):
        line = ('{"url":"http://10.10.1.100:8180","status_code":302,'
                '"location":"/admin/","webserver":"Apache-Coyote/1.1"}\n')
        result = self._run(fake_run(stdout=line), port=8180)
        self.assertEqual(result["http_status"], 302)
        self.assertEqual(result["location"], "/admin/")
        self.assertEqual(result["server"], "Apache-Coyote/1.1")
        self.assertEqual(result["technologies"], [])


class ErrorTests(Base):

    def assert_clean_error(self, result, status):
        self.assertEqual(result["status"], status)
        self.assertEqual(result["technologies"], [])
        self.assertIsNone(result["http_status"])
        self.assertTrue(result["error"])
        no_dashes(self, result["error"])

    def test_no_output_is_failed(self):
        self.assert_clean_error(self._run(fake_run(stdout="")), "failed")

    def test_failed_flag_is_failed(self):
        self.assert_clean_error(self._run(fake_run(stdout='{"failed":true}\n')), "failed")

    def test_timeout(self):
        def run(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])
        result = self._run(mock.Mock(side_effect=run))
        self.assert_clean_error(result, "timeout")
        self.assertIn("60 seconds", result["error"])
        self.assertTrue(result["command"].startswith("httpx-toolkit "))

    def test_cannot_start_is_failed(self):
        self.assert_clean_error(self._run(mock.Mock(side_effect=OSError("boom"))), "failed")

    def test_not_json_is_bad_output(self):
        result = self._run(fake_run(stdout="not json\n"))
        self.assert_clean_error(result, "bad-output")
        self.assertEqual(result["raw_json"], "not json\n")

    def test_nonzero_exit_is_reported(self):
        result = self._run(fake_run(stdout="", returncode=1, stderr="[FTL] bad input"))
        self.assert_clean_error(result, "failed")
        self.assertIn("exited with code 1: [FTL] bad input", result["error"])


# ---- basic header check -------------------------------------------------

def headers(**values):
    message = Message()
    for name, value in values.items():
        message[name.replace("_", "-")] = value
    return message


class FakeResponse:

    def __init__(self, code=200, hdrs=None, body=b""):
        self.code, self.headers, self.body = code, hdrs or headers(), body
        self.read_sizes = []
        self.closed = False

    def getcode(self):
        return self.code

    def read(self, size=-1):
        self.read_sizes.append(size)
        return self.body if size < 0 else self.body[:size]

    def close(self):
        self.closed = True


class BasicCheckTests(unittest.TestCase):

    def _basic(self, answer, port=80, use_https=False):
        opener = mock.Mock()
        if isinstance(answer, BaseException):
            opener.open.side_effect = answer
        else:
            opener.open.return_value = answer
        with mock.patch.object(httpx_scan, "is_authorized", return_value=True), \
             mock.patch.object(httpx_scan, "build_opener", return_value=opener) as build:
            result = httpx_scan.basic_http_fingerprint(TARGET, port, use_https=use_https)
        return result, build, opener

    def test_headers_and_title_exactly_as_sent(self):
        page = FakeResponse(200, headers(Server="Apache/2.2.8 (Ubuntu) DAV/2",
                                         X_Powered_By="PHP/5.2.4-2ubuntu5.10"),
                            b"<html><head><title>Metasploitable2 - Linux</title></head>"
                            b"<title>second</title>")
        result, _, opener = self._basic(page)
        self.assertEqual(result, {
            "status": "ok", "url": "http://10.10.1.100:80", "method": "basic header check",
            "http_status": 200, "server": "Apache/2.2.8 (Ubuntu) DAV/2",
            "x_powered_by": "PHP/5.2.4-2ubuntu5.10", "title": "Metasploitable2 - Linux"})
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.full_url, "http://10.10.1.100:80")
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 10)
        self.assertEqual(opener.open.call_count, 1)
        self.assertTrue(page.closed)

    def test_reads_at_most_64_kb(self):
        page = FakeResponse(200, headers(), b"x" * 200000)
        self._basic(page)
        self.assertEqual(page.read_sizes, [65536])

    def test_redirects_are_not_followed(self):
        moved = HTTPError("http://10.10.1.100:8180", 302, "Found",
                          headers(Server="Apache-Coyote/1.1", Location="/admin/"),
                          io.BytesIO(b""))
        result, build, opener = self._basic(moved, port=8180)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["http_status"], 302)
        self.assertEqual(result["server"], "Apache-Coyote/1.1")
        self.assertEqual(opener.open.call_count, 1)
        handlers = build.call_args.args
        self.assertTrue(any(isinstance(h, httpx_scan._NoRedirect) for h in handlers))
        self.assertIsNone(httpx_scan._NoRedirect().redirect_request(
            None, None, 302, "Found", {}, "http://10.10.1.100:8180/admin/"))

    def test_https_accepts_self_signed_and_says_so(self):
        result, build, _ = self._basic(FakeResponse(), port=443, use_https=True)
        tls = [h for h in build.call_args.args if isinstance(h, HTTPSHandler)]
        self.assertEqual(len(tls), 1)
        self.assertEqual(tls[0]._context.verify_mode, ssl.CERT_NONE)
        self.assertFalse(tls[0]._context.check_hostname)
        self.assertEqual(result["url"], "https://10.10.1.100:443")
        self.assertIn("self signed", result["certificate_check"])

    def test_http_keeps_certificate_checks_out(self):
        result, build, _ = self._basic(FakeResponse())
        self.assertFalse(any(isinstance(h, HTTPSHandler) for h in build.call_args.args))
        self.assertNotIn("certificate_check", result)

    def test_missing_headers_and_title_are_empty(self):
        result, _, _ = self._basic(FakeResponse(200, headers(), b"<p>no title</p>"))
        self.assertEqual((result["server"], result["x_powered_by"], result["title"]),
                         ("", "", ""))

    def test_timeout_and_failure(self):
        result, _, _ = self._basic(URLError(TimeoutError("timed out")))
        self.assertEqual(result["status"], "timeout")
        no_dashes(self, result["error"])
        result, _, _ = self._basic(URLError(ConnectionRefusedError(111, "Connection refused")))
        self.assertEqual(result["status"], "failed")
        no_dashes(self, result["error"])


if __name__ == "__main__":
    unittest.main()
