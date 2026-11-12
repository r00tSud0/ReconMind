"""
Offline tests for the testssl.sh wrapper: the authorization gate running
before testssl.sh, a missing binary, the command for a direct TLS port and for
STARTTLS smtp, JSON parsing with the severity filter, the not-tls status and
clean error statuses. subprocess.run is replaced by a fake that writes a
canned JSON file, so testssl.sh never runs.
"""

import json
import os
import shlex
import subprocess
import unittest
from unittest import mock

from reconmind.tools import testssl_scan

TARGET = "10.10.1.100"
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "testssl_scan.json")
with open(FIXTURE) as _fh:
    JSON_TEXT = _fh.read()

EXPECTED_FLAGS = ["--quiet", "--color", "0", "--warnings", "off"]


def json_path_of(cmd):
    return cmd[cmd.index("--jsonfile") + 1]


def fake_testssl(json_text, returncode=0, stdout="", stderr=""):
    """Stand in for subprocess.run: writes json_text into the --jsonfile path.
    json_text None writes nothing, like testssl.sh stopping early."""
    seen = []

    def run(cmd, **kwargs):
        path = json_path_of(cmd)
        seen.append(path)
        # testssl.sh refuses to overwrite, so the path must not exist yet.
        assert not os.path.exists(path), "JSON path already exists"
        if json_text is not None:
            with open(path, "w") as fh:
                fh.write(json_text)
        return mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)

    fake = mock.Mock(side_effect=run)
    fake.json_paths = seen
    return fake


def which_only(name):
    return lambda binary: "/usr/bin/" + binary if binary == name else None


class Base(unittest.TestCase):

    def _run(self, run, port=443, starttls=None, binary="testssl", target=TARGET):
        with mock.patch.object(testssl_scan, "is_authorized", return_value=True), \
             mock.patch.object(testssl_scan.shutil, "which", side_effect=which_only(binary)), \
             mock.patch.object(testssl_scan.subprocess, "run", run):
            return testssl_scan.run_testssl(target, port, starttls=starttls)


class GateTests(unittest.TestCase):

    def test_refusal_never_reaches_subprocess(self):
        with mock.patch.object(testssl_scan, "is_authorized", return_value=False) as gate, \
             mock.patch.object(testssl_scan.shutil, "which") as which, \
             mock.patch.object(testssl_scan.tempfile, "mkdtemp") as mkdtemp, \
             mock.patch.object(testssl_scan.subprocess, "run") as run:
            result = testssl_scan.run_testssl("8.8.8.8", 443)
        gate.assert_called_once_with("8.8.8.8")
        run.assert_not_called()
        which.assert_not_called()
        mkdtemp.assert_not_called()
        self.assertEqual(result["status"], "refused")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["command"], "")

    def test_gate_runs_before_port_and_starttls_checks(self):
        with mock.patch.object(testssl_scan, "is_authorized", return_value=False) as gate, \
             mock.patch.object(testssl_scan.subprocess, "run") as run:
            result = testssl_scan.run_testssl(TARGET, "not a port", starttls="bogus")
        gate.assert_called_once()
        run.assert_not_called()
        self.assertEqual(result["status"], "refused")


class MissingBinaryTests(unittest.TestCase):

    def test_missing_testssl_does_not_crash(self):
        with mock.patch.object(testssl_scan, "is_authorized", return_value=True), \
             mock.patch.object(testssl_scan.shutil, "which", return_value=None) as which, \
             mock.patch.object(testssl_scan.subprocess, "run") as run:
            result = testssl_scan.run_testssl(TARGET, 443)
        run.assert_not_called()
        looked_for = [c.args[0] for c in which.call_args_list]
        self.assertEqual(looked_for, ["testssl", "testssl.sh"])
        self.assertEqual(result["status"], "testssl-not-found")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["port"], 443)
        self.assertTrue(result["error"])

    def test_testssl_dot_sh_name_is_used_when_found(self):
        run = fake_testssl(JSON_TEXT)
        result = Base()._run(run, binary="testssl.sh")
        self.assertEqual(run.call_args.args[0][0], "testssl.sh")
        self.assertEqual(result["status"], "ok")


class CommandTests(Base):

    def test_direct_tls_command_and_timeout(self):
        run = fake_testssl(JSON_TEXT)
        result = self._run(run, port=443)
        self.assertEqual(run.call_count, 1)
        cmd = run.call_args.args[0]
        path = json_path_of(cmd)
        self.assertEqual(cmd, ["testssl"] + EXPECTED_FLAGS
                         + ["--jsonfile", path, "10.10.1.100:443"])
        self.assertEqual(run.call_args.kwargs["timeout"], 600)
        self.assertEqual(result["command"], shlex.join(cmd))
        self.assertEqual(result["target"], TARGET)
        self.assertEqual(result["port"], 443)
        self.assertIsNone(result["starttls"])

    def test_starttls_smtp_command(self):
        run = fake_testssl(JSON_TEXT)
        result = self._run(run, port=25, starttls="smtp")
        cmd = run.call_args.args[0]
        path = json_path_of(cmd)
        self.assertEqual(cmd, ["testssl"] + EXPECTED_FLAGS
                         + ["--jsonfile", path, "--starttls", "smtp", "10.10.1.100:25"])
        self.assertEqual(result["starttls"], "smtp")

    def test_no_other_options(self):
        run = fake_testssl(JSON_TEXT)
        self._run(run, port=25, starttls="smtp")
        options = [a for a in run.call_args.args[0] if a.startswith("-")]
        self.assertEqual(options, ["--quiet", "--color", "--warnings", "--jsonfile",
                                   "--starttls"])

    def test_temp_json_is_deleted(self):
        run = fake_testssl(JSON_TEXT)
        self._run(run)
        self.assertEqual(len(run.json_paths), 1)
        self.assertFalse(os.path.exists(run.json_paths[0]))
        self.assertFalse(os.path.exists(os.path.dirname(run.json_paths[0])))

    def test_bad_port_never_runs_testssl(self):
        run = fake_testssl(JSON_TEXT)
        for port in (0, 70000, "abc"):
            self.assertEqual(self._run(run, port=port)["status"], "bad-port")
        run.assert_not_called()

    def test_unknown_starttls_never_runs_testssl(self):
        run = fake_testssl(JSON_TEXT)
        result = self._run(run, port=389, starttls="ldap")
        self.assertEqual(result["status"], "bad-starttls")
        run.assert_not_called()


class ParseTests(Base):

    def test_findings_from_fixture(self):
        result = self._run(fake_testssl(JSON_TEXT))
        self.assertEqual(result["status"], "ok")
        self.assertNotIn("error", result)
        ids = [f["id"] for f in result["findings"]]
        # testssl.sh order kept. OK and INFO findings are dropped unless they
        # are protocol or certificate findings; WARN is dropped too.
        self.assertEqual(ids, [
            "SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3",
            "cipherlist_EXPORT", "cipherlist_3DES_IDEA",
            "cert_signatureAlgorithm", "cert_keySize", "cert_commonName",
            "cert_notAfter", "cert_expirationStatus", "cert_chain_of_trust",
            "POODLE_SSL", "SWEET32", "BEAST", "RC4"])
        for dropped in ("engine_problem", "service", "cipherlist_NULL", "heartbleed",
                        "scanTime"):
            self.assertNotIn(dropped, ids)

    def test_finding_shape_and_text_exactly_as_given(self):
        result = self._run(fake_testssl(JSON_TEXT))
        by_id = {f["id"]: f for f in result["findings"]}
        self.assertEqual(by_id["POODLE_SSL"], {
            "id": "POODLE_SSL", "severity": "HIGH",
            "finding": "VULNERABLE, uses SSLv3+CBC (check TLS_FALLBACK_SCSV mitigation below)",
            "cve": "CVE-2014-3566", "cwe": "CWE-310"})
        self.assertEqual(by_id["BEAST"]["finding"],
                         "VULNERABLE -- but also supports higher protocols  TLSv1.1 TLSv1.2 "
                         "(likely mitigated)")
        self.assertEqual(by_id["SWEET32"]["cve"], "CVE-2016-2183 CVE-2016-6329")
        self.assertEqual(by_id["cert_commonName"]["cve"], "")
        self.assertEqual(by_id["cert_commonName"]["cwe"], "")

    def test_severity_filter(self):
        entries = [
            {"id": "x_low", "severity": "LOW", "finding": "a"},
            {"id": "x_medium", "severity": "MEDIUM", "finding": "b"},
            {"id": "x_high", "severity": "HIGH", "finding": "c"},
            {"id": "x_critical", "severity": "CRITICAL", "finding": "d"},
            {"id": "x_ok", "severity": "OK", "finding": "e"},
            {"id": "x_info", "severity": "INFO", "finding": "f"},
            {"id": "x_warn", "severity": "WARN", "finding": "g"},
            {"id": "TLS1_2", "severity": "OK", "finding": "offered"},
            {"id": "cert_trust", "severity": "INFO", "finding": "Ok via SAN"},
        ]
        result = self._run(fake_testssl(json.dumps(entries)))
        self.assertEqual([f["id"] for f in result["findings"]],
                         ["x_low", "x_medium", "x_high", "x_critical", "TLS1_2", "cert_trust"])

    def test_severity_rank(self):
        ranks = [testssl_scan.severity_rank(s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW",
                                                          "OK", "INFO", None)]
        self.assertEqual(ranks, [0, 1, 2, 3, 4, 4, 4])


class NotTlsTests(Base):

    def test_not_tls_from_json(self):
        entries = [{"id": "scanProblem", "severity": "FATAL",
                    "finding": "10.10.1.100:22 doesn't seem to be a TLS/SSL enabled server"}]
        result = self._run(fake_testssl(json.dumps(entries)), port=22)
        self.assertEqual(result["status"], "not-tls")
        self.assertEqual(result["findings"], [])

    def test_not_tls_from_output_without_json(self):
        run = fake_testssl(None, returncode=1,
                           stdout=" 10.10.1.100:22 doesn't seem to be a TLS/SSL enabled server")
        result = self._run(run, port=22)
        self.assertEqual(result["status"], "not-tls")
        self.assertNotIn("exited with code", result["error"])


class BadJsonTests(Base):

    def assert_clean_error(self, result, status):
        self.assertEqual(result["status"], status)
        self.assertEqual(result["findings"], [])
        self.assertTrue(result["error"])
        self.assertNotIn("—", result["error"])
        self.assertNotIn(" - ", result["error"])

    def test_no_json_file(self):
        self.assert_clean_error(self._run(fake_testssl(None)), "empty-json")

    def test_empty_json(self):
        run = fake_testssl("")
        self.assert_clean_error(self._run(run), "empty-json")
        self.assertFalse(os.path.exists(run.json_paths[0]))

    def test_broken_json(self):
        run = fake_testssl('[{"id": "SSLv2", "sever')
        self.assert_clean_error(self._run(run), "bad-json")
        self.assertFalse(os.path.exists(run.json_paths[0]))

    def test_wrong_shape(self):
        self.assert_clean_error(self._run(fake_testssl('{"id": "SSLv2"}')), "bad-json")

    def test_fatal_scan_problem_is_failed(self):
        entries = [{"id": "scanProblem", "severity": "FATAL",
                    "finding": "Can't connect to 10.10.1.100:443"}]
        result = self._run(fake_testssl(json.dumps(entries), returncode=249))
        self.assert_clean_error(result, "failed")
        self.assertIn("Can't connect to 10.10.1.100:443", result["error"])
        self.assertIn("exited with code 249", result["error"])

    def test_timeout(self):
        seen = []

        def run(cmd, **kwargs):
            seen.append(json_path_of(cmd))
            raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

        result = self._run(mock.Mock(side_effect=run))
        self.assert_clean_error(result, "timeout")
        self.assertTrue(result["command"].startswith("testssl "))
        self.assertFalse(os.path.exists(os.path.dirname(seen[0])))


class HelperTests(unittest.TestCase):

    def test_direct_tls(self):
        for port in ({"service": "http", "tunnel": "ssl"}, {"service": "https"},
                     {"service": "ssl/http"}, {"service": "ssl/imap"},
                     {"service": "smtp", "tunnel": "ssl"}):
            self.assertTrue(testssl_scan.direct_tls(port), port)
        for port in ({"service": "http"}, {"service": "smtp"}, {"service": "ssh"},
                     {"service": None}):
            self.assertFalse(testssl_scan.direct_tls(port), port)

    def test_starttls_protocol(self):
        expected = {"smtp": "smtp", "ftp": "ftp", "imap": "imap", "pop3": "pop3",
                    "postgresql": "postgres", "ssh": None, "http": None, "mysql": None}
        for service, proto in expected.items():
            self.assertEqual(testssl_scan.starttls_protocol({"service": service}), proto)
        # Already wrapped in TLS: direct, never STARTTLS.
        self.assertIsNone(testssl_scan.starttls_protocol({"service": "smtp", "tunnel": "ssl"}))

    def test_build_target(self):
        self.assertEqual(testssl_scan.build_target("10.10.1.100", 443), "10.10.1.100:443")
        self.assertEqual(testssl_scan.build_target("fe80::1", "443"), "[fe80::1]:443")


if __name__ == "__main__":
    unittest.main()
