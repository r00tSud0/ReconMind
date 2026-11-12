"""
Offline tests for the tls_check agent tool and the report's TLS section:
tls_check needs nmap_scan first, only accepts TLS or STARTTLS capable ports,
picks STARTTLS for plain text mail, ftp and postgresql services, stores results
in scan["tls"] and returns a compact observation. The report lists protocols,
certificate findings and rated findings per port, and the ports not checked.
run_testssl is replaced by a mock, so testssl.sh never runs.
"""

import copy
import json
import os
import tempfile
import unittest
from unittest import mock

from reconmind.agent import prompts, tools as toolmod
from reconmind.core import report as reportmod
from reconmind.core.report import build_report
from reconmind.tools import testssl_scan

TARGET = "10.10.1.100"
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "testssl_scan.json")
with open(FIXTURE) as _fh:
    _status, FIXTURE_FINDINGS, _error = testssl_scan._parse_json(_fh.read())
assert _status == "ok"

SCAN = {
    "target": TARGET, "status": "ok",
    "ports": [
        {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH",
         "version": "4.7p1", "tunnel": ""},
        {"port": 25, "protocol": "tcp", "service": "smtp", "product": "Postfix smtpd",
         "version": "", "tunnel": ""},
        {"port": 80, "protocol": "tcp", "service": "http", "product": "Apache httpd",
         "version": "2.2.8", "tunnel": ""},
        {"port": 443, "protocol": "tcp", "service": "http", "product": "Apache httpd",
         "version": "2.2.8", "tunnel": "ssl"},
        {"port": 993, "protocol": "tcp", "service": "imap", "product": "Dovecot imapd",
         "version": "", "tunnel": "ssl"},
        {"port": 3306, "protocol": "tcp", "service": "mysql", "product": "MySQL",
         "version": "5.0.51a-3ubuntu5", "tunnel": ""},
        {"port": 5432, "protocol": "tcp", "service": "postgresql", "product": "PostgreSQL DB",
         "version": "8.3.0 - 8.3.7", "tunnel": ""},
        {"port": 8443, "protocol": "tcp", "service": "https", "product": "", "version": ""},
    ],
}
ALLOWED = "25 (STARTTLS smtp), 443, 993, 5432 (STARTTLS postgres), 8443"


def ok_result(port=443, starttls=None):
    return {"status": "ok", "target": TARGET, "port": port, "starttls": starttls,
            "command": "testssl --quiet --color 0 --warnings off --jsonfile /tmp/x/testssl.json "
                       "{t}:{p}".format(t=TARGET, p=port),
            "findings": copy.deepcopy(FIXTURE_FINDINGS)}


def toolbox():
    tb = toolmod.ToolBox(TARGET)
    tb.scan = copy.deepcopy(SCAN)
    return tb


class TlsCheckTests(unittest.TestCase):

    def test_requires_nmap_scan_first(self):
        tb = toolmod.ToolBox(TARGET)
        with mock.patch.object(toolmod, "run_testssl") as run:
            obs, is_error = tb.call("tls_check", {"port": 443})
        self.assertTrue(is_error)
        self.assertIn("Run nmap_scan first", obs)
        run.assert_not_called()

    def test_refuses_port_that_is_not_tls_capable(self):
        for port, service in ((22, "ssh"), (80, "http"), (3306, "mysql")):
            tb = toolbox()
            with mock.patch.object(toolmod, "run_testssl") as run:
                obs, is_error = tb.call("tls_check", {"port": port})
            self.assertTrue(is_error)
            message = json.loads(obs)["error"]
            self.assertIn("Port {p} ({s}) is not a TLS or STARTTLS capable service".format(
                p=port, s=service), message)
            self.assertIn("TLS ports you can check: {a}.".format(a=ALLOWED), message)
            run.assert_not_called()
            self.assertNotIn("tls", tb.scan)

    def test_refuses_port_not_in_scan(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_testssl") as run:
            obs, is_error = tb.call("tls_check", {"port": 465})
        self.assertTrue(is_error)
        message = json.loads(obs)["error"]
        self.assertIn("Port 465 was not found open in the scan", message)
        self.assertIn(ALLOWED, message)
        run.assert_not_called()

    def test_direct_and_starttls_choice(self):
        expected = {25: "smtp", 443: None, 993: None, 5432: "postgres", 8443: None}
        for port, starttls in expected.items():
            tb = toolbox()
            with mock.patch.object(toolmod, "run_testssl",
                                   return_value=ok_result(port, starttls)) as run:
                tb.call("tls_check", {"port": port})
            run.assert_called_once_with(TARGET, port, starttls=starttls)

    def test_other_starttls_services_and_ssl_slash_names(self):
        tb = toolbox()
        tb.scan["ports"] += [
            {"port": 21, "protocol": "tcp", "service": "ftp"},
            {"port": 110, "protocol": "tcp", "service": "pop3"},
            {"port": 143, "protocol": "tcp", "service": "imap"},
            {"port": 9443, "protocol": "tcp", "service": "ssl/http"},
        ]
        expected = {21: "ftp", 110: "pop3", 143: "imap", 9443: None}
        for port, starttls in expected.items():
            with mock.patch.object(toolmod, "run_testssl",
                                   return_value=ok_result(port, starttls)) as run:
                obs, is_error = tb.call("tls_check", {"port": port})
            self.assertFalse(is_error, obs)
            run.assert_called_once_with(TARGET, port, starttls=starttls)

    def test_stores_result_and_returns_compact_observation(self):
        tb = toolbox()
        result = ok_result()
        with mock.patch.object(toolmod, "run_testssl", return_value=result):
            obs, is_error = tb.call("tls_check", {"port": 443})
        self.assertFalse(is_error)
        self.assertEqual(tb.scan["tls"][443], result)
        data = json.loads(obs)
        self.assertEqual(data["port"], 443)
        self.assertIsNone(data["starttls"])
        self.assertNotIn("command", data)
        self.assertEqual(data["severity_counts"],
                         {"CRITICAL": 3, "HIGH": 3, "MEDIUM": 3, "LOW": 1})
        self.assertEqual([f["id"] for f in data["findings"]], [
            "cipherlist_EXPORT", "cert_expirationStatus", "cert_chain_of_trust",
            "SSLv3", "POODLE_SSL", "RC4",
            "cipherlist_3DES_IDEA", "cert_signatureAlgorithm", "BEAST"])
        poodle = next(f for f in data["findings"] if f["id"] == "POODLE_SSL")
        self.assertEqual(poodle, {
            "id": "POODLE_SSL", "severity": "HIGH",
            "finding": "VULNERABLE, uses SSLv3+CBC (check TLS_FALLBACK_SCSV mitigation below)",
            "cve": "CVE-2014-3566", "cwe": "CWE-310"})
        export = next(f for f in data["findings"] if f["id"] == "cipherlist_EXPORT")
        self.assertNotIn("cve", export)  # empty values are left out

    def test_several_ports_are_all_stored(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_testssl", return_value=ok_result()):
            tb.call("tls_check", {"port": 443})
            tb.call("tls_check", {"port": 25})
        self.assertEqual(sorted(tb.scan["tls"]), [25, 443])

    def test_only_this_runs_target_is_used(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_testssl", return_value=ok_result()) as run:
            obs, is_error = tb.call("tls_check", {"port": 443, "target": "10.10.1.200"})
        self.assertTrue(is_error)  # no target argument accepted
        run.assert_not_called()

    def test_not_tls_is_a_normal_observation(self):
        tb = toolbox()
        result = {"status": "not-tls", "target": TARGET, "port": 25, "starttls": "smtp",
                  "command": "testssl ...", "findings": [],
                  "error": "testssl.sh reports the service does not speak TLS."}
        with mock.patch.object(toolmod, "run_testssl", return_value=result):
            obs, is_error = tb.call("tls_check", {"port": 25})
        self.assertFalse(is_error)
        self.assertEqual(json.loads(obs)["status"], "not-tls")
        self.assertEqual(tb.scan["tls"][25]["status"], "not-tls")

    def test_missing_testssl_is_an_error_observation(self):
        tb = toolbox()
        result = {"status": "testssl-not-found", "target": TARGET, "port": 443,
                  "starttls": None, "command": "", "findings": [],
                  "error": "testssl.sh is not installed on this machine."}
        with mock.patch.object(toolmod, "run_testssl", return_value=result):
            obs, is_error = tb.call("tls_check", {"port": 443})
        self.assertTrue(is_error)
        self.assertIn("testssl.sh is not installed", obs)
        self.assertEqual(tb.scan["tls"][443]["status"], "testssl-not-found")

    def test_failed_run_says_not_checked(self):
        tb = toolbox()
        result = {"status": "timeout", "target": TARGET, "port": 443, "starttls": None,
                  "command": "testssl ...", "findings": [],
                  "error": "testssl.sh did not finish within 600 seconds."}
        with mock.patch.object(toolmod, "run_testssl", return_value=result):
            obs, is_error = tb.call("tls_check", {"port": 443})
        self.assertTrue(is_error)
        message = json.loads(obs)["error"]
        self.assertIn("status=timeout", message)
        self.assertIn("This port was not checked.", message)
        self.assertNotIn(" - ", message)

    def test_gate_refusal_is_reported(self):
        tb = toolbox()
        result = {"status": "refused", "target": "", "port": None, "starttls": None,
                  "command": "", "findings": []}
        with mock.patch.object(toolmod, "run_testssl", return_value=result):
            obs, is_error = tb.call("tls_check", {"port": 443})
        self.assertTrue(is_error)
        self.assertIn("authorization gate", obs)


class SpecAndPromptTests(unittest.TestCase):

    def test_tool_spec(self):
        spec = next(s for s in toolmod.TOOL_SPECS if s["name"] == "tls_check")
        self.assertIn("testssl.sh", spec["description"])
        schema = spec["input_schema"]
        self.assertEqual(list(schema["properties"]), ["port"])
        self.assertEqual(schema["properties"]["port"]["type"], "integer")
        self.assertEqual(schema["required"], ["port"])

    def test_prompt_rule(self):
        self.assertIn("After nmap_scan, call tls_check once for every TLS or STARTTLS "
                      "capable port it allows", prompts.SYSTEM_PROMPT)
        self.assertIn("After nmap_scan, call web_fingerprint once", prompts.SYSTEM_PROMPT)
        self.assertIn("END OF SUMMARY", prompts.SYSTEM_PROMPT)

    def test_new_text_has_no_dash_separators(self):
        spec = next(s for s in toolmod.TOOL_SPECS if s["name"] == "tls_check")
        for text in (spec["description"], prompts.SYSTEM_PROMPT):
            self.assertNotIn("—", text)
            self.assertNotIn(" - ", text)


# ---- report ---------------------------------------------------------------

TLS_HEAD = "## TLS checks (testssl.sh)"
REPORT_PORTS = [p for p in SCAN["ports"] if p["port"] in (22, 25, 80, 443, 5432)]
TLS_SCAN = {
    "target": TARGET, "status": "ok", "ports": copy.deepcopy(REPORT_PORTS),
    "tls": {
        443: ok_result(),
        25: {"status": "timeout", "target": TARGET, "port": 25, "starttls": "smtp",
             "command": "testssl ...", "findings": [],
             "error": "testssl.sh did not finish within 600 seconds."},
    },
}


def read_report(scan):
    with open(build_report(scan)) as fh:
        return fh.read()


def tls_part(report):
    return report.split(TLS_HEAD)[1].split("## Notes")[0]


class TlsReportTests(unittest.TestCase):

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def test_section_after_web_before_notes(self):
        report = read_report(TLS_SCAN)
        self.assertLess(report.index("## Web technology (whatweb)"), report.index(TLS_HEAD))
        self.assertLess(report.index(TLS_HEAD), report.index("## Notes"))

    def test_port_shows_protocols_certificate_and_findings(self):
        section = tls_part(read_report(TLS_SCAN))
        self.assertIn("**443/tcp** (direct TLS)\nProtocols offered: SSLv3, TLS 1.0\n", section)
        self.assertIn("Certificate:\n"
                      "- cert_signatureAlgorithm: SHA1 with RSA (MEDIUM)\n"
                      "- cert_keySize: RSA 1024 bits (INFO)\n"
                      "- cert_commonName: ubuntu804-base.localdomain (OK)\n"
                      "- cert_notAfter: 2010-04-16 14:07 (OK)\n"
                      "- cert_expirationStatus: expired (CRITICAL)\n"
                      "- cert_chain_of_trust: failed (self signed). (CRITICAL)\n", section)
        self.assertIn(
            "Findings, most severe first:\n"
            "- [CRITICAL] cipherlist_EXPORT: offered\n"
            "- [CRITICAL] cert_expirationStatus: expired\n"
            "- [CRITICAL] cert_chain_of_trust: failed (self signed).\n"
            "- [HIGH] SSLv3: offered\n"
            "- [HIGH] POODLE_SSL: VULNERABLE, uses SSLv3+CBC (check TLS_FALLBACK_SCSV "
            "mitigation below) (CVE-2014-3566)\n"
            "- [HIGH] RC4: VULNERABLE (NOT ok): RC4-SHA RC4-MD5 (CVE-2013-2566 CVE-2015-2808)\n"
            "- [MEDIUM] cipherlist_3DES_IDEA: offered\n"
            "- [MEDIUM] cert_signatureAlgorithm: SHA1 with RSA\n"
            "- [MEDIUM] BEAST: VULNERABLE -- but also supports higher protocols  TLSv1.1 "
            "TLSv1.2 (likely mitigated) (CVE-2011-3389)\n"
            "- [LOW] SWEET32: VULNERABLE, uses 64 bit block ciphers "
            "(CVE-2016-2183 CVE-2016-6329)\n", section)
        # OK and INFO findings are never in the rated list.
        self.assertNotIn("] cert_commonName", section)
        self.assertNotIn("] TLS1:", section)

    def test_failed_run_says_not_checked(self):
        section = tls_part(read_report(TLS_SCAN))
        self.assertIn("**25/tcp** (STARTTLS smtp)\n"
                      "_testssl.sh did not complete (status timeout), so this port was not "
                      "checked._", section)

    def test_not_tls_port(self):
        scan = copy.deepcopy(TLS_SCAN)
        scan["tls"][25] = {"status": "not-tls", "target": TARGET, "port": 25,
                           "starttls": "smtp", "command": "testssl ...", "findings": []}
        section = tls_part(read_report(scan))
        self.assertIn("**25/tcp** (STARTTLS smtp)\n"
                      "_testssl.sh reports this port does not speak TLS._", section)

    def test_not_checked_line(self):
        section = tls_part(read_report(TLS_SCAN))
        self.assertIn("**Not checked:** these TLS or STARTTLS capable ports were not checked "
                      "with testssl.sh: 5432/tcp (postgresql, STARTTLS postgres).", section)
        self.assertNotIn("22/tcp", section)  # ssh is not TLS capable
        self.assertNotIn("80/tcp", section)  # plain http is not TLS capable

    def test_all_ports_not_checked_without_tls_results(self):
        scan = {k: v for k, v in TLS_SCAN.items() if k != "tls"}
        section = tls_part(read_report(scan))
        self.assertIn("testssl.sh: 25/tcp (smtp, STARTTLS smtp), 443/tcp (http, direct TLS), "
                      "5432/tcp (postgresql, STARTTLS postgres).", section)

    def test_string_port_keys_from_json(self):
        scan = dict(TLS_SCAN, tls={str(k): v for k, v in TLS_SCAN["tls"].items()})
        section = tls_part(read_report(scan))
        self.assertIn("**443/tcp** (direct TLS)", section)
        self.assertIn("testssl.sh: 5432/tcp (postgresql, STARTTLS postgres).", section)

    def test_no_section_without_tls_ports(self):
        plain = {"target": TARGET, "status": "ok",
                 "ports": [p for p in copy.deepcopy(REPORT_PORTS) if p["port"] in (22, 80)]}
        self.assertNotIn(TLS_HEAD, read_report(plain))
        self.assertNotIn(TLS_HEAD, read_report({"target": TARGET, "status": "ok",
                                                "ports": []}))

    def test_tls_text_has_no_em_dashes_or_dash_separators(self):
        not_tls = copy.deepcopy(TLS_SCAN)
        not_tls["tls"][25] = {"status": "not-tls", "port": 25, "findings": []}
        text = tls_part(read_report(TLS_SCAN))
        text += tls_part(read_report(not_tls))
        text += tls_part(read_report({k: v for k, v in TLS_SCAN.items() if k != "tls"}))
        for f in FIXTURE_FINDINGS:  # testssl.sh data, not our text
            for value in (f["finding"], f["cve"], f["cwe"]):
                if value:
                    text = text.replace(value, "")
        for p in REPORT_PORTS:  # nmap data, not our text
            text = text.replace(p["version"], "") if p["version"] else text
        self.assertTrue(text.strip())
        self.assertNotIn("—", text)
        self.assertNotIn(" - ", text)
        for constant in (reportmod.TLS_HEAD, reportmod.TLS_NOT_CHECKED, reportmod.TLS_FAILED,
                         reportmod.TLS_NOT_TLS, reportmod.TLS_NO_FINDINGS,
                         reportmod.TLS_NO_CERT):
            self.assertNotIn("—", constant)
            self.assertNotIn(" - ", constant)


if __name__ == "__main__":
    unittest.main()
