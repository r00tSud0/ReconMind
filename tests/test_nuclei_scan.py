"""
Offline tests for the nuclei wrapper: the authorization gate running before
nuclei, a missing nuclei, missing templates, the templates version, the exact
safe command flags, JSONL parsing into findings (CVE and CWE lists, blank
lines) and clean error statuses. subprocess.run is replaced by a fake that
answers the templates version call and writes a canned JSONL file, so nuclei
never runs.
"""

import os
import shlex
import subprocess
import unittest
from unittest import mock

from reconmind.tools import nuclei_scan

TARGET = "10.10.1.100"
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "nuclei_output.jsonl")
with open(FIXTURE) as _fh:
    JSONL_TEXT = _fh.read()

# What nuclei -templates-version prints (to stderr): a banner with the engine
# version, then the templates version line.
VERSION_OUTPUT = (
    "\n                     __     _\n   ____  __  _______/ /__  (_)\n"
    "\t\tprojectdiscovery.io\n\n"
    "[INF] Current nuclei version: v3.3.7 (latest)\n"
    "[INF] Public nuclei-templates version: v10.5.2 (/root/nuclei-templates)\n")
NO_TEMPLATES_OUTPUT = ("[INF] Current nuclei version: v3.3.7 (latest)\n"
                       "[ERR] nuclei-templates are not installed\n")

VERSION_CMD = ["nuclei", "-templates-version", "-no-color", "-disable-update-check"]


def out_path_of(cmd):
    return cmd[cmd.index("-o") + 1]


def is_version_call(cmd):
    return "-templates-version" in cmd


def fake_nuclei(jsonl_text, version_output=VERSION_OUTPUT, returncode=0, stderr="",
                write=True):
    """Stand in for subprocess.run. The templates version call gets
    version_output; the scan call writes jsonl_text into the -o file."""
    seen = []

    def run(cmd, **kwargs):
        if is_version_call(cmd):
            return mock.Mock(returncode=0, stdout="", stderr=version_output)
        path = out_path_of(cmd)
        seen.append(path)
        if write:
            with open(path, "w") as fh:
                fh.write(jsonl_text)
        return mock.Mock(returncode=returncode, stdout="", stderr=stderr)

    fake = mock.Mock(side_effect=run)
    fake.out_paths = seen
    return fake


def scan_call(run):
    """The one call that is not the templates version call."""
    calls = [c for c in run.call_args_list if not is_version_call(c.args[0])]
    assert len(calls) == 1, calls
    return calls[0]


def run_with(run, port=80, use_https=False):
    with mock.patch.object(nuclei_scan, "is_authorized", return_value=True), \
         mock.patch.object(nuclei_scan.shutil, "which", return_value="/usr/bin/nuclei"), \
         mock.patch.object(nuclei_scan.subprocess, "run", run):
        return nuclei_scan.run_nuclei(TARGET, port, use_https=use_https)


class GateTests(unittest.TestCase):

    def test_refusal_never_reaches_subprocess(self):
        with mock.patch.object(nuclei_scan, "is_authorized", return_value=False) as gate, \
             mock.patch.object(nuclei_scan.shutil, "which") as which, \
             mock.patch.object(nuclei_scan.tempfile, "mkdtemp") as mkdtemp, \
             mock.patch.object(nuclei_scan.subprocess, "run") as run:
            result = nuclei_scan.run_nuclei("8.8.8.8", 80)
        gate.assert_called_once_with("8.8.8.8")
        run.assert_not_called()
        which.assert_not_called()
        mkdtemp.assert_not_called()
        self.assertEqual(result["status"], "refused")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["command"], "")
        self.assertEqual(result["templates_version"], "")
        self.assertEqual(result["raw_jsonl"], "")

    def test_gate_runs_before_port_check(self):
        with mock.patch.object(nuclei_scan, "is_authorized", return_value=False) as gate, \
             mock.patch.object(nuclei_scan.subprocess, "run") as run:
            result = nuclei_scan.run_nuclei(TARGET, "not a port")
        gate.assert_called_once()
        run.assert_not_called()
        self.assertEqual(result["status"], "refused")


class MissingNucleiTests(unittest.TestCase):

    def test_missing_nuclei_does_not_crash(self):
        with mock.patch.object(nuclei_scan, "is_authorized", return_value=True), \
             mock.patch.object(nuclei_scan.shutil, "which", return_value=None) as which, \
             mock.patch.object(nuclei_scan.subprocess, "run") as run:
            result = nuclei_scan.run_nuclei(TARGET, 80)
        which.assert_called_once_with("nuclei")
        run.assert_not_called()
        self.assertEqual(result["status"], "nuclei-not-found")
        self.assertEqual(result["url"], "http://10.10.1.100:80")
        self.assertEqual(result["findings"], [])
        self.assertTrue(result["error"])


class TemplatesVersionTests(unittest.TestCase):

    def test_missing_templates_never_scans(self):
        run = fake_nuclei(JSONL_TEXT, version_output=NO_TEMPLATES_OUTPUT)
        with mock.patch.object(nuclei_scan.tempfile, "mkdtemp") as mkdtemp:
            result = run_with(run)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0], VERSION_CMD)
        mkdtemp.assert_not_called()
        self.assertEqual(result["status"], "templates-not-found")
        self.assertIn("nuclei -update-templates", result["error"])
        self.assertIn("once", result["error"])
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["command"], "")
        self.assertNotIn("—", result["error"])
        self.assertNotIn(" - ", result["error"])

    def test_version_call_and_value(self):
        run = fake_nuclei(JSONL_TEXT)
        result = run_with(run)
        first = run.call_args_list[0]
        self.assertEqual(first.args[0], VERSION_CMD)
        self.assertEqual(first.kwargs["timeout"], 60)
        self.assertEqual(result["templates_version"], "v10.5.2")  # not the engine v3.3.7

    def test_version_on_stdout(self):
        self.assertEqual(nuclei_scan.parse_templates_version(
            "[INF] Current nuclei-templates version: v9.8.1 (latest)"), "v9.8.1")
        self.assertEqual(nuclei_scan.parse_templates_version(NO_TEMPLATES_OUTPUT), "")
        self.assertEqual(nuclei_scan.parse_templates_version(""), "")

    def test_version_call_timeout(self):
        def run(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

        result = run_with(mock.Mock(side_effect=run))
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["error"])


class CommandTests(unittest.TestCase):

    def test_exact_command_and_timeout(self):
        run = fake_nuclei(JSONL_TEXT)
        result = run_with(run, port=80)
        self.assertEqual(run.call_count, 2)
        call = scan_call(run)
        cmd = call.args[0]
        out = out_path_of(cmd)
        self.assertEqual(cmd, [
            "nuclei", "-u", "http://10.10.1.100:80", "-type", "http",
            "-severity", "low,medium,high,critical",
            "-exclude-tags", "dos,fuzz,intrusive,default-login,bruteforce,brute-force",
            "-no-interactsh", "-disable-update-check", "-rate-limit", "50",
            "-concurrency", "10", "-timeout", "10", "-retries", "1", "-omit-raw",
            "-no-color", "-silent", "-jsonl", "-o", out])
        self.assertEqual(os.path.basename(out), "nuclei.jsonl")
        self.assertTrue(os.path.basename(os.path.dirname(out)).startswith("reconmind_nuclei_"))
        self.assertEqual(call.kwargs["timeout"], 1800)
        self.assertEqual(result["url"], "http://10.10.1.100:80")
        self.assertEqual(result["command"], shlex.join(cmd))

    def test_safety_flags(self):
        run = fake_nuclei(JSONL_TEXT)
        run_with(run)
        cmd = scan_call(run).args[0]
        self.assertIn("-no-interactsh", cmd)
        self.assertIn("-disable-update-check", cmd)
        self.assertEqual(cmd[cmd.index("-severity") + 1], "low,medium,high,critical")
        tags = cmd[cmd.index("-exclude-tags") + 1].split(",")
        self.assertEqual(tags, ["dos", "fuzz", "intrusive", "default-login", "bruteforce",
                                "brute-force"])
        self.assertEqual(cmd[cmd.index("-type") + 1], "http")

    def test_no_update_credential_or_extra_template_options(self):
        run = fake_nuclei(JSONL_TEXT)
        run_with(run)
        banned = ("-update-templates", "-ut", "-update", "-up", "-update-template-dir",
                  "-ud", "-H", "-header", "-var", "-V", "-proxy", "-p", "-interactsh-url",
                  "-iserver", "-interactsh-token", "-itoken", "-dast", "-fuzz", "-headless",
                  "-code", "-file", "-t", "-templates", "-w", "-workflows", "-tags",
                  "-include-tags", "-itags", "-it", "-include-templates", "-as",
                  "-automatic-scan", "-secret-file", "-sf", "-auth")
        for call in run.call_args_list:  # the version call too
            cmd = call.args[0]
            for flag in banned:
                self.assertNotIn(flag, cmd)
            joined = " ".join(cmd).lower()
            for word in ("password", "passwd", "username", "token", "cookie"):
                self.assertNotIn(word, joined)

    def test_https_url(self):
        run = fake_nuclei(JSONL_TEXT)
        result = run_with(run, port=8443, use_https=True)
        cmd = scan_call(run).args[0]
        self.assertEqual(cmd[cmd.index("-u") + 1], "https://10.10.1.100:8443")
        self.assertEqual(result["url"], "https://10.10.1.100:8443")

    def test_temp_directory_is_deleted(self):
        run = fake_nuclei(JSONL_TEXT)
        run_with(run)
        self.assertEqual(len(run.out_paths), 1)
        self.assertFalse(os.path.exists(os.path.dirname(run.out_paths[0])))

    def test_bad_port_never_runs_nuclei(self):
        run = fake_nuclei(JSONL_TEXT)
        for port in (0, 70000, "abc"):
            self.assertEqual(run_with(run, port=port)["status"], "bad-port")
        run.assert_not_called()


class ParseTests(unittest.TestCase):

    def test_findings_from_fixture(self):
        result = run_with(fake_nuclei(JSONL_TEXT))
        self.assertEqual(result["status"], "ok")
        self.assertNotIn("error", result)
        findings = result["findings"]
        self.assertEqual([f["template_id"] for f in findings], [
            "phpinfo-files", "CVE-2012-1823", "CVE-2009-1151",
            "apache-mod-negotiation-listing"])  # nuclei's order
        self.assertEqual(findings[0], {
            "template_id": "phpinfo-files", "name": "PHPInfo Page - Detect",
            "severity": "low", "matched_at": "http://10.10.1.100:80/phpinfo.php",
            "matcher_name": "", "extracted": ["5.2.4-2ubuntu5.10"], "cve": [],
            "cwe": ["cwe-200"], "tags": ["config", "exposure", "phpinfo"]})

    def test_cve_and_cwe_lists(self):
        by_id = {f["template_id"]: f for f in run_with(fake_nuclei(JSONL_TEXT))["findings"]}
        self.assertEqual(by_id["CVE-2012-1823"]["cve"], ["CVE-2012-1823"])
        self.assertEqual(by_id["CVE-2012-1823"]["cwe"], ["CWE-20"])
        self.assertEqual(by_id["CVE-2012-1823"]["severity"], "high")
        self.assertEqual(by_id["CVE-2009-1151"]["cve"], ["CVE-2009-1151"])
        self.assertEqual(by_id["CVE-2009-1151"]["severity"], "critical")
        self.assertEqual(by_id["apache-mod-negotiation-listing"]["cve"], [])  # null in JSONL
        self.assertEqual(by_id["apache-mod-negotiation-listing"]["matcher_name"],
                         "multiple-choices")
        for f in by_id.values():
            self.assertIsInstance(f["cve"], list)
            self.assertIsInstance(f["cwe"], list)

    def test_result_keys(self):
        result = run_with(fake_nuclei(JSONL_TEXT))
        self.assertEqual(set(result), {"status", "url", "templates_version", "command",
                                       "findings", "raw_jsonl"})
        self.assertEqual(set(result["findings"][0]), {
            "template_id", "name", "severity", "matched_at", "matcher_name", "extracted",
            "cve", "cwe", "tags"})

    def test_blank_lines_are_skipped(self):
        self.assertIn("\n\n", JSONL_TEXT)  # the fixture has one
        lines = JSONL_TEXT.strip().splitlines()
        text = "\n\n   \n" + "\n \t\n".join(lines) + "\n\n"
        result = run_with(fake_nuclei(text))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(result["findings"]), 4)
        self.assertEqual(result["raw_jsonl"], text)

    def test_raw_jsonl_is_kept_as_evidence(self):
        result = run_with(fake_nuclei(JSONL_TEXT))
        self.assertEqual(result["raw_jsonl"], JSONL_TEXT)

    def test_no_output_file_is_ok_with_no_findings(self):
        run = fake_nuclei("", write=False)
        result = run_with(run)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["raw_jsonl"], "")
        self.assertEqual(result["templates_version"], "v10.5.2")
        self.assertNotIn("error", result)
        self.assertFalse(os.path.exists(os.path.dirname(run.out_paths[0])))

    def test_empty_file_is_ok_with_no_findings(self):
        result = run_with(fake_nuclei("\n"))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["findings"], [])

    def test_severity_rank(self):
        ranks = [nuclei_scan.severity_rank(s) for s in
                 ("critical", "HIGH", "medium", "low", "info", "unknown", "weird", None)]
        self.assertEqual(ranks, [0, 1, 2, 3, 4, 5, 6, 6])


class BadOutputTests(unittest.TestCase):

    def assert_clean_error(self, result, status):
        self.assertEqual(result["status"], status)
        self.assertEqual(result["findings"], [])
        self.assertTrue(result["error"])
        self.assertNotIn("—", result["error"])
        self.assertNotIn(" - ", result["error"])

    def test_broken_line(self):
        run = fake_nuclei(JSONL_TEXT.splitlines()[0] + '\n{"template-id":"x","info":{"na\n')
        self.assert_clean_error(run_with(run), "bad-jsonl")
        self.assertFalse(os.path.exists(os.path.dirname(run.out_paths[0])))

    def test_line_not_an_object(self):
        self.assert_clean_error(run_with(fake_nuclei("[1, 2]\n")), "bad-jsonl")

    def test_nonzero_exit_without_output(self):
        run = fake_nuclei("", write=False, returncode=1,
                          stderr="[FTL] Could not run nuclei: no templates provided for scan")
        result = run_with(run)
        self.assert_clean_error(result, "failed")
        self.assertIn("exited with code 1", result["error"])
        self.assertIn("no templates provided", result["error"])

    def test_timeout(self):
        seen = []

        def run(cmd, **kwargs):
            if is_version_call(cmd):
                return mock.Mock(returncode=0, stdout="", stderr=VERSION_OUTPUT)
            seen.append(out_path_of(cmd))
            raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

        result = run_with(mock.Mock(side_effect=run))
        self.assert_clean_error(result, "timeout")
        self.assertIn("1800 seconds", result["error"])
        self.assertTrue(result["command"].startswith("nuclei "))
        self.assertFalse(os.path.exists(os.path.dirname(seen[0])))


if __name__ == "__main__":
    unittest.main()
