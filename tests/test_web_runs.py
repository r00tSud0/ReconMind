"""
Offline tests for reconmind/web/runs.py: the progress event reader (complete
lines only, since, limit, bad lines), run id validation, run file path
containment (.., symlinked folders and files), and what the Report screen
derives from a saved run (findings that match the index counts, the port
spectrum, the AI summary, code findings without folders).

Nothing here needs the web packages, starts a process or uses the network.

    python3 -m unittest discover -s tests -v
"""

import json
import os
import tempfile
import unittest

from reconmind.core import history
from reconmind.core import report as report_mod
from reconmind.core.scan_plan import build_plan
from reconmind.web import runs

RUN_ID = "20261112_213600_10.10.1.20"


def write_lines(path, lines, end="\n"):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + end)


def event(kind, **data):
    return json.dumps(dict({"time": "2026-11-12T21:36:00", "kind": kind}, **data))


class ReadEventsTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "job.events.jsonl")

    def tearDown(self):
        self._tmp.cleanup()

    def test_missing_file_gives_nothing_and_keeps_since(self):
        self.assertEqual(runs.read_events(self.path), ([], 0, False))
        self.assertEqual(runs.read_events(self.path, since=7), ([], 7, False))

    def test_reads_every_complete_line_in_order(self):
        write_lines(self.path, [event("plan", target="10.10.1.20"), event("step", tool="nmap_scan")])
        events, next_line, more = runs.read_events(self.path)
        self.assertEqual([e["kind"] for e in events], ["plan", "step"])
        self.assertEqual(next_line, 2)
        self.assertFalse(more)

    def test_since_skips_lines_already_read(self):
        write_lines(self.path, [event("plan"), event("ports", ports=[]), event("finished")])
        events, next_line, _ = runs.read_events(self.path, since=2)
        self.assertEqual([e["kind"] for e in events], ["finished"])
        self.assertEqual(next_line, 3)
        self.assertEqual(runs.read_events(self.path, since=3), ([], 3, False))

    def test_a_line_still_being_written_waits_for_its_newline(self):
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(event("plan") + "\n" + '{"kind": "st')
        events, next_line, _ = runs.read_events(self.path)
        self.assertEqual([e["kind"] for e in events], ["plan"])
        self.assertEqual(next_line, 1)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write('ep", "tool": "nmap_scan"}\n')
        events, next_line, _ = runs.read_events(self.path, since=1)
        self.assertEqual(events, [{"kind": "step", "tool": "nmap_scan"}])
        self.assertEqual(next_line, 2)

    def test_bad_lines_are_skipped_but_counted(self):
        with open(self.path, "wb") as fh:
            fh.write(b"not json\n")
            fh.write(b"[1, 2]\n")
            fh.write(b"\xff\xfe broken utf-8\n")
            fh.write(event("finished", status="ok").encode("utf-8") + b"\n")
        events, next_line, _ = runs.read_events(self.path)
        self.assertEqual([e["kind"] for e in events], ["finished"])
        self.assertEqual(next_line, 4)

    def test_limit_stops_early_and_says_there_is_more(self):
        write_lines(self.path, [event("command", command="c{n}".format(n=n)) for n in range(5)])
        events, next_line, more = runs.read_events(self.path, limit=2)
        self.assertEqual([e["command"] for e in events], ["c0", "c1"])
        self.assertEqual(next_line, 2)
        self.assertTrue(more)
        events, next_line, more = runs.read_events(self.path, since=next_line, limit=2)
        self.assertEqual([e["command"] for e in events], ["c2", "c3"])
        events, next_line, more = runs.read_events(self.path, since=next_line, limit=2)
        self.assertEqual([e["command"] for e in events], ["c4"])
        self.assertEqual(next_line, 5)
        self.assertFalse(more)

    def test_since_past_the_end_waits_there(self):
        write_lines(self.path, [event("plan")])
        self.assertEqual(runs.read_events(self.path, since=10), ([], 10, False))

    def test_negative_since_reads_from_the_start(self):
        write_lines(self.path, [event("plan")])
        events, next_line, _ = runs.read_events(self.path, since=-5)
        self.assertEqual(len(events), 1)
        self.assertEqual(next_line, 1)


class RunIdTests(unittest.TestCase):

    def test_ids_new_run_id_makes_are_valid(self):
        from datetime import datetime
        when = datetime(2026, 11, 12, 21, 36, 0)
        for target in ("10.10.1.20", "app.py", "my project", "../../etc"):
            run_id = history.new_run_id(target, when)
            if ".." in run_id:
                continue
            self.assertTrue(runs.valid_run_id(run_id), run_id)
        self.assertTrue(runs.valid_run_id(RUN_ID + "_2"))

    def test_other_ids_are_not(self):
        for bad in ("", "abc", "..", "../" + RUN_ID, RUN_ID + "/report.md", "20261112_213600_..",
                    "20261112_213600_a..b", "2026111_213600_x", "20261112-213600_x",
                    RUN_ID + "\n", " " + RUN_ID, "20261112_213600_" + "a" * 161, None, 5):
            self.assertFalse(runs.valid_run_id(bad), repr(bad))


class RunFileTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.report_dir = os.path.join(self._tmp.name, "reports")
        self.folder = os.path.join(self.report_dir, RUN_ID)
        os.makedirs(self.folder)
        for name in runs.RUN_FILES:
            with open(os.path.join(self.folder, name), "w") as fh:
                fh.write("{}")

    def tearDown(self):
        self._tmp.cleanup()

    def test_a_file_inside_its_run_folder_is_found(self):
        path = runs.run_file(self.report_dir, RUN_ID, history.REPORT_NAME)
        self.assertEqual(path, os.path.join(os.path.realpath(self.report_dir), RUN_ID, "report.md"))

    def test_unknown_names_are_refused(self):
        with self.assertRaises(ValueError):
            runs.run_file(self.report_dir, RUN_ID, "index.json")

    def test_missing_files_and_bad_ids_are_none(self):
        self.assertIsNone(runs.run_file(self.report_dir, RUN_ID + "_2", history.REPORT_NAME))
        self.assertIsNone(runs.run_file(self.report_dir, "..", history.REPORT_NAME))
        os.remove(os.path.join(self.folder, history.EVIDENCE_NAME))
        self.assertIsNone(runs.run_file(self.report_dir, RUN_ID, history.EVIDENCE_NAME))

    def test_a_folder_in_place_of_the_file_is_none(self):
        os.remove(os.path.join(self.folder, history.SCAN_NAME))
        os.makedirs(os.path.join(self.folder, history.SCAN_NAME))
        self.assertIsNone(runs.run_file(self.report_dir, RUN_ID, history.SCAN_NAME))

    @unittest.skipUnless(hasattr(os, "symlink"), "needs symlinks")
    def test_a_symlinked_run_folder_is_refused(self):
        outside = os.path.join(self._tmp.name, "outside")
        os.makedirs(outside)
        with open(os.path.join(outside, "report.md"), "w") as fh:
            fh.write("secret")
        link_id = "20261112_213600_link"
        os.symlink(outside, os.path.join(self.report_dir, link_id))
        self.assertIsNone(runs.run_file(self.report_dir, link_id, history.REPORT_NAME))

    @unittest.skipUnless(hasattr(os, "symlink"), "needs symlinks")
    def test_a_symlinked_file_is_refused(self):
        outside = os.path.join(self._tmp.name, "secret.txt")
        with open(outside, "w") as fh:
            fh.write("secret")
        target = os.path.join(self.folder, history.REPORT_NAME)
        os.remove(target)
        os.symlink(outside, target)
        self.assertIsNone(runs.run_file(self.report_dir, RUN_ID, history.REPORT_NAME))

    @unittest.skipUnless(hasattr(os, "symlink"), "needs symlinks")
    def test_a_symlink_to_another_run_is_refused(self):
        other = "20261112_213600_other"
        os.makedirs(os.path.join(self.report_dir, other))
        target = os.path.join(self.report_dir, other, history.REPORT_NAME)
        os.symlink(os.path.join(self.folder, history.REPORT_NAME), target)
        self.assertIsNone(runs.run_file(self.report_dir, other, history.REPORT_NAME))


# ---- what the Report screen derives ------------------------------------------

PLAN = build_plan("10.10.1.20")

RESULTS = {
    "target": "10.10.1.20",
    "status": "ok",
    "ports": [
        {"port": 21, "protocol": "tcp", "service": "ftp", "product": "vsftpd", "version": "2.3.4",
         "exploits": [{"title": "vsftpd 2.3.4 - Backdoor Command Execution", "edb_id": "49757",
                       "match": "exact_version"}]},
        {"port": 23, "protocol": "tcp", "service": "telnet", "product": "Linux telnetd", "version": ""},
        {"port": 80, "protocol": "tcp", "service": "http", "product": "Apache httpd", "version": "2.2.8"},
        {"port": 443, "protocol": "tcp", "service": "https", "product": "Apache httpd", "version": "2.2.8"},
    ],
    # JSON object keys are always text, as in a saved scan.json.
    "nuclei": {"80": {"status": "ok", "findings": [
        {"severity": "medium", "name": "phpMyAdmin panel", "template_id": "phpmyadmin-panel",
         "matched_at": "http://10.10.1.20/phpMyAdmin/"},
        {"severity": "info", "name": "Apache detected", "template_id": "apache-detect"}]}},
    "tls": {"443": {"status": "ok", "findings": [
        {"severity": "HIGH", "id": "SSLv3", "finding": "offered", "cve": "CVE-2014-3566"},
        {"severity": "OK", "id": "TLS1_2", "finding": "offered"}]}},
    "nvd": {"status": "ok", "products": [{"cves": [{"id": "CVE-2011-2523", "cvss_score": 9.8}]}]},
    "attack_map": {"status": "ok", "ports": [
        {"port": 23, "techniques": [{"id": "T1021", "name": "Remote Services", "sources": ["rule"],
                                     "confidence": 1.0}]}]},
}


class FindingTests(unittest.TestCase):

    def test_findings_match_the_index_counts(self):
        findings = runs.recon_findings(RESULTS, PLAN.to_dict())
        counts = dict.fromkeys(history.SEVERITIES, 0)
        for f in findings:
            counts[f["severity"]] += 1
        self.assertEqual(counts, history.finding_counts(RESULTS, PLAN))

    def test_findings_are_most_severe_first_with_their_evidence(self):
        findings = runs.recon_findings(RESULTS, PLAN.to_dict())
        self.assertEqual([(f["severity"], f["port"], f["source"]) for f in findings],
                         [("high", 23, "Risk rule"), ("high", 443, "testssl.sh"),
                          ("medium", 80, "nuclei")])
        telnet = findings[0]
        self.assertEqual(telnet["ids"], ["T1021"])
        self.assertEqual(telnet["where"], "Port 23, telnet")
        self.assertTrue(telnet["evidence"][0].startswith("nmap  23/tcp open telnet"))
        self.assertIn("CVE-2014-3566", findings[1]["evidence"][0])

    def test_risk_flags_only_when_exploit_hunt_ran(self):
        plan = build_plan("10.10.1.20", actions=["surface", "vulns", "crypto"]).to_dict()
        sources = {f["source"] for f in runs.recon_findings(RESULTS, plan)}
        self.assertNotIn("Risk rule", sources)

    def test_spectrum_has_every_open_port_with_its_worst_finding(self):
        findings = runs.recon_findings(RESULTS, PLAN.to_dict())
        self.assertEqual(runs.spectrum(RESULTS, findings), [
            {"port": 21, "service": "ftp", "severity": "none"},
            {"port": 23, "service": "telnet", "severity": "high"},
            {"port": 80, "service": "http", "severity": "medium"},
            {"port": 443, "service": "https", "severity": "high"},
        ])

    def test_broken_results_give_no_findings(self):
        self.assertEqual(runs.recon_findings(None), [])
        self.assertEqual(runs.recon_findings({"ports": "nope", "nuclei": [1], "tls": {"x": "y"}}), [])

    def test_code_findings_name_the_file_never_its_folder(self):
        results = {"findings": [{
            "severity": "high", "file": "src/deep/app.py", "line": 12, "cwe": ["CWE-78"],
            "sources": ["semgrep", "bandit"], "rule_ids": {"semgrep": "py.os-system", "bandit": "B605"},
            "messages": {"semgrep": "Command injection. Use a list.", "bandit": "Shell call."},
            "snippet": "os.system(cmd)"}]}
        (finding,) = runs.code_findings(results)
        self.assertEqual(finding["where"], "app.py, line 12")
        self.assertEqual(finding["source"], "Semgrep and Bandit")
        self.assertEqual(finding["title"], "Command injection")
        self.assertEqual(finding["ids"], ["CWE-78"])
        self.assertNotIn("src/deep", json.dumps(finding))


class SummaryTests(unittest.TestCase):

    def test_ai_summary_text_and_unverified_references(self):
        markdown = "\n".join([
            "# ReconMind Report", "", "## Analyst summary (ReconMind agent)", "",
            report_mod.SUMMARY_LABEL, "", "Two backdoors.", "", "Patch Samba.", "",
            "**Unverified references**", "", "_Not found in any tool result for this scan:_",
            "- CVE-2099-0001", "", "**ATT&CK check**", "", "| ID |", "", "## Scan details", "- x"])
        result = runs.summary(markdown)
        self.assertEqual(result["state"], "ok")
        self.assertEqual(result["text"], "Two backdoors.\n\nPatch Samba.")
        self.assertEqual(result["unverified"], ["CVE-2099-0001"])

    def test_ai_off(self):
        markdown = "# ReconMind Report\n\n_{n}_\n".format(n=report_mod.STANDARD_NOTE)
        self.assertEqual(runs.summary(markdown)["state"], "off")
        self.assertEqual(runs.summary("# R\n", {"mode": "standard"})["state"], "off")

    def test_failed_and_rate_limited(self):
        for notice, state in ((report_mod.SUMMARY_UNAVAILABLE, "failed"),
                              (report_mod.SUMMARY_RATE_LIMITED, "rate_limited")):
            markdown = "## Analyst summary (ReconMind agent)\n\n{n}\n\n## Open ports\n".format(n=notice)
            self.assertEqual(runs.summary(markdown)["state"], state)

    def test_no_summary_section(self):
        self.assertEqual(runs.summary("# ReconMind Report\n")["state"], "none")
        self.assertEqual(runs.summary(None)["state"], "none")


if __name__ == "__main__":
    unittest.main()
