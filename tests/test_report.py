"""
Offline tests for the report's exploit labels, links and Notes totals.
"""

import os
import tempfile
import unittest

from reconmind.core.attack_check import SKIPPED_MISSING, AttackCheck, AttackRow
from reconmind.core.report import build_report


def read_report(scan):
    with open(build_report(scan)) as fh:
        return fh.read()


def exploit(title, edb_id, match, query):
    return {"title": title, "edb_id": edb_id, "match": match, "query": query}


SCAN = {
    "target": "10.10.1.100", "status": "ok",
    "ports": [
        {"port": 21, "protocol": "tcp", "service": "ftp", "product": "vsftpd", "version": "2.3.4",
         "exploits": [exploit("vsftpd 2.3.4 - Backdoor Command Execution", "49757",
                              "exact_version", "vsftpd 2.3.4")]},
        {"port": 3306, "protocol": "tcp", "service": "mysql", "product": "MySQL",
         "version": "5.0.51a-3ubuntu5",
         "exploits": [exploit("MySQL 5.0.x - Overflow", "100", "version_family", "MySQL 5.0"),
                      exploit("MySQL 5.0.x - Bypass", "101", "version_family", "MySQL 5.0")]},
        {"port": 445, "protocol": "tcp", "service": "netbios-ssn", "product": "Samba smbd",
         "version": "3.X - 4.X",
         "exploits": [exploit("Samba - Something", "200", "product_only", "Samba")]},
        {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH",
         "version": "4.7p1", "exploits": []},
    ],
}


class ReportTests(unittest.TestCase):

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)
        self.report = read_report(SCAN)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def test_exploit_line_format(self):
        self.assertIn("- vsftpd 2.3.4 - Backdoor Command Execution (EDB-49757) [exact_version] "
                      "Link: https://www.exploit-db.com/exploits/49757", self.report)
        self.assertIn("- MySQL 5.0.x - Overflow (EDB-100) [version_family] "
                      "Link: https://www.exploit-db.com/exploits/100", self.report)
        self.assertIn("- Samba - Something (EDB-200) [product_only] "
                      "Link: https://www.exploit-db.com/exploits/200", self.report)

    def test_label_wording_and_query(self):
        self.assertIn("_Matched on exact version. Query: `vsftpd 2.3.4`_", self.report)
        self.assertIn("_Matched on version family only (patch level not confirmed). "
                      "Query: `MySQL 5.0`_", self.report)
        self.assertIn("_Matched on product name only (version unknown, unconfirmed). "
                      "Query: `Samba`_", self.report)

    def test_notes_totals(self):
        self.assertIn("4 known exploit match(es) across those services: 1 exact version, "
                      "2 version family (unconfirmed), 1 product only (unconfirmed).",
                      self.report)

    def test_unlabeled_entries_still_render(self):
        scan = dict(SCAN, ports=[dict(SCAN["ports"][0], exploits=[
            {"title": "Old entry", "edb_id": "1"}])])
        report = read_report(scan)
        self.assertIn("- Old entry (EDB-1) Link: https://www.exploit-db.com/exploits/1", report)
        self.assertNotIn("Matched on", report)


class RiskAndFailureReportTests(unittest.TestCase):

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    SCAN = {
        "target": "10.10.1.100", "status": "ok",
        "ports": [
            {"port": 80, "protocol": "tcp", "service": "http", "product": "Apache httpd",
             "version": "2.2.8", "exploits": [], "exploit_status": "lookup_failed",
             "lookup_error": "searchsploit exited with code 1"},
            {"port": 5900, "protocol": "tcp", "service": "vnc", "product": "VNC",
             "version": "protocol 3.3", "exploits": []},
            {"port": 23, "protocol": "tcp", "service": "telnet", "product": "Linux telnetd",
             "version": "", "exploits": []},
            {"port": 1524, "protocol": "tcp", "service": "bindshell",
             "product": "Metasploitable root shell", "version": "", "exploits": []},
            {"port": 8180, "protocol": "tcp", "service": "http", "product": "Apache httpd",
             "version": "2.2.8", "exploits": [
                 exploit("Apache + PHP < 5.3.12 / < 5.4.2 - cgi-bin Remote Code Execution",
                         "29290", "unverified", "Apache 2.2.8")]},
        ],
    }

    def test_risky_section_most_severe_first(self):
        report = read_report(self.SCAN)
        self.assertIn("## Exposed risky services", report)
        section = report.split("## Exposed risky services")[1].split("## ")[0]
        rows = [line for line in section.splitlines() if line.startswith("| ") and "/tcp" in line]
        self.assertEqual([r.split(" | ")[0] for r in rows], ["| 1524/tcp", "| 23/tcp", "| 5900/tcp"])
        self.assertIn("| critical | Unauthenticated root shell.", rows[0])
        self.assertLess(report.index("## Exposed risky services"),
                        report.index("## Known exploits"))

    def test_no_risky_section_without_flags(self):
        self.assertNotIn("## Exposed risky services", read_report(SCAN))

    def test_lookup_failed_wording(self):
        report = read_report(self.SCAN)
        self.assertIn("_Exploit lookup failed: searchsploit exited with code 1. Not checked. "
                      "This does not mean there are no exploits._", report)
        self.assertIn("Exploit lookup failed for 1 port(s), so those services were not checked.",
                      report)

    def test_unverified_label_and_count(self):
        report = read_report(self.SCAN)
        self.assertIn("_Version range could not be checked against the scanned version "
                      "(unconfirmed). Query: `Apache 2.2.8`_", report)
        self.assertIn("[unverified]", report)
        self.assertIn("1 match(es) unverified", report)
        self.assertIn("3 risky service(s) flagged.", report)

    def test_no_dash_separators_or_em_dashes_in_written_text(self):
        report = read_report(self.SCAN)
        titles = [e["title"] for p in self.SCAN["ports"] for e in p["exploits"]]
        for title in titles:
            report = report.replace(title, "")
        self.assertNotIn("\u2014", report)
        self.assertNotIn(" - ", report)


class SummarySectionTests(unittest.TestCase):

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def build(self, **kwargs):
        with open(build_report(SCAN, **kwargs)) as fh:
            return fh.read()

    def test_summary_is_labeled_as_ai_interpretation(self):
        report = self.build(analyst_summary="### Key findings\nx")
        self.assertIn("## Analyst summary (ReconMind agent)", report)
        self.assertIn("_AI interpretation. The tables below are the verified tool "
                      "results._", report)
        self.assertNotIn("Unverified references", report)

    def test_unverified_references_are_listed(self):
        report = self.build(analyst_summary="### Key findings\nx",
                            unverified_refs=["EDB-99999", "CVE-2007-2447"])
        self.assertIn("**Unverified references**", report)
        self.assertIn("- EDB-99999", report)
        self.assertIn("- CVE-2007-2447", report)

    def test_failed_summary_shows_notice_and_all_facts(self):
        report = self.build(summary_failed=True)
        self.assertIn("Analyst summary unavailable: the model output failed "
                      "validation.", report)
        self.assertNotIn("AI interpretation", report)
        self.assertIn("## Open ports", report)
        self.assertIn("## Known exploits (Exploit-DB)", report)
        self.assertIn("## Notes", report)

    def test_rate_limited_notice_and_all_facts(self):
        report = self.build(rate_limited=True)
        self.assertIn("Analyst summary unavailable: the model was busy (rate limited).", report)
        self.assertNotIn("failed validation", report)
        self.assertNotIn("AI interpretation", report)
        self.assertIn("## Open ports", report)
        self.assertIn("## Known exploits (Exploit-DB)", report)

    def test_attack_check_table(self):
        check = AttackCheck(None, [
            AttackRow("T1190", "Exploit Public-Facing Application",
                      "Exploit Public-Facing Application", "verified"),
            AttackRow("T1021.004", "Pass the Hash", "Remote Services: SSH", "name_mismatch"),
            AttackRow("T9999", "a|b", "", "unknown_id"),
            AttackRow("T1190", "", "Exploit Public-Facing Application", "name_mismatch"),
        ])
        report = self.build(analyst_summary="### Key findings\nx",
                            unverified_refs=["EDB-1"], attack_check=check)
        self.assertIn("**ATT&CK check**", report)
        self.assertIn("| ID | Name given | Official name | Result |", report)
        self.assertIn("| T1021.004 | Pass the Hash | Remote Services: SSH | name_mismatch |",
                      report)
        self.assertIn("| T9999 | a\\|b | (not in MITRE data) | unknown_id |", report)
        self.assertIn("| T1190 | (none) | Exploit Public-Facing Application | name_mismatch |",
                      report)
        # under the summary and its references, above the fact tables
        self.assertLess(report.index("- EDB-1"), report.index("**ATT&CK check**"))
        self.assertLess(report.index("**ATT&CK check**"), report.index("## Open ports"))

    def test_attack_check_skipped_message(self):
        report = self.build(analyst_summary="### Key findings\nx",
                            attack_check=AttackCheck(SKIPPED_MISSING, []))
        self.assertIn("ATT&CK check skipped: MITRE data file missing", report)
        self.assertNotIn("| ID | Name given", report)

    def test_attack_check_without_ids(self):
        report = self.build(analyst_summary="### Key findings\nx",
                            attack_check=AttackCheck(None, []))
        self.assertIn("No ATT&CK technique IDs found in the summary.", report)

    def test_no_summary_section_without_summary(self):
        self.assertNotIn("Analyst summary", self.build())

    def test_summary_text_has_no_em_dashes_or_dash_separators(self):
        check = AttackCheck(None, [AttackRow("T1190", "x", "y", "verified")])
        report = self.build(analyst_summary="### Key findings\nx", unverified_refs=["EDB-1"],
                            attack_check=check)
        report += self.build(analyst_summary="### Key findings\nx",
                             attack_check=AttackCheck(SKIPPED_MISSING, []))
        report += self.build(analyst_summary="### Key findings\nx",
                             attack_check=AttackCheck(None, []))
        report += self.build(summary_failed=True)
        report += self.build(rate_limited=True)
        for p in SCAN["ports"]:
            for e in p["exploits"]:
                report = report.replace(e["title"], "")
        for p in SCAN["ports"]:
            report = report.replace(p["version"], "")  # nmap data, not our text
        self.assertNotIn("\u2014", report)
        self.assertNotIn(" - ", report)


if __name__ == "__main__":
    unittest.main()
