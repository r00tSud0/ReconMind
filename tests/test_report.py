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


SCAN_INFO = {
    "source_ip": "10.10.1.5", "nmap_version": "7.94",
    "mode": "all 65535 ports, two pass",
    "commands": [
        "nmap -Pn -p- -T4 --reason -oX /tmp/p1.xml 10.10.1.100",
        "nmap -Pn -sV --script smb-os-discovery,irc-info -T4 --reason -p 21,22,445,3306 "
        "-oX /tmp/p2.xml 10.10.1.100",
    ],
    "started": "2026-11-04 10:00:00", "elapsed_seconds": 81.7,
}
FILTERED_STATES = [
    {"state": "filtered", "count": 65531, "reasons": {"no-response": 65531}},
    {"state": "open", "count": 4, "reasons": {"syn-ack": 4}},
]
CLOSED_STATES = [
    {"state": "closed", "count": 996, "reasons": {"reset": 996}},
    {"state": "open", "count": 4, "reasons": {"syn-ack": 4}},
]
FILTERED_NOTE = ("Filtered ports gave no answer or returned a firewall block message, so "
                 "their true state is unknown from this scan location. A firewall is likely "
                 "between the scanner and the target.")


class ScanDetailsReportTests(unittest.TestCase):

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def test_scan_details_section(self):
        report = read_report(dict(SCAN, scan_info=SCAN_INFO, port_states=FILTERED_STATES))
        self.assertIn("## Scan details", report)
        self.assertIn("- Scanned from: 10.10.1.5", report)
        self.assertIn("- nmap version: 7.94", report)
        self.assertIn("- Mode: all 65535 ports, two pass", report)
        self.assertIn("- Pass 1 (discovery): `{c}`".format(c=SCAN_INFO["commands"][0]), report)
        self.assertIn("- Pass 2 (detail): `{c}`".format(c=SCAN_INFO["commands"][1]), report)
        self.assertIn("- Duration: 81.70 seconds", report)
        self.assertLess(report.index("**Generated:**"), report.index("## Scan details"))
        self.assertLess(report.index("## Scan details"), report.index("## Open ports"))

    def test_single_pass_shows_one_command(self):
        info = dict(SCAN_INFO, mode="top 1000 ports", commands=[
            "nmap -Pn -sV --script smb-os-discovery,irc-info -T4 --reason -oX /tmp/a.xml "
            "10.10.1.100"])
        report = read_report(dict(SCAN, scan_info=info, port_states=CLOSED_STATES))
        self.assertIn("- Mode: top 1000 ports", report)
        self.assertIn("- Command: `{c}`".format(c=info["commands"][0]), report)
        self.assertNotIn("Pass 1", report)

    def test_no_scan_details_without_scan_info(self):
        report = read_report(SCAN)
        self.assertNotIn("## Scan details", report)
        self.assertNotIn("**Port states:**", report)

    def test_port_state_line_under_ports_table(self):
        report = read_report(dict(SCAN, scan_info=SCAN_INFO, port_states=FILTERED_STATES))
        line = "**Port states:** 65,531 filtered (no-response), 0 closed, 4 open."
        self.assertIn(line, report)
        self.assertLess(report.index("| 22 | tcp | ssh |"), report.index(line))
        self.assertLess(report.index(line), report.index("## Known exploits"))

    def test_multiple_reasons_are_counted(self):
        states = [{"state": "filtered", "count": 65531,
                   "reasons": {"no-response": 65529, "admin-prohibited": 2}},
                  {"state": "open", "count": 4, "reasons": {"syn-ack": 4}}]
        report = read_report(dict(SCAN, port_states=states))
        self.assertIn("**Port states:** 65,531 filtered (65,529 no-response, "
                      "2 admin-prohibited), 0 closed, 4 open.", report)

    def test_filtered_note_only_when_filtered(self):
        filtered = read_report(dict(SCAN, scan_info=SCAN_INFO, port_states=FILTERED_STATES))
        self.assertIn(FILTERED_NOTE, filtered)
        closed = read_report(dict(SCAN, scan_info=SCAN_INFO, port_states=CLOSED_STATES))
        self.assertIn("**Port states:** 0 filtered, 996 closed, 4 open.", closed)
        self.assertNotIn(FILTERED_NOTE, closed)

    def test_no_open_ports_still_shows_states_and_skipped_pass(self):
        info = dict(SCAN_INFO, commands=SCAN_INFO["commands"][:1])
        states = [{"state": "filtered", "count": 65535, "reasons": {"no-response": 65535}},
                  {"state": "open", "count": 0, "reasons": {}}]
        report = read_report({"target": "10.10.1.100", "status": "ok", "ports": [],
                              "scan_info": info, "port_states": states})
        self.assertIn("- Pass 2 (detail): skipped, pass 1 found no open ports.", report)
        self.assertIn("The scan ran but found no open ports.", report)
        self.assertIn("**Port states:** 65,535 filtered (no-response), 0 closed, 0 open.",
                      report)
        self.assertIn(FILTERED_NOTE, report)

    def test_refused_scan_has_no_scan_details(self):
        report = read_report({"target": "8.8.8.8", "status": "refused", "ports": [],
                              "scan_info": SCAN_INFO})
        self.assertNotIn("## Scan details", report)

    def test_new_text_has_no_em_dashes_or_dash_separators(self):
        report = read_report(dict(SCAN, scan_info=SCAN_INFO, port_states=FILTERED_STATES))
        report += read_report(dict(SCAN, scan_info=SCAN_INFO, port_states=CLOSED_STATES))
        report += read_report({"target": "10.10.1.100", "status": "ok", "ports": [],
                               "scan_info": dict(SCAN_INFO, commands=SCAN_INFO["commands"][:1]),
                               "port_states": FILTERED_STATES})
        for p in SCAN["ports"]:
            for e in p["exploits"]:
                report = report.replace(e["title"], "")
            report = report.replace(p["version"], "")  # nmap data, not our text
        self.assertNotIn("—", report)
        self.assertNotIn(" - ", report)


LAB_STATES = [
    {"state": "filtered", "count": 52683, "reasons": {"no-response": 52683}},
    {"state": "closed", "count": 12840, "reasons": {"reset": 12840}},
    {"state": "open", "count": 12, "reasons": {"syn-ack": 12}},
]
LOST = [
    {"port": 21, "protocol": "tcp", "pass2_state": "filtered", "pass2_reason": "no-response"},
    {"port": 22, "protocol": "tcp", "pass2_state": "filtered", "pass2_reason": "no-response"},
]
WARNING_HEAD = "**Warning: unconfirmed ports.**"


class UnconfirmedReportTests(unittest.TestCase):

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def lost_scan(self):
        return {"target": "10.10.1.100", "status": "ok", "ports": [],
                "unconfirmed_ports": LOST, "scan_info": SCAN_INFO,
                "port_states": LAB_STATES}

    def test_no_warning_when_key_missing_or_empty(self):
        self.assertNotIn(WARNING_HEAD, read_report(dict(SCAN, port_states=FILTERED_STATES)))
        self.assertNotIn(WARNING_HEAD, read_report(
            dict(SCAN, port_states=FILTERED_STATES, unconfirmed_ports=[])))
        empty = read_report({"target": "10.10.1.100", "status": "ok", "ports": [],
                             "unconfirmed_ports": [], "port_states": FILTERED_STATES})
        self.assertNotIn(WARNING_HEAD, empty)
        self.assertIn("The scan ran but found no open ports.", empty)

    def test_all_lost_explains_the_empty_result(self):
        report = read_report(self.lost_scan())
        self.assertNotIn("found no open ports", report)
        self.assertIn("The scan ran but no port was confirmed open.", report)
        self.assertIn(WARNING_HEAD, report)
        self.assertIn("answered as open in the discovery pass but not in the detail "
                      "pass: 21/tcp (detail pass: filtered, no-response), 22/tcp "
                      "(detail pass: filtered, no-response).", report)
        self.assertIn("packets were lost along the network path", report)
        self.assertIn("Rerun the scan", report)
        states = report.index("**Port states:**")
        self.assertLess(states, report.index(WARNING_HEAD))
        self.assertLess(report.index(WARNING_HEAD), report.index(FILTERED_NOTE))

    def test_partial_shows_table_and_warning(self):
        lost = [dict(LOST[0], port=8080)]  # SCAN's own ports are the confirmed ones
        report = read_report(dict(SCAN, unconfirmed_ports=lost, scan_info=SCAN_INFO,
                                  port_states=FILTERED_STATES))
        self.assertIn("## Open ports", report)
        self.assertNotIn("| 8080 |", report)
        self.assertLess(report.index("**Port states:**"), report.index(WARNING_HEAD))
        self.assertLess(report.index(WARNING_HEAD), report.index("## Known exploits"))
        self.assertIn("8080/tcp (detail pass: filtered, no-response).", report)
        self.assertIn("1 more port(s) answered as open in discovery only", report)

    def test_warning_without_port_states_or_reason(self):
        report = read_report({"target": "10.10.1.100", "status": "ok", "ports": [],
                              "unconfirmed_ports": [{"port": 80, "protocol": "tcp",
                                                     "pass2_state": "closed",
                                                     "pass2_reason": ""}]})
        self.assertIn("80/tcp (detail pass: closed).", report)
        self.assertIn("no port was confirmed open", report)

    def test_warning_text_has_no_em_dashes_or_dash_separators(self):
        report = read_report(self.lost_scan())
        report += read_report(dict(SCAN, unconfirmed_ports=LOST, scan_info=SCAN_INFO,
                                   port_states=FILTERED_STATES))
        for p in SCAN["ports"]:
            for e in p["exploits"]:
                report = report.replace(e["title"], "")
            report = report.replace(p["version"], "")  # nmap data, not our text
        self.assertIn(WARNING_HEAD, report)
        self.assertNotIn("—", report)
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


WEB_SCAN = {
    "target": "10.10.1.100", "status": "ok",
    "ports": [
        {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH",
         "version": "4.7p1", "exploits": []},
        {"port": 80, "protocol": "tcp", "service": "http", "product": "Apache httpd",
         "version": "2.2.8", "exploits": [
             exploit("Apache 2.2.8 - Something", "300", "exact_version", "Apache 2.2.8")]},
        {"port": 443, "protocol": "tcp", "service": "http", "tunnel": "ssl",
         "product": "Apache httpd", "version": "2.2.8", "exploits": []},
        {"port": 8180, "protocol": "tcp", "service": "http", "product": "Apache Tomcat",
         "version": "5.5", "exploits": []},
    ],
    "web": {
        # Built from httpx's real output for Metasploitable's port 80.
        80: {"status": "ok", "url": "http://10.10.1.100:80", "http_status": 200,
             "server": "Apache/2.2.8 (Ubuntu) DAV/2", "title": "Metasploitable2 - Linux",
             "location": "", "command": "httpx-toolkit ...", "raw_json": '{"raw": "evidence"}',
             "technologies": [
                 {"name": "Apache HTTP Server", "version": "2.2.8",
                  "raw": "Apache HTTP Server:2.2.8"},
                 {"name": "PHP", "version": "5.2.4", "raw": "PHP:5.2.4"},
                 {"name": "Ubuntu", "version": "", "raw": "Ubuntu"},
                 {"name": "bun", "version": "", "raw": "bun"},
                 {"name": "mod_dav", "version": "2", "raw": "mod_dav:2"},
             ]},
        443: {"status": "bad-output", "url": "https://10.10.1.100:443", "http_status": None,
              "server": "", "title": "", "location": "", "technologies": [],
              "command": "httpx-toolkit ...", "raw_json": "not json",
              "error": "httpx output is not a JSON object."},
    },
}
WEB_HEAD = "## Web technology (httpx)"
FINGERPRINT_NOTE = ("Technologies are matched by Wappalyzer fingerprints and can include "
                    "false matches. Only technologies with a version are used for CVE "
                    "lookups.")
BASIC_8180 = {"status": "ok", "url": "http://10.10.1.100:8180", "method": "basic header check",
              "http_status": 200, "server": "Apache-Coyote/1.1", "x_powered_by": "",
              "title": "Apache Tomcat/5.5", "fallback_reason": "timeout",
              "httpx_error": "httpx did not finish within 60 seconds."}


class WebReportTests(unittest.TestCase):

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def section(self, report):
        return report.split(WEB_HEAD)[1].split("\n## ")[0]

    def test_web_section_lists_url_status_server_title_and_technologies(self):
        section = self.section(read_report(WEB_SCAN))
        self.assertIn("**80/tcp**\n\n"
                      "- URL: http://10.10.1.100:80\n"
                      "- HTTP status: 200\n"
                      "- Server: Apache/2.2.8 (Ubuntu) DAV/2\n"
                      "- Title: Metasploitable2 - Linux\n\n"
                      "Technologies:\n\n"
                      "- Apache HTTP Server, version 2.2.8\n"
                      "- PHP, version 5.2.4\n"
                      "- Ubuntu\n"
                      "- bun\n"
                      "- mod_dav, version 2\n", section)
        self.assertNotIn("Redirect location", section)
        self.assertNotIn("evidence", section)  # raw_json is never printed

    def test_fingerprint_note_is_always_there(self):
        self.assertIn(WEB_HEAD + "\n\n" + FINGERPRINT_NOTE + "\n", read_report(WEB_SCAN))
        scan = {k: v for k, v in WEB_SCAN.items() if k != "web"}
        self.assertIn(FINGERPRINT_NOTE, self.section(read_report(scan)))

    def test_redirect_location_is_shown(self):
        web = dict(WEB_SCAN["web"])
        web[80] = dict(web[80], http_status=302, location="/phpinfo.php")
        section = self.section(read_report(dict(WEB_SCAN, web=web)))
        self.assertIn("- HTTP status: 302\n- Server: Apache/2.2.8 (Ubuntu) DAV/2\n"
                      "- Title: Metasploitable2 - Linux\n- Redirect location: /phpinfo.php\n",
                      section)

    def test_no_technologies(self):
        web = {80: dict(WEB_SCAN["web"][80], technologies=[])}
        section = self.section(read_report(dict(WEB_SCAN, web=web)))
        self.assertIn("_httpx matched no technologies._", section)

    def test_basic_header_check_result(self):
        web = {**WEB_SCAN["web"], 8180: BASIC_8180}
        section = self.section(read_report(dict(WEB_SCAN, web=web)))
        self.assertIn("**8180/tcp**\n\n"
                      "Basic header check (httpx timeout)\n\n"
                      "_httpx did not complete, so only the server's own headers and title "
                      "are shown. No technology matching was done._\n\n"
                      "- URL: http://10.10.1.100:8180\n"
                      "- HTTP status: 200\n"
                      "- Server: Apache-Coyote/1.1\n"
                      "- X-Powered-By: not reported\n"
                      "- Title: Apache Tomcat/5.5\n", section)
        self.assertNotIn("8180/tcp (http).", section)  # checked, so not in "Not checked"

    def test_basic_header_check_notes_unverified_certificate(self):
        basic = dict(BASIC_8180, url="https://10.10.1.100:443",
                     certificate_check="Certificate not verified: self signed "
                                       "certificates are accepted on lab targets.")
        web = {**WEB_SCAN["web"], 443: basic}
        section = self.section(read_report(dict(WEB_SCAN, web=web)))
        self.assertIn("Certificate not verified: self signed certificates are accepted "
                      "on lab targets.", section)

    def test_failed_basic_header_check_says_not_checked(self):
        basic = dict(BASIC_8180, status="failed", http_status=None, server="", title="",
                     error="The request failed: refused")
        web = {**WEB_SCAN["web"], 8180: basic}
        section = self.section(read_report(dict(WEB_SCAN, web=web)))
        self.assertIn("_httpx did not complete (status timeout) and the basic header check "
                      "failed too (status failed), so this port was not checked._", section)

    def test_web_section_after_exploits_before_notes(self):
        report = read_report(WEB_SCAN)
        self.assertLess(report.index("## Known exploits"), report.index(WEB_HEAD))
        self.assertLess(report.index(WEB_HEAD), report.index("## Notes"))

    def test_not_checked_line(self):
        report = read_report(WEB_SCAN)
        self.assertIn("**Not checked:** these open web ports were not fingerprinted with "
                      "httpx: 8180/tcp (http).", report)
        section = report.split(WEB_HEAD)[1].split("## Notes")[0]
        self.assertNotIn("22/tcp", section)  # ssh is not a web port

    def test_failed_run_says_not_checked(self):
        section = self.section(read_report(WEB_SCAN))
        self.assertIn("**443/tcp**\n\n_httpx did not complete (status bad-output), so this "
                      "port was not checked._", section)

    def test_all_web_ports_not_checked_without_web_results(self):
        scan = {k: v for k, v in WEB_SCAN.items() if k != "web"}
        report = read_report(scan)
        self.assertIn(WEB_HEAD, report)
        self.assertIn("httpx: 80/tcp (http), 443/tcp (http), 8180/tcp (http).", report)

    def test_string_port_keys_from_json(self):
        scan = dict(WEB_SCAN, web={str(k): v for k, v in WEB_SCAN["web"].items()})
        report = read_report(scan)
        self.assertIn("**80/tcp**\n\n- URL: http://10.10.1.100:80\n", report)
        self.assertIn("httpx: 8180/tcp (http).", report)

    def test_no_section_without_web_ports(self):
        self.assertNotIn(WEB_HEAD, read_report(SCAN))
        self.assertNotIn(WEB_HEAD, read_report({"target": "10.10.1.100", "status": "ok",
                                                "ports": []}))

    def test_web_text_has_no_em_dashes_or_dash_separators(self):
        web = {**WEB_SCAN["web"], 8180: BASIC_8180}
        report = read_report(dict(WEB_SCAN, web=web))
        report += read_report({k: v for k, v in WEB_SCAN.items() if k != "web"})
        for p in WEB_SCAN["ports"]:
            for e in p["exploits"]:
                report = report.replace(e["title"], "")
            report = report.replace(p["version"], "")  # nmap data, not our text
        for result in web.values():  # httpx and header data, not our text
            for key in ("server", "title", "x_powered_by"):
                if result.get(key):
                    report = report.replace(result[key], "")
            for t in result.get("technologies", []):
                report = report.replace(t["raw"], "")
        self.assertIn(WEB_HEAD, report)
        self.assertIn(FINGERPRINT_NOTE, report)
        self.assertNotIn("\u2014", report)
        self.assertNotIn(" - ", report)


ATTACK_MAP = {
    "status": "ok", "error": "", "run_name": "run3", "threshold": 0.85,
    "model_sha256": "0123456789abcdef" * 4, "mitre_check": None,
    "ports": [
        {"port": 21, "protocol": "tcp", "service": "ftp", "text": "Port 21/tcp is open.",
         "techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application",
                         "sources": ["model"], "confidence": 0.91}],
         "lower_confidence": [{"id": "T1005", "name": "Data from Local System",
                               "source": "model, lower confidence", "confidence": 0.62}],
         "dropped": [{"id": "T9999", "source": "model", "reason": "unknown_id"}]},
        {"port": 23, "protocol": "tcp", "service": "telnet", "text": "Port 23/tcp is open.",
         "techniques": [{"id": "T1021", "name": "Remote Services", "sources": ["rule", "model"],
                         "confidence": 1.0, "model_probability": 0.95},
                        {"id": "T1040", "name": "Network Sniffing", "sources": ["rule"],
                         "confidence": 1.0}],
         "lower_confidence": [], "dropped": []},
    ],
}
MAP_SCAN = {"target": "10.10.1.100", "status": "ok", "ports": [
    {"port": 21, "protocol": "tcp", "service": "ftp", "product": "vsftpd", "version": "2.3.4"},
    {"port": 23, "protocol": "tcp", "service": "telnet", "product": "Linux telnetd",
     "version": ""},
]}
MAPPING_HEAD = "## MITRE ATT&CK mapping"
UNAVAILABLE_LINE = ("Mapper: status not-installed. The model is unavailable, so only rule "
                    "mappings are shown.")


def unavailable_map():
    rules_only = dict(ATTACK_MAP, status="not-installed", run_name="", threshold=None,
                      model_sha256="")
    rules_only["ports"] = [dict(p, lower_confidence=[], dropped=[],
                                techniques=[t for t in p["techniques"]
                                            if "rule" in t["sources"]])
                           for p in ATTACK_MAP["ports"]]
    for p in rules_only["ports"]:
        p["techniques"] = [dict(t, sources=["rule"]) for t in p["techniques"]]
        for t in p["techniques"]:
            t.pop("model_probability", None)
    return rules_only


class AttackMapReportTests(unittest.TestCase):

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def test_confirmed_table_one_row_per_technique(self):
        report = read_report(dict(MAP_SCAN, attack_map=ATTACK_MAP))
        self.assertIn(MAPPING_HEAD, report)
        self.assertIn("| Port | ID | Name | Source | Confidence | MITRE check |", report)
        self.assertIn("| 21/tcp | T1190 | Exploit Public-Facing Application | model | 0.91 "
                      "| active |", report)
        self.assertIn("| 23/tcp | T1021 | Remote Services | rule and model | 1.00 (model 0.95) "
                      "| active |", report)
        self.assertIn("| 23/tcp | T1040 | Network Sniffing | rule | 1.00 | active |", report)

    def test_lower_confidence_suggestions_have_their_own_table(self):
        report = read_report(dict(MAP_SCAN, attack_map=ATTACK_MAP))
        section = report.split(MAPPING_HEAD, 1)[1]
        lower = section.index("**Lower confidence suggestions**")
        row = ("| 21/tcp | T1005 | Data from Local System | model, lower confidence | 0.62 "
               "| active |")
        self.assertLess(section.index("| 23/tcp | T1040 |"), lower)
        self.assertLess(lower, section.index(row))
        self.assertIn("These are not mappings and are not counted.", section)

    def test_dropped_ids_and_mapper_line(self):
        report = read_report(dict(MAP_SCAN, attack_map=ATTACK_MAP))
        section = report.split(MAPPING_HEAD, 1)[1]
        self.assertIn("- 21/tcp T9999 (model): unknown_id", section)
        mapper = "Mapper: status ok, run run3, threshold 0.85, model SHA-256 0123456789ab\n"
        self.assertIn(mapper, section)
        self.assertNotIn("0123456789abc\n", section)  # only the first 12 characters
        self.assertLess(section.index("**Lower confidence suggestions**"),
                        section.index("Mapper:"))

    def test_unavailable_model_shows_status_and_rules_only(self):
        report = read_report(dict(MAP_SCAN, attack_map=unavailable_map()))
        self.assertIn(UNAVAILABLE_LINE, report)
        self.assertNotIn("model SHA-256", report)
        self.assertIn("| 23/tcp | T1021 | Remote Services | rule | 1.00 | active |", report)
        self.assertNotIn("**Lower confidence suggestions**", report)

    def test_section_sits_before_notes(self):
        report = read_report(dict(MAP_SCAN, attack_map=ATTACK_MAP))
        self.assertLess(report.index("## Open ports"), report.index(MAPPING_HEAD))
        self.assertLess(report.index(MAPPING_HEAD), report.index("## Notes"))
        self.assertNotIn("Next stage", report)

    def test_no_section_without_a_mapping(self):
        self.assertNotIn(MAPPING_HEAD, read_report(MAP_SCAN))

    def test_no_confirmed_technique(self):
        empty = dict(ATTACK_MAP, ports=[dict(p, techniques=[]) for p in ATTACK_MAP["ports"]])
        report = read_report(dict(MAP_SCAN, attack_map=empty))
        self.assertIn("_No technique was confirmed for any open port._", report)

    def test_mapping_text_has_no_em_dashes_or_dash_separators(self):
        report = read_report(dict(MAP_SCAN, attack_map=ATTACK_MAP))
        report += read_report(dict(MAP_SCAN, attack_map=unavailable_map()))
        self.assertIn(MAPPING_HEAD, report)
        self.assertNotIn("\u2014", report)
        self.assertNotIn("\u2013", report)
        self.assertNotIn(" - ", report)


if __name__ == "__main__":
    unittest.main()
