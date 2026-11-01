"""
Offline tests for the report's exploit labels, links and Notes totals.
"""

import os
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
