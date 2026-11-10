"""
Offline tests for reconmind.ai.finding_text. No network, no nmap, no model:
the text is built straight from port dicts.

    python3 -m unittest discover -s tests -v
"""

import unittest

from reconmind.ai.finding_text import finding_text


def port(**kw):
    base = {"port": 22, "protocol": "tcp", "service": "ssh",
            "product": "OpenSSH", "version": "4.7p1"}
    base.update(kw)
    return base


def exploit(title, edb_id, match):
    return {"title": title, "edb_id": edb_id, "match": match}


class FindingTextTests(unittest.TestCase):

    def test_basic_port(self):
        self.assertEqual(
            finding_text(port()),
            "Port 22/tcp is open running ssh: OpenSSH 4.7p1.")

    def test_risky_port_adds_risk(self):
        text = finding_text(port(port=23, service="telnet",
                                 product="Linux telnetd", version=""))
        self.assertTrue(text.startswith(
            "Port 23/tcp is open running telnet: Linux telnetd."))
        self.assertIn(" Risk: Telnet login.", text)

    def test_distccd_port_adds_risk(self):
        text = finding_text(port(port=3632, service="distccd",
                                 product="distccd", version="v1"))
        self.assertTrue(text.startswith(
            "Port 3632/tcp is open running distccd: distccd v1."))
        self.assertIn(" Risk: distcc compile daemon exposed.", text)

    def test_exact_version_before_version_family(self):
        p = port(exploits=[exploit("family hit", "2", "version_family"),
                           exploit("exact hit", "1", "exact_version")])
        text = finding_text(p)
        self.assertIn(
            "Known exploits (Exploit-DB): exact hit (EDB-1); family hit (EDB-2).",
            text)
        self.assertLess(text.index("exact hit"), text.index("family hit"))

    def test_product_only_and_unverified_are_left_out(self):
        p = port(exploits=[exploit("product only hit", "1", "product_only"),
                           exploit("unverified hit", "2", "unverified")])
        self.assertEqual(finding_text(p),
                         "Port 22/tcp is open running ssh: OpenSSH 4.7p1.")

    def test_three_title_cap(self):
        p = port(exploits=[exploit("t%d" % i, str(i), "exact_version")
                           for i in range(5)])
        text = finding_text(p)
        self.assertIn("t0 (EDB-0); t1 (EDB-1); t2 (EDB-2).", text)
        self.assertNotIn("t3", text)
        self.assertNotIn("t4", text)

    def test_missing_version(self):
        self.assertEqual(
            finding_text(port(version="")),
            "Port 22/tcp is open running ssh: OpenSSH.")

    def test_missing_product_and_version(self):
        self.assertEqual(
            finding_text(port(product="", version="")),
            "Port 22/tcp is open running ssh.")

    def test_version_without_product(self):
        self.assertEqual(
            finding_text(port(port=111, service="rpcbind", product="",
                              version="2")),
            "Port 111/tcp is open running rpcbind, version 2.")

    def test_no_product_no_version_has_no_colon(self):
        self.assertEqual(
            finding_text(port(port=514, service="tcpwrapped", product="",
                              version="")),
            "Port 514/tcp is open running tcpwrapped.")

    def test_unknown_service_is_unidentified(self):
        self.assertEqual(
            finding_text(port(port=8180, service="unknown", product="",
                              version="")),
            "Port 8180/tcp is open running an unidentified service.")

    def test_empty_service_is_unidentified(self):
        self.assertEqual(
            finding_text(port(port=8180, service="", product="", version="")),
            "Port 8180/tcp is open running an unidentified service.")

    def test_lookup_failed_adds_nothing_about_exploits(self):
        p = port(exploits=[], exploit_status="lookup_failed",
                 lookup_error="searchsploit is not installed on this machine")
        self.assertEqual(finding_text(p),
                         "Port 22/tcp is open running ssh: OpenSSH 4.7p1.")


if __name__ == "__main__":
    unittest.main()
