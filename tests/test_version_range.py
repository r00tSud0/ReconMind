"""
Offline tests for the version range checker, using real Exploit-DB titles.

    python3 -m unittest discover -s tests -v
"""

import unittest

from reconmind.tools.version_range import (
    AFFECTED, NOT_AFFECTED, UNVERIFIED, check, compare, parse_expression, parse_version)


class RequiredTitleTests(unittest.TestCase):
    """The titles from the Metasploitable run, with the scanned version."""

    CASES = [
        ("Samba < 3.0.20 - Remote Heap Overflow", "Samba", "3.0.20", NOT_AFFECTED),
        ("Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution",
         "Samba", "3.0.20", AFFECTED),
        ("Samba 3.0.10 < 3.3.5 - Format String / Security Bypass", "Samba", "3.0.20", AFFECTED),
        ("Samba < 3.6.2 (x86) - Denial of Service (PoC)", "Samba", "3.0.20", AFFECTED),
        ("Apache + PHP < 5.3.12 / < 5.4.2 - cgi-bin Remote Code Execution",
         "Apache", "2.2.8", UNVERIFIED),
        ("Apache CXF < 2.5.10/2.6.7/2.7.4 - Denial of Service", "Apache", "2.2.8", UNVERIFIED),
        ("Apache < 2.0.64 / < 2.2.21 mod_setenvif - Integer Overflow", "Apache", "2.2.8", AFFECTED),
        ("Apache < 2.2.34 / < 2.4.27 - OPTIONS Memory Leak", "Apache", "2.2.8", AFFECTED),
        ("OpenSSH 2.3 < 7.7 - Username Enumeration", "OpenSSH", "4.7", AFFECTED),
        ("Oracle MySQL < 5.1.49 - 'DDL' Statements Denial of Service", "MySQL", "5.0.51", AFFECTED),
        ("vsftpd 2.3.4 - Backdoor Command Execution", "vsftpd", "2.3.4", AFFECTED),
        ("UnrealIRCd 3.2.8.1 - Backdoor Command Execution (Metasploit)",
         "UnrealIRCd", "3.2.8.1", AFFECTED),
    ]

    def test_required_titles(self):
        for title, name, version, expected in self.CASES:
            with self.subTest(title=title):
                self.assertEqual(check(title, name, version), expected)

    def test_postgresql_list_keeps_the_family(self):
        self.assertEqual(check("PostgreSQL 8.2/8.3/8.4 - UDF for Command Execution",
                               "PostgreSQL", "8.3", family_only=True), AFFECTED)


class VersionOrderTests(unittest.TestCase):

    def test_release_candidate_sorts_before_release(self):
        self.assertEqual(compare(parse_version("3.0.25rc3"), parse_version("3.0.25")), -1)
        self.assertEqual(compare(parse_version("3.0.25rc2"), parse_version("3.0.25rc3")), -1)
        self.assertEqual(compare(parse_version("3.0.24"), parse_version("3.0.25rc1")), -1)
        self.assertEqual(compare(parse_version("1.0beta1"), parse_version("1.0rc1")), -1)

    def test_patch_suffix_sorts_after_release(self):
        self.assertEqual(compare(parse_version("4.7p1"), parse_version("4.7")), 1)

    def test_missing_parts_are_zero(self):
        self.assertEqual(compare(parse_version("3.0"), parse_version("3.0.0")), 0)

    def test_not_a_version(self):
        self.assertIsNone(parse_version("mod_ssl"))
        self.assertIsNone(parse_version(""))


class ExpressionTests(unittest.TestCase):

    def test_bounds(self):
        self.assertEqual(check("Foo < 2.0 - X", "Foo", "1.9"), AFFECTED)
        self.assertEqual(check("Foo < 2.0 - X", "Foo", "2.0"), NOT_AFFECTED)
        self.assertEqual(check("Foo <= 2.0 - X", "Foo", "2.0"), AFFECTED)
        self.assertEqual(check("Foo <= 2.0 - X", "Foo", "2.0.1"), NOT_AFFECTED)
        self.assertEqual(check("Foo 1.5 < 2.0 - X", "Foo", "1.4"), NOT_AFFECTED)
        self.assertEqual(check("Foo 3.0.20 < 3.0.25rc3 - X", "Foo", "3.0.25"), NOT_AFFECTED)

    def test_wildcard(self):
        self.assertEqual(check("Samba 3.x - X", "Samba", "3.0.20"), AFFECTED)
        self.assertEqual(check("Samba 3.x - X", "Samba", "4.1.0"), NOT_AFFECTED)
        self.assertEqual(check("MySQL 5.0.x - X", "MySQL", "5.0.51"), AFFECTED)

    def test_list_and_single(self):
        self.assertEqual(check("PostgreSQL 8.2/8.3/8.4 - X", "PostgreSQL", "8.3.1"), AFFECTED)
        self.assertEqual(check("PostgreSQL 8.2/8.3/8.4 - X", "PostgreSQL", "9.0"), NOT_AFFECTED)
        self.assertEqual(check("vsftpd 2.3.4 - X", "vsftpd", "2.3.5"), NOT_AFFECTED)
        self.assertEqual(check("Apache 2.2 - X", "Apache", "2.2.8"), AFFECTED)

    def test_branch_bounds(self):
        title = "Foo < 2.5.10/2.6.7/2.7.4 - X"
        self.assertEqual(check(title, "Foo", "2.6.5"), AFFECTED)
        self.assertEqual(check(title, "Foo", "2.6.8"), NOT_AFFECTED)
        self.assertEqual(check(title, "Foo", "2.4.0"), AFFECTED)

    def test_alternatives_stop_at_the_title_separator(self):
        alts = parse_expression("Samba 3.0.10 < 3.3.5 - Format String / Security Bypass", "Samba")
        self.assertEqual(len(alts), 1)
        alts = parse_expression("Apache < 2.0.64 / < 2.2.21 mod_setenvif - X", "Apache")
        self.assertEqual(len(alts), 2)

    def test_unverified_when_name_is_missing_or_not_followed_by_a_version(self):
        self.assertEqual(check("Something Else 1.0 - X", "Samba", "3.0.20"), UNVERIFIED)
        self.assertEqual(check("Apache mod_ssl < 2.8.7 - X", "Apache", "2.2.8"), UNVERIFIED)
        self.assertEqual(check("Samba - Something", "Samba", "3.0.20"), UNVERIFIED)

    def test_name_is_a_whole_word(self):
        self.assertEqual(check("MySQLDumper 1.24 - X", "MySQL", "5.0.51"), UNVERIFIED)

    def test_name_is_case_insensitive(self):
        self.assertEqual(check("ProFTPd 1.3.3c - X", "ProFTPD", "1.3.3c"), AFFECTED)


class FamilyTests(unittest.TestCase):
    """version_family results are dropped only if the whole family is excluded."""

    def test_family_partly_below_bound_is_kept(self):
        self.assertEqual(check("Samba < 3.0.20 - X", "Samba", "3.0", family_only=True), AFFECTED)

    def test_family_entirely_above_bound_is_dropped(self):
        self.assertEqual(check("Samba < 2.2.8 - X", "Samba", "3.0", family_only=True), NOT_AFFECTED)

    def test_family_entirely_below_range_is_dropped(self):
        self.assertEqual(check("Foo 3.1 < 3.5 - X", "Foo", "3.0", family_only=True), NOT_AFFECTED)
        self.assertEqual(check("Foo 3.0.5 < 3.5 - X", "Foo", "3.0", family_only=True), AFFECTED)

    def test_family_points(self):
        self.assertEqual(check("Foo 3.0.20 - X", "Foo", "3.0", family_only=True), AFFECTED)
        self.assertEqual(check("Foo 3.1.2 - X", "Foo", "3.0", family_only=True), NOT_AFFECTED)
        self.assertEqual(check("Foo 3.x - X", "Foo", "3.0", family_only=True), AFFECTED)

    def test_family_uses_major_minor_of_full_version(self):
        self.assertEqual(check("MySQL < 5.0.10 - X", "MySQL", "5.0.51", family_only=True), AFFECTED)


if __name__ == "__main__":
    unittest.main()
