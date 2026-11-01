"""
Offline tests for the analyst summary checker (plain code, no AI).

    python3 -m unittest discover -s tests -v
"""

import unittest

from reconmind.core.summary_check import (
    END_MARKER, REQUIRED_HEADINGS, check_summary, clean_published, find_unverified_refs,
    normalize_dashes, strip_preamble)

SCAN = {
    "target": "10.10.1.100", "status": "ok",
    "ports": [{"port": 21, "product": "vsftpd", "version": "2.3.4",
               "exploits": [{"title": "vsftpd 2.3.4 Backdoor", "edb_id": "49757"}]},
              {"port": 21, "product": "ProFTPD", "version": "1.3.3c",
               "exploits": [{"title": "ProFTPD 1.3.3c Backdoor", "edb_id": "17491"}]}],
}


def summary(*bodies, headings=REQUIRED_HEADINGS, marker=True):
    bodies = bodies or ["text"] * len(headings)
    text = "\n".join("{h}\n{b}\n".format(h=h, b=b) for h, b in zip(headings, bodies))
    return text + END_MARKER + "\n" if marker else text


VALID = summary("1. vsftpd 2.3.4 backdoor on 21/tcp (EDB-49757), confirmed.",
                "Backdoor shell, then pivot.", "T1190 Exploit Public-Facing Application",
                "Upgrade vsftpd.")


class StructureTests(unittest.TestCase):

    def test_valid_summary(self):
        result = check_summary(VALID, SCAN)
        self.assertTrue(result.valid, result.problems)
        self.assertEqual(result.text, VALID.strip()[:-len(END_MARKER)].rstrip())
        self.assertNotIn(END_MARKER, result.text)
        self.assertEqual(result.unverified_refs, [])

    def test_thinking_text_is_stripped(self):
        result = check_summary("Let me think about the ports first.\nOK.\n" + VALID, SCAN)
        self.assertTrue(result.valid)
        self.assertTrue(result.text.startswith("### Key findings"))
        self.assertNotIn("Let me think", result.text)

    def test_missing_heading_is_invalid(self):
        self.assertFalse(check_summary(summary(headings=REQUIRED_HEADINGS[:3]), SCAN).valid)

    def test_truncated_draft_is_invalid(self):
        draft = "Thinking...\n### Key findings\n- x\n### Likely attack"
        result = check_summary(draft, SCAN)
        self.assertFalse(result.valid)
        self.assertTrue(result.problems)

    def test_missing_end_marker_is_invalid(self):
        cut = summary("a", "b", "T1190 Exploit Public-Facing Application",
                      "1. Upgrade vsftpd.\n2. Upgrade Post", marker=False)
        result = check_summary(cut, SCAN)
        self.assertFalse(result.valid)
        self.assertIn("missing END OF SUMMARY marker (summary may be cut off)",
                      result.problems)

    def test_text_after_end_marker_is_invalid(self):
        self.assertFalse(check_summary(VALID + "Hope this helps!\n", SCAN).valid)

    def test_marker_must_be_exact(self):
        self.assertFalse(check_summary(VALID.replace(END_MARKER, "**END OF SUMMARY**"),
                                       SCAN).valid)
        self.assertFalse(check_summary(VALID.replace(END_MARKER, "End of summary"),
                                       SCAN).valid)

    def test_marker_with_trailing_blank_lines_is_valid(self):
        result = check_summary(VALID + "\n\n  \n", SCAN)
        self.assertTrue(result.valid, result.problems)
        self.assertNotIn(END_MARKER, result.text)

    def test_reordered_headings_are_invalid(self):
        order = (REQUIRED_HEADINGS[1], REQUIRED_HEADINGS[0]) + REQUIRED_HEADINGS[2:]
        self.assertFalse(check_summary(summary(headings=order), SCAN).valid)

    def test_extra_heading_is_invalid(self):
        extra = summary(*["text"] * 4, "Bye",
                        headings=REQUIRED_HEADINGS + ("### Closing remarks",))
        self.assertFalse(check_summary(extra, SCAN).valid)
        extra = summary(*["text"] * 4, "More", headings=REQUIRED_HEADINGS + ("## Next steps",))
        self.assertFalse(check_summary(extra, SCAN).valid)
        self.assertFalse(check_summary(VALID.replace("### Recommended", "#### Recommended"),
                                       SCAN).valid)

    def test_empty_section_is_invalid(self):
        self.assertFalse(check_summary(summary("a", "b", "c", ""), SCAN).valid)

    def test_no_heading_or_no_text_is_invalid(self):
        for text in (None, "", "   ", "Just prose, no sections."):
            self.assertFalse(check_summary(text, SCAN).valid)
        self.assertEqual(strip_preamble(None), "")


class ReferenceTests(unittest.TestCase):

    def test_known_edb_is_not_flagged(self):
        self.assertEqual(find_unverified_refs("See EDB-49757 and EDB-ID: 49757.", SCAN), [])

    def test_unknown_edb_forms_are_flagged(self):
        text = ("EDB-99999, EDB-ID 11111, EDB ID: 22222, "
                "https://www.exploit-db.com/exploits/33333 and EDB-99999 again")
        self.assertEqual(find_unverified_refs(text, SCAN),
                         ["EDB-99999", "EDB-11111", "EDB-22222", "EDB-33333"])

    def test_every_cve_is_flagged(self):
        self.assertEqual(find_unverified_refs("cve-2011-2523 and CVE-2007-2447", SCAN),
                         ["CVE-2011-2523", "CVE-2007-2447"])

    def test_refs_do_not_make_a_summary_invalid(self):
        result = check_summary(VALID.replace("EDB-49757", "EDB-1 CVE-2011-2523"), SCAN)
        self.assertTrue(result.valid)
        self.assertEqual(result.unverified_refs, ["EDB-1", "CVE-2011-2523"])


class DashTests(unittest.TestCase):

    def test_non_breaking_hyphen_cve_is_flagged(self):
        self.assertEqual(find_unverified_refs("CVE\u20112011\u20112523", SCAN),
                         ["CVE-2011-2523"])

    def test_non_breaking_hyphen_known_edb_is_not_flagged(self):
        self.assertEqual(find_unverified_refs("EDB\u201117491", SCAN), [])

    def test_non_breaking_hyphen_unknown_edb_is_flagged(self):
        self.assertEqual(find_unverified_refs("EDB\u201199999", SCAN), ["EDB-99999"])

    def test_every_unicode_dash_becomes_ascii(self):
        for ch in "\u2010\u2011\u2012\u2013\u2014\u2015\u2212":
            self.assertEqual(normalize_dashes("a" + ch + "b"), "a-b")

    def test_published_text_dashes(self):
        self.assertEqual(clean_published("vsftpd \u2013 backdoor \u2014 confirmed"),
                         "vsftpd, backdoor, confirmed")
        self.assertEqual(clean_published("ports 21\u201323, a\u2014b"), "ports 21-23, a-b")

    def test_check_summary_publishes_and_checks_clean_text(self):
        text = VALID.replace("Upgrade vsftpd.",
                             "Upgrade vsftpd \u2014 see CVE\u20112011\u20112523.")
        result = check_summary(text, SCAN)
        self.assertTrue(result.valid, result.problems)
        self.assertIn("Upgrade vsftpd, see CVE-2011-2523.", result.text)
        self.assertNotIn("\u2014", result.text)
        self.assertNotIn("\u2011", result.text)
        self.assertEqual(result.unverified_refs, ["CVE-2011-2523"])


if __name__ == "__main__":
    unittest.main()
