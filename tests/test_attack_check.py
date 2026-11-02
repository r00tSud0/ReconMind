"""
Offline tests for the ATT&CK check and the MITRE data update script.

Uses a small fixture data file, never the network:

    python3 -m unittest discover -s tests -v
"""

import importlib.util
import os
import tempfile
import unittest

from reconmind.core.attack_check import (
    SKIPPED_MISSING, SKIPPED_UNREADABLE, check_attack, find_techniques)

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "fixtures", "attack_techniques.json")
SCRIPT = os.path.join(os.path.dirname(HERE), "scripts", "update_attack_data.py")


def results(text):
    check = check_attack(text, path=FIXTURE)
    return {(r.id, r.given): (r.official, r.result) for r in check.rows}


class ResultTests(unittest.TestCase):

    def test_wrong_name_is_name_mismatch(self):
        self.assertEqual(results("T1021.004 Pass the Hash"),
                         {("T1021.004", "Pass the Hash"): ("Remote Services: SSH", "name_mismatch")})

    def test_official_name_is_verified(self):
        self.assertEqual(results("T1190 Exploit Public-Facing Application"),
                         {("T1190", "Exploit Public-Facing Application"):
                          ("Exploit Public-Facing Application", "verified")})

    def test_case_insensitive_and_extra_words(self):
        rows = results("- **T1190** - exploit public-facing application (vsftpd backdoor)")
        self.assertEqual(list(rows.values()), [("Exploit Public-Facing Application", "verified")])

    def test_sub_technique_full_or_short_name_is_verified(self):
        self.assertEqual(list(results("T1021.004 Remote Services: SSH").values())[0][1], "verified")
        self.assertEqual(list(results("T1021.004 (SSH)").values())[0][1], "verified")

    def test_parent_name_alone_does_not_verify_sub_technique(self):
        self.assertEqual(list(results("T1021.004 Remote Services").values())[0][1],
                         "name_mismatch")

    def test_deprecated_id(self):
        self.assertEqual(results("T1086 PowerShell"),
                         {("T1086", "PowerShell"): ("PowerShell", "deprecated")})

    def test_revoked_id(self):
        self.assertEqual(list(results("T1173 Dynamic Data Exchange").values())[0][1], "revoked")

    def test_unknown_id(self):
        self.assertEqual(results("T9999 Made Up Technique"),
                         {("T9999", "Made Up Technique"): ("", "unknown_id")})

    def test_id_without_name_is_mismatch(self):
        self.assertEqual(list(results("Technique: T1190").values())[0][1], "name_mismatch")


class ExtractionTests(unittest.TestCase):

    def test_table_row_uses_next_cell(self):
        text = ("| ID | Technique |\n|----|-----------|\n"
                "| T1190 | Exploit Public-Facing Application |\n"
                "| T1021.004 | Pass the Hash |")
        self.assertEqual(find_techniques(text),
                         [("T1190", "Exploit Public-Facing Application"),
                          ("T1021.004", "Pass the Hash")])

    def test_table_cell_with_id_and_name(self):
        self.assertEqual(find_techniques("| 21/tcp | T1190 Exploit Public-Facing Application |"),
                         [("T1190", "Exploit Public-Facing Application")])

    def test_several_ids_on_one_line(self):
        self.assertEqual(
            find_techniques("T1190 Exploit Public-Facing Application, T1059 Command and "
                            "Scripting Interpreter"),
            [("T1190", "Exploit Public-Facing Application"),
             ("T1059", "Command and Scripting Interpreter")])

    def test_repeated_pairs_are_listed_once(self):
        self.assertEqual(len(find_techniques("T1190 Exploit\nT1190 Exploit\nT1190 Other")), 2)

    def test_no_ids(self):
        self.assertEqual(check_attack("No techniques here.", path=FIXTURE).rows, [])


class DataFileTests(unittest.TestCase):

    def test_missing_file_is_skipped(self):
        check = check_attack("T1190 Exploit Public-Facing Application",
                             path=os.path.join(HERE, "no_such_file.json"))
        self.assertEqual(check.skipped, SKIPPED_MISSING)
        self.assertEqual(SKIPPED_MISSING, "ATT&CK check skipped: MITRE data file missing")
        self.assertEqual(check.rows, [])

    def test_unreadable_file_is_skipped(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("{not json")
        try:
            self.assertEqual(check_attack("T1190", path=fh.name).skipped, SKIPPED_UNREADABLE)
        finally:
            os.unlink(fh.name)


def load_script():
    spec = importlib.util.spec_from_file_location("update_attack_data", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pattern(tid, name, sub=False, **extra):
    obj = {"type": "attack-pattern", "name": name, "x_mitre_is_subtechnique": sub,
           "external_references": [{"source_name": "capec", "external_id": "CAPEC-1"},
                                   {"source_name": "mitre-attack", "external_id": tid}]}
    obj.update(extra)
    return obj


class UpdateScriptTests(unittest.TestCase):
    """build_table only; the download in main() is never called here."""

    BUNDLE = {"type": "bundle", "objects": [
        {"type": "x-mitre-collection", "x_mitre_version": "99.1"},
        pattern("T1021", "Remote Services"),
        pattern("T1021.004", "SSH", sub=True),
        pattern("T1086", "PowerShell", x_mitre_deprecated=True),
        pattern("T1173", "Dynamic Data Exchange", revoked=True),
        pattern("T1190", "Old Name", revoked=True),
        pattern("T1190", "Exploit Public-Facing Application"),
        {"type": "malware", "name": "Not a technique",
         "external_references": [{"source_name": "mitre-attack", "external_id": "S0001"}]},
        {"type": "attack-pattern", "name": "No ATT&CK ID", "external_references": []},
    ]}

    def setUp(self):
        self.table = load_script().build_table(self.BUNDLE, downloaded="2026-11-01")
        self.techniques = self.table["techniques"]

    def test_version_and_date(self):
        self.assertEqual(self.table["attack_version"], "99.1")
        self.assertEqual(self.table["downloaded"], "2026-11-01")
        self.assertIn("enterprise-attack.json", self.table["source"])

    def test_only_attack_patterns_with_ids(self):
        self.assertEqual(sorted(self.techniques),
                         ["T1021", "T1021.004", "T1086", "T1173", "T1190"])

    def test_sub_technique_full_name(self):
        self.assertEqual(self.techniques["T1021.004"]["name"], "Remote Services: SSH")
        self.assertEqual(self.techniques["T1021.004"]["short_name"], "SSH")

    def test_flags(self):
        self.assertTrue(self.techniques["T1086"]["deprecated"])
        self.assertFalse(self.techniques["T1086"]["revoked"])
        self.assertTrue(self.techniques["T1173"]["revoked"])

    def test_active_entry_wins_over_revoked_duplicate(self):
        self.assertEqual(self.techniques["T1190"]["name"], "Exploit Public-Facing Application")
        self.assertFalse(self.techniques["T1190"]["revoked"])

    def test_missing_collection_version(self):
        table = load_script().build_table({"objects": []})
        self.assertEqual(table["attack_version"], "unknown")
        self.assertEqual(table["techniques"], {})


if __name__ == "__main__":
    unittest.main()
