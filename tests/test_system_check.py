"""Offline checks for Step 4 System and code evidence. No live scans or keys."""
import os
import tempfile
import unittest
from unittest import mock

from reconmind.core import config
from reconmind.web import runs, system


class CodeEvidenceTests(unittest.TestCase):
    def test_saved_code_snippet_is_supplied_with_location(self):
        data = {"findings": [{
            "severity": "high", "file": "src/app.py", "line": 24, "end_line": 25,
            "messages": {"semgrep": "Unsafe operation"}, "rule_ids": {"semgrep": "python.bad"},
            "sources": ["semgrep"], "snippet": 'run(user)\\nprint("done")',
        }]}
        item, = runs.code_findings(data)
        self.assertEqual(item["code"]["file"], "app.py")
        self.assertEqual(item["code"]["line"], 24)
        self.assertEqual(item["code"]["end_line"], 25)
        self.assertEqual(item["code"]["snippet"], 'run(user)\\nprint("done")')


class SystemCheckTests(unittest.TestCase):
    def test_does_not_return_any_key_value(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {
                "OPENROUTER_API_KEY": "secret-do-not-return-me",
                "NVD_API_KEY": "nvd-secret-do-not-return-me",
                "RECONMIND_PROVIDER": "openrouter",
            }):
                with mock.patch.object(system, "_tools", return_value=[]):
                    snap = system.snapshot(os.path.join(d, "reports"))
        self.assertTrue(snap["ai"]["key_set"])
        self.assertTrue(snap["nvd"]["key_set"])
        self.assertNotIn("secret-do-not-return-me", str(snap))
        self.assertNotIn("nvd-secret-do-not-return-me", str(snap))
        self.assertEqual(snap["safety"]["allowlist"], config.ALLOWLIST)
        self.assertEqual(snap["safety"]["denylist"], config.DENYLIST)

    def test_engine_binary_selection_and_missing_install(self):
        with mock.patch.object(system.shutil, "which", return_value=None), \
                mock.patch.object(system.httpx_scan, "find_binary", return_value=None):
            tools = system._tools()
        self.assertEqual(len(tools), len(system.TOOLS))
        self.assertTrue(all(t["status"] == "missing" for t in tools))
        # Installer-first: System reports readiness only, never install commands.
        self.assertTrue(all("install" not in t for t in tools))
        self.assertNotIn("apt install", str(system.TOOLS))
        self.assertNotIn("pip install", str(system.TOOLS))


if __name__ == "__main__":
    unittest.main()
