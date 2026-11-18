"""Scan-time code-context tests, no tools or network."""
import os
import tempfile
import unittest
from reconmind.code.code_scan import add_display_context
from reconmind.web.runs import code_findings


class ContextTests(unittest.TestCase):
    def test_nearby_context_and_highlight_range(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "x.py"), "w") as f:
                for i in range(1, 15): f.write("line %s\n" % i)
            finding = {"file": "x.py", "line": 7, "end_line": 8,
                       "snippet": "line 7\nline 8", "severity": "high",
                       "sources": ["bandit"], "messages": {"bandit": "test"}}
            add_display_context([finding], d)
            self.assertEqual(finding["display_context_start"], 4)
            self.assertEqual(finding["display_context"].splitlines()[0], "line 4")
            self.assertEqual(finding["display_context"].splitlines()[-1], "line 11")
            self.assertEqual(finding["snippet"], "line 7\nline 8")
            code = code_findings({"findings": [finding]})[0]["code"]
            self.assertEqual(code["context_start"], 4)

    def test_refuses_outside_path(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, "safe"))
            with open(os.path.join(d, "secret.py"), "w") as f:
                f.write("secret")
            finding = {"file": "../secret.py", "line": 1, "end_line": 1}
            add_display_context([finding], os.path.join(d, "safe"))
            self.assertNotIn("display_context", finding)

if __name__ == "__main__":
    unittest.main()
