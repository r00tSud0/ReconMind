"""
Offline tests for evaluation/scripts/collect_findings.py. Nothing is scanned:
run_nmap and search_exploits are mocked and all output goes to a temp folder.

    python3 -m unittest discover -s evaluation/tests -t . -v
"""

import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from reconmind.agent import tools as toolmod

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "scripts", "collect_findings.py")

TARGET = "10.10.1.100"
FAKE_SCAN = {
    "target": TARGET, "status": "ok",
    "ports": [
        {"port": 21, "protocol": "tcp", "service": "ftp",
         "product": "vsftpd", "version": "2.3.4"},
        {"port": 22, "protocol": "tcp", "service": "ssh",
         "product": "OpenSSH", "version": "4.7p1"},
    ],
}


def load_script():
    spec = importlib.util.spec_from_file_location("collect_findings", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cf = load_script()


def fresh_scan():
    """A fresh copy each time, since ToolBox enriches the ports in place."""
    return dict(FAKE_SCAN, ports=[dict(p) for p in FAKE_SCAN["ports"]])


class CollectFindingsTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.out = os.path.join(self._tmp.name, "findings.jsonl")
        self.scans = os.path.join(self._tmp.name, "scans")
        self._patch_scans = mock.patch.object(cf, "SCANS_DIR", self.scans)
        self._patch_scans.start()

    def tearDown(self):
        self._patch_scans.stop()
        self._tmp.cleanup()

    def _run(self, *extra):
        return cf.main(["collect_findings.py", TARGET, "--out", self.out, *extra])

    def _lines(self):
        with open(self.out) as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def test_refused_target_exits_2_and_never_scans(self):
        with mock.patch.object(cf, "is_authorized", return_value=False), \
             mock.patch.object(toolmod, "run_nmap") as run_nmap:
            code = self._run()
        self.assertEqual(code, 2)
        run_nmap.assert_not_called()
        self.assertFalse(os.path.exists(self.out))
        self.assertFalse(os.path.exists(self.scans))

    def test_normal_run_writes_scan_and_one_line_per_port(self):
        with mock.patch.object(cf, "is_authorized", return_value=True), \
             mock.patch.object(toolmod, "run_nmap", return_value=fresh_scan()), \
             mock.patch.object(toolmod, "search_exploits", return_value=[]):
            code = self._run()
        self.assertEqual(code, 0)

        lines = self._lines()
        self.assertEqual([r["id"] for r in lines],
                         ["10.10.1.100:21/tcp", "10.10.1.100:22/tcp"])
        self.assertTrue(all("labels" not in r for r in lines))
        self.assertEqual(set(lines[0]),
                         {"id", "target", "port", "protocol", "text", "scan_file"})
        self.assertEqual(lines[0]["port"], 21)
        self.assertEqual(lines[0]["protocol"], "tcp")
        self.assertIn("vsftpd 2.3.4", lines[0]["text"])

        # Exactly one scan file was saved and the findings point at it.
        saved = os.listdir(self.scans)
        self.assertEqual(len(saved), 1)
        self.assertTrue(saved[0].startswith("10.10.1.100_"))
        self.assertTrue(lines[0]["scan_file"].endswith(saved[0]))

    def test_second_run_skips_duplicates(self):
        with mock.patch.object(cf, "is_authorized", return_value=True), \
             mock.patch.object(toolmod, "run_nmap",
                               side_effect=lambda *a, **k: fresh_scan()), \
             mock.patch.object(toolmod, "search_exploits", return_value=[]):
            self.assertEqual(self._run(), 0)
            self.assertEqual(self._run(), 0)
        # The second run adds nothing, so there are still two lines.
        self.assertEqual(len(self._lines()), 2)

    def test_unconfirmed_ports_warn_and_exit_3_after_saving_scan(self):
        scan = fresh_scan()
        scan["ports"] = scan["ports"][:1]  # only 21 confirmed
        scan["unconfirmed_ports"] = [
            {"port": 22, "protocol": "tcp", "pass2_state": "filtered",
             "pass2_reason": "no-response"},
            {"port": 8080, "protocol": "tcp", "pass2_state": "filtered",
             "pass2_reason": "no-response"},
        ]
        out = io.StringIO()
        with mock.patch.object(cf, "is_authorized", return_value=True), \
             mock.patch.object(toolmod, "run_nmap", return_value=scan), \
             mock.patch.object(toolmod, "search_exploits", return_value=[]), \
             contextlib.redirect_stdout(out):
            code = self._run("--all-ports")
        self.assertEqual(code, 3)
        printed = out.getvalue()
        self.assertIn("WARNING", printed)
        self.assertIn("22/tcp, 8080/tcp", printed)
        self.assertIn("Rerun the scan", printed)

        # The scan file is still written, with the unconfirmed ports in it.
        saved = os.listdir(self.scans)
        self.assertEqual(len(saved), 1)
        with open(os.path.join(self.scans, saved[0])) as fh:
            self.assertEqual([u["port"] for u in json.load(fh)["unconfirmed_ports"]],
                             [22, 8080])
        # Only the confirmed port became a finding.
        self.assertEqual([r["id"] for r in self._lines()], ["10.10.1.100:21/tcp"])

    def test_empty_unconfirmed_list_exits_0(self):
        scan = dict(fresh_scan(), unconfirmed_ports=[])
        with mock.patch.object(cf, "is_authorized", return_value=True), \
             mock.patch.object(toolmod, "run_nmap", return_value=scan), \
             mock.patch.object(toolmod, "search_exploits", return_value=[]), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self._run(), 0)

    def _saved_scan(self):
        """Write a saved scan file like this script does and return its path."""
        os.makedirs(self.scans, exist_ok=True)
        path = os.path.join(self.scans, "10.10.1.100_20261104_120000.json")
        with open(path, "w") as fh:
            json.dump(fresh_scan(), fh)
        return path

    def _run_from_scan(self, path):
        return cf.main(["collect_findings.py", "--from-scan", path,
                        "--out", self.out])

    def test_from_scan_builds_findings_without_gate_or_scan(self):
        path = self._saved_scan()
        with mock.patch.object(cf, "is_authorized") as gate, \
             mock.patch.object(toolmod, "run_nmap") as run_nmap, \
             contextlib.redirect_stdout(io.StringIO()):
            code = self._run_from_scan(path)
        self.assertEqual(code, 0)
        gate.assert_not_called()
        run_nmap.assert_not_called()

        lines = self._lines()
        self.assertEqual([r["id"] for r in lines],
                         ["10.10.1.100:21/tcp", "10.10.1.100:22/tcp"])
        self.assertTrue(all("labels" not in r for r in lines))
        self.assertEqual(lines[0]["target"], TARGET)
        self.assertEqual(lines[0]["text"],
                         "Port 21/tcp is open running ftp: vsftpd 2.3.4.")
        self.assertEqual(lines[0]["scan_file"],
                         os.path.relpath(path, cf.REPO_ROOT))
        # No new scan file was written next to the saved one.
        self.assertEqual(os.listdir(self.scans), [os.path.basename(path)])

    def test_from_scan_skips_duplicates(self):
        path = self._saved_scan()
        with mock.patch.object(cf, "is_authorized") as gate, \
             mock.patch.object(toolmod, "run_nmap") as run_nmap, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self._run_from_scan(path), 0)
            self.assertEqual(self._run_from_scan(path), 0)
        gate.assert_not_called()
        run_nmap.assert_not_called()
        self.assertEqual(len(self._lines()), 2)

    def test_both_target_and_from_scan_is_an_error(self):
        path = self._saved_scan()
        with mock.patch.object(cf, "is_authorized") as gate, \
             mock.patch.object(toolmod, "run_nmap") as run_nmap, \
             contextlib.redirect_stderr(io.StringIO()), \
             self.assertRaises(SystemExit) as ctx:
            cf.main(["collect_findings.py", TARGET, "--from-scan", path,
                     "--out", self.out])
        self.assertEqual(ctx.exception.code, 2)
        gate.assert_not_called()
        run_nmap.assert_not_called()
        self.assertFalse(os.path.exists(self.out))

    def test_neither_target_nor_from_scan_is_an_error(self):
        with mock.patch.object(cf, "is_authorized") as gate, \
             mock.patch.object(toolmod, "run_nmap") as run_nmap, \
             contextlib.redirect_stderr(io.StringIO()), \
             self.assertRaises(SystemExit) as ctx:
            cf.main(["collect_findings.py", "--out", self.out])
        self.assertEqual(ctx.exception.code, 2)
        gate.assert_not_called()
        run_nmap.assert_not_called()
        self.assertFalse(os.path.exists(self.out))


if __name__ == "__main__":
    unittest.main()
