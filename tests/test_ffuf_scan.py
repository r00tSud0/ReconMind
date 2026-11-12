"""
Offline tests for the ffuf wrapper: the authorization gate running before
ffuf, a missing ffuf, a missing wordlist, the exact command flags, JSON
parsing into results, the wordlist line count and SHA-256, and clean error
statuses for empty and broken output. subprocess.run is replaced by a fake
that writes a canned JSON file, so ffuf never runs.
"""

import hashlib
import json
import os
import shlex
import subprocess
import tempfile
import unittest
from unittest import mock

from reconmind.tools import ffuf_scan

TARGET = "10.10.1.100"
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "ffuf_output.json")
with open(FIXTURE) as _fh:
    JSON_TEXT = _fh.read()

WORDS = b".htaccess\n.htpasswd\nadmin\ncgi-bin/\ndav\nindex\nindex.php\nphpinfo\ntest\ntwiki"


def out_path_of(cmd):
    return cmd[cmd.index("-o") + 1]


def fake_ffuf(json_text, returncode=0, stderr="", write=True):
    """Stand in for subprocess.run: writes json_text into the -o file."""
    seen = []

    def run(cmd, **kwargs):
        path = out_path_of(cmd)
        seen.append(path)
        if write:
            with open(path, "w") as fh:
                fh.write(json_text)
        return mock.Mock(returncode=returncode, stdout="", stderr=stderr)

    fake = mock.Mock(side_effect=run)
    fake.out_paths = seen
    return fake


class Base(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.wordlist = os.path.join(self._tmp.name, "common.txt")
        with open(self.wordlist, "wb") as fh:
            fh.write(WORDS)

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, run, port=80, use_https=False, wordlist="given"):
        wordlist = self.wordlist if wordlist == "given" else wordlist
        with mock.patch.object(ffuf_scan, "is_authorized", return_value=True), \
             mock.patch.object(ffuf_scan.shutil, "which", return_value="/usr/bin/ffuf"), \
             mock.patch.object(ffuf_scan.subprocess, "run", run):
            return ffuf_scan.run_ffuf(TARGET, port, use_https=use_https, wordlist=wordlist)


class GateTests(unittest.TestCase):

    def test_refusal_never_reaches_subprocess(self):
        with mock.patch.object(ffuf_scan, "is_authorized", return_value=False) as gate, \
             mock.patch.object(ffuf_scan.shutil, "which") as which, \
             mock.patch.object(ffuf_scan.tempfile, "mkdtemp") as mkdtemp, \
             mock.patch.object(ffuf_scan, "pick_wordlist") as pick, \
             mock.patch.object(ffuf_scan.subprocess, "run") as run:
            result = ffuf_scan.run_ffuf("8.8.8.8", 80)
        gate.assert_called_once_with("8.8.8.8")
        run.assert_not_called()
        which.assert_not_called()
        mkdtemp.assert_not_called()
        pick.assert_not_called()
        self.assertEqual(result["status"], "refused")
        self.assertEqual(result["results"], [])
        self.assertEqual(result["command"], "")
        self.assertEqual(result["raw_json"], "")

    def test_gate_runs_before_port_check(self):
        with mock.patch.object(ffuf_scan, "is_authorized", return_value=False) as gate, \
             mock.patch.object(ffuf_scan.subprocess, "run") as run:
            result = ffuf_scan.run_ffuf(TARGET, "not a port")
        gate.assert_called_once()
        run.assert_not_called()
        self.assertEqual(result["status"], "refused")


class MissingFfufTests(unittest.TestCase):

    def test_missing_ffuf_does_not_crash(self):
        with mock.patch.object(ffuf_scan, "is_authorized", return_value=True), \
             mock.patch.object(ffuf_scan.shutil, "which", return_value=None) as which, \
             mock.patch.object(ffuf_scan.subprocess, "run") as run:
            result = ffuf_scan.run_ffuf(TARGET, 80)
        which.assert_called_once_with("ffuf")
        run.assert_not_called()
        self.assertEqual(result["status"], "ffuf-not-found")
        self.assertEqual(result["url"], "http://10.10.1.100:80")
        self.assertEqual(result["results"], [])
        self.assertTrue(result["error"])


class WordlistTests(Base):

    def test_missing_default_wordlists(self):
        missing = (os.path.join(self._tmp.name, "a.txt"), os.path.join(self._tmp.name, "b.txt"))
        run = fake_ffuf(JSON_TEXT)
        with mock.patch.object(ffuf_scan, "DEFAULT_WORDLISTS", missing):
            result = self._run(run, wordlist=None)
        run.assert_not_called()
        self.assertEqual(result["status"], "wordlist-not-found")
        self.assertEqual(result["results"], [])
        self.assertIn(missing[0], result["error"])
        self.assertIn(missing[1], result["error"])

    def test_missing_given_wordlist_is_not_swapped_for_a_default(self):
        run = fake_ffuf(JSON_TEXT)
        given = os.path.join(self._tmp.name, "nope.txt")
        with mock.patch.object(ffuf_scan, "DEFAULT_WORDLISTS", (self.wordlist,)):
            result = self._run(run, wordlist=given)
        run.assert_not_called()
        self.assertEqual(result["status"], "wordlist-not-found")
        self.assertEqual(result["wordlist"], given)

    def test_first_existing_default_is_used(self):
        missing = os.path.join(self._tmp.name, "dirb_common.txt")
        run = fake_ffuf(JSON_TEXT)
        with mock.patch.object(ffuf_scan, "DEFAULT_WORDLISTS", (missing, self.wordlist)):
            result = self._run(run, wordlist=None)
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[cmd.index("-w") + 1], self.wordlist)
        self.assertEqual(result["wordlist"], self.wordlist)

    def test_default_wordlist_order(self):
        self.assertEqual(ffuf_scan.DEFAULT_WORDLISTS, (
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt"))

    def test_line_count_and_sha256_are_recorded(self):
        result = self._run(fake_ffuf(JSON_TEXT))
        self.assertEqual(result["wordlist_lines"], 10)  # last line has no newline
        self.assertEqual(result["wordlist_sha256"], hashlib.sha256(WORDS).hexdigest())

    def test_line_count_with_trailing_newline(self):
        with open(self.wordlist, "wb") as fh:
            fh.write(b"admin\nbackup\n")
        self.assertEqual(ffuf_scan.wordlist_facts(self.wordlist)[0], 2)


class CommandTests(Base):

    def test_exact_command_and_timeout(self):
        run = fake_ffuf(JSON_TEXT)
        result = self._run(run, port=80)
        self.assertEqual(run.call_count, 1)
        cmd = run.call_args.args[0]
        out = out_path_of(cmd)
        self.assertEqual(cmd, [
            "ffuf", "-u", "http://10.10.1.100:80/FUZZ", "-w", self.wordlist,
            "-rate", "50", "-t", "10", "-timeout", "10", "-maxtime", "300", "-ac",
            "-mc", "200,204,301,302,307,401,403,405", "-noninteractive", "-s",
            "-of", "json", "-o", out])
        self.assertEqual(os.path.basename(out), "ffuf.json")
        self.assertTrue(os.path.basename(os.path.dirname(out)).startswith("reconmind_ffuf_"))
        self.assertEqual(run.call_args.kwargs["timeout"], 360)
        self.assertEqual(result["url"], "http://10.10.1.100:80")
        self.assertEqual(result["command"], shlex.join(cmd))

    def test_rate_and_auto_calibration(self):
        run = fake_ffuf(JSON_TEXT)
        self._run(run)
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[cmd.index("-rate") + 1], "50")
        self.assertIn("-ac", cmd)

    def test_discovery_only(self):
        run = fake_ffuf(JSON_TEXT)
        self._run(run)
        cmd = run.call_args.args[0]
        for banned in ("-recursion", "-recursion-depth", "-recursion-strategy", "-X",
                       "-d", "-request", "-H", "-b", "-x", "-replay-proxy", "-mode",
                       "-D", "-e"):
            self.assertNotIn(banned, cmd)
        self.assertNotIn("recursion", " ".join(cmd))
        self.assertEqual(cmd.count("FUZZ"), 0)  # only inside the URL
        self.assertTrue(cmd[cmd.index("-u") + 1].endswith("/FUZZ"))

    def test_https_url(self):
        run = fake_ffuf(JSON_TEXT)
        result = self._run(run, port=8443, use_https=True)
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[cmd.index("-u") + 1], "https://10.10.1.100:8443/FUZZ")
        self.assertEqual(result["url"], "https://10.10.1.100:8443")

    def test_temp_directory_is_deleted(self):
        run = fake_ffuf(JSON_TEXT)
        self._run(run)
        self.assertEqual(len(run.out_paths), 1)
        self.assertFalse(os.path.exists(os.path.dirname(run.out_paths[0])))

    def test_bad_port_never_runs_ffuf(self):
        run = fake_ffuf(JSON_TEXT)
        for port in (0, 70000, "abc"):
            self.assertEqual(self._run(run, port=port)["status"], "bad-port")
        run.assert_not_called()


class ParseTests(Base):

    def test_results_from_fixture(self):
        result = self._run(fake_ffuf(JSON_TEXT))
        self.assertEqual(result["status"], "ok")
        self.assertNotIn("error", result)
        self.assertEqual(len(result["results"]), 12)
        self.assertEqual(result["results"][0], {
            "path": "twiki", "status": 301, "length": 323, "words": 21, "lines": 10,
            "redirect": "http://10.10.1.100/twiki/"})
        by_path = {r["path"]: r for r in result["results"]}
        self.assertEqual(by_path["phpinfo.php"], {
            "path": "phpinfo.php", "status": 200, "length": 48083, "words": 2409,
            "lines": 657, "redirect": ""})
        self.assertEqual(by_path["cgi-bin/"]["status"], 403)  # path exactly as ffuf gave it
        self.assertIn("phpMyAdmin", by_path)  # case kept

    def test_result_keys(self):
        result = self._run(fake_ffuf(JSON_TEXT))
        self.assertEqual(set(result), {"status", "url", "wordlist", "wordlist_lines",
                                       "wordlist_sha256", "command", "results",
                                       "dropped_empty", "raw_json"})
        self.assertEqual(result["dropped_empty"], 0)

    def test_empty_path_is_dropped_and_counted(self):
        data = json.loads(JSON_TEXT)
        blank = dict(data["results"][0], input={"FFUFHASH": "7c2a0", "FUZZ": ""},
                     status=200, redirectlocation="")
        data["results"].insert(0, blank)
        data["results"].append(dict(blank))
        data["results"].append(dict(blank, input={"FFUFHASH": "7c2a0", "FUZZ": "\r"}))
        text = json.dumps(data)
        result = self._run(fake_ffuf(text))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["dropped_empty"], 3)
        self.assertEqual(len(result["results"]), 12)
        self.assertNotIn("", [r["path"] for r in result["results"]])
        self.assertEqual(result["results"][0]["path"], "twiki")  # order kept
        self.assertEqual(result["raw_json"], text)  # evidence still has them

    def test_raw_json_is_kept_as_evidence(self):
        result = self._run(fake_ffuf(JSON_TEXT))
        self.assertEqual(result["raw_json"], JSON_TEXT)

    def test_no_results(self):
        result = self._run(fake_ffuf(json.dumps({"commandline": "ffuf", "results": []})))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["results"], [])


class BadOutputTests(Base):

    def assert_clean_error(self, result, status):
        self.assertEqual(result["status"], status)
        self.assertEqual(result["results"], [])
        self.assertTrue(result["error"])
        self.assertNotIn("—", result["error"])
        self.assertNotIn(" - ", result["error"])

    def test_no_output_file(self):
        run = fake_ffuf("", write=False)
        self.assert_clean_error(self._run(run), "empty-output")
        self.assertFalse(os.path.exists(os.path.dirname(run.out_paths[0])))

    def test_broken_json(self):
        run = fake_ffuf('{"results":[{"input":{"FUZZ":"adm')
        self.assert_clean_error(self._run(run), "bad-json")
        self.assertFalse(os.path.exists(os.path.dirname(run.out_paths[0])))

    def test_wrong_shape(self):
        self.assert_clean_error(self._run(fake_ffuf("[]")), "bad-json")
        self.assert_clean_error(self._run(fake_ffuf('{"results": {}}')), "bad-json")

    def test_nonzero_exit_is_reported_in_error(self):
        result = self._run(fake_ffuf("", returncode=1, stderr="Encountered error(s)"))
        self.assert_clean_error(result, "empty-output")
        self.assertIn("exited with code 1", result["error"])

    def test_timeout(self):
        seen = []

        def run(cmd, **kwargs):
            seen.append(out_path_of(cmd))
            raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

        result = self._run(mock.Mock(side_effect=run))
        self.assert_clean_error(result, "timeout")
        self.assertTrue(result["command"].startswith("ffuf "))
        self.assertFalse(os.path.exists(os.path.dirname(seen[0])))


if __name__ == "__main__":
    unittest.main()
