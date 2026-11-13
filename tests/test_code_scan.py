"""
Offline tests for the ReconMind code scan and the input router.

subprocess.run and shutil.which are replaced by FakeTools, which plays back
the Semgrep and Bandit JSON fixtures, and a fake LLM client stands in for the
provider. No semgrep, no bandit, no network and no API key are needed:

    python3 -m unittest tests.test_code_scan -v
"""

import ast
import contextlib
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime
from types import SimpleNamespace as NS
from unittest import mock

from reconmind import __main__ as router
from reconmind.agent import __main__ as agent_main
from reconmind.agent import llm
from reconmind.code import bandit_scan, code_scan, explain, inputs, semgrep_scan
from reconmind.code import report as code_report
from reconmind.core import history

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")
REPO = os.path.dirname(HERE)
APP = os.path.join(REPO, "examples", "vulnerable_python", "app.py")
PINNED = semgrep_scan.PINNED_COMMIT
OTHER_COMMIT = "0123456789abcdef0123456789abcdef01234567"
SEMGREP_VERSION = "1.95.0"
BANDIT_VERSION = "bandit 1.8.6\n  python version = 3.12.3 (main)\n"
STARTED = datetime(2026, 11, 12, 10, 0, 0)
FINISHED = datetime(2026, 11, 12, 10, 5, 30)
SHELL_LINE = '    return subprocess.check_output("ping -c 1 " + host, shell=True)'
SHELL_RULE = "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"
FIXED_LINE = ("Findings come from Semgrep and Bandit pattern rules. Each one marks code that "
              "matches a known vulnerable pattern and needs a human review to confirm.")

EXPECTED_FINDINGS = [
    ("high", "app.py", 21, ["semgrep", "bandit"]),
    ("high", "app.py", 25, ["semgrep", "bandit"]),
    ("high", "app.py", 29, ["semgrep"]),
    ("medium", "app.py", 16, ["bandit"]),
    ("medium", "app.py", 17, ["semgrep"]),
    ("medium", "app.py", 29, ["bandit"]),
    ("medium", "app.py", 33, ["semgrep", "bandit"]),
    ("low", "app.py", 5, ["bandit"]),
    ("low", "app.py", 7, ["bandit"]),
    ("low", "app.py", 11, ["bandit"]),
]
EXPECTED_COUNTS = {"high": 3, "medium": 4, "low": 3}

GOOD_TEXT = ("### app.py:21\n"
             "Why it is dangerous: shell=True hands the host value to a shell (CWE-78).\n"
             "How an attacker could use it: a host like 'x; id' runs a second command.\n"
             "How to fix it: pass a list of arguments and keep shell=False.\n")
BAD_TEXT = GOOD_TEXT + "\n### app.py:99\nAlso see CWE-79 and lib/other.py:3.\n"


def fixture(name, root):
    with open(os.path.join(FIXTURES, name)) as fh:
        return fh.read().replace("__ROOT__", root)


class FakeTools:
    """Stands in for shutil.which and subprocess.run. Records every call."""

    def __init__(self, root, semgrep=None, bandit=None, semgrep_code=0, bandit_code=1,
                 missing=()):
        self.outputs = {
            "semgrep": semgrep if semgrep is not None else fixture("semgrep_app.json", root),
            "bandit": bandit if bandit is not None else fixture("bandit_app.json", root),
        }
        self.codes = {"semgrep": semgrep_code, "bandit": bandit_code}
        self.missing = set(missing)
        self.calls = []

    def which(self, name):
        return None if name in self.missing else "/usr/bin/" + name

    def run(self, cmd, **kwargs):
        self.calls.append((list(cmd), kwargs))
        name = cmd[0]
        if list(cmd[1:]) == ["--version"]:
            out = SEMGREP_VERSION + "\n" if name == "semgrep" else BANDIT_VERSION
            return NS(returncode=0, stdout=out, stderr="")
        out = self.outputs[name]
        if isinstance(out, BaseException):
            raise out
        code = self.codes[name]
        return NS(returncode=code, stdout=out, stderr="" if code in (0, 1) else "boom\nmore")

    def scans(self, name):
        return [c for c in self.calls if c[0][0] == name and c[0][1:] != ["--version"]]

    def used(self, name):
        return [c for c in self.calls if c[0][0] == name]

    @contextlib.contextmanager
    def active(self):
        with mock.patch("shutil.which", side_effect=self.which), \
                mock.patch("subprocess.run", side_effect=self.run):
            yield self


class FakeLLM:
    """A provider client that returns fixed text (or a whole response), or raises, and records requests."""

    def __init__(self, text="", error=None, response=None):
        self.text = text
        self.error = error
        self.response = response
        self.requests = []
        self.messages = NS(create=self._create)

    def _create(self, **kwargs):
        self.requests.append(kwargs)
        if self.error is not None:
            raise self.error
        if self.response is not None:
            return self.response
        return NS(content=[NS(type="text", text=self.text)], stop_reason="end_turn")


class FakeOpenAI:
    """An openai.OpenAI stand in: plays back Chat Completions responses and records requests."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []
        self.chat = NS(completions=NS(create=self._create))

    def _create(self, **request):
        self.requests.append(request)
        return self.responses.pop(0)


def openai_response(text, finish, completion=None, reasoning=None):
    usage = {}
    if completion is not None:
        usage["completion_tokens"] = completion
    if reasoning is not None:
        usage["completion_tokens_details"] = {"reasoning_tokens": reasoning}
    return {"choices": [{"message": {"content": text}, "finish_reason": finish}],
            "usage": usage}


class CodeTestCase(unittest.TestCase):

    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="reconmind_code_test_"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.project = os.path.join(self.tmp, "project")
        os.makedirs(self.project)
        shutil.copy(APP, os.path.join(self.project, "app.py"))
        self.rules = os.path.join(self.tmp, "rules")
        for lang in ("python", "javascript"):
            os.makedirs(os.path.join(self.rules, lang))
        self.write_head(PINNED + "\n")
        env = mock.patch.dict(os.environ, {semgrep_scan.RULES_ENV: self.rules})
        env.start()
        self.addCleanup(env.stop)

    def write_head(self, text, name="HEAD"):
        path = os.path.join(self.rules, ".git", *name.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(text)

    def write(self, path, text="x = 1\n"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(text)
        return path

    def in_tmp(self):
        old = os.getcwd()
        os.chdir(self.tmp)
        self.addCleanup(os.chdir, old)

    def scan(self, path=None, tools=None, **kwargs):
        tools = tools or FakeTools(self.project)
        with tools.active():
            return code_scan.run_code_scan(path or self.project, **kwargs), tools

    def report(self, scan):
        return code_report.render_code_report(scan, generated=STARTED)

    def finding(self, scan, line, source):
        return next(f for f in scan["findings"] if f["line"] == line and source in f["sources"])


# ---- inputs ----------------------------------------------------------------

class InputTests(CodeTestCase):

    def refused(self, path):
        with self.assertRaises(inputs.InputError) as ctx:
            inputs.validate_input(path)
        return str(ctx.exception)

    def test_missing_path_is_refused(self):
        self.assertIn("does not exist", self.refused(os.path.join(self.tmp, "nope")))
        self.assertIn("does not exist", self.refused(""))

    def test_single_python_file(self):
        info = inputs.validate_input(os.path.join(self.project, "app.py"))
        self.assertEqual((info.is_dir, info.files, info.languages),
                         (False, ["app.py"], {"python": 1}))
        self.assertEqual(info.total_bytes, os.path.getsize(APP))

    def test_folder_languages(self):
        folder = os.path.join(self.tmp, "multi")
        for name in ("a.py", "b.js", "c.jsx", "d.mjs", "e.ts", "f.tsx", "g.php", "h.java",
                     "i.go", "j.rb", "k.c", "sub/l.h", "README.md", "notes.txt"):
            self.write(os.path.join(folder, name))
        info = inputs.validate_input(folder)
        self.assertTrue(info.is_dir)
        self.assertEqual(info.languages, {"python": 1, "javascript": 3, "typescript": 2,
                                          "php": 1, "java": 1, "go": 1, "ruby": 1, "c": 2})
        self.assertEqual(len(info.files), 12)
        self.assertIn(os.path.join("sub", "l.h"), info.files)

    def test_language_detection_by_extension(self):
        self.assertEqual(inputs.LANGUAGES, {
            ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
            ".ts": "typescript", ".tsx": "typescript", ".php": "php", ".java": "java",
            ".go": "go", ".rb": "ruby", ".c": "c", ".h": "c"})
        self.assertEqual(inputs.language_of("x/Y.PY"), "python")
        self.assertIsNone(inputs.language_of("notes.md"))
        self.assertIsNone(inputs.language_of("Makefile"))

    def test_unsupported_file_is_refused(self):
        path = self.write(os.path.join(self.tmp, "notes.md"))
        self.assertIn("no source file in a supported language", self.refused(path))

    def test_folder_without_source_is_refused(self):
        folder = os.path.join(self.tmp, "docs")
        self.write(os.path.join(folder, "README.md"))
        self.assertIn("no source file in a supported language", self.refused(folder))

    def test_git_folder_is_not_counted(self):
        folder = os.path.join(self.tmp, "repo")
        self.write(os.path.join(folder, ".git", "hooks", "hook.py"))
        self.write(os.path.join(folder, "a.py"))
        self.assertEqual(inputs.validate_input(folder).files, ["a.py"])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs mkfifo")
    def test_special_file_is_refused(self):
        path = os.path.join(self.tmp, "pipe.py")
        os.mkfifo(path)
        self.assertIn("not a regular file or a folder", self.refused(path))

    def test_file_limit(self):
        folder = os.path.join(self.tmp, "many")
        for n in range(4):
            self.write(os.path.join(folder, "m{n}.py".format(n=n)))
        with mock.patch.object(inputs, "MAX_FILES", 3):
            self.assertIn("more than 3 source files", self.refused(folder))

    def test_file_limit_counts_only_source_files(self):
        folder = os.path.join(self.tmp, "mixed")
        for n in range(3):
            self.write(os.path.join(folder, "m{n}.py".format(n=n)))
            self.write(os.path.join(folder, "d{n}.md".format(n=n)))
        with mock.patch.object(inputs, "MAX_FILES", 3):
            self.assertEqual(len(inputs.validate_input(folder).files), 3)

    def test_size_limit(self):
        folder = os.path.join(self.tmp, "big")
        big = self.write(os.path.join(folder, "big.py"), "x" * (1024 * 1024 + 1))
        with mock.patch.object(inputs, "MAX_BYTES", 1024 * 1024):
            self.assertIn("more than 1 MB of source code", self.refused(folder))
            self.assertIn("more than 1 MB of source code", self.refused(big))

    def test_link_to_an_outside_file_is_refused(self):
        outside = self.write(os.path.join(self.tmp, "secret.py"))
        folder = os.path.join(self.tmp, "linked")
        self.write(os.path.join(folder, "a.py"))
        os.symlink(outside, os.path.join(folder, "b.py"))
        message = self.refused(folder)
        self.assertIn("symbolic links that point outside it", message)
        self.assertIn("b.py", message)

    def test_link_to_an_outside_folder_is_refused(self):
        outside = os.path.join(self.tmp, "elsewhere")
        self.write(os.path.join(outside, "x.py"))
        folder = os.path.join(self.tmp, "linked_dir")
        self.write(os.path.join(folder, "a.py"))
        os.symlink(outside, os.path.join(folder, "lib"))
        self.assertIn("lib", self.refused(folder))

    def test_link_inside_is_allowed_and_not_counted_twice(self):
        folder = os.path.join(self.tmp, "inner")
        target = self.write(os.path.join(folder, "a.py"))
        os.symlink(target, os.path.join(folder, "b.py"))
        self.assertEqual(inputs.validate_input(folder).files, ["a.py"])

    def test_input_link_is_resolved_once(self):
        alias = os.path.join(self.tmp, "alias")
        os.symlink(self.project, alias)
        self.assertEqual(inputs.validate_input(alias).root, self.project)

    def test_read_snippet(self):
        path = os.path.join(self.project, "app.py")
        self.assertEqual(inputs.read_snippet(self.project, path, 21, 21), SHELL_LINE)
        self.assertEqual(inputs.read_snippet(self.project, path, 0), "")
        self.assertEqual(inputs.read_snippet(self.project, path, "x"), "")

    def test_snippet_never_reads_outside_the_input(self):
        outside = self.write(os.path.join(self.tmp, "other.py"), "secret = 1\n")
        self.assertEqual(inputs.read_snippet(self.project, outside, 1, 1), "")

    def test_snippet_is_capped(self):
        path = self.write(os.path.join(self.project, "long.py"),
                          "".join("line{n} = {n}\n".format(n=n) for n in range(100)))
        snippet = inputs.read_snippet(self.project, path, 1, 100)
        self.assertEqual(len(snippet.splitlines()), inputs.MAX_SNIPPET_LINES)


# ---- semgrep ---------------------------------------------------------------

class SemgrepTests(CodeTestCase):

    def run_semgrep(self, tools=None, languages=("python",)):
        tools = tools or FakeTools(self.project)
        with tools.active():
            result = semgrep_scan.run_semgrep(self.project, list(languages))
        return result, tools

    def test_exact_command_and_no_network_settings(self):
        result, tools = self.run_semgrep(languages=["python", "javascript"])
        (cmd, kwargs), = tools.scans("semgrep")
        self.assertEqual(cmd, [
            "semgrep", "scan", "--json", "--metrics=off", "--disable-version-check", "--quiet",
            "--timeout", "30", "--max-target-bytes", "1000000",
            "--config", os.path.join(self.rules, "javascript"),
            "--config", os.path.join(self.rules, "python"),
            self.project])
        self.assertEqual(kwargs["env"]["SEMGREP_SEND_METRICS"], "off")
        self.assertEqual(kwargs["timeout"], 600)
        self.assertEqual(result["command"], shlex.join(cmd))
        (version_cmd, version_kwargs), = [c for c in tools.used("semgrep")
                                          if c[0][1:] == ["--version"]]
        self.assertEqual(version_cmd, ["semgrep", "--version"])
        self.assertEqual(version_kwargs["env"]["SEMGREP_SEND_METRICS"], "off")

    def test_only_languages_with_a_rules_folder(self):
        result, tools = self.run_semgrep(languages=["python", "ruby"])
        (cmd, _), = tools.scans("semgrep")
        self.assertEqual([cmd[i + 1] for i, a in enumerate(cmd) if a == "--config"],
                         [os.path.join(self.rules, "python")])
        self.assertEqual(result["languages"], ["python"])

    def test_no_rules_for_the_languages(self):
        result, tools = self.run_semgrep(languages=["ruby"])
        self.assertEqual(result["status"], "no-rules-for-languages")
        self.assertEqual(tools.scans("semgrep"), [])

    def test_version_recorded(self):
        result, _ = self.run_semgrep()
        self.assertEqual(result["version"], SEMGREP_VERSION)

    def test_only_the_security_category_is_kept(self):
        result, _ = self.run_semgrep()
        self.assertEqual(result["status"], "ok")
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertEqual(len(rule_ids), 5)
        self.assertFalse(any("best-practice" in r for r in rule_ids))

    def test_values_kept_exactly(self):
        result, _ = self.run_semgrep()
        raw = next(r for r in json.loads(fixture("semgrep_app.json", self.project))["results"]
                   if r["check_id"] == SHELL_RULE)
        meta = raw["extra"]["metadata"]
        finding = next(f for f in result["findings"] if f["rule_id"] == SHELL_RULE)
        self.assertEqual(finding["file"], os.path.join(self.project, "app.py"))
        self.assertEqual((finding["start_line"], finding["end_line"]), (21, 21))
        self.assertEqual(finding["message"], raw["extra"]["message"])
        self.assertEqual(finding["severity"], "ERROR")
        for key in ("cwe", "owasp", "references", "confidence", "likelihood", "impact"):
            self.assertEqual(finding[key], meta[key], key)

    def test_snippet_is_read_from_the_file(self):
        result, _ = self.run_semgrep()
        finding = next(f for f in result["findings"] if f["rule_id"] == SHELL_RULE)
        self.assertEqual(finding["snippet"], SHELL_LINE)
        self.assertFalse(any("requires login" in f["snippet"] for f in result["findings"]))

    def test_missing_binary(self):
        result, tools = self.run_semgrep(FakeTools(self.project, missing={"semgrep"}))
        self.assertEqual(result["status"], "semgrep-not-found")
        self.assertEqual(tools.calls, [])

    def test_missing_rules(self):
        missing = os.path.join(self.tmp, "no_rules_here")
        with mock.patch.dict(os.environ, {semgrep_scan.RULES_ENV: missing}):
            result, tools = self.run_semgrep()
        self.assertEqual(result["status"], "rules-not-found")
        self.assertIn("git clone https://github.com/semgrep/semgrep-rules", result["error"])
        self.assertIn("checkout " + PINNED, result["error"])
        self.assertEqual(tools.scans("semgrep"), [])

    def test_default_rules_folder(self):
        with mock.patch.dict(os.environ):
            os.environ.pop(semgrep_scan.RULES_ENV, None)
            self.assertEqual(semgrep_scan.rules_dir(),
                             os.path.expanduser("~/.local/share/reconmind/semgrep-rules"))
            self.assertEqual(semgrep_scan.setup_command(), (
                "git clone https://github.com/semgrep/semgrep-rules "
                "~/.local/share/reconmind/semgrep-rules && git -C "
                "~/.local/share/reconmind/semgrep-rules checkout " + PINNED))

    def test_pinned_commit_gives_no_warning(self):
        result, _ = self.run_semgrep()
        self.assertEqual((result["rules_commit"], result["warning"]), (PINNED, ""))

    def test_other_commit_gives_a_warning(self):
        self.write_head(OTHER_COMMIT + "\n")
        result, _ = self.run_semgrep()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["rules_commit"], OTHER_COMMIT)
        self.assertIn("differs from the pinned commit " + PINNED, result["warning"])

    def test_commit_from_a_branch_ref(self):
        self.write_head("ref: refs/heads/main\n")
        self.write_head(PINNED + "\n", "refs/heads/main")
        self.assertEqual(semgrep_scan.read_rules_commit(self.rules), PINNED)

    def test_commit_from_packed_refs(self):
        self.write_head("ref: refs/heads/main\n")
        self.write_head("# pack-refs with: peeled fully-peeled sorted\n"
                        "{c} refs/heads/main\n".format(c=PINNED), "packed-refs")
        self.assertEqual(semgrep_scan.read_rules_commit(self.rules), PINNED)

    def test_unreadable_commit_gives_a_warning(self):
        shutil.rmtree(os.path.join(self.rules, ".git"))
        result, _ = self.run_semgrep()
        self.assertEqual(result["rules_commit"], "")
        self.assertIn("could not be read", result["warning"])

    def test_exit_code_1_is_not_an_error(self):
        result, _ = self.run_semgrep(FakeTools(self.project, semgrep_code=1))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(result["findings"]), 5)

    def test_other_exit_code_fails(self):
        result, _ = self.run_semgrep(FakeTools(self.project, semgrep_code=2))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error"], "Semgrep exited with code 2: boom")

    def test_timeout(self):
        tools = FakeTools(self.project,
                          semgrep=subprocess.TimeoutExpired(cmd="semgrep", timeout=600))
        result, _ = self.run_semgrep(tools)
        self.assertEqual(result["status"], "timeout")

    def test_bad_output(self):
        for text in ("not json", '{"no_results": 1}'):
            result, _ = self.run_semgrep(FakeTools(self.project, semgrep=text))
            self.assertEqual(result["status"], "bad-json", text)

    def test_tool_errors_are_kept(self):
        text = json.dumps({"results": [], "errors": [
            {"type": "Syntax error", "message": "Syntax error at line app.py:3"}]})
        result, _ = self.run_semgrep(FakeTools(self.project, semgrep=text))
        self.assertEqual(result["tool_errors"], ["Syntax error at line app.py:3"])
        self.assertEqual(result["tool_error_count"], 1)


# ---- bandit ----------------------------------------------------------------

class BanditTests(CodeTestCase):

    def run_bandit(self, tools=None):
        tools = tools or FakeTools(self.project)
        with tools.active():
            result = bandit_scan.run_bandit(self.project)
        return result, tools

    def test_exact_command_and_version(self):
        result, tools = self.run_bandit()
        (cmd, _), = tools.scans("bandit")
        self.assertEqual(cmd, ["bandit", "-r", self.project, "-f", "json", "-q"])
        self.assertEqual(result["version"], "bandit 1.8.6")

    def test_exit_code_1_means_findings(self):
        result, _ = self.run_bandit()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(result["findings"]), 8)

    def test_fields_kept_exactly(self):
        result, _ = self.run_bandit()
        raw = next(r for r in json.loads(fixture("bandit_app.json", self.project))["results"]
                   if r["test_id"] == "B602")
        finding = next(f for f in result["findings"] if f["test_id"] == "B602")
        for key in ("test_id", "test_name", "issue_text", "issue_severity", "issue_confidence",
                    "filename", "line_number", "line_range", "code", "more_info"):
            self.assertEqual(finding[key], raw[key], key)
        self.assertEqual((finding["cwe_id"], finding["cwe_link"]),
                         (78, "https://cwe.mitre.org/data/definitions/78.html"))
        self.assertEqual(finding["snippet"], SHELL_LINE)

    def test_missing_binary(self):
        result, tools = self.run_bandit(FakeTools(self.project, missing={"bandit"}))
        self.assertEqual(result["status"], "bandit-not-found")
        self.assertEqual(tools.calls, [])

    def test_other_exit_code_fails(self):
        result, _ = self.run_bandit(FakeTools(self.project, bandit_code=2))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error"], "Bandit exited with code 2: boom")

    def test_timeout_and_bad_output(self):
        tools = FakeTools(self.project,
                          bandit=subprocess.TimeoutExpired(cmd="bandit", timeout=600))
        self.assertEqual(self.run_bandit(tools)[0]["status"], "timeout")
        self.assertEqual(self.run_bandit(FakeTools(self.project, bandit="{"))[0]["status"],
                         "bad-json")


# ---- merged scan -----------------------------------------------------------

class CodeScanTests(CodeTestCase):

    def test_merged_findings_and_order(self):
        scan, _ = self.scan()
        self.assertEqual([(f["severity"], f["file"], f["line"], f["sources"])
                          for f in scan["findings"]], EXPECTED_FINDINGS)
        self.assertEqual(scan["counts"], EXPECTED_COUNTS)
        self.assertEqual(scan["status"], "ok")

    def test_merge_needs_a_shared_cwe(self):
        scan, _ = self.scan()
        semgrep = self.finding(scan, 29, "semgrep")
        bandit = self.finding(scan, 29, "bandit")
        self.assertIsNot(semgrep, bandit)
        self.assertEqual((semgrep["cwe"], bandit["cwe"]), (["CWE-502"], ["CWE-20"]))

    def test_merge_needs_the_same_line(self):
        scan, _ = self.scan()
        self.assertEqual(self.finding(scan, 16, "bandit")["sources"], ["bandit"])
        self.assertEqual(self.finding(scan, 17, "semgrep")["sources"], ["semgrep"])

    def test_merged_finding_keeps_both_tools(self):
        scan, _ = self.scan()
        finding = self.finding(scan, 21, "semgrep")
        self.assertEqual(finding["rule_ids"], {"semgrep": SHELL_RULE, "bandit": "B602"})
        self.assertEqual(finding["tool_severity"], {"semgrep": "ERROR", "bandit": "HIGH"})
        self.assertEqual(finding["semgrep"]["severity"], "ERROR")
        self.assertEqual(finding["bandit"]["issue_severity"], "HIGH")
        self.assertEqual(finding["cwe"], ["CWE-78"])
        self.assertEqual(finding["snippet"], SHELL_LINE)
        self.assertIn("https://docs.python.org/3/library/subprocess.html", finding["references"])
        self.assertIn("https://cwe.mitre.org/data/definitions/78.html", finding["references"])
        self.assertIn("https://bandit.readthedocs.io/en/1.8.6/plugins/"
                      "b602_subprocess_popen_with_shell_equals_true.html", finding["references"])

    def test_merged_severity_is_the_higher_one(self):
        scan, _ = self.scan()
        finding = self.finding(scan, 25, "semgrep")  # Semgrep WARNING, Bandit HIGH
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["tool_severity"], {"semgrep": "WARNING", "bandit": "HIGH"})

    def test_severity_normalization(self):
        for value, expected in (("ERROR", "high"), ("WARNING", "medium"), ("INFO", "low"),
                                ("warning", "medium")):
            self.assertEqual(code_scan.normalize_severity(code_scan.SEMGREP_SEVERITY, value),
                             expected)
        for value, expected in (("HIGH", "high"), ("MEDIUM", "medium"), ("LOW", "low")):
            self.assertEqual(code_scan.normalize_severity(code_scan.BANDIT_SEVERITY, value),
                             expected)
        for table in (code_scan.SEMGREP_SEVERITY, code_scan.BANDIT_SEVERITY):
            for value in ("UNDEFINED", "", None):
                self.assertEqual(code_scan.normalize_severity(table, value), "unknown")
        self.assertGreater(code_scan.severity_rank("unknown"), code_scan.severity_rank("low"))

    def test_unknown_severity_is_kept_counted_and_sorted_last(self):
        data = json.loads(fixture("bandit_app.json", self.project))
        for result in data["results"]:
            if result["test_id"] == "B105":
                result["issue_severity"] = "UNDEFINED"
        scan, _ = self.scan(tools=FakeTools(self.project, bandit=json.dumps(data)))
        last = scan["findings"][-1]
        self.assertEqual((last["severity"], last["line"], last["tool_severity"]),
                         ("unknown", 11, {"bandit": "UNDEFINED"}))
        self.assertEqual(last["bandit"]["issue_severity"], "UNDEFINED")
        self.assertEqual(scan["counts"], {"high": 3, "medium": 4, "low": 2, "unknown": 1})
        text = self.report(scan)
        self.assertIn("| Unknown | 1 |", text)
        self.assertEqual(re.findall(r"^### \d+\. (\w+) at (\S+)", text, re.M)[-1],
                         ("UNKNOWN", "app.py:11"))
        self.assertIn("* **Severity:** unknown (tool values: Bandit UNDEFINED)", text)

    def test_cwe_ids(self):
        self.assertEqual(code_scan.cwe_ids(["CWE-89: Improper Neutralization", 89, "CWE-78",
                                            None, 0]),
                         ["CWE-78", "CWE-89"])

    def test_single_file_input(self):
        scan, _ = self.scan(os.path.join(self.project, "app.py"))
        self.assertEqual(scan["input_type"], "file")
        self.assertEqual([(f["severity"], f["file"], f["line"], f["sources"])
                          for f in scan["findings"]], EXPECTED_FINDINGS)

    def test_bandit_does_not_run_without_python(self):
        folder = os.path.join(self.tmp, "web")
        self.write(os.path.join(folder, "a.js"), "eval(location.hash)\n")
        tools = FakeTools(folder, semgrep='{"results": [], "errors": []}')
        scan, _ = self.scan(folder, tools)
        self.assertEqual(scan["tools"]["bandit"]["status"], "no-python-files")
        self.assertEqual(tools.used("bandit"), [])
        (cmd, _), = tools.scans("semgrep")
        self.assertIn(os.path.join(self.rules, "javascript"), cmd)

    def test_no_tool_ran(self):
        scan, _ = self.scan(tools=FakeTools(self.project, missing={"semgrep", "bandit"}))
        self.assertEqual(scan["status"], "no-tool-ran")
        self.assertEqual(scan["findings"], [])

    def test_explain_is_off_by_default_and_makes_no_llm_call(self):
        with mock.patch.object(llm, "load_config") as load, \
                mock.patch.object(llm, "make_client") as make:
            scan, _ = self.scan()
        load.assert_not_called()
        make.assert_not_called()
        self.assertIsNone(scan["explanation"])

    def test_the_analyzed_code_is_never_imported(self):
        self.scan()
        for module in list(sys.modules.values()):
            path = getattr(module, "__file__", None) or ""
            self.assertFalse(os.path.realpath(path).startswith(self.project + os.sep), path)


# ---- report ----------------------------------------------------------------

def tool_strings(scan):
    """Every value a tool wrote (and the model text), longest first."""
    values = [scan.get("input", "")]

    def collect(value):
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, dict):
            for item in value.values():
                collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)

    for finding in scan["findings"]:
        collect(finding["semgrep"])
        collect(finding["bandit"])
        values.append(finding["snippet"])
    for result in scan["tools"].values():
        for key in ("command", "version", "rules_path", "tool_errors"):
            collect(result.get(key))
    if scan.get("explanation"):
        values.append(scan["explanation"].get("text", ""))
    return sorted({v for v in values if v}, key=len, reverse=True)


class ReportTests(CodeTestCase):

    def test_header_and_fixed_line(self):
        text = self.report(self.scan()[0])
        self.assertTrue(text.startswith("# ReconMind Code Report\n"))
        self.assertIn("**Input:** " + self.project, text)
        self.assertIn(FIXED_LINE, text)
        self.assertEqual(code_report.FIXED_LINE, FIXED_LINE)

    def test_files_tools_and_counts(self):
        text = self.report(self.scan()[0])
        self.assertIn("| python | 1 |", text)
        self.assertIn("| Semgrep | ok | 1.95.0 |", text)
        self.assertIn("| Bandit | ok | bandit 1.8.6 |", text)
        self.assertIn("commit `{c}` (pinned `{c}`)".format(c=PINNED), text)
        for row in ("| High | 3 |", "| Medium | 4 |", "| Low | 3 |"):
            self.assertIn(row, text)
        self.assertNotIn("| Unknown |", text)
        self.assertNotIn("**Warning:**", text)

    def test_finding_details(self):
        text = self.report(self.scan()[0])
        start = text.index("### 1. HIGH at app.py:21")
        section = text[start:text.index("### 2.", start)]
        for expected in ("**CWE:** CWE-78", "**Found by:** Semgrep and Bandit",
                         "`" + SHELL_RULE + "`", "`B602` subprocess_popen_with_shell_equals_true",
                         "subprocess call with shell=True identified, security issue.",
                         "Found 'subprocess' function 'check_output' with 'shell=True'.",
                         "```python\n" + SHELL_LINE + "\n```",
                         "* https://cwe.mitre.org/data/definitions/78.html",
                         "severity ERROR, confidence MEDIUM, likelihood HIGH, impact LOW"):
            self.assertIn(expected, section)

    def test_findings_most_severe_first_then_file_and_line(self):
        text = self.report(self.scan()[0])
        headings = re.findall(r"^### \d+\. (\w+) at (\S+)", text, re.M)
        self.assertEqual(headings, [(s.upper(), "{f}:{n}".format(f=f, n=n))
                                    for s, f, n, _ in EXPECTED_FINDINGS])

    def test_tools_that_did_not_run_are_listed(self):
        text = self.report(self.scan(tools=FakeTools(self.project, missing={"bandit"}))[0])
        self.assertIn("**Did not run:**", text)
        self.assertIn("* Bandit: bandit-not-found.", text)
        self.assertIn("| Bandit | bandit-not-found | not reported |", text)

    def test_missing_rules_are_listed_with_the_setup_command(self):
        with mock.patch.dict(os.environ, {semgrep_scan.RULES_ENV: os.path.join(self.tmp, "x")}):
            text = self.report(self.scan()[0])
        self.assertIn("* Semgrep: rules-not-found.", text)
        self.assertIn("checkout " + PINNED, text)

    def test_rules_warning_is_shown(self):
        self.write_head(OTHER_COMMIT + "\n")
        text = self.report(self.scan()[0])
        self.assertIn("**Warning:** Rules commit " + OTHER_COMMIT, text)

    def test_no_explanation_section_without_explain(self):
        self.assertNotIn("## AI explanation", self.report(self.scan()[0]))

    def test_no_dash_separators_in_our_text(self):
        self.write_head(OTHER_COMMIT + "\n")
        scans = [self.scan()[0],
                 self.scan(tools=FakeTools(self.project, missing={"bandit"}))[0],
                 self.scan(explain=True, client=FakeLLM(BAD_TEXT), model="m")[0],
                 self.scan(explain=True, client=FakeLLM(error=RuntimeError("down")),
                           model="m")[0]]
        for scan in scans:
            text = self.report(scan)
            for value in tool_strings(scan):
                text = text.replace(value, "")
            self.assertIn("# ReconMind Code Report", text)
            for dash in ("—", "–", " - "):
                self.assertNotIn(dash, text)

    def test_our_docstrings_and_prompt_have_no_dash_separators(self):
        from reconmind.code import report as report_module
        modules = (inputs, semgrep_scan, bandit_scan, code_scan, explain, report_module, router)
        for module in modules:
            with open(module.__file__) as fh:
                tree = ast.parse(fh.read())
            nodes = [tree] + [n for n in ast.walk(tree)
                              if isinstance(n, (ast.FunctionDef, ast.ClassDef))]
            for node in nodes:
                doc = ast.get_docstring(node) or ""
                for dash in ("—", "–", " - "):
                    self.assertNotIn(dash, doc, module.__name__)
        for dash in ("—", "–", " - "):
            self.assertNotIn(dash, explain.SYSTEM_PROMPT)


# ---- history ---------------------------------------------------------------

class HistoryTests(CodeTestCase):

    def setUp(self):
        super().setUp()
        self.in_tmp()

    def test_code_run_is_saved(self):
        scan, _ = self.scan()
        record = history.save_code_run(scan, started=STARTED, finished=FINISHED)
        self.assertEqual(record.run_id, "20261112_100000_project")
        folder = os.path.join("reports", record.run_id)
        self.assertEqual(sorted(os.listdir(folder)), ["report.md", "scan.json"])
        with open(record.report_path) as fh:
            self.assertTrue(fh.read().startswith("# ReconMind Code Report"))
        with open(os.path.join(folder, "scan.json")) as fh:
            data = json.load(fh)
        self.assertEqual((data["run_id"], data["kind"]), (record.run_id, "code"))
        self.assertEqual(data["results"]["counts"], EXPECTED_COUNTS)
        self.assertEqual(history.read_index(), [{
            "run_id": "20261112_100000_project", "kind": "code", "input": self.project,
            "started": "2026-11-12T10:00:00", "finished": "2026-11-12T10:05:30",
            "status": "ok", "languages": {"python": 1}, "findings": EXPECTED_COUNTS,
            "ai_explanation": False,
        }])

    def test_index_records_that_the_explanation_ran(self):
        scan, _ = self.scan(explain=True, client=FakeLLM(GOOD_TEXT), model="m")
        history.save_code_run(scan, started=STARTED, finished=FINISHED)
        self.assertTrue(history.read_index()[-1]["ai_explanation"])

    def test_skipped_explanation_is_not_counted_as_ran(self):
        scan, _ = self.scan(explain=True, client=FakeLLM(error=RuntimeError("down")), model="m")
        history.save_code_run(scan, started=STARTED, finished=FINISHED)
        self.assertFalse(history.read_index()[-1]["ai_explanation"])

    def test_recon_and_code_entries_share_the_index(self):
        history.save_run({"target": "10.10.1.100", "status": "refused", "ports": []},
                         started=STARTED, finished=STARTED)
        history.save_code_run(self.scan()[0], started=STARTED, finished=FINISHED)
        self.assertEqual([e["kind"] for e in history.read_index()], ["recon", "code"])

    def test_old_entries_without_kind_are_recon(self):
        self.assertEqual(history.entry_kind({"run_id": "old"}), "recon")
        self.assertEqual(history.entry_kind({"run_id": "x", "kind": "code"}), "code")


# ---- router ----------------------------------------------------------------

class RouterTests(CodeTestCase):

    def setUp(self):
        super().setUp()
        self.in_tmp()

    def run_router(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = router.main(["python3 -m reconmind"] + list(args))
        return code, out.getvalue()

    def test_ip_runs_recon_with_the_same_options(self):
        args = ["10.10.1.100", "--preset", "quick", "--ports", "22,80", "--actions", "exploits",
                "--provider", "ollama", "--model", "m"]
        with mock.patch.object(agent_main, "main", return_value=0) as agent, \
                mock.patch.object(code_scan, "run_code_scan") as code:
            rc, _ = self.run_router(*args)
        self.assertEqual(rc, 0)
        agent.assert_called_once_with(["python3 -m reconmind.agent"] + args)
        code.assert_not_called()

    def test_gate_runs_first_for_an_ip(self):
        with mock.patch.object(agent_main, "is_authorized", return_value=False) as gate, \
                mock.patch.object(llm, "load_config") as load, \
                mock.patch.object(code_scan, "run_code_scan") as code:
            rc, out = self.run_router("10.10.1.250")
        self.assertEqual(rc, 2)
        gate.assert_called_once_with("10.10.1.250")
        load.assert_not_called()
        code.assert_not_called()
        self.assertIn("REFUSED", out)

    def test_folder_runs_the_code_scan(self):
        with FakeTools(self.project).active(), \
                mock.patch.object(agent_main, "main") as agent, \
                mock.patch.object(agent_main, "is_authorized") as gate:
            rc, out = self.run_router(self.project)
        self.assertEqual(rc, 0)
        agent.assert_not_called()
        gate.assert_not_called()
        self.assertIn("findings:    3 high, 4 medium, 3 low", out)
        self.assertIn("explanation: not requested", out)
        self.assertEqual(history.read_index()[-1]["kind"], "code")

    def test_file_runs_the_code_scan(self):
        with FakeTools(self.project).active():
            rc, out = self.run_router(os.path.join(self.project, "app.py"))
        self.assertEqual(rc, 0)
        self.assertIn("ReconMind code scan", out)

    def test_anything_else_is_an_error_naming_both_choices(self):
        for value in ("not-a-thing", "10.10.1.300", "::1", os.path.join(self.tmp, "gone.py")):
            with mock.patch.object(agent_main, "main") as agent, \
                    mock.patch.object(code_scan, "run_code_scan") as code:
                rc, out = self.run_router(value)
            self.assertEqual(rc, 1, value)
            self.assertIn("neither an IPv4 address nor an existing file or folder", out)
            self.assertIn("to run recon", out)
            self.assertIn("to run a code scan", out)
            agent.assert_not_called()
            code.assert_not_called()

    def test_explain_with_an_ip_is_refused(self):
        with mock.patch.object(agent_main, "main") as agent:
            rc, out = self.run_router("10.10.1.100", "--explain")
        self.assertEqual(rc, 1)
        self.assertIn("--explain is only for a code scan", out)
        agent.assert_not_called()

    def test_recon_options_with_a_path_are_refused(self):
        with mock.patch.object(code_scan, "run_code_scan") as code:
            rc, out = self.run_router(self.project, "--preset", "quick")
        self.assertEqual(rc, 1)
        self.assertIn("--preset only apply to an IPv4 target", out)
        code.assert_not_called()

    def test_explain_is_off_by_default(self):
        self.assertFalse(router._parse_args([self.project]).explain)

    def test_bad_input_gives_a_clear_error(self):
        folder = os.path.join(self.tmp, "docs")
        self.write(os.path.join(folder, "README.md"))
        rc, out = self.run_router(folder)
        self.assertEqual(rc, 1)
        self.assertIn("Cannot scan:", out)
        self.assertIn("no source file in a supported language", out)

    def test_agent_entry_point_is_unchanged(self):
        self.assertEqual(agent_main._parse_args(["10.10.1.100"]).target, "10.10.1.100")


# ---- AI explanation --------------------------------------------------------

class ExplainTests(CodeTestCase):

    def test_sends_finding_details_not_whole_files(self):
        scan, _ = self.scan()
        client = FakeLLM(GOOD_TEXT)
        result = explain.explain_findings(scan["findings"], model="test-model", client=client)
        (request,), = [client.requests]
        content = request["messages"][0]["content"]
        for expected in ("app.py:21", "B602", SHELL_RULE, "CWE-78", "shell=True)",
                         "subprocess call with shell=True identified"):
            self.assertIn(expected, content)
        self.assertNotIn("def find_user", content)  # a line no finding points at
        self.assertNotIn("INTENTIONALLY INSECURE", content)
        self.assertEqual(request["model"], "test-model")
        self.assertEqual(request["system"], explain.SYSTEM_PROMPT)
        self.assertEqual((result["status"], result["unverified"], result["sent"]),
                         ("ok", [], True))

    def test_verification_flags_what_no_tool_reported(self):
        scan, _ = self.scan()
        result = explain.explain_findings(scan["findings"], model="m", client=FakeLLM(BAD_TEXT))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["unverified"], ["app.py:99", "CWE-79", "lib/other.py:3"])

    def test_verify_explanation(self):
        findings = self.scan()[0]["findings"]
        self.assertEqual(explain.verify_explanation(
            "See app.py:16 and app.py:17, CWE-89 and CWE 20.", findings), [])
        self.assertEqual(explain.verify_explanation(
            "Look at app.py:12 for CWE 999.", findings), ["app.py:12", "CWE-999"])

    def test_explanation_never_changes_the_findings(self):
        scan, _ = self.scan()
        before = json.dumps(scan["findings"], sort_keys=True)
        explain.explain_findings(scan["findings"], model="m", client=FakeLLM(BAD_TEXT))
        self.assertEqual(json.dumps(scan["findings"], sort_keys=True), before)

    def test_skipped_when_no_provider_is_set(self):
        findings = self.scan()[0]["findings"]
        with mock.patch.dict(os.environ, {}, clear=True):
            result = explain.explain_findings(findings)
        self.assertEqual(result["status"], "skipped")
        self.assertTrue(result["reason"].startswith("no LLM provider is configured"))
        self.assertFalse(result["sent"])

    def test_failed_call_is_skipped(self):
        findings = self.scan()[0]["findings"]
        for error in (RuntimeError("connection refused"), llm.RateLimited("busy")):
            result = explain.explain_findings(findings, model="m", client=FakeLLM(error=error))
            self.assertEqual(result["status"], "skipped")
            self.assertTrue(result["reason"].startswith("the LLM call failed"))
            self.assertTrue(result["sent"])

    def test_budget_is_16000_like_the_prompted_mapper(self):
        findings = self.scan()[0]["findings"]
        client = FakeLLM(GOOD_TEXT)
        explain.explain_findings(findings, model="m", client=client)
        self.assertEqual(explain.MAX_TOKENS, 16000)
        self.assertEqual(client.requests[0]["max_tokens"], 16000)

    def test_empty_answer_is_retried_with_double_the_budget(self):
        findings = self.scan()[0]["findings"]
        native = FakeOpenAI([openai_response("", "length", 16000, 16000),
                             openai_response(GOOD_TEXT, "stop", 20000, 18000)])
        result = explain.explain_findings(findings, model="m",
                                          client=llm.OpenAICompatClient(native))
        self.assertEqual([r["max_tokens"] for r in native.requests], [16000, 32000])
        self.assertEqual(result["status"], "ok")
        self.assertIn("### app.py:21", result["text"])

    def test_still_empty_names_finish_reason_and_token_usage(self):
        findings = self.scan()[0]["findings"]
        native = FakeOpenAI([openai_response("", "length", 16000, 16000),
                             openai_response("", "length", 32000, 31950)])
        result = explain.explain_findings(findings, model="m",
                                          client=llm.OpenAICompatClient(native))
        self.assertEqual([r["max_tokens"] for r in native.requests], [16000, 32000])
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["reason"], "the model returned no text (finish reason: length, "
                                           "token usage: 32000 completion, 31950 reasoning)")
        self.assertTrue(result["sent"])

    def test_empty_reply_that_did_not_run_out_is_not_retried(self):
        findings = self.scan()[0]["findings"]
        native = FakeOpenAI([openai_response("", "stop", 3)])
        result = explain.explain_findings(findings, model="m",
                                          client=llm.OpenAICompatClient(native))
        self.assertEqual(len(native.requests), 1)
        self.assertEqual(result["reason"], "the model returned no text (finish reason: stop, "
                                           "token usage: 3 completion)")

    def test_empty_answer_without_reported_usage(self):
        findings = self.scan()[0]["findings"]
        for response, finish in ((NS(content=[], stop_reason="end_turn"), "end_turn"),
                                 (NS(content=[]), "not reported")):
            result = explain.explain_findings(findings, model="m",
                                              client=FakeLLM(response=response))
            self.assertEqual(result["status"], "skipped")
            self.assertEqual(result["reason"], "the model returned no text (finish reason: "
                                               "{f}, token usage: not reported)".format(f=finish))

    def test_report_shows_why_an_empty_answer_was_skipped(self):
        response = NS(content=[], stop_reason="max_tokens", finish_reason="length",
                      token_usage={"completion_tokens": 32000, "reasoning_tokens": 32000})
        scan, _ = self.scan(explain=True, client=FakeLLM(response=response), model="m")
        self.assertIn("finish reason: length, token usage: 32000 completion, 32000 reasoning",
                      self.report(scan))

    def test_no_findings_means_no_call(self):
        client = FakeLLM(GOOD_TEXT)
        result = explain.explain_findings([], model="m", client=client)
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(client.requests, [])

    def test_report_shows_the_explanation_after_the_findings(self):
        scan, _ = self.scan(explain=True, client=FakeLLM(BAD_TEXT), provider="ollama",
                            model="test-model")
        self.assertEqual(scan["counts"], EXPECTED_COUNTS)
        text = self.report(scan)
        self.assertLess(text.index("## Findings\n"), text.index("## AI explanation"))
        self.assertLess(text.index("### 10. LOW"), text.index("## AI explanation"))
        self.assertIn("_AI interpretation of the tool findings above.", text)
        self.assertIn("sent to the configured LLM provider (ollama, model test-model)", text)
        self.assertIn("**Unverified references**", text)
        self.assertIn("* app.py:99", text)
        self.assertIn("* CWE-79", text)

    def test_report_says_skipped_without_a_provider(self):
        with mock.patch.dict(os.environ, {semgrep_scan.RULES_ENV: self.rules}, clear=True):
            scan, _ = self.scan(explain=True)
        text = self.report(scan)
        self.assertIn("AI explanation skipped: no LLM provider is configured", text)
        self.assertIn("This report has the tool findings only.", text)
        self.assertNotIn("sent to the configured LLM provider", text)
        self.assertIn("### 1. HIGH at app.py:21", text)


# ---- no network in the scanning modules -------------------------------------

NETWORK_MODULES = ("socket", "ssl", "urllib", "urllib3", "http", "requests", "httpx",
                   "aiohttp", "websocket", "websockets", "ftplib", "smtplib", "openai",
                   "anthropic")


def imports_of(path):
    """[(module name, at module level)] for every import in a source file."""
    with open(path) as fh:
        tree = ast.parse(fh.read())
    top = set(id(n) for n in tree.body)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [(a.name, id(node) in top) for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.append((node.module, id(node) in top))
            found += [(node.module + "." + a.name, id(node) in top) for a in node.names]
    return found


class NoNetworkImportTests(unittest.TestCase):

    def test_scanning_modules_import_no_network_library(self):
        for module in (inputs, semgrep_scan, bandit_scan, code_scan, code_report):
            for name, at_top in imports_of(module.__file__):
                self.assertNotIn(name.split(".")[0], NETWORK_MODULES, module.__name__)
                self.assertFalse(name.startswith("reconmind.agent"), module.__name__)
                if name.startswith("reconmind.code.explain"):
                    self.assertIs(module, code_scan)
                    self.assertFalse(at_top, "explain must only load when --explain is given")

    def test_explain_reaches_the_network_only_through_llm(self):
        names = [name for name, _ in imports_of(explain.__file__)]
        self.assertIn("reconmind.agent.llm", names)
        for name in names:
            self.assertNotIn(name.split(".")[0], NETWORK_MODULES)


if __name__ == "__main__":
    unittest.main()
