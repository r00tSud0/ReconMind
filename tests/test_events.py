"""
Offline tests for progress events (reconmind/core/events.py): nothing is
written when RECONMIND_EVENTS is unset, one valid JSON line per emit when it
is set, and emit never raises, whatever the path or the data. Also the code
scan's progress callback, its step events and the router's progress lines.

    python3 -m unittest discover -s tests -v
"""

import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime
from unittest import mock

from reconmind.core import events


class EventTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "job.events.jsonl")

    def tearDown(self):
        self._tmp.cleanup()

    def lines(self):
        with open(self.path, encoding="utf-8") as fh:
            return fh.read().splitlines()

    def test_unset_writes_nothing(self):
        env = {k: v for k, v in os.environ.items() if k != events.ENV_VAR}
        with mock.patch.dict(os.environ, env, clear=True):
            events.emit("step", tool="nmap_scan", status="start")
            events.emit("finished", status="ok")
        self.assertEqual(os.listdir(self._tmp.name), [])

    def test_empty_value_writes_nothing(self):
        with mock.patch.dict(os.environ, {events.ENV_VAR: ""}):
            events.emit("step", tool="nmap_scan")
        self.assertEqual(os.listdir(self._tmp.name), [])

    def test_one_json_line_per_emit(self):
        with mock.patch.dict(os.environ, {events.ENV_VAR: self.path}):
            events.emit("plan", preset="standard", ports="top", actions=["surface"],
                        mode="standard")
            events.emit("step", action="web", tool="web_fingerprint", port=80, status="start")
            events.emit("finished", status="ok", run_id="20261115_100000_10.10.1.100")
        lines = self.lines()
        self.assertEqual(len(lines), 3)
        records = [json.loads(line) for line in lines]
        self.assertEqual([r["kind"] for r in records], ["plan", "step", "finished"])
        self.assertEqual(records[1], dict(records[1], action="web", tool="web_fingerprint",
                                          port=80, status="start"))
        for record in records:
            datetime.strptime(record["time"], events.TIME_FORMAT)  # a valid ISO time
            self.assertEqual(list(record)[:2], ["time", "kind"])

    def test_appends_to_an_existing_file(self):
        with open(self.path, "w") as fh:
            fh.write('{"kind": "earlier"}\n')
        with mock.patch.dict(os.environ, {events.ENV_VAR: self.path}):
            events.emit("step", status="done")
        self.assertEqual(len(self.lines()), 2)

    def test_data_cannot_replace_time_or_kind(self):
        with mock.patch.dict(os.environ, {events.ENV_VAR: self.path}):
            events.emit("step", time="not a time")
        record = json.loads(self.lines()[0])
        self.assertEqual(record["kind"], "step")
        self.assertNotEqual(record["time"], "not a time")

    def test_never_raises_on_a_bad_path(self):
        bad = (os.path.join(self._tmp.name, "missing", "folder", "x.jsonl"),
               self._tmp.name)  # a folder, not a file
        for path in bad:
            with self.subTest(path=path), mock.patch.dict(os.environ, {events.ENV_VAR: path}):
                events.emit("step", status="start")  # must not raise

    def test_never_raises_on_odd_data(self):
        class Unprintable:
            def __str__(self):
                raise RuntimeError("no")

        with mock.patch.dict(os.environ, {events.ENV_VAR: self.path}):
            events.emit("step", value=Unprintable())  # must not raise
            events.emit("step", ports={1, 2})        # a set becomes text, not an error
        self.assertEqual(len(self.lines()), 1)


class CodeScanEventTests(unittest.TestCase):
    """run_code_scan reports semgrep, bandit and the explanation as steps."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.events = os.path.join(self._tmp.name, "code.events.jsonl")
        self.source = os.path.join(self._tmp.name, "app.py")
        with open(self.source, "w") as fh:
            fh.write("print('hi')\n")

    def tearDown(self):
        self._tmp.cleanup()

    def test_progress_callback_and_step_events(self):
        from reconmind.code import code_scan

        ok = {"status": "ok", "findings": []}
        seen = []
        with mock.patch.object(code_scan, "run_semgrep", return_value=dict(ok)), \
             mock.patch.object(code_scan, "run_bandit", return_value=dict(ok)), \
             mock.patch.dict(os.environ, {events.ENV_VAR: self.events}):
            code_scan.run_code_scan(self.source, explain=True,
                                    progress=lambda step, status: seen.append((step, status)))
        # No findings, so the explanation is skipped without any model call.
        self.assertEqual(seen, [("semgrep", "start"), ("semgrep", "done"),
                                ("bandit", "start"), ("bandit", "done"),
                                ("explanation", "start"), ("explanation", "skipped")])
        with open(self.events) as fh:
            records = [json.loads(line) for line in fh]
        self.assertEqual([(r["kind"], r["tool"], r["status"]) for r in records],
                         [("step",) + s for s in seen])

    def test_router_prints_each_step_as_it_starts(self):
        from reconmind import __main__ as router
        from reconmind.code import code_scan
        from reconmind.code.inputs import InputError

        def scan_then_stop(path, progress=None, **kwargs):
            for step in ("semgrep", "bandit", "explanation"):
                progress(step, "start")
            raise InputError("stopped for the test")

        out = io.StringIO()
        with mock.patch.object(code_scan, "run_code_scan", side_effect=scan_then_stop), \
             contextlib.redirect_stdout(out):
            router.main(["python3 -m reconmind", self.source])
        self.assertEqual(out.getvalue().splitlines()[:3],
                         ["running semgrep...", "running bandit...",
                          "writing the AI explanation..."])


if __name__ == "__main__":
    unittest.main()
