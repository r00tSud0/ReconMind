"""
Offline tests for Model A: reconmind/ai/prompted_mapper.py and
scripts/eval_prompted.py. A fake client stands in for the provider, so no
key, network or SDK is needed:

    python3 -m unittest discover -s tests -v
"""

import contextlib
import importlib.util
import io
import json
import os
import re
import tempfile
import unittest
from types import SimpleNamespace as NS
from unittest import mock

from reconmind.agent import llm
from reconmind.ai import prompted_mapper as pm

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "scripts", "eval_prompted.py")

TABLE = [{"id": "T1001", "name": "Data Obfuscation"},
         {"id": "T1002", "name": "Data Compressed"}]

# Each sentence names its gold technique, so the fake model can "answer" it.
EVAL_ROWS = [
    {"id": "e1", "sentence": "They used T1001 here.", "labels": ["T1001"]},
    {"id": "e2", "sentence": "Nothing to see.", "labels": []},
    {"id": "e3", "sentence": "Then T1002 happened.", "labels": ["T1002"]},
    {"id": "e4", "sentence": "Also nothing.", "labels": []},
    {"id": "e5", "sentence": "Both T1001 and T1002.", "labels": ["T1001", "T1002"]},
    {"id": "e6", "sentence": "Quiet line.", "labels": []},
]


def load_script():
    spec = importlib.util.spec_from_file_location("eval_prompted", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def answer_for(user_message):
    """A perfect JSON answer built from the IDs written in each numbered line."""
    out = {}
    for line in user_message.splitlines():
        m = re.match(r"(\d+)\. (.*)", line)
        if m:
            out[m.group(1)] = sorted(set(re.findall(r"T\d{4}", m.group(2))))
    return json.dumps(out)


class FakeClient:
    """
    client.messages.create(**kw). script is a list of "good", "garbage" or an
    exception, one per call; after it runs out every call is "good".
    """

    def __init__(self, script=()):
        self.script = list(script)
        self.requests = []
        self.messages = self

    def create(self, **kwargs):
        self.requests.append(kwargs)
        step = self.script.pop(0) if self.script else "good"
        if isinstance(step, Exception):
            raise step
        text = "not json at all" if step == "garbage" else answer_for(
            kwargs["messages"][0]["content"])
        return NS(content=[NS(type="text", text=text)], stop_reason="end_turn")

    def sent_ids(self):
        """Sentence numbers per request, mapped back to sentence text."""
        return [re.findall(r"^\d+\. (.*)$", r["messages"][0]["content"], re.M)
                for r in self.requests]


class ReasoningOpenAI:
    """
    An OpenAI-compatible endpoint whose reasoning model spends its whole
    budget thinking and returns an empty answer cut off by length.
    """

    def __init__(self):
        self.requests = []
        self.chat = NS(completions=NS(create=self._create))

    def _create(self, **kwargs):
        self.requests.append(kwargs)
        budget = kwargs["max_tokens"]
        return NS(choices=[NS(message=NS(content="", tool_calls=None), finish_reason="length")],
                  usage=NS(completion_tokens=budget,
                           completion_tokens_details=NS(reasoning_tokens=budget)))


def reasoning_client():
    fake = ReasoningOpenAI()
    return llm.OpenAICompatClient(fake), fake


class ParseTests(unittest.TestCase):

    def test_good_json(self):
        self.assertEqual(pm.parse_response('{"1": ["T1190"], "2": []}', 2), [["T1190"], []])

    def test_json_in_code_fence(self):
        text = 'Here you go:\n```json\n{"1": ["t1059.001 "], "2": ["T1105"]}\n```'
        self.assertEqual(pm.parse_response(text, 2), [["T1059.001"], ["T1105"]])

    def test_plain_fence(self):
        self.assertEqual(pm.parse_response('```\n{"1": []}\n```', 1), [[]])

    def test_prose_around_json(self):
        self.assertEqual(pm.parse_response('Sure. {"1": ["T1190"]} Done.', 1), [["T1190"]])

    def test_garbage(self):
        for text in ("not json", "", "{broken", "[1, 2]", None):
            self.assertIsNone(pm.parse_response(text, 1), text)

    def test_missing_key_is_invalid(self):
        self.assertIsNone(pm.parse_response('{"1": []}', 2))

    def test_non_list_value_is_invalid(self):
        self.assertIsNone(pm.parse_response('{"1": "T1190"}', 1))
        self.assertIsNone(pm.parse_response('{"1": [1190]}', 1))

    def test_out_of_set_ids_are_kept(self):
        self.assertEqual(pm.parse_response('{"1": ["T9999"]}', 1), [["T9999"]])

    def test_extra_keys_ignored(self):
        self.assertEqual(pm.parse_response('{"1": [], "7": ["T1"]}', 1), [[]])

    def test_prompt_lists_ids_and_names(self):
        system, user = pm.build_prompt(["a  b", "c"], TABLE)
        self.assertIn("T1001  Data Obfuscation", system)
        self.assertIn("JSON only", system)
        self.assertEqual(user.splitlines()[1:], ["1. a b", "2. c"])


class ClassifyBatchTests(unittest.TestCase):

    def test_ok_at_temperature_zero(self):
        client = FakeClient()
        rec = pm.classify_batch(client, "m", EVAL_ROWS[:2], TABLE)
        self.assertEqual(rec["status"], "ok")
        self.assertEqual(rec["predictions"], {"e1": ["T1001"], "e2": []})
        self.assertEqual(client.requests[0]["temperature"], 0)
        self.assertEqual(client.requests[0]["model"], "m")

    def test_retry_once_then_success(self):
        client = FakeClient(["garbage", "good"])
        rec = pm.classify_batch(client, "m", EVAL_ROWS[:2], TABLE)
        self.assertEqual(rec["status"], "ok")
        self.assertEqual(len(client.requests), 2)

    def test_two_failures_recorded_as_failed(self):
        client = FakeClient(["garbage", "garbage", "good"])
        rec = pm.classify_batch(client, "m", EVAL_ROWS[:2], TABLE)
        self.assertEqual(rec["status"], "failed")
        self.assertEqual(rec["predictions"], {})
        self.assertEqual(rec["raw"], ["not json at all", "not json at all"])
        self.assertEqual(len(client.requests), 2)  # no third try

    def test_rate_limit_propagates(self):
        client = FakeClient([llm.RateLimited(llm.RATE_LIMIT_MESSAGE)])
        with self.assertRaises(llm.RateLimited):
            pm.classify_batch(client, "m", EVAL_ROWS[:2], TABLE)

    def test_default_budget_is_16000(self):
        client = FakeClient()
        pm.classify_batch(client, "m", EVAL_ROWS[:2], TABLE)
        self.assertEqual(pm.MAX_TOKENS, 16000)
        self.assertEqual(client.requests[0]["max_tokens"], 16000)

    def test_attempts_recorded_for_ok_batch(self):
        rec = pm.classify_batch(FakeClient(["garbage", "good"]), "m", EVAL_ROWS[:2], TABLE)
        self.assertEqual(rec["attempts"], [{"finish_reason": "end_turn"},
                                           {"finish_reason": "end_turn"}])
        self.assertFalse(pm.ran_out_of_length(rec))

    def test_empty_length_batch_records_reason_and_tokens(self):
        client, fake = reasoning_client()
        rec = pm.classify_batch(client, "m", EVAL_ROWS[:2], TABLE, max_tokens=2048)
        self.assertEqual(rec["status"], "failed")
        self.assertEqual(rec["raw"], ["", ""])
        # each attempt: the original call, then the llm layer's doubled retry
        self.assertEqual([r["max_tokens"] for r in fake.requests], [2048, 4096, 2048, 4096])
        self.assertEqual(rec["attempts"], [{
            "finish_reason": "length", "completion_tokens": 4096,
            "reasoning_tokens": 4096, "empty_reason": "length"}] * 2)
        self.assertTrue(pm.ran_out_of_length(rec))

    def test_garbage_failure_is_not_a_length_failure(self):
        rec = pm.classify_batch(FakeClient(["garbage", "garbage"]), "m", EVAL_ROWS[:2], TABLE)
        self.assertFalse(pm.ran_out_of_length(rec))


class RunTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.raw = os.path.join(self._tmp.name, "raw.jsonl")

    def tearDown(self):
        self._tmp.cleanup()

    def run_pm(self, client, **kw):
        return pm.run(client, "m", EVAL_ROWS, TABLE, self.raw, "sha", batch_size=2,
                      log=lambda *_: None, **kw)

    def test_resume_after_rate_limit(self):
        first = FakeClient(["good", "good", llm.RateLimited("busy")])
        with self.assertRaises(llm.RateLimited):
            self.run_pm(first)
        records = pm.read_records(self.raw)
        self.assertEqual(len(records), 2)
        state = pm.sentence_state(records)
        self.assertEqual(pm.progress(EVAL_ROWS, state), {"total": 6, "done": 4, "failed": 0})

        second = FakeClient()
        state = self.run_pm(second)
        self.assertEqual(second.sent_ids(), [["Both T1001 and T1002.", "Quiet line."]])
        self.assertEqual(pm.progress(EVAL_ROWS, state)["done"], 6)

        third = FakeClient()
        self.run_pm(third)
        self.assertEqual(third.requests, [])  # nothing left to send

    def test_truncated_last_line_is_redone(self):
        self.run_pm(FakeClient())
        with open(self.raw) as fh:
            lines = fh.readlines()
        with open(self.raw, "w") as fh:
            fh.writelines(lines[:-1] + [lines[-1][:20]])
        client = FakeClient()
        self.run_pm(client)
        self.assertEqual(len(client.requests), 1)

    def test_eval_sha_mismatch_stops(self):
        with open(self.raw, "w") as fh:
            fh.write(json.dumps({"batch_ids": ["e1"], "status": "ok",
                                 "predictions": {"e1": []}, "eval_sha256": "other"}) + "\n")
        client = FakeClient()
        with self.assertRaises(pm.MapperError):
            self.run_pm(client)
        self.assertEqual(client.requests, [])

    def test_failed_counts_as_done_and_retry_failed_replaces_it(self):
        state = self.run_pm(FakeClient(["garbage", "garbage"]))
        self.assertEqual(pm.progress(EVAL_ROWS, state), {"total": 6, "done": 6, "failed": 2})
        preds = pm.predictions(EVAL_ROWS, state)
        self.assertEqual(preds["e1"], [])  # never guessed

        plain = FakeClient()
        self.run_pm(plain)
        self.assertEqual(plain.requests, [])  # failed is done without the flag

        retry = FakeClient()
        state = self.run_pm(retry, retry_failed=True)
        self.assertEqual(retry.sent_ids(), [["They used T1001 here.", "Nothing to see."]])
        self.assertEqual(pm.progress(EVAL_ROWS, state)["failed"], 0)
        self.assertEqual(pm.predictions(EVAL_ROWS, state)["e1"], ["T1001"])


class ScriptTests(unittest.TestCase):

    def setUp(self):
        self.script = load_script()
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)  # no .env is read
        self._env = mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "k"}, clear=True)
        self._env.start()
        self.data = os.path.join(self._tmp.name, "data")
        self.results = os.path.join(self._tmp.name, "results")
        os.makedirs(self.data)
        with open(os.path.join(self.data, "eval.jsonl"), "w") as fh:
            fh.write("".join(json.dumps(r) + "\n" for r in EVAL_ROWS))
        with open(os.path.join(self.data, "labels.json"), "w") as fh:
            json.dump(TABLE, fh)

    def tearDown(self):
        self._env.stop()
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def main(self, client, *extra):
        out = io.StringIO()
        with mock.patch.object(llm, "make_client", return_value=client), \
             contextlib.redirect_stdout(out):
            code = self.script.main(["eval_prompted.py", "--model", "vendor/m:free",
                                     "--batch-size", "2", "--data-dir", self.data,
                                     "--results-dir", self.results] + list(extra))
        return code, out.getvalue()

    def metrics_path(self):
        return os.path.join(self.results, "prompted_vendor_m_free_metrics.json")

    def test_rate_limit_then_resume_writes_metrics(self):
        code, out = self.main(FakeClient(["good", "good", llm.RateLimited("busy")]))
        self.assertEqual(code, 1)
        self.assertIn("rate limited", out)
        self.assertIn("4 of 6 sentences done", out)
        self.assertNotIn("Traceback", out)
        self.assertTrue(os.path.exists(
            os.path.join(self.results, "raw", "prompted_vendor_m_free.jsonl")))
        self.assertFalse(os.path.exists(self.metrics_path()))

        client = FakeClient()
        code, out = self.main(client)
        self.assertEqual(code, 0)
        self.assertEqual(len(client.requests), 1)
        with open(self.metrics_path()) as fh:
            saved = json.load(fh)
        self.assertEqual(saved["model"], "vendor/m:free")
        self.assertEqual(saved["temperature"], 0)
        self.assertEqual(saved["failed_sentences"], 0)
        self.assertAlmostEqual(saved["metrics"]["micro"]["f1"], 1.0)
        self.assertAlmostEqual(saved["metrics"]["exact_match"], 1.0)
        self.assertIn("micro:", out)

    def test_failed_batches_score_as_empty(self):
        code, out = self.main(FakeClient(["garbage", "garbage"]))
        self.assertEqual(code, 0)
        with open(self.metrics_path()) as fh:
            saved = json.load(fh)
        self.assertEqual(saved["failed_sentences"], 2)
        self.assertEqual(saved["metrics"]["micro"]["fn"], 1)  # e1's T1001 missed

    def test_missing_eval_set(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = self.script.main(["eval_prompted.py", "--data-dir",
                                     os.path.join(self._tmp.name, "nope")])
        self.assertEqual(code, 1)
        self.assertIn("prepare_tram_data.py", out.getvalue())

    def raw_records(self):
        return pm.read_records(os.path.join(self.results, "raw", "prompted_vendor_m_free.jsonl"))

    def test_length_failure_prints_reason_and_stores_attempts(self):
        client, fake = reasoning_client()
        code, out = self.main(client, "--max-batches", "1")
        self.assertEqual(code, 0)
        self.assertIn("batch 1: model ran out of length budget (raise --max-tokens)", out)
        self.assertNotIn("Traceback", out)
        rec = self.raw_records()[0]
        self.assertEqual(rec["status"], "failed")
        self.assertEqual(rec["raw"], ["", ""])
        self.assertEqual(rec["max_tokens"], 16000)
        self.assertEqual(len(rec["attempts"]), 2)
        for attempt in rec["attempts"]:
            self.assertEqual(attempt["finish_reason"], "length")
            self.assertEqual(attempt["empty_reason"], "length")
            self.assertEqual(attempt["completion_tokens"], 32000)  # after the doubled retry
            self.assertEqual(attempt["reasoning_tokens"], 32000)

    def test_garbage_failure_prints_no_length_reason(self):
        code, out = self.main(FakeClient(["garbage", "garbage"]))
        self.assertEqual(code, 0)
        self.assertNotIn("length budget", out)

    def test_max_tokens_flag(self):
        client = FakeClient()
        code, out = self.main(client, "--max-tokens", "500")
        self.assertEqual(code, 0)
        self.assertEqual({r["max_tokens"] for r in client.requests}, {500})
        self.assertIn("max_tokens=500", out)
        with open(self.metrics_path()) as fh:
            self.assertEqual(json.load(fh)["max_tokens"], 500)
        self.assertTrue(all(r["max_tokens"] == 500 for r in self.raw_records()))

    def test_bad_flag_values_stop(self):
        for flag in ("--max-tokens", "--max-batches", "--batch-size"):
            code, out = self.main(FakeClient(), flag, "0")
            self.assertEqual(code, 1, flag)
            self.assertIn("{f} must be at least 1".format(f=flag), out)

    def test_max_batches_sends_one_batch_and_does_not_score(self):
        client = FakeClient()
        code, out = self.main(client, "--max-batches", "1")
        self.assertEqual(code, 0)
        self.assertEqual(len(client.requests), 1)
        self.assertIn("Stopped after --max-batches 1. 2 of 6 sentences done", out)
        self.assertFalse(os.path.exists(self.metrics_path()))

        rest = FakeClient()  # a later full run resumes after that batch
        code, out = self.main(rest)
        self.assertEqual(code, 0)
        self.assertEqual(len(rest.requests), 2)
        self.assertTrue(os.path.exists(self.metrics_path()))

    def test_retry_failed_redoes_only_failed_batches(self):
        # batch 1 ok, batch 2 fails twice, batch 3 ok
        code, out = self.main(FakeClient(["good", "garbage", "garbage", "good"]))
        self.assertEqual(code, 0)
        with open(self.metrics_path()) as fh:
            self.assertEqual(json.load(fh)["failed_sentences"], 2)

        retry = FakeClient()
        code, out = self.main(retry, "--retry-failed")
        self.assertEqual(code, 0)
        self.assertEqual(retry.sent_ids(), [["Then T1002 happened.", "Also nothing."]])
        with open(self.metrics_path()) as fh:
            saved = json.load(fh)
        self.assertEqual(saved["failed_sentences"], 0)
        self.assertAlmostEqual(saved["metrics"]["micro"]["f1"], 1.0)

    def test_router_model_warns(self):
        code, out = self.main_with_model(FakeClient(), "openrouter/free")
        self.assertEqual(code, 0)
        self.assertIn("may not be reproducible", out)

    def main_with_model(self, client, model):
        out = io.StringIO()
        with mock.patch.object(llm, "make_client", return_value=client), \
             contextlib.redirect_stdout(out):
            code = self.script.main(["eval_prompted.py", "--model", model,
                                     "--data-dir", self.data, "--results-dir", self.results])
        return code, out.getvalue()


if __name__ == "__main__":
    unittest.main()
