"""
Offline tests for evaluation/scripts/score_reconmind_exam.py. A fake client
stands in for the provider and every file lives in a temp folder:

    python3 -m unittest evaluation.tests.test_score_reconmind_exam -v
"""

import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from reconmind.agent import llm
from evaluation.tests.test_prompted_mapper import FakeClient

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "scripts", "score_reconmind_exam.py")

TABLE = [{"id": "T1001", "name": "Data Obfuscation"},
         {"id": "T1002", "name": "Data Compressed"}]

# Each finding names the TRAM IDs the fake model will "answer". f1's gold also
# has T9001, which is outside the TRAM table.
FINDINGS = [
    {"id": "f1", "text": "Uses T1001 here."},
    {"id": "f2", "text": "Nothing to see."},
    {"id": "f3", "text": "Then T1002 happened."},
]
GOLD = [
    {"id": "f1", "labels": ["T1001", "T9001"], "rule": "test"},
    {"id": "f2", "labels": [], "rule": "test"},
    {"id": "f3", "labels": ["T1002"], "rule": "test"},
]
# Model B: f1 right, f2 a false positive, f3 missed.
MODEL_B = {"f1": ["T1001"], "f2": ["T1002"], "f3": []}

MODEL = "vendor/m:free"
RAW_A = "prompted_vendor_m_free_reconmind_exam.jsonl"
RAW_A_RUN3 = "prompted_vendor_m_free_reconmind_exam_run3labels.jsonl"
DEFAULT_METRICS = "reconmind_exam_metrics_run2_tram50.json"

# A run 3 label table: TRAM's two IDs plus one only run 3 has.
RUN3_TABLE = TABLE + [{"id": "T7777", "name": "Run Three Only"}]
# Model B run 3's label set, from the header line of its raw file.
RUN3_B_LABELS = ["T1001", "T1002", "T5555"]


def load_script():
    spec = importlib.util.spec_from_file_location("score_reconmind_exam", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_jsonl(path, rows):
    with open(path, "w") as fh:
        fh.write("".join(json.dumps(r) + "\n" for r in rows))


class ScoreExamTests(unittest.TestCase):

    def setUp(self):
        self.script = load_script()
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)  # no .env is read
        self._env = mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "k"}, clear=True)
        self._env.start()
        self.data = os.path.join(self._tmp.name, "exam")
        self.tram = os.path.join(self._tmp.name, "tram")
        self.run3 = os.path.join(self._tmp.name, "run3")
        self.results = os.path.join(self._tmp.name, "results")
        for d in (self.data, self.tram, self.run3, os.path.join(self.results, "raw")):
            os.makedirs(d)
        write_jsonl(os.path.join(self.data, "findings.jsonl"), FINDINGS)
        write_jsonl(os.path.join(self.data, "labels.jsonl"), GOLD)
        with open(os.path.join(self.tram, "labels.json"), "w") as fh:
            json.dump(TABLE, fh)
        with open(os.path.join(self.run3, "labels.json"), "w") as fh:
            json.dump(RUN3_TABLE, fh)
        with open(os.path.join(self.results, "finetuned_scibert_run2_metrics.json"), "w") as fh:
            json.dump({"model": "allenai/scibert_scivocab_uncased", "run_name": "run2",
                       "threshold": 0.65, "max_length": 512}, fh)

    def tearDown(self):
        self._env.stop()
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def write_model_b(self, run="run2", preds=MODEL_B, labels=None, n_probs=None):
        """Model B raw file; labels adds a header line, n_probs sets each probs length."""
        width = n_probs if n_probs is not None else len(labels or TABLE)
        rows = [{"labels": labels, "run_name": run}] if labels is not None else []
        rows += [{"id": i, "pred": p, "probs": [0.0] * width} for i, p in preds.items()]
        write_jsonl(os.path.join(self.results, "raw",
                                 "finetuned_scibert_{r}_reconmind_exam.jsonl".format(r=run)),
                    rows)

    def write_run3_b_metrics(self):
        with open(os.path.join(self.results, "finetuned_scibert_run3_metrics.json"), "w") as fh:
            json.dump({"model": "allenai/scibert_scivocab_uncased", "run_name": "run3",
                       "threshold": 0.4, "max_length": 256}, fh)

    def main(self, client, *extra):
        out = io.StringIO()
        with mock.patch.object(llm, "make_client", return_value=client) as make, \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = self.script.main(["score_reconmind_exam.py", "--model", MODEL,
                                     "--data-dir", self.data, "--tram-dir", self.tram,
                                     "--run3-dir", self.run3,
                                     "--results-dir", self.results] + list(extra))
        self.make_client = make
        return code, out.getvalue()

    def saved(self, name=DEFAULT_METRICS):
        with open(os.path.join(self.results, name)) as fh:
            return json.load(fh)

    def exists(self, *parts):
        return os.path.exists(os.path.join(self.results, *parts))

    @staticmethod
    def technique_ids(res):
        return {r["id"] for r in res["per_technique"]}

    def assertScores(self, res, p, r, f1, macro_f1, exact):
        self.assertAlmostEqual(res["micro"]["precision"], p)
        self.assertAlmostEqual(res["micro"]["recall"], r)
        self.assertAlmostEqual(res["micro"]["f1"], f1)
        self.assertAlmostEqual(res["macro"]["f1"], macro_f1)
        self.assertAlmostEqual(res["exact_match"], exact)

    def test_both_scorings_on_known_answers(self):
        self.write_model_b()
        code, out = self.main(FakeClient())
        self.assertEqual(code, 0)
        saved = self.saved()

        a = saved["model_a"]
        self.assertEqual(a["model"], MODEL)
        self.assertEqual(a["temperature"], 0)
        self.assertEqual(a["max_tokens"], 16000)
        # A predicts f1 [T1001], f2 [], f3 [T1002]; it misses only T9001.
        self.assertScores(a["scores"]["all_labels"], 1.0, 2 / 3, 0.8, 2 / 3, 2 / 3)
        self.assertScores(a["scores"]["tram50_only"], 1.0, 1.0, 1.0, 1.0, 1.0)

        b = saved["model_b"]
        self.assertEqual(b["threshold"], 0.65)
        self.assertEqual(b["model"], "allenai/scibert_scivocab_uncased")
        self.assertScores(b["scores"]["all_labels"], 0.5, 1 / 3, 0.4, 1 / 3, 0.0)
        self.assertScores(b["scores"]["tram50_only"], 0.5, 0.5, 0.5, 0.5, 1 / 3)
        # Run 2's raw file has no header, so its label set is TRAM's 50.
        self.assertEqual(b["label_set_from"], "TRAM 50 (raw file has no labels header)")
        self.assertEqual(b["label_set_size"], 2)

        self.assertEqual(saved["model_b_run"], "run2")
        self.assertEqual(saved["model_a_labels"], "tram50")
        self.assertEqual(a["label_table"], "TRAM 50")
        self.assertFalse(self.exists("reconmind_exam_metrics.json"))
        self.assertTrue(self.exists("raw", RAW_A))

        self.assertEqual(saved["per_finding"], [
            {"id": "f1", "gold": ["T1001", "T9001"], "model_a": ["T1001"], "model_b": ["T1001"]},
            {"id": "f2", "gold": [], "model_a": [], "model_b": ["T1002"]},
            {"id": "f3", "gold": ["T1002"], "model_a": ["T1002"], "model_b": []},
        ])
        for word in ("micro F1", "macro F1", "all_labels", "tram50_only", "Model A", "Model B"):
            self.assertIn(word, out)
        self.assertNotIn("—", out)
        self.assertNotIn("--------", out)

    def test_gold_outside_tram_counted_then_dropped(self):
        code, out = self.main(FakeClient())
        self.assertEqual(code, 0)
        saved = self.saved()
        self.assertEqual(saved["gold"], {"gold_labels": 3, "outside_tram50": 1,
                                         "ids": {"T9001": 1}})
        self.assertIn("3 total, 1 outside TRAM's 50 (T9001)", out)

        all_labels = saved["model_a"]["scores"]["all_labels"]
        rows = {r["id"]: r for r in all_labels["per_technique"]}
        self.assertEqual(rows["T9001"]["support"], 1)
        self.assertEqual(rows["T9001"]["fn"], 1)
        self.assertEqual(all_labels["micro"]["fn"], 1)

        tram50 = saved["model_a"]["scores"]["tram50_only"]
        self.assertNotIn("T9001", {r["id"] for r in tram50["per_technique"]})
        self.assertEqual(tram50["micro"]["fn"], 0)

    def test_missing_model_b_file_gives_clear_message(self):
        code, out = self.main(FakeClient())
        self.assertEqual(code, 0)
        self.assertIn("finetuned_scibert_run2_reconmind_exam.jsonl not found", out)
        self.assertIn("Run evaluation/notebooks/predict_reconmind_exam.ipynb in Colab first", out)
        saved = self.saved()
        self.assertIsNone(saved["model_b"])
        self.assertTrue(all(r["model_b"] is None for r in saved["per_finding"]))
        self.assertIsNotNone(saved["model_a"])

    def test_skip_model_a_makes_no_api_calls(self):
        self.write_model_b()
        client = FakeClient()
        code, out = self.main(client, "--skip-model-a")
        self.assertEqual(code, 0)
        self.make_client.assert_not_called()
        self.assertEqual(client.requests, [])
        self.assertIn("no raw file yet", out)
        self.assertIsNone(self.saved()["model_a"])
        self.assertIsNotNone(self.saved()["model_b"])

        self.main(FakeClient())  # answer every finding once
        later = FakeClient()
        code, out = self.main(later, "--skip-model-a")
        self.assertEqual(code, 0)
        self.make_client.assert_not_called()
        self.assertEqual(later.requests, [])
        self.assertAlmostEqual(
            self.saved()["model_a"]["scores"]["tram50_only"]["micro"]["f1"], 1.0)

    def test_skip_model_a_needs_no_key(self):
        self.write_model_b()
        with mock.patch.dict(os.environ, {}, clear=True):
            code, out = self.main(FakeClient(), "--skip-model-a")
        self.assertEqual(code, 0)
        self.make_client.assert_not_called()

    def test_resume_skips_findings_already_answered(self):
        first = FakeClient(["good", llm.RateLimited("busy")])
        code, out = self.main(first, "--batch-size", "1")
        self.assertEqual(code, 1)
        self.assertIn("rate limited", out)
        self.assertIn("1 of 3 findings done", out)
        self.assertNotIn("Traceback", out)
        self.assertTrue(self.exists("raw", RAW_A))
        self.assertFalse(self.exists(DEFAULT_METRICS))

        second = FakeClient()
        code, out = self.main(second, "--batch-size", "1")
        self.assertEqual(code, 0)
        self.assertEqual(second.sent_ids(), [["Nothing to see."], ["Then T1002 happened."]])
        self.assertAlmostEqual(
            self.saved()["model_a"]["scores"]["all_labels"]["micro"]["f1"], 0.8)

        third = FakeClient()
        self.main(third, "--batch-size", "1")
        self.assertEqual(third.requests, [])

    # Tests for the model b run flag.

    def test_model_b_run3_reads_its_own_raw_and_metrics_files(self):
        # Run 2's file predicts nothing; if it were read, f1 would score 0.
        self.write_model_b("run2", preds={i: [] for i in MODEL_B})
        self.write_model_b("run3", labels=RUN3_B_LABELS)
        self.write_run3_b_metrics()
        code, out = self.main(FakeClient(), "--skip-model-a", "--model-b-run", "run3")
        self.assertEqual(code, 0, out)
        self.assertFalse(self.exists(DEFAULT_METRICS))
        saved = self.saved("reconmind_exam_metrics_run3_tram50.json")
        self.assertEqual(saved["model_b_run"], "run3")
        b = saved["model_b"]
        self.assertEqual(b["threshold"], 0.4)
        self.assertEqual(b["run_name"], "run3")
        self.assertEqual(b["max_length"], 256)
        self.assertTrue(b["raw_file"].endswith("finetuned_scibert_run3_reconmind_exam.jsonl"))
        self.assertTrue(b["threshold_from"].endswith("finetuned_scibert_run3_metrics.json"))
        self.assertEqual([r["model_b"] for r in saved["per_finding"]],
                         [MODEL_B["f1"], MODEL_B["f2"], MODEL_B["f3"]])
        self.assertScores(b["scores"]["tram50_only"], 0.5, 0.5, 0.5, 0.5, 1 / 3)

    def test_all_labels_is_tram_plus_model_b_labels_plus_gold(self):
        self.write_model_b("run3", labels=RUN3_B_LABELS)
        self.write_run3_b_metrics()
        code, out = self.main(FakeClient(), "--model-b-run", "run3")
        self.assertEqual(code, 0, out)
        saved = self.saved("reconmind_exam_metrics_run3_tram50.json")
        expected = {"T1001", "T1002", "T5555", "T9001"}  # TRAM, Model B's T5555, gold T9001
        self.assertEqual(saved["all_labels_size"], 4)
        self.assertEqual(saved["model_b"]["label_set_size"], 3)
        self.assertEqual(saved["model_b"]["label_set_from"], "raw file header")
        for model in ("model_a", "model_b"):
            scores = saved[model]["scores"]
            self.assertEqual(self.technique_ids(scores["all_labels"]), expected)
            self.assertEqual(self.technique_ids(scores["tram50_only"]), {"T1001", "T1002"})
        # T5555 has no gold support, so the headline numbers match the run 2 case.
        self.assertScores(saved["model_b"]["scores"]["all_labels"], 0.5, 1 / 3, 0.4, 1 / 3, 0.0)
        self.assertScores(saved["model_a"]["scores"]["all_labels"], 1.0, 2 / 3, 0.8, 2 / 3, 2 / 3)

    def test_model_b_header_must_match_probs_length(self):
        self.write_model_b("run3", labels=RUN3_B_LABELS, n_probs=2)
        code, out = self.main(FakeClient(), "--skip-model-a", "--model-b-run", "run3")
        self.assertEqual(code, 1)
        self.assertIn("has 2 probabilities but the header lists 3 labels", out)

    def test_missing_model_b_run3_file_names_the_run3_notebook(self):
        code, out = self.main(FakeClient(), "--model-b-run", "run3")
        self.assertEqual(code, 0)
        self.assertIn("finetuned_scibert_run3_reconmind_exam.jsonl not found", out)
        self.assertIn("evaluation/notebooks/train_attack_mapper_run3.ipynb", out)
        self.assertIsNone(self.saved("reconmind_exam_metrics_run3_tram50.json")["model_b"])

    def test_model_b_run_name_must_be_plain(self):
        code, _ = self.main(FakeClient(), "--model-b-run", "../run2")
        self.assertEqual(code, 1)

    # Tests for the model a labels flag.

    def test_model_a_run3_labels_use_the_run3_table_and_their_own_raw_file(self):
        self.write_model_b()
        client = FakeClient()
        code, out = self.main(client, "--model-a-labels", "run3")
        self.assertEqual(code, 0, out)
        self.assertTrue(client.requests)
        self.assertIn("T7777  Run Three Only", client.requests[0]["system"])
        self.assertTrue(self.exists("raw", RAW_A_RUN3))
        self.assertFalse(self.exists("raw", RAW_A))
        self.assertFalse(self.exists(DEFAULT_METRICS))
        saved = self.saved("reconmind_exam_metrics_run2_run3.json")
        self.assertEqual(saved["model_a_labels"], "run3")
        a = saved["model_a"]
        self.assertEqual(a["label_table"], "run3 (3 IDs)")
        self.assertTrue(a["raw_file"].endswith(RAW_A_RUN3))
        # Model A's own table is not part of all_labels: TRAM, Model B (TRAM 50), gold.
        self.assertEqual(self.technique_ids(a["scores"]["all_labels"]),
                         {"T1001", "T1002", "T9001"})
        self.assertScores(a["scores"]["tram50_only"], 1.0, 1.0, 1.0, 1.0, 1.0)

    def test_the_two_model_a_raw_files_never_mix(self):
        self.main(FakeClient(), "--model-a-labels", "run3")
        tram_client = FakeClient()
        code, out = self.main(tram_client)  # tram50 must not resume from the run3 file
        self.assertEqual(code, 0, out)
        self.assertTrue(tram_client.requests)
        self.assertNotIn("T7777", tram_client.requests[0]["system"])
        self.assertTrue(self.exists("raw", RAW_A))
        self.assertTrue(self.exists("raw", RAW_A_RUN3))

        again = FakeClient()
        self.main(again, "--model-a-labels", "run3")  # resumes from its own file
        self.assertEqual(again.requests, [])
        self.assertTrue(self.exists(DEFAULT_METRICS))
        self.assertTrue(self.exists("reconmind_exam_metrics_run2_run3.json"))

    def test_model_a_run3_labels_without_the_file_gives_clear_message(self):
        os.remove(os.path.join(self.run3, "labels.json"))
        client = FakeClient()
        code, out = self.main(client, "--model-a-labels", "run3")
        self.assertEqual(code, 1)
        self.assertIn("Cannot read the run 3 label table", out)
        self.assertIn("prepare_run3_data.py", out)
        self.assertEqual(client.requests, [])

    def test_unknown_model_a_labels_value_is_refused(self):
        client = FakeClient()
        code, _ = self.main(client, "--model-a-labels", "run9")
        self.assertEqual(code, 1)
        self.assertEqual(client.requests, [])


if __name__ == "__main__":
    unittest.main()
