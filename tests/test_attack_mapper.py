"""
Offline tests for the ATT&CK mapper model loader. torch and transformers are
never imported: a small fake backend stands in for them.

    python3 -m unittest discover -s tests -v
"""

import contextlib
import hashlib
import json
import math
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace as NS
from unittest import mock

from reconmind.ai import attack_mapper

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LABELS = ["T1190", "T1059", "T1021"]
WEIGHTS = b"fake safetensors bytes"
METRICS = {"run_name": "run3", "threshold": 0.85, "max_length": 256}


def write_model_dir(folder, labels=LABELS, config_labels=None, metrics=METRICS, skip=()):
    """The files the run 3 notebook saves, with fake weights."""
    config_labels = labels if config_labels is None else config_labels
    files = {
        "config.json": json.dumps({"id2label": {str(i): lab
                                                for i, lab in enumerate(config_labels)}}),
        "tokenizer_config.json": "{}",
        "labels.json": json.dumps([{"id": lab, "name": lab} for lab in labels]),
        attack_mapper.METRICS_NAME: metrics if isinstance(metrics, str) else json.dumps(metrics),
    }
    for name, text in files.items():
        if name not in skip:
            with open(os.path.join(folder, name), "w") as fh:
                fh.write(text)
    if "model.safetensors" not in skip:
        with open(os.path.join(folder, "model.safetensors"), "wb") as fh:
            fh.write(WEIGHTS)


def logit(p):
    return math.log(p / (1 - p))


class FakeTensor:
    def __init__(self, rows):
        self.rows = rows

    def float(self):
        return self

    def tolist(self):
        return [list(r) for r in self.rows]


class FakeTorch:
    @staticmethod
    def no_grad():
        return contextlib.nullcontext()

    @staticmethod
    def sigmoid(tensor):
        return FakeTensor([[1 / (1 + math.exp(-x)) for x in row] for row in tensor.rows])


class FakeTokenizer:
    def __init__(self):
        self.calls = []

    def __call__(self, texts, **kwargs):
        self.calls.append(dict(kwargs, count=len(texts)))
        return {"texts": list(texts)}


class FakeModel:
    def __init__(self, labels, probs_by_text=None):
        self.config = NS(id2label=dict(enumerate(labels)), num_labels=len(labels))
        self.probs_by_text = probs_by_text or {}
        self.device = None
        self.evaluated = False

    def to(self, device):
        self.device = device
        return self

    def eval(self):
        self.evaluated = True
        return self

    def __call__(self, texts):
        default = [0.1] * self.config.num_labels
        return NS(logits=FakeTensor([[logit(p) for p in self.probs_by_text.get(t, default)]
                                     for t in texts]))


def fake_backend(model, tokenizer, calls, error=None):
    """An _import_backend replacement returning a fake torch and transformers."""
    def from_tokenizer(path, **kwargs):
        calls.append(("tokenizer", path, kwargs))
        return tokenizer

    def from_model(path, **kwargs):
        calls.append(("model", path, kwargs))
        if error:
            raise error
        return model

    transformers = NS(AutoTokenizer=NS(from_pretrained=from_tokenizer),
                      AutoModelForSequenceClassification=NS(from_pretrained=from_model))
    return lambda: (FakeTorch, transformers)


class LoaderTests(unittest.TestCase):

    def setUp(self):
        attack_mapper.clear_cache()
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name

    def tearDown(self):
        attack_mapper.clear_cache()
        self._tmp.cleanup()

    def load_with(self, model, tokenizer=None, error=None):
        calls = []
        with mock.patch.object(attack_mapper, "_import_backend",
                               fake_backend(model, tokenizer or FakeTokenizer(), calls, error)):
            return attack_mapper.load(self.dir), calls

    def test_default_folder_is_under_the_repo_root(self):
        with mock.patch.dict(os.environ):
            os.environ.pop(attack_mapper.DIR_ENV, None)
            self.assertEqual(attack_mapper.model_dir(),
                             os.path.join(REPO_ROOT, "models", "attack_mapper_run3"))

    def test_env_var_sets_the_folder(self):
        with mock.patch.dict(os.environ, {attack_mapper.DIR_ENV: self.dir}):
            self.assertEqual(attack_mapper.model_dir(), os.path.abspath(self.dir))
            predictor = attack_mapper.load()
        self.assertEqual(predictor.directory, os.path.abspath(self.dir))
        self.assertEqual(predictor.status, attack_mapper.STATUS_MODEL_MISSING)

    def test_empty_folder_is_model_missing(self):
        predictor = attack_mapper.load(self.dir)
        self.assertEqual(predictor.status, "model-missing")
        for name in attack_mapper.REQUIRED_FILES:
            self.assertIn(name, predictor.error)
        with self.assertRaises(RuntimeError):
            predictor.predict(["text"])

    def test_one_missing_file_is_model_missing(self):
        write_model_dir(self.dir, skip=("model.safetensors",))
        predictor = attack_mapper.load(self.dir)
        self.assertEqual(predictor.status, "model-missing")
        self.assertIn("model.safetensors", predictor.error)
        self.assertNotIn("labels.json", predictor.error)

    def test_unreadable_metrics_is_model_missing(self):
        write_model_dir(self.dir, metrics="not json")
        self.assertEqual(attack_mapper.load(self.dir).status, "model-missing")

    def test_label_order_is_checked_against_config_before_torch(self):
        write_model_dir(self.dir, config_labels=list(reversed(LABELS)))
        backend = mock.Mock()
        with mock.patch.object(attack_mapper, "_import_backend", backend):
            predictor = attack_mapper.load(self.dir)
        backend.assert_not_called()
        self.assertEqual(predictor.status, "label-mismatch")
        self.assertEqual(predictor.error, attack_mapper.LABEL_MISMATCH_CONFIG)
        self.assertEqual((predictor.run_name, predictor.threshold, predictor.max_length),
                         ("run3", 0.85, 256))
        self.assertEqual(predictor.sha256, hashlib.sha256(WEIGHTS).hexdigest())

    def test_label_order_is_checked_against_the_loaded_model(self):
        write_model_dir(self.dir)
        predictor, _ = self.load_with(FakeModel(list(reversed(LABELS))))
        self.assertEqual(predictor.status, "label-mismatch")
        self.assertEqual(predictor.error, attack_mapper.LABEL_MISMATCH_MODEL)

    def test_not_installed_when_the_import_fails(self):
        write_model_dir(self.dir)
        with mock.patch.object(attack_mapper, "_import_backend",
                               side_effect=ImportError("No module named 'torch'")):
            predictor = attack_mapper.load(self.dir)
        self.assertEqual(predictor.status, "not-installed")
        self.assertIn("torch", predictor.error)
        self.assertEqual(predictor.run_name, "run3")
        self.assertEqual(predictor.threshold, 0.85)
        self.assertEqual(predictor.sha256, hashlib.sha256(WEIGHTS).hexdigest())

    def test_not_installed_with_the_real_import_blocked(self):
        write_model_dir(self.dir)
        with mock.patch.dict(sys.modules, {"torch": None, "transformers": None}):
            predictor = attack_mapper.load(self.dir)
        self.assertEqual(predictor.status, "not-installed")

    def test_load_failure_is_model_missing(self):
        write_model_dir(self.dir)
        predictor, _ = self.load_with(FakeModel(LABELS), error=OSError("bad weights"))
        self.assertEqual(predictor.status, "model-missing")
        self.assertIn("bad weights", predictor.error)

    def test_ok_loads_local_files_on_cpu(self):
        write_model_dir(self.dir)
        model = FakeModel(LABELS)
        predictor, calls = self.load_with(model)
        self.assertEqual(predictor.status, "ok")
        self.assertEqual(predictor.labels, LABELS)
        self.assertEqual(predictor.sha256, hashlib.sha256(WEIGHTS).hexdigest())
        self.assertEqual([c[0] for c in calls], ["tokenizer", "model"])
        for _, path, kwargs in calls:
            self.assertEqual(path, os.path.abspath(self.dir))
            self.assertTrue(kwargs.get("local_files_only"))
        self.assertEqual(model.device, "cpu")
        self.assertTrue(model.evaluated)

    def test_predict_returns_every_technique_at_or_above_half(self):
        write_model_dir(self.dir)
        tokenizer = FakeTokenizer()
        model = FakeModel(LABELS, {"a": [0.6, 0.9, 0.3], "b": [0.2, 0.1, 0.49]})
        predictor, _ = self.load_with(model, tokenizer)
        hits = predictor.predict(["a", "b"])
        self.assertEqual([[h[0] for h in row] for row in hits], [["T1059", "T1190"], []])
        self.assertAlmostEqual(hits[0][0][1], 0.9)
        self.assertAlmostEqual(hits[0][1][1], 0.6)
        self.assertEqual(tokenizer.calls[0]["max_length"], 256)
        self.assertTrue(tokenizer.calls[0]["truncation"])

    def test_predict_runs_in_batches(self):
        write_model_dir(self.dir)
        tokenizer = FakeTokenizer()
        predictor, _ = self.load_with(FakeModel(LABELS), tokenizer)
        self.assertEqual(len(predictor.predict(["x"] * 20)), 20)
        self.assertEqual([c["count"] for c in tokenizer.calls], [16, 4])

    def test_each_folder_is_loaded_once(self):
        with mock.patch.object(attack_mapper, "_load", wraps=attack_mapper._load) as load:
            first = attack_mapper.load(self.dir)
            second = attack_mapper.load(self.dir)
        self.assertIs(first, second)
        load.assert_called_once()

    def test_labels_may_be_plain_ids(self):
        path = os.path.join(self.dir, "labels.json")
        with open(path, "w") as fh:
            json.dump(["T1190", {"id": "T1059"}], fh)
        self.assertEqual(attack_mapper.read_labels(path), ["T1190", "T1059"])


if __name__ == "__main__":
    unittest.main()
