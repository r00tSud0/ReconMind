"""
ReconMind ATT&CK mapper model.

Loads the fine tuned SciBERT model from training run 3
(evaluation/notebooks/train_attack_mapper_run3.ipynb) and predicts MITRE
ATT&CK technique IDs for finding text. The model folder holds the files that
notebook saved:

    config.json and model.safetensors      the model
    tokenizer_config.json and the rest     the tokenizer
    labels.json                            technique IDs in output order
    finetuned_scibert_run3_metrics.json    run name, threshold and max length

The folder is RECONMIND_MAPPER_DIR, or models/attack_mapper_run3 under the
repo root. load() returns a Predictor whose status is one of:

    ok              the model is loaded and predict() works
    not-installed   torch or transformers is not installed
    model-missing   a required file is missing or unreadable, or the model
                    could not be loaded
    label-mismatch  labels.json is not in the model's id2label order, so a
                    score could be read under the wrong technique ID

The label order is checked twice, as the prediction notebook does: against
config.json before torch is imported, and against the loaded model.

torch and transformers are optional. They are imported only inside the
loader, so ReconMind and its tests run without them; then only rule mappings
are made. Inference runs on the CPU, files are only read from the folder and
never downloaded, and each folder is loaded once per run and cached.
"""

import hashlib
import json
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DIR_ENV = "RECONMIND_MAPPER_DIR"
DEFAULT_DIR = os.path.join(REPO_ROOT, "models", "attack_mapper_run3")

CONFIG_NAME = "config.json"
WEIGHTS_NAME = "model.safetensors"
TOKENIZER_NAME = "tokenizer_config.json"
LABELS_NAME = "labels.json"
METRICS_NAME = "finetuned_scibert_run3_metrics.json"
REQUIRED_FILES = (CONFIG_NAME, WEIGHTS_NAME, TOKENIZER_NAME, LABELS_NAME, METRICS_NAME)

STATUS_OK = "ok"
STATUS_NOT_INSTALLED = "not-installed"
STATUS_MODEL_MISSING = "model-missing"
STATUS_LABEL_MISMATCH = "label-mismatch"

# predict() returns every technique at or above this probability. Only those
# at or above the model's own threshold count as mappings (see mapping.py).
SUGGESTION_FLOOR = 0.50
BATCH_SIZE = 16

LABEL_MISMATCH_CONFIG = "labels.json order does not match id2label in config.json"
LABEL_MISMATCH_MODEL = "labels.json order does not match the loaded model's id2label"

_CACHE = {}


def model_dir():
    """The model folder: RECONMIND_MAPPER_DIR, or the default under the repo root."""
    return os.path.abspath(os.environ.get(DIR_ENV) or DEFAULT_DIR)


class Predictor:
    """One model folder, loaded or not. predict() needs status ok."""

    def __init__(self, status, directory, error="", run_name="", threshold=None,
                 max_length=None, sha256="", labels=(), backend=None):
        self.status = status
        self.directory = directory
        self.error = error
        self.run_name = run_name
        self.threshold = threshold
        self.max_length = max_length
        self.sha256 = sha256
        self.labels = list(labels)
        self._backend = backend  # (torch, tokenizer, model) when status is ok

    def predict(self, texts):
        """
        For each text, [(technique ID, probability)] for every technique with
        probability SUGGESTION_FLOOR or higher, highest first. CPU only.
        """
        if self.status != STATUS_OK:
            raise RuntimeError("The ATT&CK mapper model is not loaded (status {s}).".format(
                s=self.status))
        torch, tokenizer, model = self._backend
        texts = list(texts)
        results = []
        with torch.no_grad():
            for start in range(0, len(texts), BATCH_SIZE):
                batch = tokenizer(texts[start:start + BATCH_SIZE], truncation=True,
                                  max_length=self.max_length, padding=True,
                                  return_tensors="pt")
                logits = model(**batch).logits
                for row in torch.sigmoid(logits.float()).tolist():
                    hits = [(label, prob) for label, prob in zip(self.labels, row)
                            if prob >= SUGGESTION_FLOOR]
                    hits.sort(key=lambda hit: (-hit[1], hit[0]))
                    results.append(hits)
        return results


def _import_backend():
    """torch and transformers, imported only here. Raises ImportError."""
    import torch
    import transformers
    return torch, transformers


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path):
    with open(path) as fh:
        return json.load(fh)


def read_labels(path):
    """Technique IDs from labels.json, in order. Entries are {"id": ...} or plain IDs."""
    data = _read_json(path)
    if not isinstance(data, list):
        raise ValueError("labels.json does not hold a list")
    return [str(t["id"] if isinstance(t, dict) else t) for t in data]


def config_label_order(path):
    """The id2label order stored in config.json, or [] if it has none or has gaps."""
    id2label = _read_json(path).get("id2label") or {}
    try:
        return [str(id2label[str(i)]) for i in range(len(id2label))]
    except KeyError:
        return []


def _model_label_order(model):
    """The loaded model's id2label order, or [] if it cannot be read."""
    try:
        id2label = model.config.id2label
        return [str(id2label[i]) for i in range(model.config.num_labels)]
    except (AttributeError, KeyError, TypeError):
        return []


def _load(directory):
    """A Predictor for one folder. Never raises."""
    missing = [n for n in REQUIRED_FILES if not os.path.isfile(os.path.join(directory, n))]
    if missing:
        return Predictor(STATUS_MODEL_MISSING, directory,
                         error="missing from {d}: {m}".format(d=directory, m=", ".join(missing)))
    try:
        metrics = _read_json(os.path.join(directory, METRICS_NAME))
        info = {
            "run_name": str(metrics.get("run_name") or ""),
            "threshold": float(metrics["threshold"]),
            "max_length": int(metrics["max_length"]),
            "labels": read_labels(os.path.join(directory, LABELS_NAME)),
            "sha256": _sha256(os.path.join(directory, WEIGHTS_NAME)),
        }
        config_order = config_label_order(os.path.join(directory, CONFIG_NAME))
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        return Predictor(STATUS_MODEL_MISSING, directory,
                         error="unreadable model file in {d}: {e}".format(d=directory, e=exc))

    if not info["labels"] or config_order != info["labels"]:
        return Predictor(STATUS_LABEL_MISMATCH, directory, error=LABEL_MISMATCH_CONFIG, **info)

    try:
        torch, transformers = _import_backend()
    except ImportError as exc:
        return Predictor(STATUS_NOT_INSTALLED, directory,
                         error="torch or transformers is not installed: {e}".format(e=exc),
                         **info)

    try:
        tokenizer = transformers.AutoTokenizer.from_pretrained(directory, local_files_only=True)
        model = transformers.AutoModelForSequenceClassification.from_pretrained(
            directory, local_files_only=True)
        model.to("cpu")
        model.eval()
    except Exception as exc:  # any loading failure means no usable model
        return Predictor(STATUS_MODEL_MISSING, directory,
                         error="the model could not be loaded: {e}".format(e=exc), **info)

    if _model_label_order(model) != info["labels"]:
        return Predictor(STATUS_LABEL_MISMATCH, directory, error=LABEL_MISMATCH_MODEL, **info)
    return Predictor(STATUS_OK, directory, backend=(torch, tokenizer, model), **info)


def load(directory=None):
    """
    The Predictor for a model folder (default model_dir()). Each folder is
    loaded once per run and cached, a failed load too, so a missing model is
    not searched for again on every call.
    """
    directory = os.path.abspath(directory) if directory else model_dir()
    if directory not in _CACHE:
        _CACHE[directory] = _load(directory)
    return _CACHE[directory]


def clear_cache():
    """Forget every loaded folder. For tests."""
    _CACHE.clear()
