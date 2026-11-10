"""
Score Model A (prompted LLM) and Model B (fine tuned SciBERT run 2) on the
ReconMind test set: evaluation/data/reconmind_eval/findings.jsonl with the
answer key in labels.jsonl.

    python3 evaluation/scripts/score_reconmind_exam.py [--provider NAME] [--model ID]
                                                       [--skip-model-a] [--batch-size 25]

Model A classifies every finding's text with prompted_mapper, using the same
50 TRAM technique table, temperature 0 and max tokens default as
eval_prompted.py. Finished batches are saved to
evaluation/results/raw/prompted_<model>_reconmind_exam.jsonl and the next run
resumes from it. --skip-model-a sends nothing and only scores raw files that
already exist.

Model B's predictions come from evaluation/notebooks/predict_reconmind_exam.ipynb,
saved as evaluation/results/raw/finetuned_scibert_run2_reconmind_exam.jsonl.
Its threshold and base model id are read from
evaluation/results/finetuned_scibert_run2_metrics.json.

Each model is scored two ways with metrics.score:
  all_labels   label set is the 50 TRAM IDs plus every ID in labels.jsonl.
  tram50_only  gold labels are filtered to the 50 TRAM IDs, label set is the 50.

Results go to evaluation/results/reconmind_exam_metrics.json.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from reconmind.agent import llm  # noqa: E402
from reconmind.agent.__main__ import MISSING_PACKAGE, _load_dotenv  # noqa: E402
from evaluation.attack_mapper import metrics, prompted_mapper  # noqa: E402

EXAM_DIR = os.path.join(REPO_ROOT, "evaluation", "data", "reconmind_eval")
TRAM_DIR = os.path.join(REPO_ROOT, "evaluation", "data", "tram")
RESULTS_DIR = os.path.join(REPO_ROOT, "evaluation", "results")
ROUTER_MODELS = {"openrouter/free"}

MODEL_B_RUN = "run2"
MODEL_B_RAW = "finetuned_scibert_run2_reconmind_exam.jsonl"
MODEL_B_METRICS = "finetuned_scibert_run2_metrics.json"
NOTEBOOK = "evaluation/notebooks/predict_reconmind_exam.ipynb"
SCORINGS = ("all_labels", "tram50_only")


def safe_name(model):
    # Same file naming as eval_prompted.py.
    return re.sub(r"[^A-Za-z0-9._-]", "_", model)


def _parse_args(args):
    parser = argparse.ArgumentParser(prog="python3 evaluation/scripts/score_reconmind_exam.py")
    parser.add_argument("--provider", help="one of: " + ", ".join(sorted(llm.PROVIDERS)))
    parser.add_argument("--model", help="model id for Model A")
    parser.add_argument("--skip-model-a", action="store_true",
                        help="send nothing, only score raw files that already exist")
    parser.add_argument("--batch-size", type=int, default=25,
                        help="findings per Model A request (default 25)")
    parser.add_argument("--data-dir", default=EXAM_DIR,
                        help="folder with findings.jsonl and labels.jsonl")
    parser.add_argument("--tram-dir", default=TRAM_DIR, help="folder with the TRAM labels.json")
    parser.add_argument("--results-dir", default=RESULTS_DIR, help="where results are written")
    return parser.parse_args(args)


# ---- inputs ----------------------------------------------------------------

def _read_jsonl_bytes(raw):
    return [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]


def load_exam(data_dir):
    """(findings, gold {id: labels}, findings sha256). Ids must match one to one."""
    with open(os.path.join(data_dir, "findings.jsonl"), "rb") as fh:
        raw = fh.read()
    findings = _read_jsonl_bytes(raw)
    with open(os.path.join(data_dir, "labels.jsonl"), "rb") as fh:
        answers = _read_jsonl_bytes(fh.read())
    gold = {a["id"]: sorted(set(a["labels"])) for a in answers}
    ids = [f["id"] for f in findings]
    if len(set(ids)) != len(ids):
        raise ValueError("findings.jsonl has duplicate ids")
    if set(ids) != set(gold) or len(answers) != len(gold):
        raise ValueError("findings.jsonl and labels.jsonl do not list the same finding ids")
    return findings, gold, hashlib.sha256(raw).hexdigest()


def load_tram_table(tram_dir):
    with open(os.path.join(tram_dir, "labels.json")) as fh:
        return json.load(fh)


def load_model_b(results_dir, finding_ids):
    """({id: pred list}, raw path), or (None, raw path) when the file is missing."""
    path = os.path.join(results_dir, "raw", MODEL_B_RAW)
    if not os.path.exists(path):
        return None, path
    preds = {}
    with open(path) as fh:
        for line in fh:
            if line.strip():
                rec = json.loads(line)
                preds[rec["id"]] = sorted(set(rec["pred"]))
    missing = sorted(set(finding_ids) - set(preds))
    if missing:
        raise ValueError("{p} has no prediction for {n} findings, for example {e}. "
                         "Run {nb} again.".format(p=path, n=len(missing), e=missing[:3],
                                                  nb=NOTEBOOK))
    return {i: preds[i] for i in finding_ids}, path


def load_model_b_info(results_dir):
    """Threshold and base model id from the run 2 training metrics, if present."""
    path = os.path.join(results_dir, MODEL_B_METRICS)
    try:
        with open(path) as fh:
            saved = json.load(fh)
    except (OSError, ValueError):
        return {"model": None, "run_name": MODEL_B_RUN, "threshold": None,
                "max_length": None, "info_file": None}
    return {"model": saved.get("model"), "run_name": saved.get("run_name", MODEL_B_RUN),
            "threshold": saved.get("threshold"), "max_length": saved.get("max_length"),
            "info_file": path}


# ---- scoring -----------------------------------------------------------------

def score_both(gold, pred, tram_ids):
    """{"all_labels": ..., "tram50_only": ...} from metrics.score."""
    tram = set(tram_ids)
    all_labels = sorted(tram | {lab for labs in gold.values() for lab in labs})
    gold_tram = {i: [lab for lab in labs if lab in tram] for i, labs in gold.items()}
    return {
        "all_labels": metrics.score(gold, pred, all_labels),
        "tram50_only": metrics.score(gold_tram, pred, sorted(tram)),
    }


def outside_tram(gold, tram_ids):
    tram = set(tram_ids)
    counts = Counter(lab for labs in gold.values() for lab in labs if lab not in tram)
    total = sum(len(labs) for labs in gold.values())
    return {"gold_labels": total, "outside_tram50": sum(counts.values()),
            "ids": dict(sorted(counts.items()))}


# ---- Model A -----------------------------------------------------------------

def _stopped(p, reason):
    print("{r}. {d} of {t} findings done ({f} failed). Run again later to resume.".format(
        r=reason, d=p["done"], t=p["total"], f=p["failed"]))


def _model_a_config(args):
    """(config or None, model id or None, error message or None)."""
    try:
        config = llm.load_config(provider=args.provider, model=args.model)
        return config, config.model, None
    except llm.ConfigError as exc:
        if args.skip_model_a:
            # No key is needed to score a file that already exists.
            model = args.model or os.environ.get("RECONMIND_MODEL")
            return None, model, None
        return None, None, str(exc)


def run_model_a(config, rows, table, exam_sha, raw_path, batch_size):
    """
    Classify findings not yet done. Returns (state, exit code or None).
    An exit code means stop now without writing metrics.
    """
    try:
        client = llm.make_client(config)
    except ImportError:
        print(MISSING_PACKAGE)
        return None, 1
    try:
        state = prompted_mapper.run(client, config.model, rows, table, raw_path,
                                    exam_sha, batch_size=batch_size,
                                    max_tokens=prompted_mapper.MAX_TOKENS)
    except prompted_mapper.MapperError as exc:
        print(exc)
        return None, 1
    except (llm.RateLimited, KeyboardInterrupt, Exception) as exc:
        state = prompted_mapper.sentence_state(prompted_mapper.read_records(raw_path))
        if isinstance(exc, llm.RateLimited):
            reason = "Stopped: rate limited"
        elif isinstance(exc, KeyboardInterrupt):
            reason = "Stopped by user"
        else:
            reason = "Stopped on error ({t}: {e})".format(t=type(exc).__name__, e=exc)
        _stopped(prompted_mapper.progress(rows, state), reason)
        return None, 1
    return state, None


def read_model_a(rows, exam_sha, raw_path):
    """State from an existing raw file, or None if there is none."""
    if not os.path.exists(raw_path):
        return None
    records = prompted_mapper.read_records(raw_path)
    prompted_mapper.check_records(records, exam_sha)
    return prompted_mapper.sentence_state(records)


# ---- output ------------------------------------------------------------------

def _fmt(x):
    return "{v:.3f}".format(v=x)


def print_table(models, outside):
    header = "{m:<9} {s:<12} {p:>8} {r:>8} {f:>8} {mf:>9} {e:>7}".format(
        m="model", s="scoring", p="micro P", r="micro R", f="micro F1", mf="macro F1",
        e="exact")
    print()
    print(header)
    for label, entry in models:
        if entry is None or entry.get("scores") is None:
            print("{m:<9} not scored".format(m=label))
            continue
        for name in SCORINGS:
            res = entry["scores"][name]
            mi = res["micro"]
            print("{m:<9} {s:<12} {p:>8} {r:>8} {f:>8} {mf:>9} {e:>7}".format(
                m=label, s=name, p=_fmt(mi["precision"]), r=_fmt(mi["recall"]),
                f=_fmt(mi["f1"]), mf=_fmt(res["macro"]["f1"]), e=_fmt(res["exact_match"])))
    print()
    print("gold labels: {t} total, {o} outside TRAM's 50{ids}".format(
        t=outside["gold_labels"], o=outside["outside_tram50"],
        ids=" ({i})".format(i=", ".join(outside["ids"])) if outside["ids"] else ""))


def main(argv):
    try:
        args = _parse_args(argv[1:])
    except SystemExit:
        return 1
    if args.batch_size < 1:
        print("--batch-size must be at least 1")
        return 1

    try:
        findings, gold, exam_sha = load_exam(args.data_dir)
    except (OSError, ValueError, KeyError) as exc:
        print("Cannot read the ReconMind test set in {d}: {e}".format(d=args.data_dir, e=exc))
        return 1
    try:
        table = load_tram_table(args.tram_dir)
    except (OSError, ValueError) as exc:
        print("Cannot read the TRAM label table in {d}: {e}".format(d=args.tram_dir, e=exc))
        print("Run python3 evaluation/scripts/prepare_tram_data.py first.")
        return 1
    tram_ids = [t["id"] for t in table]
    finding_ids = [f["id"] for f in findings]
    rows = [{"id": f["id"], "sentence": f["text"]} for f in findings]
    raw_dir = os.path.join(args.results_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)

    # Model A
    _load_dotenv()
    config, model_a_id, err = _model_a_config(args)
    if err:
        print(err)
        return 1
    model_a = None
    a_preds = None
    if model_a_id is None:
        print("Model A: no model id known, pass --model to score its raw file.")
    else:
        raw_a = os.path.join(raw_dir, "prompted_{m}_reconmind_exam.jsonl".format(
            m=safe_name(model_a_id)))
        print("Model A (prompted)  model={m}  batch={b}  max_tokens={t}{s}".format(
            m=model_a_id, b=args.batch_size, t=prompted_mapper.MAX_TOKENS,
            s="  (skip: scoring saved answers only)" if args.skip_model_a else ""))
        if model_a_id in ROUTER_MODELS:
            print("WARNING: {m} routes to different models between runs, so this result "
                  "may not be reproducible. Prefer a pinned model id.".format(m=model_a_id))
        print("raw results:", raw_a)
        if args.skip_model_a:
            try:
                state = read_model_a(rows, exam_sha, raw_a)
            except prompted_mapper.MapperError as exc:
                print(exc)
                return 1
            if state is None:
                print("Model A: no raw file yet, not scored. Run without --skip-model-a.")
        else:
            state, code = run_model_a(config, rows, table, exam_sha, raw_a, args.batch_size)
            if code is not None:
                return code
        if state is not None:
            p = prompted_mapper.progress(rows, state)
            if p["done"] < p["total"]:
                print("Model A: only {d} of {t} findings answered, not scored. "
                      "Run without --skip-model-a to finish.".format(d=p["done"], t=p["total"]))
            else:
                a_preds = prompted_mapper.predictions(rows, state)
                model_a = {
                    "model_kind": "prompted",
                    "provider": config.name if config else None,
                    "model": model_a_id,
                    "batch_size": args.batch_size,
                    "max_tokens": prompted_mapper.MAX_TOKENS,
                    "temperature": prompted_mapper.TEMPERATURE,
                    "label_table": "TRAM 50",
                    "failed_findings": p["failed"],
                    "raw_file": os.path.relpath(raw_a, REPO_ROOT),
                    "scores": score_both(gold, a_preds, tram_ids),
                }

    # Model B
    model_b = None
    try:
        b_preds, raw_b = load_model_b(args.results_dir, finding_ids)
    except (OSError, ValueError, KeyError) as exc:
        print("Model B: cannot read its predictions: {e}".format(e=exc))
        return 1
    if b_preds is None:
        print("Model B: {p} not found. Run {nb} in Colab first, then put the downloaded "
              "file in evaluation/results/raw/.".format(p=raw_b, nb=NOTEBOOK))
    else:
        info = load_model_b_info(args.results_dir)
        model_b = {
            "model_kind": "finetuned",
            "provider": "huggingface",
            "model": info["model"],
            "run_name": info["run_name"],
            "threshold": info["threshold"],
            "max_length": info["max_length"],
            "threshold_from": (os.path.relpath(info["info_file"], REPO_ROOT)
                               if info["info_file"] else None),
            "raw_file": os.path.relpath(raw_b, REPO_ROOT),
            "scores": score_both(gold, b_preds, tram_ids),
        }

    if model_a is None and model_b is None:
        print("Nothing to score.")
        return 1

    outside = outside_tram(gold, tram_ids)
    out = {
        "exam": "reconmind_eval",
        "findings_sha256": exam_sha,
        "n_findings": len(findings),
        "gold": outside,
        "scorings": {
            "all_labels": "label set is the 50 TRAM IDs plus every ID in labels.jsonl",
            "tram50_only": "gold filtered to the 50 TRAM IDs, label set is the 50",
        },
        "written": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "model_a": model_a,
        "model_b": model_b,
        "per_finding": [
            {"id": i, "gold": gold[i],
             "model_a": a_preds[i] if model_a else None,
             "model_b": b_preds[i] if model_b else None}
            for i in finding_ids
        ],
    }
    metrics_path = os.path.join(args.results_dir, "reconmind_exam_metrics.json")
    with open(metrics_path, "w") as fh:
        json.dump(out, fh, indent=1)
        fh.write("\n")

    print_table((("Model A", model_a), ("Model B", model_b)), outside)
    if model_b is not None:
        print("Model B threshold: {t}".format(t=model_b["threshold"]))
    if model_a is not None and model_a["failed_findings"]:
        print("Model A failed findings (scored as empty): {n}".format(
            n=model_a["failed_findings"]))
    print("metrics:", metrics_path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
