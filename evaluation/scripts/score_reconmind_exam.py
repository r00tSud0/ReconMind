"""
Score Model A (prompted LLM) and Model B (fine tuned SciBERT) on the
ReconMind test set: evaluation/data/reconmind_eval/findings.jsonl with the
answer key in labels.jsonl.

    python3 evaluation/scripts/score_reconmind_exam.py [--provider NAME] [--model ID]
                                                       [--skip-model-a] [--batch-size 25]
                                                       [--model-b-run run2]
                                                       [--model-a-labels tram50|run3]

Model A classifies every finding's text with prompted_mapper, at temperature 0
with the same max tokens default as eval_prompted.py. Its label table is set
by --model-a-labels:
  tram50  the 50 TRAM IDs (default). Raw file:
          evaluation/results/raw/prompted_<model>_reconmind_exam.jsonl
  run3    evaluation/data/run3/labels.json. Raw file:
          evaluation/results/raw/prompted_<model>_reconmind_exam_run3labels.jsonl
The two raw files never mix. Finished batches are saved to the raw file and
the next run resumes from it. --skip-model-a sends nothing and only scores raw
files that already exist.

Model B's run is set by --model-b-run NAME (default run2). Its predictions are
read from evaluation/results/raw/finetuned_scibert_<NAME>_reconmind_exam.jsonl
and its threshold and base model id from
evaluation/results/finetuned_scibert_<NAME>_metrics.json. Run 2's file comes
from evaluation/notebooks/predict_reconmind_exam.ipynb, later runs' from
evaluation/notebooks/train_attack_mapper_<NAME>.ipynb. The raw file may start
with a header line {"labels": [...], ...} giving Model B's label set (the
order of every probs row); with no header the label set is TRAM's 50, which
is what run 2 was trained on.

Each model is scored two ways with metrics.score:
  all_labels   label set is the 50 TRAM IDs plus Model B's label set plus
               every ID in labels.jsonl.
  tram50_only  gold labels are filtered to the 50 TRAM IDs, label set is the 50.

Results go to
evaluation/results/reconmind_exam_metrics_<model b run>_<model a labels>.json.
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
RUN3_DIR = os.path.join(REPO_ROOT, "evaluation", "data", "run3")
RESULTS_DIR = os.path.join(REPO_ROOT, "evaluation", "results")
ROUTER_MODELS = {"openrouter/free"}

MODEL_B_RUN = "run2"
MODEL_A_LABELS = ("tram50", "run3")
RUN_NAME_RE = re.compile(r"[A-Za-z0-9_]+")
SCORINGS = ("all_labels", "tram50_only")


def safe_name(model):
    # Same file naming as eval_prompted.py.
    return re.sub(r"[^A-Za-z0-9._-]", "_", model)


def model_b_raw_name(run):
    return "finetuned_scibert_{r}_reconmind_exam.jsonl".format(r=run)


def model_b_metrics_name(run):
    return "finetuned_scibert_{r}_metrics.json".format(r=run)


def model_b_notebook(run):
    if run == "run2":
        return "evaluation/notebooks/predict_reconmind_exam.ipynb"
    return "evaluation/notebooks/train_attack_mapper_{r}.ipynb".format(r=run)


def model_a_raw_name(model, label_table):
    """tram50 keeps the original name; run3 adds _run3labels so the two never mix."""
    suffix = "" if label_table == "tram50" else "_" + label_table + "labels"
    return "prompted_{m}_reconmind_exam{s}.jsonl".format(m=safe_name(model), s=suffix)


def metrics_name(model_b_run, model_a_labels):
    return "reconmind_exam_metrics_{b}_{a}.json".format(b=model_b_run, a=model_a_labels)


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
    parser.add_argument("--run3-dir", default=RUN3_DIR, help="folder with the run 3 labels.json")
    parser.add_argument("--results-dir", default=RESULTS_DIR, help="where results are written")
    parser.add_argument("--model-b-run", default=MODEL_B_RUN, metavar="NAME",
                        help="Model B training run whose files are read (default run2)")
    parser.add_argument("--model-a-labels", default="tram50", choices=MODEL_A_LABELS,
                        help="Model A label table: tram50 (default) or run3")
    parsed = parser.parse_args(args)
    if not RUN_NAME_RE.fullmatch(parsed.model_b_run):
        parser.error("--model-b-run may only hold letters, digits and underscores")
    return parsed


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


def load_model_a_table(args, tram_table):
    """(label table, description) for Model A's --model-a-labels choice."""
    if args.model_a_labels == "tram50":
        return tram_table, "TRAM 50"
    with open(os.path.join(args.run3_dir, "labels.json")) as fh:
        table = json.load(fh)
    return table, "run3 ({n} IDs)".format(n=len(table))


def load_model_b(results_dir, finding_ids, run=MODEL_B_RUN):
    """
    ({id: pred list}, raw path, label IDs or None). (None, raw path, None) when
    the file is missing. Label IDs come from a header line {"labels": [...]},
    which must be the first line; each row's probs must then match its length.
    """
    path = os.path.join(results_dir, "raw", model_b_raw_name(run))
    if not os.path.exists(path):
        return None, path, None
    preds, labels = {}, None
    with open(path) as fh:
        for n, line in enumerate((x for x in fh if x.strip()), 1):
            rec = json.loads(line)
            if "id" not in rec and "labels" in rec:
                if n != 1:
                    raise ValueError("{p}: a labels header is only allowed on the first "
                                     "line".format(p=path))
                labels = list(rec["labels"])
                continue
            if labels is not None and "probs" in rec and len(rec["probs"]) != len(labels):
                raise ValueError("{p}: {i} has {k} probabilities but the header lists {m} "
                                 "labels".format(p=path, i=rec["id"], k=len(rec["probs"]),
                                                 m=len(labels)))
            preds[rec["id"]] = sorted(set(rec["pred"]))
    missing = sorted(set(finding_ids) - set(preds))
    if missing:
        raise ValueError("{p} has no prediction for {n} findings, for example {e}. "
                         "Run {nb} again.".format(p=path, n=len(missing), e=missing[:3],
                                                  nb=model_b_notebook(run)))
    return {i: preds[i] for i in finding_ids}, path, labels


def load_model_b_info(results_dir, run=MODEL_B_RUN):
    """Threshold and base model id from that run's training metrics, if present."""
    path = os.path.join(results_dir, model_b_metrics_name(run))
    try:
        with open(path) as fh:
            saved = json.load(fh)
    except (OSError, ValueError):
        return {"model": None, "run_name": run, "threshold": None,
                "max_length": None, "info_file": None}
    return {"model": saved.get("model"), "run_name": saved.get("run_name", run),
            "threshold": saved.get("threshold"), "max_length": saved.get("max_length"),
            "info_file": path}


# ---- scoring -----------------------------------------------------------------

def all_label_set(gold, tram_ids, model_b_ids=()):
    """TRAM's 50, plus Model B's label set, plus every gold ID, sorted."""
    gold_ids = {lab for labs in gold.values() for lab in labs}
    return sorted(set(tram_ids) | set(model_b_ids) | gold_ids)


def score_both(gold, pred, tram_ids, all_labels=None):
    """
    {"all_labels": ..., "tram50_only": ...} from metrics.score. all_labels is
    the label set from all_label_set; without it, TRAM's 50 plus the gold IDs.
    """
    tram = set(tram_ids)
    if all_labels is None:
        all_labels = all_label_set(gold, tram_ids)
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
    try:
        a_table, a_table_name = load_model_a_table(args, table)
    except (OSError, ValueError) as exc:
        print("Cannot read the run 3 label table in {d}: {e}".format(d=args.run3_dir, e=exc))
        print("Run python3 evaluation/scripts/prepare_run3_data.py first.")
        return 1
    finding_ids = [f["id"] for f in findings]
    rows = [{"id": f["id"], "sentence": f["text"]} for f in findings]
    raw_dir = os.path.join(args.results_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)

    # Model B is read first: its label set is part of the all_labels scoring.
    run_b = args.model_b_run
    try:
        b_preds, raw_b, b_labels = load_model_b(args.results_dir, finding_ids, run_b)
    except (OSError, ValueError, KeyError) as exc:
        print("Model B: cannot read its predictions: {e}".format(e=exc))
        return 1
    if b_preds is None:
        b_label_ids, b_label_source = [], None
    elif b_labels is not None:
        b_label_ids, b_label_source = b_labels, "raw file header"
    else:
        b_label_ids, b_label_source = tram_ids, "TRAM 50 (raw file has no labels header)"
    all_labels = all_label_set(gold, tram_ids, b_label_ids)

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
        raw_a = os.path.join(raw_dir, model_a_raw_name(model_a_id, args.model_a_labels))
        print("Model A (prompted)  model={m}  labels={l}  batch={b}  max_tokens={t}{s}".format(
            m=model_a_id, l=a_table_name, b=args.batch_size, t=prompted_mapper.MAX_TOKENS,
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
            state, code = run_model_a(config, rows, a_table, exam_sha, raw_a, args.batch_size)
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
                    "label_table": a_table_name,
                    "failed_findings": p["failed"],
                    "raw_file": os.path.relpath(raw_a, REPO_ROOT),
                    "scores": score_both(gold, a_preds, tram_ids, all_labels),
                }

    # Model B
    model_b = None
    if b_preds is None:
        print("Model B: {p} not found. Run {nb} in Colab first, then put the downloaded "
              "file in evaluation/results/raw/.".format(p=raw_b, nb=model_b_notebook(run_b)))
    else:
        info = load_model_b_info(args.results_dir, run_b)
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
            "label_set_size": len(b_label_ids),
            "label_set_from": b_label_source,
            "scores": score_both(gold, b_preds, tram_ids, all_labels),
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
        "model_b_run": run_b,
        "model_a_labels": args.model_a_labels,
        "scorings": {
            "all_labels": "label set is the 50 TRAM IDs plus Model B's label set plus "
                          "every ID in labels.jsonl",
            "tram50_only": "gold filtered to the 50 TRAM IDs, label set is the 50",
        },
        "all_labels_size": len(all_labels),
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
    metrics_path = os.path.join(args.results_dir, metrics_name(run_b, args.model_a_labels))
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
