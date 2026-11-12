"""
Score Model A (the prompted LLM) on the frozen TRAM eval set.

    python3 evaluation/scripts/eval_prompted.py [--provider NAME] [--model ID]
                                                [--batch-size 25] [--retry-failed]
                                                [--max-tokens 16000] [--max-batches N]

Run evaluation/scripts/prepare_tram_data.py first. Provider settings work like the agent
(.env or flags, see reconmind/agent/__main__.py).

Each finished batch is saved to evaluation/results/raw/prompted_<model>.jsonl and the
next run resumes from it, so a daily request limit just means running it
again tomorrow. On a rate limit the run stops cleanly and says how many
sentences are done. When every sentence has a result, the metrics are
written to evaluation/results/prompted_<model>_metrics.json and the headline numbers
are printed.

Failed batches (unparseable twice) count as done and score as empty
predictions. --retry-failed sends only those batches again.

Reasoning models spend completion tokens before the answer. A batch that
failed because the length budget ran out prints "batch N: model ran out of
length budget (raise --max-tokens)". --max-batches N sends at most N batches
and then stops without scoring, which is handy for testing one batch.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from reconmind.agent import llm  # noqa: E402
from reconmind.agent.__main__ import MISSING_PACKAGE, _load_dotenv  # noqa: E402
from evaluation.attack_mapper import metrics, prompted_mapper  # noqa: E402

DATA_DIR = os.path.join(REPO_ROOT, "evaluation", "data", "tram")
RESULTS_DIR = os.path.join(REPO_ROOT, "evaluation", "results")
ROUTER_MODELS = {"openrouter/free"}


def safe_name(model):
    return re.sub(r"[^A-Za-z0-9._-]", "_", model)


def _parse_args(args):
    parser = argparse.ArgumentParser(prog="python3 evaluation/scripts/eval_prompted.py")
    parser.add_argument("--provider", help="one of: " + ", ".join(sorted(llm.PROVIDERS)))
    parser.add_argument("--model", help="model id for this run")
    parser.add_argument("--batch-size", type=int, default=25,
                        help="sentences per request (default 25)")
    parser.add_argument("--retry-failed", action="store_true",
                        help="send the failed batches again")
    parser.add_argument("--max-tokens", type=int, default=prompted_mapper.MAX_TOKENS,
                        help="completion token budget per request (default {d})".format(
                            d=prompted_mapper.MAX_TOKENS))
    parser.add_argument("--max-batches", type=int,
                        help="send at most this many batches, then stop (for testing)")
    parser.add_argument("--data-dir", default=DATA_DIR, help="folder with eval.jsonl and labels.json")
    parser.add_argument("--results-dir", default=RESULTS_DIR, help="where results are written")
    return parser.parse_args(args)


def _load_eval(data_dir):
    eval_path = os.path.join(data_dir, "eval.jsonl")
    with open(eval_path, "rb") as fh:
        raw = fh.read()
    rows = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    with open(os.path.join(data_dir, "labels.json")) as fh:
        table = json.load(fh)
    return rows, table, hashlib.sha256(raw).hexdigest()


def _stopped(p, reason):
    print("{r}. {d} of {t} sentences done ({f} failed). Run again later to resume.".format(
        r=reason, d=p["done"], t=p["total"], f=p["failed"]))


def main(argv):
    try:
        args = _parse_args(argv[1:])
    except SystemExit:
        return 1
    for flag, value in (("--batch-size", args.batch_size), ("--max-tokens", args.max_tokens),
                        ("--max-batches", args.max_batches)):
        if value is not None and value < 1:
            print("{f} must be at least 1".format(f=flag))
            return 1

    try:
        eval_rows, table, eval_sha = _load_eval(args.data_dir)
    except (OSError, ValueError) as exc:
        print("Cannot read the eval set in {d}: {e}".format(d=args.data_dir, e=exc))
        print("Run python3 evaluation/scripts/prepare_tram_data.py first.")
        return 1

    _load_dotenv()
    try:
        config = llm.load_config(provider=args.provider, model=args.model)
    except llm.ConfigError as exc:
        print(exc)
        return 1
    try:
        client = llm.make_client(config)
    except ImportError:
        print(MISSING_PACKAGE)
        return 1

    name = safe_name(config.model)
    raw_dir = os.path.join(args.results_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    raw_path = os.path.join(raw_dir, "prompted_{m}.jsonl".format(m=name))
    metrics_path = os.path.join(args.results_dir, "prompted_{m}_metrics.json".format(m=name))

    print("Model A (prompted)  provider={p}  model={m}  batch={b}  max_tokens={t}".format(
        p=config.name, m=config.model, b=args.batch_size, t=args.max_tokens))
    if config.model in ROUTER_MODELS:
        print("WARNING: {m} routes to different models between runs, so this result "
              "may not be reproducible. Prefer a pinned model id.".format(m=config.model))
    print("raw results:", raw_path)

    try:
        state = prompted_mapper.run(client, config.model, eval_rows, table, raw_path,
                                    eval_sha, batch_size=args.batch_size,
                                    retry_failed=args.retry_failed,
                                    max_tokens=args.max_tokens,
                                    max_batches=args.max_batches)
    except prompted_mapper.MapperError as exc:
        print(exc)
        return 1
    except (llm.RateLimited, KeyboardInterrupt, Exception) as exc:
        state = prompted_mapper.sentence_state(prompted_mapper.read_records(raw_path))
        if isinstance(exc, llm.RateLimited):
            reason = "Stopped: rate limited"
        elif isinstance(exc, KeyboardInterrupt):
            reason = "Stopped by user"
        else:
            reason = "Stopped on error ({t}: {e})".format(t=type(exc).__name__, e=exc)
        _stopped(prompted_mapper.progress(eval_rows, state), reason)
        return 1

    p = prompted_mapper.progress(eval_rows, state)
    if p["done"] < p["total"] and args.max_batches:
        _stopped(p, "Stopped after --max-batches {n}".format(n=args.max_batches))
        return 0
    if p["done"] < p["total"]:  # cannot happen after a clean run, but never score a partial set
        _stopped(p, "Incomplete")
        return 1

    gold = {r["id"]: r["labels"] for r in eval_rows}
    result = metrics.score(gold, prompted_mapper.predictions(eval_rows, state),
                           [t["id"] for t in table])
    out = {
        "model_kind": "prompted",
        "provider": config.name,
        "model": config.model,
        "batch_size": args.batch_size,
        "max_tokens": args.max_tokens,
        "temperature": prompted_mapper.TEMPERATURE,
        "eval_sha256": eval_sha,
        "failed_sentences": p["failed"],
        "written": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "metrics": result,
    }
    os.makedirs(args.results_dir, exist_ok=True)
    with open(metrics_path, "w") as fh:
        json.dump(out, fh, indent=1)
        fh.write("\n")

    mi, ma = result["micro"], result["macro"]
    print("-" * 60)
    print("sentences:    {n} ({l} labeled, {u} unlabeled)".format(
        n=result["n_sentences"], l=result["n_labeled"], u=result["n_unlabeled"]))
    print("micro:        P {p:.3f}  R {r:.3f}  F1 {f:.3f}".format(
        p=mi["precision"], r=mi["recall"], f=mi["f1"]))
    print("macro F1:     {f:.3f} over {n} techniques".format(
        f=ma["f1"], n=ma["n_techniques_averaged"]))
    print("exact match:  {e:.3f}".format(e=result["exact_match"]))
    print("out of set:   {n} predicted IDs".format(n=result["out_of_set"]["count"]))
    print("failed:       {n} sentences".format(n=p["failed"]))
    if result["zero_support_techniques"]:
        print("zero support: {z}".format(z=", ".join(result["zero_support_techniques"])))
    print("metrics:     ", metrics_path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
