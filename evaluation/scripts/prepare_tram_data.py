"""
Prepare the MITRE TRAM data for the Stage 3 ATT&CK mapper experiment.

    python3 evaluation/scripts/prepare_tram_data.py

Downloads TRAM multi_label.json pinned to one commit, checks its SHA-256,
splits it 70/15/15 by report (doc_title, never by sentence), builds the eval
set both models are scored on, and writes everything to evaluation/data/tram/:

    train.jsonl, val.jsonl, test.jsonl   rows {id, sentence, labels, doc_title}
    eval.jsonl                           every labeled test sentence plus an
                                         equal number of unlabeled ones
    labels.json                          the 50 IDs, sorted, with official
                                         names from reconmind/data/attack_techniques.json
    split_info.json                      commit, checksum, seeds, counts

Split seed: seeds 0 to 999 are tried. A seed is kept only if all 50
techniques appear in train. Among those, the one with the most techniques
present in test wins, lowest seed on ties.

The download is cached as evaluation/data/tram/multi_label.json and the checksum is
verified on every run, cached or not. Standard library only.
"""

import hashlib
import json
import os
import random
import sys
import urllib.request
from collections import Counter

TRAM_COMMIT = "f29793d8d665f7f552898696e00065ef24a29a20"
TRAM_URL = ("https://raw.githubusercontent.com/center-for-threat-informed-defense/tram/"
            + TRAM_COMMIT + "/data/tram2-data/multi_label.json")
TRAM_SHA256 = "8a0c6644e4477eab28c92efd3bd7004b9563cb120ae1681d7d0a05dc170cd91b"
EXPECTED_LABELS = 50
SEEDS = range(1000)
EVAL_SEED = 0
TRAIN_FRAC = 0.70
VAL_FRAC = 0.15

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT_DIR = os.path.join(REPO_ROOT, "evaluation", "data", "tram")
CACHE_PATH = os.path.join(OUT_DIR, "multi_label.json")
ATTACK_PATH = os.path.join(REPO_ROOT, "reconmind", "data", "attack_techniques.json")


class DataError(ValueError):
    """The input data is not what this script expects. The message says why."""


# ---- pure functions (tested offline) ------------------------------------

def sha256_hex(raw):
    return hashlib.sha256(raw).hexdigest()


def sha256_ok(raw, expected=TRAM_SHA256):
    return sha256_hex(raw) == expected


def load_rows(raw):
    """Parse the TRAM file bytes into rows with a stable id (file order)."""
    data = json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
    if not isinstance(data, list):
        raise DataError("expected a JSON list of rows")
    rows = []
    for n, row in enumerate(data, 1):
        if not isinstance(row, dict):
            raise DataError("row {n} is not an object".format(n=n))
        sentence, labels, title = row.get("sentence"), row.get("labels"), row.get("doc_title")
        if not isinstance(sentence, str):
            raise DataError("row {n}: 'sentence' is not a string".format(n=n))
        if not isinstance(labels, list) or not all(isinstance(x, str) for x in labels):
            raise DataError("row {n}: 'labels' is not a list of strings".format(n=n))
        if not isinstance(title, str):
            raise DataError("row {n}: 'doc_title' is not a string".format(n=n))
        rows.append({
            "id": "tram-{n:05d}".format(n=n),
            "sentence": sentence,
            "labels": sorted(set(labels)),
            "doc_title": title,
        })
    return rows


def label_set(rows):
    """Sorted distinct technique IDs across all rows."""
    return sorted({lab for row in rows for lab in row["labels"]})


def split_docs(doc_titles, seed):
    """(train, val, test) sets of doc titles, 70/15/15 by document count."""
    docs = sorted(set(doc_titles))
    random.Random(seed).shuffle(docs)
    n = len(docs)
    n_train = round(TRAIN_FRAC * n)
    n_val = round(VAL_FRAC * n)
    return (set(docs[:n_train]),
            set(docs[n_train:n_train + n_val]),
            set(docs[n_train + n_val:]))


def _labels_in(rows, docs):
    return {lab for row in rows if row["doc_title"] in docs for lab in row["labels"]}


def choose_seed(rows, labels, seeds=SEEDS):
    """
    The seed whose split puts every label in train and the most labels in
    test, lowest seed on ties. Returns (seed, test_coverage, valid_seed_count).
    """
    titles = [row["doc_title"] for row in rows]
    wanted = set(labels)
    best, best_cov, valid = None, -1, 0
    for seed in seeds:
        train, _, test = split_docs(titles, seed)
        if not wanted <= _labels_in(rows, train):
            continue
        valid += 1
        cov = len(wanted & _labels_in(rows, test))
        if cov > best_cov:  # strict: an equal score never replaces a lower seed
            best, best_cov = seed, cov
    if best is None:
        raise DataError("no seed in {a}..{b} puts all {n} techniques in train".format(
            a=min(seeds), b=max(seeds), n=len(wanted)))
    return best, best_cov, valid


def split_rows(rows, seed):
    """{"train": [...], "val": [...], "test": [...]} keeping file order."""
    train, val, _ = split_docs([row["doc_title"] for row in rows], seed)
    out = {"train": [], "val": [], "test": []}
    for row in rows:
        name = "train" if row["doc_title"] in train else (
            "val" if row["doc_title"] in val else "test")
        out[name].append(row)
    return out


def build_eval(test_rows, seed=EVAL_SEED):
    """
    Every labeled test row plus an equal number of unlabeled test rows
    sampled with a fixed seed, then shuffled with the same RNG so batches
    mix both kinds. Returns (eval_rows, shortfall); shortfall > 0 means
    there were fewer unlabeled rows than labeled ones and all were taken.
    """
    labeled = [r for r in test_rows if r["labels"]]
    unlabeled = [r for r in test_rows if not r["labels"]]
    rng = random.Random(seed)
    take = min(len(labeled), len(unlabeled))
    sample = rng.sample(unlabeled, take)
    rows = labeled + sample
    rng.shuffle(rows)
    return rows, len(labeled) - take


def label_table(labels, techniques):
    """[{id, name, deprecated, revoked}] sorted by ID. Unknown IDs raise."""
    missing = [lab for lab in labels if lab not in techniques]
    if missing:
        raise DataError("not in the MITRE ATT&CK table: {m}. Run "
                        "scripts/update_attack_data.py or check the label.".format(
                            m=", ".join(missing)))
    return [{
        "id": lab,
        "name": techniques[lab]["name"],
        "deprecated": bool(techniques[lab].get("deprecated", False)),
        "revoked": bool(techniques[lab].get("revoked", False)),
    } for lab in sorted(labels)]


def technique_counts(rows):
    return dict(sorted(Counter(lab for row in rows for lab in row["labels"]).items()))


def jsonl_text(rows):
    return "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)


# ---- I/O ----------------------------------------------------------------

def _fetch():
    if os.path.exists(CACHE_PATH):
        print("Using cached", CACHE_PATH)
        with open(CACHE_PATH, "rb") as fh:
            return fh.read()
    print("Downloading", TRAM_URL)
    with urllib.request.urlopen(TRAM_URL, timeout=120) as resp:
        raw = resp.read()
    if sha256_ok(raw):  # never cache a file that failed the check
        with open(CACHE_PATH, "wb") as fh:
            fh.write(raw)
    return raw


def _write(name, text):
    path = os.path.join(OUT_DIR, name)
    with open(path, "w") as fh:
        fh.write(text)
    return path


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    raw = _fetch()
    actual = sha256_hex(raw)
    if actual != TRAM_SHA256:
        print("ERROR: checksum mismatch for TRAM multi_label.json")
        print("  expected", TRAM_SHA256)
        print("  actual  ", actual)
        print("Nothing was written. If the cached file is bad, delete", CACHE_PATH)
        return 1

    try:
        rows = load_rows(raw)
        labels = label_set(rows)
        if len(labels) != EXPECTED_LABELS:
            raise DataError("expected {e} distinct techniques, found {n}".format(
                e=EXPECTED_LABELS, n=len(labels)))
        with open(ATTACK_PATH) as fh:
            techniques = json.load(fh)["techniques"]
        table = label_table(labels, techniques)
        seed, test_cov, valid = choose_seed(rows, labels)
    except (DataError, OSError, KeyError, ValueError) as exc:
        print("ERROR:", exc)
        return 1

    splits = split_rows(rows, seed)
    eval_rows, shortfall = build_eval(splits["test"], EVAL_SEED)
    eval_text = jsonl_text(eval_rows)

    for name in ("train", "val", "test"):
        _write(name + ".jsonl", jsonl_text(splits[name]))
    _write("eval.jsonl", eval_text)
    _write("labels.json", json.dumps(table, indent=1) + "\n")

    info = {
        "source_url": TRAM_URL,
        "commit": TRAM_COMMIT,
        "sha256": TRAM_SHA256,
        "split_seed": seed,
        "seeds_tried": [min(SEEDS), max(SEEDS)],
        "valid_seeds": valid,
        "split_unit": "doc_title",
        "fractions": {"train": TRAIN_FRAC, "val": VAL_FRAC,
                      "test": round(1 - TRAIN_FRAC - VAL_FRAC, 2)},
        "n_labels": len(labels),
        "test_technique_coverage": test_cov,
        "splits": {name: {
            "docs": len({r["doc_title"] for r in part}),
            "sentences": len(part),
            "labeled": sum(1 for r in part if r["labels"]),
            "unlabeled": sum(1 for r in part if not r["labels"]),
            "per_technique": technique_counts(part),
        } for name, part in splits.items()},
        "eval": {
            "seed": EVAL_SEED,
            "sentences": len(eval_rows),
            "labeled": sum(1 for r in eval_rows if r["labels"]),
            "unlabeled": sum(1 for r in eval_rows if not r["labels"]),
            "unlabeled_shortfall": shortfall,
            "per_technique": technique_counts(eval_rows),
            "sha256": sha256_hex(eval_text.encode("utf-8")),
        },
    }
    _write("split_info.json", json.dumps(info, indent=1) + "\n")

    flagged = [t["id"] for t in table if t["deprecated"] or t["revoked"]]
    print("rows {r}, docs {d}, labels {n}".format(
        r=len(rows), d=len({r["doc_title"] for r in rows}), n=len(labels)))
    print("split seed {s} ({v} valid seeds), {c} of {n} techniques in test".format(
        s=seed, v=valid, c=test_cov, n=len(labels)))
    for name in ("train", "val", "test"):
        part = info["splits"][name]
        print("  {name:<5} {d:>3} docs  {s:>5} sentences  {l:>5} labeled".format(
            name=name, d=part["docs"], s=part["sentences"], l=part["labeled"]))
    print("eval: {s} sentences ({l} labeled, {u} unlabeled)".format(
        s=info["eval"]["sentences"], l=info["eval"]["labeled"], u=info["eval"]["unlabeled"]))
    if shortfall:
        print("WARNING: {n} fewer unlabeled than labeled test sentences".format(n=shortfall))
    if flagged:
        print("NOTE: deprecated or revoked in MITRE data:", ", ".join(flagged))
    print("Wrote", OUT_DIR)
    return 0


if __name__ == "__main__":
    sys.exit(main())
