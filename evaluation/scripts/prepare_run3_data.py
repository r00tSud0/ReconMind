"""
Prepare the training data for Model B run 3.

    python3 evaluation/scripts/prepare_run3_data.py --exploitdb-csv PATH

Run 2 learned only from TRAM's threat report sentences and predicted nothing
on ReconMind's findings. Run 3 adds data that looks like those findings and
covers the techniques ReconMind needs. Every row is tagged with its source:

    attack      MITRE ATT&CK v20.0 procedure examples ("uses" relationships)
    ctid_kev    MITRE CTID KEV mappings, up to two sentences per CVE
    ctid_cve    MITRE CTID CVE mappings, text from cvelistV5
    exploitdb   Exploit-DB titles written as ReconMind finding text
    tram        evaluation/data/tram/train.jsonl and val.jsonl, split kept

CTID labels are exploitation_technique and primary_impact only. When a CVE is
in both CTID sources their labels are merged, so every row about that CVE
carries the same set. Every label is checked against
reconmind/data/attack_techniques.json; unknown, revoked and deprecated IDs are
dropped and counted per source.

Leakage rules:
    1. Every EDB ID in evaluation/data/reconmind_eval/findings.jsonl, and every
       CVE Exploit-DB links to those IDs, is removed from every source. A row
       is about a CVE if its group is that CVE, its exploit links to it, or its
       sentence names it. Exploit-DB rows whose title equals an exploit title
       in the exam text are removed too.
    2. New sentences equal to a TRAM test or eval sentence (lowercase,
       collapsed whitespace) are removed.
    3. The ReconMind answer key is never opened.
    4. After the split, a val row from a new source whose sentence equals a
       train sentence (lowercase, collapsed whitespace) is removed.

Split: the new sources go 90/10 into train and val by group id (the CVE or the
ATT&CK relationship id), seed 9, so a group never spans both. TRAM rows keep
their own split. Exact duplicate (sentence, labels) rows are removed within
each split. The label set is every ID with at least 5 rows in the final train
split; rows keep only those labels and a row left with none is kept only if it
came from TRAM.

Outputs in evaluation/data/run3/ (not committed): train.jsonl and val.jsonl
with rows {id, sentence, labels, source, group}, labels.json and
manifest.json. manifest.json is copied to evaluation/results/run3_data_manifest.json.
Its "outputs" section holds the SHA-256 of train.jsonl, val.jsonl and
labels.json, which the run 3 training notebook checks before it trains.

Pinned downloads are cached under evaluation/data/run3/cache/ and checked
against their SHA-256 on every run, cached or not. cvelistV5 files are cached
under evaluation/data/run3/cache/cve/; a CVE that cannot be fetched is skipped
and counted. Standard library only.
"""

import argparse
import csv
import hashlib
import http.client
import io
import json
import os
import random
import re
import shutil
import sys
import urllib.error
import urllib.request
from collections import Counter

ATTACK_COMMIT = "a8db2f52eb933c9c99060c123e088b3326d3a607"
ATTACK_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
              + ATTACK_COMMIT + "/enterprise-attack/enterprise-attack-20.0.json")
ATTACK_SHA256 = "2339a3c36353d5ee2c07e98af3fafbf00761e0e3979ede06402657445b7b4278"

MAPEX_COMMIT = "59f8d7230f672db0d4b197357561f47880478426"
MAPEX_BASE = ("https://raw.githubusercontent.com/center-for-threat-informed-defense/"
              "mappings-explorer/" + MAPEX_COMMIT + "/")
KEV_URL = MAPEX_BASE + ("mappings/kev/attack-16.1/kev-07.28.2025/enterprise/"
                        "kev-07.28.2025_attack-16.1-enterprise.json")
KEV_SHA256 = "b57b3d382809d9159fdda6701d21f0e67a2d655444d89301caab2c39ad54bdc7"
CVE_MAP_URL = MAPEX_BASE + "src/mapex_convert/mappings/Att%26ckToCveMappings.csv"
CVE_MAP_SHA256 = "60bd1a47562c1b1e1d594e71dd7f3f7a7d0c7bc12ebcb42a5e616220669a2801"

CVELIST_COMMIT = "e10da37d505d5e4e8875928ddfb25482721a8fa0"
CVELIST_URL = ("https://raw.githubusercontent.com/CVEProject/cvelistV5/"
               + CVELIST_COMMIT + "/cves/{year}/{bucket}xxx/{cve}.json")

PINNED = (
    {"source": "attack", "url": ATTACK_URL, "commit": ATTACK_COMMIT,
     "sha256": ATTACK_SHA256, "cache": "enterprise-attack-20.0.json"},
    {"source": "ctid_kev", "url": KEV_URL, "commit": MAPEX_COMMIT,
     "sha256": KEV_SHA256, "cache": "kev-07.28.2025_attack-16.1-enterprise.json"},
    {"source": "ctid_cve", "url": CVE_MAP_URL, "commit": MAPEX_COMMIT,
     "sha256": CVE_MAP_SHA256, "cache": "AttackToCveMappings.csv"},
)

SOURCES = ("attack", "ctid_kev", "ctid_cve", "exploitdb", "tram")
NEW_SOURCES = SOURCES[:4]
SPLITS = ("train", "val")
SPLIT_SEED = 9
TRAIN_FRAC = 0.90
MIN_TRAIN_ROWS = 5

KEEP_MAPPING_TYPES = ("exploitation_technique", "primary_impact")
# Required in every KEV mapping object. "comments" is optional: some objects
# in the real file have no such key, and missing, None or empty all mean the
# object adds no comment sentence.
KEV_KEYS = ("capability_id", "capability_description", "mapping_type", "attack_object_id")
CVE_CSV_ID = "CVE ID"
CVE_CSV_LABEL_COLUMNS = ("Exploitation Technique", "Primary Impact")
EDB_COLUMNS = ("id", "description", "codes")
EDB_SENTENCE = "Known exploits (Exploit-DB): {description} (EDB-{id})."
EXPLOITS_MARKER = "Known exploits (Exploit-DB): "

# The 16 techniques in the ReconMind answer key, taken from
# evaluation/data/reconmind_eval/LABELING.md.
EXAM_TECHNIQUES = (
    "T1005", "T1021", "T1021.004", "T1021.005", "T1039", "T1040", "T1056.001",
    "T1059", "T1059.004", "T1068", "T1105", "T1113", "T1135", "T1190",
    "T1499.004", "T1589",
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT_DIR = os.path.join(REPO_ROOT, "evaluation", "data", "run3")
CACHE_DIR = os.path.join(OUT_DIR, "cache")
CVE_CACHE_DIR = os.path.join(CACHE_DIR, "cve")
RESULTS_COPY_PATH = os.path.join(REPO_ROOT, "evaluation", "results", "run3_data_manifest.json")
ATTACK_PATH = os.path.join(REPO_ROOT, "reconmind", "data", "attack_techniques.json")
TRAM_DIR = os.path.join(REPO_ROOT, "evaluation", "data", "tram")
FINDINGS_PATH = os.path.join(REPO_ROOT, "evaluation", "data", "reconmind_eval", "findings.jsonl")

CITATION_RE = re.compile(r"\(Citation:[^()]*(?:\([^()]*\)[^()]*)*\)")
LINK_RE = re.compile(r"\[([^\]]+)\]\((?:[^()\s]|\([^()\s]*\))*\)")
SPACE_BEFORE_PUNCT_RE = re.compile(r"\s+([.,;:!?])(?=\s|$)")
CVE_RE = re.compile(r"CVE-(\d{4})-(\d{4,})", re.IGNORECASE)
TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")
EDB_ID_RE = re.compile(r"\(EDB-(\d+)\)")
EXAM_TITLE_RE = re.compile(r"(?:^|; )(.+?) \(EDB-(\d+)\)")


class DataError(ValueError):
    """The input data is not what this script expects. The message says why."""


# Pure functions (tested offline)

def sha256_hex(raw):
    return hashlib.sha256(raw).hexdigest()


def clean_text(text):
    """Drop (Citation: ...) markers, turn [Name](url) into Name, collapse whitespace."""
    text = CITATION_RE.sub(" ", str(text or ""))
    text = LINK_RE.sub(r"\1", text)
    text = " ".join(text.split())
    # A citation removed before a full stop leaves "word ." behind.
    return SPACE_BEFORE_PUNCT_RE.sub(r"\1", text)


def normalize(text):
    """Lowercase with collapsed whitespace, for the TRAM duplicate check."""
    return " ".join(str(text).lower().split())


def normalize_cve(text):
    """'CVE-YYYY-N' in upper case, or None if text is not exactly one CVE ID."""
    match = CVE_RE.fullmatch(str(text or "").strip())
    return "CVE-{y}-{n}".format(y=match.group(1), n=match.group(2)) if match else None


def cve_key(cve):
    """(year, number) so CVE IDs sort numerically."""
    match = CVE_RE.fullmatch(cve)
    return int(match.group(1)), int(match.group(2))


def cves_in(text):
    """Every CVE ID named in a piece of text."""
    return {"CVE-{y}-{n}".format(y=m.group(1), n=m.group(2))
            for m in CVE_RE.finditer(str(text or ""))}


def cvelist_url(cve):
    year, number = cve_key(cve)
    return CVELIST_URL.format(year=year, bucket=number // 1000, cve=cve)


def clean_labels(ids, techniques, tally):
    """
    The IDs that are active in ATT&CK v20, sorted and unique. Each dropped ID
    is counted in tally[reason][id], reason being unknown, revoked or deprecated.
    """
    kept = set()
    for raw in ids:
        tid = str(raw).strip().upper()
        info = techniques.get(tid) if TECHNIQUE_RE.fullmatch(tid) else None
        if info is None:
            reason = "unknown"
        elif info.get("revoked"):
            reason = "revoked"
        elif info.get("deprecated"):
            reason = "deprecated"
        else:
            kept.add(tid)
            continue
        tally.setdefault(reason, Counter())[tid] += 1
    return sorted(kept)


def _inactive(obj):
    return bool(obj.get("revoked")) or bool(obj.get("x_mitre_deprecated"))


def _attack_id(obj):
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def attack_rows(bundle):
    """
    One row per "uses" relationship that targets an active attack-pattern and
    has a description, in file order. Labels are not cleaned here.
    """
    objects = bundle.get("objects") if isinstance(bundle, dict) else None
    if not isinstance(objects, list):
        raise DataError("the ATT&CK bundle has no 'objects' list")
    patterns = {}
    for obj in objects:
        if isinstance(obj, dict) and obj.get("type") == "attack-pattern" and not _inactive(obj):
            tid = _attack_id(obj)
            if tid:
                patterns[obj.get("id")] = tid
    rows = []
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses" or _inactive(obj):
            continue
        tid = patterns.get(obj.get("target_ref"))
        sentence = clean_text(obj.get("description"))
        if tid and sentence:
            rows.append({"sentence": sentence, "labels": [tid],
                         "source": "attack", "group": obj.get("id")})
    return rows


def kev_entries(data):
    """
    {cve: {"labels", "descriptions", "comments"}} from the CTID KEV file, in
    file order. Labels come only from KEEP_MAPPING_TYPES and are not cleaned.
    Distinct non empty descriptions and comments are kept in order. Every key
    in KEV_KEYS is required; "comments" may be missing, None or empty.
    """
    objects = data.get("mapping_objects") if isinstance(data, dict) else None
    if not isinstance(objects, list):
        raise DataError("the CTID KEV file has no 'mapping_objects' list")
    out = {}
    for n, obj in enumerate(objects, 1):
        if not isinstance(obj, dict):
            raise DataError("CTID KEV mapping object {n} is not an object".format(n=n))
        missing = [key for key in KEV_KEYS if key not in obj]
        if missing:
            raise DataError("CTID KEV mapping object {n} lacks keys {m}; it has {h}".format(
                n=n, m=", ".join(missing), h=", ".join(sorted(obj))))
        cve = normalize_cve(obj.get("capability_id"))
        if not cve:
            continue
        entry = out.setdefault(cve, {"labels": set(), "descriptions": [], "comments": []})
        if obj.get("mapping_type") in KEEP_MAPPING_TYPES and obj.get("attack_object_id"):
            entry["labels"].add(str(obj["attack_object_id"]).strip())
        for field, key in (("capability_description", "descriptions"), ("comments", "comments")):
            text = clean_text(obj.get(field))
            if text and text not in entry[key]:
                entry[key].append(text)
    return out


def _csv_text(data):
    """CSV text from bytes or str, read as utf-8-sig so a byte order mark never sticks to column 1."""
    if isinstance(data, bytes):
        return data.decode("utf-8-sig")
    return data[1:] if data.startswith("﻿") else data


def cve_csv_labels(data):
    """
    {cve: set of IDs} from the CTID CVE CSV (bytes or str), Exploitation
    Technique and Primary Impact only. Header: CVE ID, Primary Impact,
    Secondary Impact, Exploitation Technique, Uncategorized, Phase.
    """
    reader = csv.DictReader(io.StringIO(_csv_text(data), newline=""))
    reader.fieldnames = [name.strip() for name in (reader.fieldnames or [])]
    missing = [c for c in (CVE_CSV_ID,) + CVE_CSV_LABEL_COLUMNS if c not in reader.fieldnames]
    if missing:
        raise DataError("the CTID CVE CSV lacks columns {m}; its header is {h}".format(
            m=", ".join(missing), h=", ".join(reader.fieldnames)))
    out = {}
    for row in reader:
        cve = normalize_cve(row.get(CVE_CSV_ID))
        if not cve:
            continue
        labels = out.setdefault(cve, set())
        for column in CVE_CSV_LABEL_COLUMNS:
            for part in (row.get(column) or "").split(";"):
                if part.strip():
                    labels.add(part.strip())
    return out


def cve_description(record):
    """The first English description in containers.cna.descriptions, or None."""
    try:
        descriptions = record["containers"]["cna"]["descriptions"]
    except (KeyError, TypeError):
        return None
    for item in descriptions if isinstance(descriptions, list) else []:
        if isinstance(item, dict) and str(item.get("lang", "")).lower().startswith("en"):
            text = " ".join(str(item.get("value") or "").split())
            return text or None
    return None


def exploitdb_entries(data):
    """[{edb_id, description, cves}] from files_exploits.csv (bytes or str), cves sorted numerically."""
    reader = csv.DictReader(io.StringIO(_csv_text(data), newline=""))
    header = reader.fieldnames or []
    missing = [c for c in EDB_COLUMNS if c not in header]
    if missing:
        raise DataError("the Exploit-DB CSV lacks columns {m}; its header is {h}".format(
            m=", ".join(missing), h=", ".join(header) if header else "(empty)"))
    entries = []
    for row in reader:
        cves = {normalize_cve(part) for part in (row.get("codes") or "").split(";")}
        entries.append({
            "edb_id": (row.get("id") or "").strip(),
            "description": " ".join((row.get("description") or "").split()),
            "cves": sorted((c for c in cves if c), key=cve_key),
        })
    return entries


def exam_exploits(findings):
    """(EDB IDs, normalized exploit titles) named in the ReconMind exam findings."""
    edb_ids, titles = set(), set()
    for finding in findings:
        text = str(finding.get("text") or "")
        edb_ids.update(EDB_ID_RE.findall(text))
        start = text.find(EXPLOITS_MARKER)
        if start >= 0:
            part = text[start + len(EXPLOITS_MARKER):]
            titles.update(normalize(m.group(1)) for m in EXAM_TITLE_RE.finditer(part))
    return edb_ids, titles


def holdout_sentences(*row_lists):
    """Normalized sentences of TRAM test and eval."""
    return {normalize(row["sentence"]) for rows in row_lists for row in rows}


def tram_rows(rows, split):
    """TRAM rows in the run 3 shape, each remembering its own split."""
    out = []
    for n, row in enumerate(rows, 1):
        if not isinstance(row.get("sentence"), str) or not isinstance(row.get("labels"), list):
            raise DataError("TRAM {s} row {n} has no sentence or labels".format(s=split, n=n))
        out.append({"id": row.get("id"), "sentence": row["sentence"], "labels": row["labels"],
                    "source": "tram", "group": row.get("doc_title", ""), "_split": split})
    return out


def merge_cve_labels(*label_maps):
    """{cve: sorted union of labels} across CTID sources, CVEs with no labels left out."""
    merged = {}
    for label_map in label_maps:
        for cve, labels in label_map.items():
            merged.setdefault(cve, set()).update(labels)
    return {cve: sorted(labels) for cve, labels in merged.items() if labels}


def kev_rows(kev, cve_labels):
    rows = []
    for cve, entry in kev.items():
        if cve in cve_labels:
            for sentence in entry["descriptions"] + entry["comments"]:
                rows.append({"sentence": sentence, "labels": list(cve_labels[cve]),
                             "source": "ctid_kev", "group": cve, "_cves": [cve]})
    return rows


def cve_rows(cve_map, cve_texts, cve_labels):
    rows = []
    for cve in cve_map:
        if cve in cve_labels and cve_texts.get(cve):
            rows.append({"sentence": cve_texts[cve], "labels": list(cve_labels[cve]),
                         "source": "ctid_cve", "group": cve, "_cves": [cve]})
    return rows


def exploitdb_rows(entries, cve_labels):
    """One finding style sentence per exploit that links a CVE with CTID labels."""
    rows = []
    for entry in entries:
        linked = [cve for cve in entry["cves"] if cve in cve_labels]
        if not linked or not entry["edb_id"] or not entry["description"]:
            continue
        labels = sorted({lab for cve in linked for lab in cve_labels[cve]})
        rows.append({
            "sentence": EDB_SENTENCE.format(description=entry["description"], id=entry["edb_id"]),
            "labels": labels, "source": "exploitdb", "group": linked[0],
            "_cves": entry["cves"], "_edb": entry["edb_id"],
            "_description": entry["description"],
        })
    return rows


def assign_ids(rows, source):
    for n, row in enumerate(rows, 1):
        row["id"] = "{s}-{n:06d}".format(s=source, n=n)
    return rows


def row_cves(row):
    cves = set(row.get("_cves") or []) | cves_in(row["sentence"])
    group = normalize_cve(row.get("group"))
    return cves | ({group} if group else set())


def split_groups(groups, seed=SPLIT_SEED, train_frac=TRAIN_FRAC):
    """(train, val) sets of group ids, train_frac of the groups in train."""
    ordered = sorted(set(groups))
    random.Random(seed).shuffle(ordered)
    n_train = round(train_frac * len(ordered))
    return set(ordered[:n_train]), set(ordered[n_train:])


def dedupe(rows):
    """Rows without exact (sentence, labels) repeats, first kept. Returns (rows, removed)."""
    seen, out = set(), []
    for row in rows:
        key = (row["sentence"], tuple(row["labels"]))
        if key not in seen:
            seen.add(key)
            out.append(row)
    return out, len(rows) - len(out)


def apply_label_set(splits, min_rows=MIN_TRAIN_ROWS):
    """
    Dedupe each split, keep the IDs with at least min_rows train rows, prune the
    rest from every row, and repeat until nothing changes, since pruning can make
    new duplicates. A row left with no labels is dropped unless it is from TRAM.
    Returns (splits, label_ids, first_counts, stats); first_counts are the train
    counts before any pruning.
    """
    stats = {"duplicates_removed": {name: 0 for name in splits},
             "dropped_no_label_in_set": {name: Counter() for name in splits}}
    current, first_counts = splits, None
    while True:
        deduped = {}
        for name, rows in current.items():
            deduped[name], removed = dedupe(rows)
            stats["duplicates_removed"][name] += removed
        counts = Counter(lab for row in deduped["train"] for lab in row["labels"])
        if first_counts is None:
            first_counts = counts
        keep = {lab for lab, n in counts.items() if n >= min_rows}
        pruned, changed = {}, False
        for name, rows in deduped.items():
            pruned[name] = []
            for row in rows:
                labels = [lab for lab in row["labels"] if lab in keep]
                if labels != row["labels"]:
                    changed = True
                if not labels and row["source"] != "tram":
                    stats["dropped_no_label_in_set"][name][row["source"]] += 1
                    continue
                pruned[name].append(dict(row, labels=labels))
        current = pruned
        if not changed:
            return current, sorted(keep), first_counts, stats


def public_row(row):
    return {key: row[key] for key in ("id", "sentence", "labels", "source", "group")}


def build(attack_bundle, kev_data, cve_map, cve_texts, edb_entries, tram_splits,
          holdout, exam_edb_ids, exam_titles, techniques,
          seed=SPLIT_SEED, min_rows=MIN_TRAIN_ROWS):
    """
    Every rule from the module docstring, with no I/O. cve_map is the output
    of cve_csv_labels, holdout of holdout_sentences, exam_titles normalized.
    Returns {"splits": {train, val}, "labels": [...], "report": {...}}.
    """
    tallies = {source: {} for source in SOURCES}

    # CTID labels per CVE: each source cleaned on its own, then merged.
    kev = kev_entries(kev_data)
    kev_labels = {cve: clean_labels(e["labels"], techniques, tallies["ctid_kev"])
                  for cve, e in kev.items()}
    csv_labels = {cve: clean_labels(ids, techniques, tallies["ctid_cve"])
                  for cve, ids in cve_map.items()}
    cve_labels = merge_cve_labels(kev_labels, csv_labels)

    by_source = {
        "attack": assign_ids(attack_rows(attack_bundle), "attack"),
        "ctid_kev": assign_ids(kev_rows(kev, cve_labels), "ctid_kev"),
        "ctid_cve": assign_ids(cve_rows(cve_map, cve_texts, cve_labels), "ctid_cve"),
        "exploitdb": assign_ids(exploitdb_rows(edb_entries, cve_labels), "exploitdb"),
        "tram": [row for name in SPLITS for row in tram_rows(tram_splits.get(name, []), name)],
    }
    for source in ("attack", "tram"):
        for row in by_source[source]:
            row["labels"] = clean_labels(row["labels"], techniques, tallies[source])
    rows_built = {source: len(rows) for source, rows in by_source.items()}

    no_valid = Counter()
    rows = []
    for source in SOURCES:
        for row in by_source[source]:
            if not row["labels"] and source != "tram":
                no_valid[source] += 1
            else:
                rows.append(row)

    # Leakage rule 1: exam EDB IDs and every CVE Exploit-DB links to them.
    exam_edb = set(exam_edb_ids)
    known_edb = {e["edb_id"] for e in edb_entries}
    exam_cves = {cve for e in edb_entries if e["edb_id"] in exam_edb for cve in e["cves"]}
    rule1, title_dups, rule2 = Counter(), 0, Counter()
    kept = []
    for row in rows:
        if row.get("_edb") in exam_edb or row_cves(row) & exam_cves:
            rule1[row["source"]] += 1
        elif row["source"] == "exploitdb" and normalize(row["_description"]) in exam_titles:
            title_dups += 1
        # Leakage rule 2: new sentences that match a TRAM test or eval sentence.
        elif row["source"] != "tram" and normalize(row["sentence"]) in holdout:
            rule2[row["source"]] += 1
        else:
            kept.append(row)

    new_groups = [row["group"] for row in kept if row["source"] != "tram"]
    train_groups, val_groups = split_groups(new_groups, seed)
    splits = {name: [] for name in SPLITS}
    for row in kept:
        if row["source"] == "tram":
            splits[row["_split"]].append(row)
        else:
            splits["train" if row["group"] in train_groups else "val"].append(row)

    splits, label_ids, first_counts, stats = apply_label_set(splits, min_rows)

    # Cross split leakage: a new source val row that repeats a train sentence.
    train_sentences = {normalize(row["sentence"]) for row in splits["train"]}
    cross_split, val_rows = Counter(), []
    for row in splits["val"]:
        if row["source"] != "tram" and normalize(row["sentence"]) in train_sentences:
            cross_split[row["source"]] += 1
        else:
            val_rows.append(row)
    splits["val"] = val_rows

    final_counts = Counter(lab for row in splits["train"] for lab in row["labels"])
    names = {tid: techniques[tid]["name"] for tid in EXAM_TECHNIQUES if tid in techniques}

    report = {
        "rows_built": rows_built,
        "dropped_labels": {source: {
            "total": sum(sum(c.values()) for c in tallies[source].values()),
            **{reason: dict(sorted(tallies[source].get(reason, Counter()).items()))
               for reason in ("unknown", "revoked", "deprecated")},
        } for source in SOURCES},
        "rows_without_valid_labels": {source: no_valid[source] for source in NEW_SOURCES},
        "leakage": {
            "exam_edb_ids": sorted(exam_edb, key=int),
            "exam_edb_ids_not_in_exploitdb_csv": sorted(exam_edb - known_edb, key=int),
            "exam_cves": sorted(exam_cves, key=cve_key),
            "rule1_rows_dropped": {source: rule1[source] for source in SOURCES},
            "exam_title_rows_dropped": title_dups,
            "rule2_rows_dropped": {source: rule2[source] for source in NEW_SOURCES},
        },
        "split": {"seed": seed, "unit": "group", "train_fraction": TRAIN_FRAC,
                  "groups": {"train": len(train_groups), "val": len(val_groups)}},
        "duplicates_removed": stats["duplicates_removed"],
        "cross_split_rows_dropped": {source: cross_split[source] for source in NEW_SOURCES},
        "rows_dropped_no_label_in_set": {
            name: {source: stats["dropped_no_label_in_set"][name][source] for source in SOURCES}
            for name in SPLITS},
        "label_set_min_train_rows": min_rows,
        "label_set_size": len(label_ids),
        "rows": {source: {name: sum(1 for r in splits[name] if r["source"] == source)
                          for name in SPLITS} for source in SOURCES},
        "split_totals": {name: {
            "rows": len(splits[name]),
            "labeled": sum(1 for r in splits[name] if r["labels"]),
            "unlabeled": sum(1 for r in splits[name] if not r["labels"]),
        } for name in SPLITS},
        "exam_techniques": {tid: {
            "name": names.get(tid, ""),
            "train_rows": final_counts.get(tid, 0),
            "train_rows_before_label_set": first_counts.get(tid, 0),
            "in_label_set": tid in label_ids,
        } for tid in EXAM_TECHNIQUES},
    }
    return {"splits": {name: [public_row(r) for r in splits[name]] for name in SPLITS},
            "labels": label_ids, "report": report}


def label_table(label_ids, techniques):
    """[{id, name, deprecated, revoked}] sorted by ID, the same shape as TRAM's labels.json."""
    return [{
        "id": tid,
        "name": techniques[tid]["name"],
        "deprecated": bool(techniques[tid].get("deprecated", False)),
        "revoked": bool(techniques[tid].get("revoked", False)),
    } for tid in sorted(label_ids)]


def jsonl_text(rows):
    return "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)


def parse_jsonl(text, name):
    rows = []
    for n, line in enumerate(text.splitlines(), 1):
        if line.strip():
            try:
                rows.append(json.loads(line))
            except ValueError as exc:
                raise DataError("{f} line {n}: {e}".format(f=name, n=n, e=exc))
    return rows


# I/O

def _http_get(url, timeout=120):
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return resp.read()


def _read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def fetch_pinned(url, expected, cache_path, fetch=None):
    """The cached file if there is one, else a download, cached only if its SHA-256 matches."""
    if os.path.exists(cache_path):
        print("Using cached", cache_path)
        return _read_bytes(cache_path)
    print("Downloading", url)
    raw = (fetch or _http_get)(url)
    if sha256_hex(raw) == expected:  # never cache a file that failed the check
        with open(cache_path, "wb") as fh:
            fh.write(raw)
    return raw


def fetch_cve_texts(cves, cache_dir, fetch=None):
    """
    ({cve: English description}, {cve: reason skipped}). Each cvelistV5 file
    is cached in cache_dir once it parses as JSON. Failures are never fatal.
    """
    fetch = fetch or _http_get
    texts, skipped, downloaded = {}, {}, 0
    for cve in sorted(set(cves), key=cve_key):
        path = os.path.join(cache_dir, cve + ".json")
        try:
            if os.path.exists(path):
                record = json.loads(_read_bytes(path).decode("utf-8"))
            else:
                raw = fetch(cvelist_url(cve))
                record = json.loads(raw.decode("utf-8"))
                with open(path, "wb") as fh:
                    fh.write(raw)
                downloaded += 1
                if downloaded % 100 == 0:
                    print("  {n} CVE files downloaded".format(n=downloaded))
        except (OSError, ValueError, http.client.HTTPException) as exc:
            skipped[cve] = "{t}: {e}".format(t=type(exc).__name__, e=exc)
            continue
        text = cve_description(record)
        if text:
            texts[cve] = text
        else:
            skipped[cve] = "no English description"
    return texts, skipped


def _write(path, text):
    with open(path, "w") as fh:
        fh.write(text)


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Prepare the Model B run 3 training data.")
    parser.add_argument("--exploitdb-csv", required=True,
                        help="path to Exploit-DB files_exploits.csv")
    return parser.parse_args(argv)


def print_summary(report, cve_fetched, cve_skipped):
    print("Rows per source and split")
    print("  {s:<10} {t:>7} {v:>7}".format(s="source", t="train", v="val"))
    for source in SOURCES:
        counts = report["rows"][source]
        print("  {s:<10} {t:>7} {v:>7}".format(s=source, t=counts["train"], v=counts["val"]))
    totals = report["split_totals"]
    print("  {s:<10} {t:>7} {v:>7}".format(
        s="total", t=totals["train"]["rows"], v=totals["val"]["rows"]))
    print("Label set: {n} techniques with at least {m} train rows".format(
        n=report["label_set_size"], m=report["label_set_min_train_rows"]))
    leak = report["leakage"]
    print("Leakage drops")
    print("  rule 1: {e} exam EDB IDs, {c} linked CVEs, {r} rows".format(
        e=len(leak["exam_edb_ids"]), c=len(leak["exam_cves"]),
        r=sum(leak["rule1_rows_dropped"].values())))
    print("  exam exploit titles under another EDB ID: {r} rows".format(
        r=leak["exam_title_rows_dropped"]))
    print("  rule 2: {r} rows equal to a TRAM test or eval sentence".format(
        r=sum(leak["rule2_rows_dropped"].values())))
    print("  cross split: {r} val rows equal to a train sentence".format(
        r=sum(report["cross_split_rows_dropped"].values())))
    if leak["exam_edb_ids_not_in_exploitdb_csv"]:
        print("WARNING: exam EDB IDs not in the Exploit-DB CSV:",
              ", ".join(leak["exam_edb_ids_not_in_exploitdb_csv"]))
    print("CVE descriptions: {f} fetched, {s} skipped".format(f=cve_fetched, s=cve_skipped))
    print("ReconMind answer key techniques, train rows")
    for tid, info in report["exam_techniques"].items():
        flag = "" if info["train_rows"] >= report["label_set_min_train_rows"] else (
            "  UNDER {m} ({b} before the label set)".format(
                m=report["label_set_min_train_rows"], b=info["train_rows_before_label_set"]))
        print("  {t:<10} {n:>6}{f}".format(t=tid, n=info["train_rows"], f=flag))


def main(argv=None):
    args = parse_args(argv)
    os.makedirs(CVE_CACHE_DIR, exist_ok=True)

    raw, sources = {}, {}
    for pin in PINNED:
        path = os.path.join(CACHE_DIR, pin["cache"])
        try:
            data = fetch_pinned(pin["url"], pin["sha256"], path)
        except (OSError, http.client.HTTPException) as exc:
            print("ERROR: could not download", pin["url"])
            print(" ", exc)
            return 1
        actual = sha256_hex(data)
        if actual != pin["sha256"]:
            print("ERROR: checksum mismatch for", pin["url"])
            print("  expected", pin["sha256"])
            print("  actual  ", actual)
            print("Nothing was written. If the cached file is bad, delete", path)
            return 1
        raw[pin["source"]] = data
        sources[pin["source"]] = {"url": pin["url"], "commit": pin["commit"],
                                  "sha256": pin["sha256"]}

    try:
        edb_raw = _read_bytes(args.exploitdb_csv)
        with open(ATTACK_PATH) as fh:
            techniques = json.load(fh)["techniques"]
        tram_raw = {name: _read_bytes(os.path.join(TRAM_DIR, name + ".jsonl"))
                    for name in ("train", "val", "test", "eval")}
        tram = {name: parse_jsonl(tram_raw[name].decode("utf-8"), name + ".jsonl")
                for name in tram_raw}
        findings = parse_jsonl(_read_bytes(FINDINGS_PATH).decode("utf-8"), "findings.jsonl")
        exam_edb, exam_titles = exam_exploits(findings)
        attack_bundle = json.loads(raw["attack"].decode("utf-8"))
        kev_data = json.loads(raw["ctid_kev"].decode("utf-8"))
        cve_map = cve_csv_labels(raw["ctid_cve"])  # decoded as utf-8-sig
        edb_entries = exploitdb_entries(edb_raw)  # decoded as utf-8-sig
    except (DataError, OSError, KeyError, ValueError) as exc:
        # Every input is parsed before anything is written, so a bad Exploit-DB
        # header or a missing CTID column or key stops the run with no output files.
        print("ERROR:", exc)
        return 1

    print("Reading {n} CVE descriptions from cvelistV5 (cached after the first run)".format(
        n=len(cve_map)))
    cve_texts, cve_skipped = fetch_cve_texts(list(cve_map), CVE_CACHE_DIR)

    try:
        result = build(attack_bundle, kev_data, cve_map, cve_texts, edb_entries,
                       {"train": tram["train"], "val": tram["val"]},
                       holdout_sentences(tram["test"], tram["eval"]),
                       exam_edb, exam_titles, techniques, SPLIT_SEED, MIN_TRAIN_ROWS)
        table = label_table(result["labels"], techniques)
    except (DataError, KeyError) as exc:
        print("ERROR:", exc)
        return 1

    texts = {name: jsonl_text(result["splits"][name]) for name in SPLITS}
    labels_text = json.dumps(table, indent=1) + "\n"
    manifest = {
        "sources": sources,
        "cvelist": {
            "commit": CVELIST_COMMIT,
            "url_template": CVELIST_URL,
            "requested": len(cve_map),
            "fetched": len(cve_texts),
            "skipped": len(cve_skipped),
            "skipped_cves": dict(sorted(cve_skipped.items(), key=lambda kv: cve_key(kv[0]))),
            "texts_sha256": sha256_hex(json.dumps(cve_texts, sort_keys=True).encode("utf-8")),
        },
        "exploitdb_csv": {"file": os.path.basename(args.exploitdb_csv),
                          "sha256": sha256_hex(edb_raw)},
        "tram_inputs": {name + ".jsonl": sha256_hex(tram_raw[name]) for name in ("train", "val")},
        **result["report"],
        # SHA-256 of each output file, checked by train_attack_mapper_run3.ipynb.
        "outputs": dict({name + ".jsonl": sha256_hex(texts[name].encode("utf-8"))
                         for name in SPLITS},
                        **{"labels.json": sha256_hex(labels_text.encode("utf-8"))}),
    }

    for name in SPLITS:
        _write(os.path.join(OUT_DIR, name + ".jsonl"), texts[name])
    _write(os.path.join(OUT_DIR, "labels.json"), labels_text)
    manifest_path = os.path.join(OUT_DIR, "manifest.json")
    _write(manifest_path, json.dumps(manifest, indent=1) + "\n")
    os.makedirs(os.path.dirname(RESULTS_COPY_PATH), exist_ok=True)
    shutil.copyfile(manifest_path, RESULTS_COPY_PATH)

    print_summary(result["report"], len(cve_texts), len(cve_skipped))
    print("Wrote", OUT_DIR)
    print("Copied the manifest to", RESULTS_COPY_PATH)
    return 0


if __name__ == "__main__":
    sys.exit(main())
