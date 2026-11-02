"""
Offline tests for scripts/prepare_tram_data.py on a tiny fake dataset.
Nothing is downloaded:

    python3 -m unittest discover -s tests -v
"""

import importlib.util
import json
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "scripts", "prepare_tram_data.py")


def load_script():
    spec = importlib.util.spec_from_file_location("prepare_tram_data", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ptd = load_script()

COMMON = ["T1001", "T1002", "T1003"]
RARE = "T1004"  # in one report only, so many seeds leave it out of train


def fake_raw():
    """10 reports, each with one labeled and two unlabeled sentences."""
    data = []
    for d in range(10):
        title = "report {d}".format(d=d)
        labels = [COMMON[d % 3]] + ([RARE] if d == 9 else [])
        data.append({"sentence": "attack step in {t}".format(t=title),
                     "labels": labels, "doc_title": title})
        for k in range(2):
            data.append({"sentence": "background {k} in {t}".format(k=k, t=title),
                         "labels": [], "doc_title": title})
    return json.dumps(data).encode("utf-8")


ROWS = ptd.load_rows(fake_raw())
LABELS = ptd.label_set(ROWS)
SEEDS = range(50)


def coverage(seed):
    """(all labels in train, labels in test) for one seed, computed directly."""
    train, _, test = ptd.split_docs([r["doc_title"] for r in ROWS], seed)
    in_train = {l for r in ROWS if r["doc_title"] in train for l in r["labels"]}
    in_test = {l for r in ROWS if r["doc_title"] in test for l in r["labels"]}
    return set(LABELS) <= in_train, len(in_test)


class LoadTests(unittest.TestCase):

    def test_rows_get_stable_ids_and_label_set(self):
        self.assertEqual(ROWS[0]["id"], "tram-00001")
        self.assertEqual(len(ROWS), 30)
        self.assertEqual(LABELS, COMMON + [RARE])

    def test_bad_row_raises(self):
        for bad in ([{"sentence": "s", "labels": "T1001", "doc_title": "d"}],
                    [{"sentence": 1, "labels": [], "doc_title": "d"}],
                    [{"sentence": "s", "labels": []}],
                    {"not": "a list"}):
            with self.assertRaises(ptd.DataError):
                ptd.load_rows(json.dumps(bad).encode())

    def test_checksum(self):
        raw = fake_raw()
        self.assertTrue(ptd.sha256_ok(raw, ptd.sha256_hex(raw)))
        self.assertFalse(ptd.sha256_ok(raw + b" ", ptd.sha256_hex(raw)))
        self.assertFalse(ptd.sha256_ok(raw))  # not the pinned TRAM file


class SplitTests(unittest.TestCase):

    def test_split_is_by_report_and_complete(self):
        splits = ptd.split_rows(ROWS, 3)
        titles = {name: {r["doc_title"] for r in part} for name, part in splits.items()}
        self.assertFalse(titles["train"] & titles["val"])
        self.assertFalse(titles["train"] & titles["test"])
        self.assertFalse(titles["val"] & titles["test"])
        self.assertEqual([len(titles[n]) for n in ("train", "val", "test")], [7, 2, 1])
        self.assertEqual(sum(len(p) for p in splits.values()), len(ROWS))

    def test_split_is_deterministic(self):
        titles = [r["doc_title"] for r in ROWS]
        self.assertEqual(ptd.split_docs(titles, 7), ptd.split_docs(list(reversed(titles)), 7))

    def test_choose_seed_skips_seeds_without_full_train_coverage(self):
        seed, cov, valid = ptd.choose_seed(ROWS, LABELS, SEEDS)
        ok = [s for s in SEEDS if coverage(s)[0]]
        self.assertLess(len(ok), len(SEEDS))  # the rare label does knock some out
        self.assertEqual(valid, len(ok))
        self.assertIn(seed, ok)

    def test_choose_seed_max_test_coverage_lowest_seed_on_ties(self):
        seed, cov, _ = ptd.choose_seed(ROWS, LABELS, SEEDS)
        scores = {s: coverage(s)[1] for s in SEEDS if coverage(s)[0]}
        self.assertEqual(cov, max(scores.values()))
        self.assertEqual(seed, min(s for s, c in scores.items() if c == cov))

    def test_no_valid_seed_raises(self):
        with self.assertRaises(ptd.DataError):
            ptd.choose_seed(ROWS, LABELS + ["T1999"], SEEDS)


class EvalTests(unittest.TestCase):

    def test_eval_has_all_labeled_plus_equal_unlabeled(self):
        test_rows = [r for r in ROWS if r["doc_title"] in ("report 0", "report 1")]
        rows, shortfall = ptd.build_eval(test_rows, 0)
        labeled = [r for r in test_rows if r["labels"]]
        self.assertEqual(shortfall, 0)
        self.assertEqual(len(rows), 2 * len(labeled))
        self.assertTrue(all(r in rows for r in labeled))
        self.assertEqual(sum(1 for r in rows if not r["labels"]), len(labeled))

    def test_eval_is_deterministic(self):
        self.assertEqual(ptd.build_eval(ROWS, 0), ptd.build_eval(ROWS, 0))

    def test_shortfall_when_too_few_unlabeled(self):
        rows = [{"id": "a", "labels": ["T1001"]}, {"id": "b", "labels": ["T1002"]},
                {"id": "c", "labels": []}]
        out, shortfall = ptd.build_eval(rows, 0)
        self.assertEqual(len(out), 3)
        self.assertEqual(shortfall, 1)


class LabelTableTests(unittest.TestCase):

    TECHS = {"T1001": {"name": "Data Obfuscation", "deprecated": False, "revoked": False},
             "T1002": {"name": "Data Compressed", "deprecated": False, "revoked": True}}

    def test_names_from_mitre_table_sorted(self):
        table = ptd.label_table(["T1002", "T1001"], self.TECHS)
        self.assertEqual([t["id"] for t in table], ["T1001", "T1002"])
        self.assertEqual(table[0]["name"], "Data Obfuscation")
        self.assertTrue(table[1]["revoked"])

    def test_missing_id_raises_and_names_it(self):
        with self.assertRaises(ptd.DataError) as ctx:
            ptd.label_table(["T1001", "T1999"], self.TECHS)
        self.assertIn("T1999", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
