"""
Offline tests for reconmind/ai/metrics.py on hand computed examples.

    python3 -m unittest discover -s tests -v
"""

import unittest

from reconmind.ai.metrics import score

A, B, C, D = "T1001", "T1002", "T1003", "T1004"
LABELS = [A, B, C, D]
OOS = "T9999"  # not in the label set

# Hand computed example:
#   sentence  gold     pred
#   s1        [A]      [A]          exact
#   s2        [A, B]   [A]          B missed
#   s3        []       [OOS]        out of set false positive
#   s4        [B]      [B, C]       C false positive (C has zero support)
#
# A: support 2, tp 2, fp 0, fn 0 -> P 1, R 1, F1 1
# B: support 2, tp 1, fp 0, fn 1 -> P 1, R 0.5, F1 2/3
# C: support 0, fp 1             -> P 0.0, R null, F1 null
# D: support 0, never predicted  -> P null, R null, F1 null
# micro: tp 3, fp 2 (C + OOS), fn 1 -> P 0.6, R 0.75, F1 2/3
# macro over A and B: P 1, R 0.75, F1 5/6
# exact match: 1 of 4 = 0.25
GOLD = [[A], [A, B], [], [B]]
PRED = [[A], [A], [OOS], [B, C]]


class HandComputedTests(unittest.TestCase):

    def setUp(self):
        self.r = score(GOLD, PRED, LABELS)
        self.rows = {row["id"]: row for row in self.r["per_technique"]}

    def test_micro(self):
        m = self.r["micro"]
        self.assertEqual((m["tp"], m["fp"], m["fn"]), (3, 2, 1))
        self.assertAlmostEqual(m["precision"], 0.6)
        self.assertAlmostEqual(m["recall"], 0.75)
        self.assertAlmostEqual(m["f1"], 2 / 3)

    def test_macro_only_supported_techniques(self):
        m = self.r["macro"]
        self.assertEqual(m["n_techniques_averaged"], 2)
        self.assertAlmostEqual(m["precision"], 1.0)
        self.assertAlmostEqual(m["recall"], 0.75)
        self.assertAlmostEqual(m["f1"], 5 / 6)

    def test_exact_match(self):
        self.assertAlmostEqual(self.r["exact_match"], 0.25)

    def test_per_technique_rows(self):
        a, b = self.rows[A], self.rows[B]
        self.assertEqual((a["support"], a["tp"], a["fp"], a["fn"]), (2, 2, 0, 0))
        self.assertAlmostEqual(a["f1"], 1.0)
        self.assertEqual((b["support"], b["tp"], b["fp"], b["fn"]), (2, 1, 0, 1))
        self.assertAlmostEqual(b["recall"], 0.5)
        self.assertAlmostEqual(b["f1"], 2 / 3)

    def test_every_label_has_a_row(self):
        self.assertEqual([row["id"] for row in self.r["per_technique"]], LABELS)

    def test_zero_support_reported_not_dropped(self):
        self.assertEqual(self.r["zero_support_techniques"], [C, D])
        c, d = self.rows[C], self.rows[D]
        self.assertTrue(c["zero_support"])
        self.assertEqual(c["fp"], 1)
        self.assertEqual(c["precision"], 0.0)
        self.assertIsNone(c["recall"])
        self.assertIsNone(c["f1"])
        self.assertTrue(d["zero_support"])
        self.assertIsNone(d["precision"])

    def test_out_of_set_counted_separately_and_in_micro_fp(self):
        self.assertEqual(self.r["out_of_set"], {"count": 1, "ids": {OOS: 1}})
        self.assertNotIn(OOS, self.rows)

    def test_counts(self):
        self.assertEqual((self.r["n_sentences"], self.r["n_labeled"], self.r["n_unlabeled"]),
                         (4, 3, 1))


class EdgeTests(unittest.TestCase):

    def test_all_empty_is_exact_match(self):
        r = score([[], []], [[], []], LABELS)
        self.assertEqual(r["exact_match"], 1.0)
        self.assertEqual(r["micro"]["f1"], 0.0)
        self.assertEqual(r["macro"]["n_techniques_averaged"], 0)

    def test_out_of_set_breaks_exact_match(self):
        r = score([[A]], [[A, OOS]], LABELS)
        self.assertEqual(r["exact_match"], 0.0)
        self.assertAlmostEqual(r["micro"]["precision"], 0.5)
        self.assertAlmostEqual(r["macro"]["precision"], 1.0)  # OOS never enters macro

    def test_duplicates_in_a_list_count_once(self):
        r = score([[A]], [[A, A]], LABELS)
        self.assertEqual(r["micro"]["fp"], 0)
        self.assertEqual(r["exact_match"], 1.0)

    def test_dict_input_matches_list_input(self):
        gold = {"s{i}".format(i=i): g for i, g in enumerate(GOLD)}
        pred = {"s{i}".format(i=i): p for i, p in enumerate(PRED)}
        self.assertEqual(score(gold, pred, LABELS), score(GOLD, PRED, LABELS))

    def test_mismatched_ids_raise(self):
        with self.assertRaises(ValueError):
            score({"a": [A]}, {"b": [A]}, LABELS)

    def test_length_mismatch_raises(self):
        with self.assertRaises(ValueError):
            score([[A]], [], LABELS)

    def test_gold_outside_label_set_raises(self):
        with self.assertRaises(ValueError):
            score([[OOS]], [[]], LABELS)


if __name__ == "__main__":
    unittest.main()
