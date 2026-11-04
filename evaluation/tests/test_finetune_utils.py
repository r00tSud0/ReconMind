"""
Offline tests for evaluation/attack_mapper/finetune_utils.py on hand made examples.

    python3 -m unittest evaluation.tests.test_finetune_utils -v
"""

import unittest

from evaluation.attack_mapper import finetune_utils as fu

A, B, C = "T1001", "T1002", "T1003"
LABELS = [A, B, C]


class MultiHotTests(unittest.TestCase):
    def test_round_trip(self):
        vec = fu.to_multi_hot([A, C], LABELS)
        self.assertEqual(vec, [1, 0, 1])
        self.assertEqual(fu.from_multi_hot(vec, LABELS), [A, C])

    def test_empty_round_trip(self):
        vec = fu.to_multi_hot([], LABELS)
        self.assertEqual(vec, [0, 0, 0])
        self.assertEqual(fu.from_multi_hot(vec, LABELS), [])

    def test_duplicates_and_order_are_normalized(self):
        vec = fu.to_multi_hot([C, A, C], LABELS)
        self.assertEqual(vec, [1, 0, 1])
        self.assertEqual(fu.from_multi_hot(vec, LABELS), [A, C])

    def test_float_vector_back_to_ids(self):
        self.assertEqual(fu.from_multi_hot([0.0, 1.0, 0.0], LABELS), [B])

    def test_unknown_id_raises(self):
        with self.assertRaises(ValueError):
            fu.to_multi_hot(["T9999"], LABELS)

    def test_wrong_length_raises(self):
        with self.assertRaises(ValueError):
            fu.from_multi_hot([1, 0], LABELS)


class PredictTests(unittest.TestCase):
    def test_thresholds_grid(self):
        self.assertEqual(len(fu.THRESHOLDS), 19)
        self.assertEqual(fu.THRESHOLDS[0], 0.05)
        self.assertEqual(fu.THRESHOLDS[-1], 0.95)
        self.assertEqual(fu.THRESHOLDS[2], 0.15)
        self.assertEqual(fu.THRESHOLDS, sorted(fu.THRESHOLDS))

    def test_equal_to_threshold_is_included(self):
        self.assertEqual(fu.predict_ids([0.5, 0.49, 0.9], LABELS, 0.5), [A, C])

    def test_all_below_gives_empty(self):
        self.assertEqual(fu.predict_ids([0.1, 0.2, 0.3], LABELS, 0.5), [])

    def test_predict_all(self):
        rows = [[0.9, 0.0, 0.0], [0.0, 0.0, 0.0]]
        self.assertEqual(fu.predict_all(rows, LABELS, 0.5), [[A], []])

    def test_wrong_length_raises(self):
        with self.assertRaises(ValueError):
            fu.predict_ids([0.9], LABELS, 0.5)


# Hand made sweep example, labels [A, B]:
#   sentence  gold   probs (A, B)
#   s1        [A]    0.9, 0.3
#   s2        [B]    0.2, 0.6
#   s3        []     0.4, 0.1
# t = 0.05:          every ID predicted, tp 2 fp 4 fn 0 -> P 1/3, R 1, F1 0.5
# t = 0.30:          s1 B and s3 A are false positives, tp 2 fp 2 -> F1 2/3
# t = 0.40:          s3 A is a false positive, tp 2 fp 1 -> F1 0.8
# t = 0.45 to 0.60:  perfect, F1 1.0 (a tie, so 0.45 wins)
# t = 0.65:          s2 B missed, tp 1 fn 1 -> F1 2/3
# t = 0.95:          nothing predicted -> F1 0.0
SWEEP_LABELS = [A, B]
SWEEP_GOLD = [[A], [B], []]
SWEEP_PROBS = [[0.9, 0.3], [0.2, 0.6], [0.4, 0.1]]


class SweepTests(unittest.TestCase):
    def setUp(self):
        self.best, self.f1, self.table = fu.sweep_threshold(
            SWEEP_GOLD, SWEEP_PROBS, SWEEP_LABELS)
        self.by_t = {row["threshold"]: row for row in self.table}

    def test_best_is_lowest_on_the_tie(self):
        self.assertEqual(self.best, 0.45)
        self.assertAlmostEqual(self.f1, 1.0)
        for t in (0.45, 0.5, 0.55, 0.6):
            self.assertAlmostEqual(self.by_t[t]["f1"], 1.0)

    def test_table_matches_hand_counts(self):
        self.assertEqual(len(self.table), 19)
        self.assertAlmostEqual(self.by_t[0.05]["precision"], 1 / 3)
        self.assertAlmostEqual(self.by_t[0.05]["recall"], 1.0)
        self.assertAlmostEqual(self.by_t[0.05]["f1"], 0.5)
        self.assertAlmostEqual(self.by_t[0.3]["f1"], 2 / 3)
        self.assertAlmostEqual(self.by_t[0.4]["f1"], 0.8)
        self.assertAlmostEqual(self.by_t[0.65]["f1"], 2 / 3)
        self.assertAlmostEqual(self.by_t[0.95]["f1"], 0.0)

    def test_all_zero_f1_returns_lowest_threshold(self):
        best, f1, _ = fu.sweep_threshold(SWEEP_GOLD, [[0.0, 0.0]] * 3, SWEEP_LABELS)
        self.assertEqual(best, 0.05)
        self.assertEqual(f1, 0.0)

    def test_tie_between_two_given_thresholds(self):
        # Both give F1 1.0; the order passed in must not matter.
        best, _, _ = fu.sweep_threshold(SWEEP_GOLD, SWEEP_PROBS, SWEEP_LABELS,
                                        thresholds=[0.6, 0.5])
        self.assertEqual(best, 0.5)

    def test_length_mismatch_raises(self):
        with self.assertRaises(ValueError):
            fu.sweep_threshold(SWEEP_GOLD, SWEEP_PROBS[:2], SWEEP_LABELS)


class MaxLengthTests(unittest.TestCase):
    def test_exactly_one_percent_stays_short(self):
        lengths = [300] + [100] * 99
        self.assertEqual(fu.choose_max_length(lengths), (256, 0.01))

    def test_over_one_percent_goes_long(self):
        lengths = [300, 300] + [100] * 98
        self.assertEqual(fu.choose_max_length(lengths), (512, 0.02))

    def test_exactly_256_is_not_cut(self):
        self.assertEqual(fu.choose_max_length([256] * 10), (256, 0.0))

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            fu.choose_max_length([])


class PosWeightTests(unittest.TestCase):
    # 10 sentences, 3 labels: label 0 in 5, label 1 in 1, label 2 in none.
    TARGETS = [[1, 1, 0]] + [[1, 0, 0]] * 4 + [[0, 0, 0]] * 5

    def test_ratio_below_cap(self):
        weights = fu.compute_pos_weight(self.TARGETS, cap=30.0)
        self.assertEqual(weights[0], 1.0)   # 5 negatives / 5 positives
        self.assertEqual(weights[1], 9.0)   # 9 negatives / 1 positive

    def test_zero_positives_gets_cap(self):
        weights = fu.compute_pos_weight(self.TARGETS, cap=30.0)
        self.assertEqual(weights[2], 30.0)

    def test_cap_applies(self):
        self.assertEqual(fu.compute_pos_weight(self.TARGETS, cap=4.0), [1.0, 4.0, 4.0])

    def test_one_weight_per_label_as_floats(self):
        weights = fu.compute_pos_weight(self.TARGETS, cap=30)
        self.assertEqual(len(weights), 3)
        self.assertTrue(all(isinstance(w, float) for w in weights))

    def test_common_label_can_go_below_one(self):
        # Present in 3 of 4 sentences: 1 negative / 3 positives.
        weights = fu.compute_pos_weight([[1], [1], [1], [0]], cap=30.0)
        self.assertAlmostEqual(weights[0], 1 / 3)

    def test_float_targets(self):
        self.assertEqual(fu.compute_pos_weight([[1.0], [0.0], [0.0]], cap=30.0), [2.0])

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            fu.compute_pos_weight([], cap=30.0)

    def test_ragged_rows_raise(self):
        with self.assertRaises(ValueError):
            fu.compute_pos_weight([[1, 0], [1]], cap=30.0)

    def test_bad_cap_raises(self):
        with self.assertRaises(ValueError):
            fu.compute_pos_weight(self.TARGETS, cap=0)


if __name__ == "__main__":
    unittest.main()
