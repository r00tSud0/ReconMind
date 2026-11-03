"""
Helpers for Model B (fine tuned SciBERT) in the ATT&CK mapper experiment.
Pure python, no torch, so they are unit tested offline. The Colab notebook
notebooks/train_attack_mapper.ipynb imports them.

    to_multi_hot(ids, labels)            -> [0, 1, 0, ...]
    from_multi_hot(vector, labels)       -> ["T1059", ...]
    predict_ids(probs, labels, t)        -> IDs with probability >= t
    predict_all(prob_rows, labels, t)    -> one ID list per sentence
    sweep_threshold(gold, prob_rows, labels)
                                         -> (threshold, micro F1, table)
    choose_max_length(token_lengths)     -> (256 or 512, share cut at 256)

labels is the ordered label list (the 50 IDs from data/tram/labels.json).
Index i of every vector and probability row belongs to labels[i].

The threshold sweep scores with reconmind/ai/metrics.py, so "micro F1" means
exactly what it means in the final report.
"""

from reconmind.ai import metrics

# 0.05, 0.10, ..., 0.95. Rounded so 0.15 is 0.15, not 0.15000000000000002.
THRESHOLDS = [round(k * 0.05, 2) for k in range(1, 20)]

SHORT_MAX_LENGTH = 256
LONG_MAX_LENGTH = 512
MAX_CUT_FRACTION = 0.01


def _check_length(row, labels, what):
    if len(row) != len(labels):
        raise ValueError("{w} has {n} entries, expected {e} (one per label)".format(
            w=what, n=len(row), e=len(labels)))


def to_multi_hot(ids, labels):
    """A 0/1 list with a 1 at the index of each ID. Unknown IDs raise ValueError."""
    index = {lab: i for i, lab in enumerate(labels)}
    vector = [0] * len(labels)
    for lab in ids:
        if lab not in index:
            raise ValueError("label outside the label set: {l}".format(l=lab))
        vector[index[lab]] = 1
    return vector


def from_multi_hot(vector, labels):
    """IDs whose entry is nonzero, in label order."""
    _check_length(vector, labels, "vector")
    return [lab for lab, v in zip(labels, vector) if v]


def predict_ids(probs, labels, threshold):
    """IDs whose probability is at least the threshold, in label order."""
    _check_length(probs, labels, "probability row")
    return [lab for lab, p in zip(labels, probs) if p >= threshold]


def predict_all(prob_rows, labels, threshold):
    return [predict_ids(row, labels, threshold) for row in prob_rows]


def sweep_threshold(gold, prob_rows, labels, thresholds=THRESHOLDS):
    """
    Try one global threshold for all labels and keep the best micro F1.

    gold is a list of ID lists aligned with prob_rows. Thresholds are tried in
    ascending order and the best is replaced only on a strictly higher F1, so
    ties go to the lowest threshold. Returns (best_threshold, best_f1, table)
    where table has one {threshold, precision, recall, f1} row per threshold.
    """
    if len(gold) != len(prob_rows):
        raise ValueError("gold has {g} sentences, probabilities have {p}".format(
            g=len(gold), p=len(prob_rows)))
    if not thresholds:
        raise ValueError("no thresholds to try")
    best_t, best_f1, table = None, -1.0, []
    for t in sorted(thresholds):
        micro = metrics.score(gold, predict_all(prob_rows, labels, t), labels)["micro"]
        table.append({"threshold": t, "precision": micro["precision"],
                      "recall": micro["recall"], "f1": micro["f1"]})
        if micro["f1"] > best_f1:
            best_t, best_f1 = t, micro["f1"]
    return best_t, best_f1, table


def choose_max_length(token_lengths, short=SHORT_MAX_LENGTH, long=LONG_MAX_LENGTH,
                      max_cut=MAX_CUT_FRACTION):
    """
    (max_length, cut_fraction): short unless more than max_cut of the
    sentences are longer than short tokens, then long. Lengths should count
    the special tokens ([CLS] and [SEP]), as the tokenizer does.
    """
    if not token_lengths:
        raise ValueError("no token lengths given")
    cut = sum(1 for n in token_lengths if n > short) / len(token_lengths)
    return (long if cut > max_cut else short), cut
