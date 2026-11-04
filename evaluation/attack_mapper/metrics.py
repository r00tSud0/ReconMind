"""
Multi-label scoring for the ATT&CK mapper experiment. Pure python, no I/O.

    score(gold, pred, labels) -> dict (JSON ready)

gold and pred are either lists of ID lists aligned by index, or dicts keyed
by sentence id (the key sets must match). labels is the label set (the 50
TRAM technique IDs).

Definitions:
  micro       precision, recall, F1 over all (sentence, ID) pairs. A
              predicted ID outside the label set counts as a false positive.
  macro       mean precision, recall, F1 over the techniques with support > 0
              in gold. Out of set IDs have no row, so they never enter macro.
  exact_match share of sentences whose predicted set equals the gold set.
              Empty equals empty counts as a match. An out of set ID breaks it.
  per_technique
              one row per label: support, tp, fp, fn, precision, recall, f1.
              A zero support technique keeps its row with zero_support true,
              recall and f1 null, and precision null if it was never
              predicted, else 0.0 (every prediction is a false positive).
  out_of_set  total count of predicted out of set IDs and a count per ID.

Zero division: when a denominator is 0 on a supported technique (or in
micro), the value is 0.0.
"""

from collections import Counter


def _align(gold, pred):
    if isinstance(gold, dict) or isinstance(pred, dict):
        if not (isinstance(gold, dict) and isinstance(pred, dict)):
            raise ValueError("gold and pred must both be lists or both be dicts")
        if set(gold) != set(pred):
            missing = sorted(set(gold) - set(pred))[:5]
            extra = sorted(set(pred) - set(gold))[:5]
            raise ValueError("sentence ids differ (missing from pred {m}, extra in pred {e})"
                             .format(m=missing, e=extra))
        keys = sorted(gold)
        return [gold[k] for k in keys], [pred[k] for k in keys]
    if len(gold) != len(pred):
        raise ValueError("gold has {g} sentences, pred has {p}".format(g=len(gold), p=len(pred)))
    return list(gold), list(pred)


def _div(a, b):
    return a / b if b else 0.0


def _f1(p, r):
    return _div(2 * p * r, p + r)


def score(gold, pred, labels):
    gold, pred = _align(gold, pred)
    label_set = set(labels)
    tp, fp, fn, support = Counter(), Counter(), Counter(), Counter()
    out_of_set = Counter()
    exact = 0

    for g, p in zip(gold, pred):
        g, p = set(g), set(p)
        unknown_gold = g - label_set
        if unknown_gold:
            raise ValueError("gold label outside the label set: {u}".format(
                u=sorted(unknown_gold)))
        if g == p:
            exact += 1
        for lab in g:
            support[lab] += 1
            if lab in p:
                tp[lab] += 1
            else:
                fn[lab] += 1
        for lab in p - g:
            if lab in label_set:
                fp[lab] += 1
            else:
                out_of_set[lab] += 1

    n_oos = sum(out_of_set.values())
    tp_all, fp_all, fn_all = sum(tp.values()), sum(fp.values()) + n_oos, sum(fn.values())
    micro_p, micro_r = _div(tp_all, tp_all + fp_all), _div(tp_all, tp_all + fn_all)

    rows, zero_support = [], []
    for lab in sorted(label_set):
        row = {"id": lab, "support": support[lab], "tp": tp[lab], "fp": fp[lab], "fn": fn[lab]}
        if support[lab] == 0:
            zero_support.append(lab)
            row.update(zero_support=True,
                       precision=0.0 if fp[lab] else None, recall=None, f1=None)
        else:
            p = _div(tp[lab], tp[lab] + fp[lab])
            r = _div(tp[lab], tp[lab] + fn[lab])
            row.update(zero_support=False, precision=p, recall=r, f1=_f1(p, r))
        rows.append(row)

    supported = [r for r in rows if not r["zero_support"]]
    n_sup = len(supported)
    macro = {
        "precision": _div(sum(r["precision"] for r in supported), n_sup),
        "recall": _div(sum(r["recall"] for r in supported), n_sup),
        "f1": _div(sum(r["f1"] for r in supported), n_sup),
        "n_techniques_averaged": n_sup,
    }

    n = len(gold)
    n_labeled = sum(1 for g in gold if g)
    return {
        "n_sentences": n,
        "n_labeled": n_labeled,
        "n_unlabeled": n - n_labeled,
        "micro": {"precision": micro_p, "recall": micro_r, "f1": _f1(micro_p, micro_r),
                  "tp": tp_all, "fp": fp_all, "fn": fn_all},
        "macro": macro,
        "exact_match": _div(exact, n),
        "out_of_set": {"count": n_oos, "ids": dict(sorted(out_of_set.items()))},
        "zero_support_techniques": zero_support,
        "per_technique": rows,
    }
