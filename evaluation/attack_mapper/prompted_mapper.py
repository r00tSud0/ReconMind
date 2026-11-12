"""
Model A for the ATT&CK mapper experiment: a prompted LLM.

Sentences are sent in batches with the 50 TRAM technique IDs and their
official names. The model must answer JSON only, one key per numbered
sentence:

    {"1": ["T1190"], "2": [], ...}

A batch whose answer cannot be parsed is retried once, then recorded as
failed. A failed batch is never guessed: when scoring, its sentences get an
empty prediction, so their gold labels count as false negatives.

Every finished batch is appended as one JSON line to a raw results file, so a
run that stops (rate limit, network error, Ctrl-C) resumes where it left off.
llm.RateLimited and other client errors propagate to the caller untouched.

Reasoning models spend completion tokens on hidden reasoning before the JSON,
so MAX_TOKENS is generous. Each record keeps finish_reason and token counts
for every attempt, and a batch that failed because the length budget ran out
is reported as such.
"""

import json
import os
import re

from reconmind.agent.llm import response_info

MAX_TOKENS = 16000  # reasoning models spend much of this before the JSON answer
TEMPERATURE = 0
LENGTH_HINT = "batch {n}: model ran out of length budget (raise --max-tokens)"

_FENCE = re.compile(r"```(?:json|JSON)?\s*(.*?)```", re.DOTALL)


class MapperError(RuntimeError):
    """The raw results file cannot be used with this eval set."""


# ---- prompt and parsing --------------------------------------------------

def build_prompt(sentences, label_table):
    """(system, user) for one batch. label_table rows have id and name."""
    techniques = "\n".join("{i}  {n}".format(i=t["id"], n=t["name"]) for t in label_table)
    system = (
        "You map sentences from cyber threat intelligence reports to MITRE ATT&CK "
        "techniques.\n\n"
        "Use only these technique IDs:\n" + techniques + "\n\n"
        "For each numbered sentence, list every technique from the list above that the "
        "sentence describes. Most sentences describe none; give an empty list for those. "
        "Do not use IDs that are not in the list.\n\n"
        "Answer with JSON only, no prose and no code fence. One key per sentence number, "
        "each value a list of IDs, for example:\n"
        '{"1": ["T1190"], "2": [], "3": ["T1059.001", "T1105"]}'
    )
    user = "Sentences:\n" + "\n".join(
        "{n}. {s}".format(n=n, s=" ".join(s.split())) for n, s in enumerate(sentences, 1))
    return system, user


def _candidates(text):
    for m in _FENCE.finditer(text):
        yield m.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        yield text[start:end + 1]


def parse_response(text, n):
    """
    A list of n ID lists, or None if the answer is not valid. IDs are
    stripped and uppercased and kept even when outside the label set.
    """
    if not isinstance(text, str):
        return None
    for chunk in _candidates(text):
        try:
            data = json.loads(chunk)
        except ValueError:
            continue
        if not isinstance(data, dict):
            continue
        out = []
        for i in range(1, n + 1):
            value = data.get(str(i))
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                out = None
                break
            out.append(sorted({x.strip().upper() for x in value if x.strip()}))
        if out is not None:
            return out
    return None


def _text(response):
    return "\n".join(getattr(b, "text", "") for b in getattr(response, "content", []) or []
                     if getattr(b, "type", "") == "text")


def ran_out_of_length(rec):
    """True when a failed batch had an attempt that stopped for length."""
    return rec.get("status") == "failed" and any(
        a.get("empty_reason") == "length" or a.get("finish_reason") in ("length", "max_tokens")
        for a in rec.get("attempts", []))


def classify_batch(client, model, rows, label_table, max_tokens=MAX_TOKENS):
    """
    One record for a batch of eval rows: status "ok" with predictions, or
    status "failed" with the raw answers after one retry. Every record lists
    finish_reason and token counts for each attempt under "attempts".
    """
    system, user = build_prompt([r["sentence"] for r in rows], label_table)
    ids = [r["id"] for r in rows]
    raws, attempts = [], []
    for _attempt in range(2):
        response = client.messages.create(
            model=model, system=system, max_tokens=max_tokens, temperature=TEMPERATURE,
            messages=[{"role": "user", "content": user}])
        attempts.append(response_info(response))
        text = _text(response)
        parsed = parse_response(text, len(rows))
        if parsed is not None:
            return {"batch_ids": ids, "status": "ok", "attempts": attempts,
                    "predictions": dict(zip(ids, parsed))}
        raws.append(text[:4000])
    return {"batch_ids": ids, "status": "failed", "predictions": {}, "raw": raws,
            "attempts": attempts}


# ---- raw results file ----------------------------------------------------

def read_records(path):
    """Records from a JSONL file. A truncated or broken line is skipped."""
    records = []
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict) and isinstance(rec.get("batch_ids"), list):
                    records.append(rec)
    except FileNotFoundError:
        pass
    return records


def check_records(records, eval_sha256):
    for rec in records:
        if rec.get("eval_sha256") != eval_sha256:
            raise MapperError(
                "raw results were made on a different eval set (eval sha256 {a}, "
                "current {b}). Move the raw file away to start over.".format(
                    a=rec.get("eval_sha256"), b=eval_sha256))


def sentence_state(records):
    """{sentence id: (status, prediction list)}; the latest record wins."""
    state = {}
    for rec in records:
        preds = rec.get("predictions") or {}
        for sid in rec["batch_ids"]:
            if rec.get("status") == "ok" and sid in preds:
                state[sid] = ("ok", preds[sid])
            else:
                state[sid] = ("failed", [])
    return state


def progress(eval_rows, state):
    ids = [r["id"] for r in eval_rows]
    done = [i for i in ids if i in state]
    return {"total": len(ids), "done": len(done),
            "failed": sum(1 for i in done if state[i][0] == "failed")}


def predictions(eval_rows, state):
    """{sentence id: ID list} for scoring. Failed sentences predict nothing."""
    return {r["id"]: list(state[r["id"]][1]) for r in eval_rows}


def run(client, model, eval_rows, label_table, raw_path, eval_sha256,
        batch_size=25, retry_failed=False, log=print, max_tokens=MAX_TOKENS,
        max_batches=None):
    """
    Classify every eval sentence not yet done (and failed ones when
    retry_failed), appending one record per batch to raw_path. max_batches
    stops after that many batches (None sends them all). Returns the final
    sentence state. Client errors, including llm.RateLimited, propagate;
    finished batches are already on disk.
    """
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1")
    if max_batches is not None and max_batches < 1:
        raise ValueError("max_batches must be at least 1")
    records = read_records(raw_path)
    check_records(records, eval_sha256)
    state = sentence_state(records)

    todo = [r for r in eval_rows
            if r["id"] not in state or (retry_failed and state[r["id"]][0] == "failed")]
    batches = [todo[i:i + batch_size] for i in range(0, len(todo), batch_size)]
    if batches:
        log("{t} sentences to classify in {b} batches".format(t=len(todo), b=len(batches)))
    if max_batches is not None and len(batches) > max_batches:
        batches = batches[:max_batches]
        log("sending only the first {m} (max batches)".format(m=max_batches))

    # A crash mid write can leave a partial last line with no newline.
    # End it so the next record starts on its own line.
    needs_newline = False
    if os.path.exists(raw_path) and os.path.getsize(raw_path) > 0:
        with open(raw_path, "rb") as fh:
            fh.seek(-1, os.SEEK_END)
            needs_newline = fh.read(1) != b"\n"

    with open(raw_path, "a") as fh:
        if needs_newline:
            fh.write("\n")
        for n, batch in enumerate(batches, 1):
            rec = classify_batch(client, model, batch, label_table, max_tokens=max_tokens)
            rec.update(model=model, eval_sha256=eval_sha256, max_tokens=max_tokens)
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
            fh.flush()
            state.update(sentence_state([rec]))
            p = progress(eval_rows, state)
            log("batch {n}/{b} {s}  ({d} of {t} sentences done)".format(
                n=n, b=len(batches), s=rec["status"], d=p["done"], t=p["total"]))
            if ran_out_of_length(rec):
                log(LENGTH_HINT.format(n=n))
    return state
