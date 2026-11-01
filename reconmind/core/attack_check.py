"""
ReconMind ATT&CK check.

Every technique ID the model wrote in its summary (T1234 or T1234.567) is
checked against MITRE's official ATT&CK data, stored locally in
reconmind/data/attack_techniques.json by scripts/update_attack_data.py.

For each ID the name the model wrote with it is taken from the same table
row, or from the same line after the ID. Results:

    verified        the official name (or the sub-technique short name)
                    appears in the name given, case insensitive
    name_mismatch   the ID exists but the name given does not match it
    unknown_id      the ID is not in the MITRE data
    deprecated      MITRE marks the technique deprecated
    revoked         MITRE revoked the technique

No network and no AI here. A missing or unreadable data file means the check
is skipped, never a crash.
"""

import json
import os
import re
from collections import namedtuple

DATA_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "data", "attack_techniques.json")

SKIPPED_MISSING = "ATT&CK check skipped: MITRE data file missing"
SKIPPED_UNREADABLE = "ATT&CK check skipped: MITRE data file unreadable"

AttackRow = namedtuple("AttackRow", "id given official result")
AttackCheck = namedtuple("AttackCheck", "skipped rows")  # skipped: None or a message

_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_EDGE_JUNK = " \t-:;,.()[]|"


def load_techniques(path=DATA_PATH):
    """(techniques dict, None) or (None, skip message)."""
    if not os.path.exists(path):
        return None, SKIPPED_MISSING
    try:
        with open(path) as fh:
            data = json.load(fh)
        techniques = data["techniques"]
        if not isinstance(techniques, dict):
            raise ValueError("techniques is not a mapping")
    except (OSError, ValueError, KeyError, TypeError):
        return None, SKIPPED_UNREADABLE
    return techniques, None


def _clean_name(text):
    text = re.sub(r"[*_`]", "", text or "")
    text = " ".join(text.split())
    return text.strip(_EDGE_JUNK)


def _names_on_line(line):
    """[(id, name given)] for every technique ID on one line."""
    matches = list(_TECHNIQUE.finditer(line))
    if not matches:
        return []
    found = []
    if line.lstrip().startswith("|"):
        cells = line.strip().strip("|").split("|")
        for i, cell in enumerate(cells):
            for m in _TECHNIQUE.finditer(cell):
                name = _clean_name(cell[m.end():])
                if not name:
                    rest = [_clean_name(c) for c in cells[i + 1:]]
                    rest = [c for c in rest if c and not _TECHNIQUE.fullmatch(c)]
                    name = rest[0] if rest else ""
                found.append((m.group(0), name))
        return found
    for n, m in enumerate(matches):
        end = matches[n + 1].start() if n + 1 < len(matches) else len(line)
        found.append((m.group(0), _clean_name(line[m.end():end])))
    return found


def find_techniques(text):
    """[(id, name given)] in order of appearance, no repeated pairs."""
    pairs = []
    for line in (text or "").splitlines():
        for pair in _names_on_line(line):
            if pair not in pairs:
                pairs.append(pair)
    return pairs


def _norm(text):
    return " ".join((text or "").lower().split())


def classify(technique_id, given, techniques):
    """(official name, result) for one ID and the name given with it."""
    entry = techniques.get(technique_id)
    if not entry:
        return "", "unknown_id"
    official = entry.get("name", "")
    if entry.get("revoked"):
        return official, "revoked"
    if entry.get("deprecated"):
        return official, "deprecated"
    given_n = _norm(given)
    candidates = [_norm(official)]
    if "." in technique_id and entry.get("short_name"):
        candidates.append(_norm(entry["short_name"]))
    if given_n and any(c and c in given_n for c in candidates):
        return official, "verified"
    return official, "name_mismatch"


def check_attack(text, path=DATA_PATH):
    """AttackCheck for every technique ID in text."""
    techniques, skipped = load_techniques(path)
    if skipped:
        return AttackCheck(skipped, [])
    rows = []
    for technique_id, given in find_techniques(text):
        official, result = classify(technique_id, given, techniques)
        rows.append(AttackRow(technique_id, given, official, result))
    return AttackCheck(None, rows)
