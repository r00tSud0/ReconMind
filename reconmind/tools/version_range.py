"""
ReconMind version range checker.

searchsploit matches titles by words, so a query like "Samba 3.0.20" also
returns "Samba < 3.0.20", which does not apply to 3.0.20 at all. These plain
rules read the version expression written right after the product name in an
Exploit-DB title and check the scanned version against it.

Supported forms (alternatives joined by " / " mean affected if any matches):

    A < B       A <= v < B
    < B, <= B   upper bound only
    A           a single version (a shorter one like "2.2" matches as a prefix)
    A/B/C       a list of versions
    3.x         a wildcard
    < A/B/C     one upper bound per branch, the bound of v's major.minor is used

Suffixes are ordered: rc, beta, alpha, pre and dev sort before the release
("3.0.25rc3" < "3.0.25"); any other letter suffix ("4.7p1", "5.0.51a") sorts
after it.

Outcomes:
    affected       the title's range includes the version
    not_affected   the title's range excludes it
    unverified     no version expression right after the product name
                   ("Apache + PHP < 5.4.2", "Apache CXF < 2.5.10"), so the
                   title cannot be checked

No AI and no I/O here, so every rule can be tested on its own.
"""

import re
from collections import namedtuple
from functools import cmp_to_key

AFFECTED = "affected"
NOT_AFFECTED = "not_affected"
UNVERIFIED = "unverified"

Version = namedtuple("Version", "nums wildcard suffix")

_PRE_RELEASE = {"dev": 0, "pre": 1, "alpha": 2, "beta": 3, "rc": 4}
_RELEASE = (1, 0, 0)

_VER = r"\d+(?:\.\d+)*(?:\.[xX*])?(?:[a-zA-Z]+\d*)?(?!\w)"
_VLIST = r"{v}(?:/{v})*".format(v=_VER)
_RANGE = re.compile(r"\s*({v})\s*(<=|<)\s*({l})".format(v=_VER, l=_VLIST))
_UPPER = re.compile(r"\s*(<=|<)\s*({l})".format(l=_VLIST))
_POINTS = re.compile(r"\s*({l})".format(l=_VLIST))
_ALT_SEP = re.compile(r"\s+/\s+")
_TOKEN = re.compile(r"(\d+(?:\.\d+)*)(\.[xX*])?([a-zA-Z]+)?(\d*)")


def parse_version(text):
    """Turn "3.0.25rc3" or "3.x" into a Version, or None if it is not one."""
    match = _TOKEN.fullmatch((text or "").strip())
    if match is None:
        return None
    nums = tuple(int(n) for n in match.group(1).split("."))
    word = (match.group(3) or "").lower()
    number = int(match.group(4) or 0)
    if not word:
        suffix = _RELEASE
    elif word in _PRE_RELEASE:
        suffix = (0, _PRE_RELEASE[word], number)
    else:
        suffix = (2, word, number)
    return Version(nums, bool(match.group(2)), suffix)


def compare(a, b):
    """-1, 0 or 1. Missing parts count as zero, so 3.0 equals 3.0.0."""
    width = max(len(a.nums), len(b.nums))
    ka = (a.nums + (0,) * (width - len(a.nums)), a.suffix)
    kb = (b.nums + (0,) * (width - len(b.nums)), b.suffix)
    return (ka > kb) - (ka < kb)


def _versions(vlist):
    return [parse_version(v) for v in vlist.split("/")]


def _parse_alt(text, pos):
    """One alternative at pos, as (alt, end) or (None, pos)."""
    match = _RANGE.match(text, pos)
    if match:
        return ("range", parse_version(match.group(1)), match.group(2),
                _versions(match.group(3))), match.end()
    match = _UPPER.match(text, pos)
    if match:
        return ("upper", match.group(1), _versions(match.group(2))), match.end()
    match = _POINTS.match(text, pos)
    if match:
        return ("points", _versions(match.group(1))), match.end()
    return None, pos


def parse_expression(title, search_name):
    """
    The alternatives written right after search_name in title, or None when
    the name is missing or is not directly followed by a version expression.
    """
    if not search_name:
        return None
    name = re.search(r"(?<!\w)" + re.escape(search_name) + r"(?!\w)", title or "", re.I)
    if name is None:
        return None
    rest = title[name.end():]
    alt, pos = _parse_alt(rest, 0)
    if alt is None:
        return None
    alts = [alt]
    while True:
        sep = _ALT_SEP.match(rest, pos)
        if sep is None:
            break
        alt, end = _parse_alt(rest, sep.end())
        if alt is None:
            break
        alts.append(alt)
        pos = end
    return alts


def _pick_bound(bounds, v):
    """The bound for v's major.minor branch, else the lowest bound."""
    same = [b for b in bounds if b.nums[:2] == v.nums[:2]]
    return same[0] if same else min(bounds, key=cmp_to_key(compare))


def _below(v, op, bound):
    result = compare(v, bound)
    return result < 0 or (op == "<=" and result == 0)


def _matches(alt, v):
    """Does one alternative include the exact version v?"""
    kind = alt[0]
    if kind == "points":
        for p in alt[1]:
            if p.wildcard or (len(p.nums) < len(v.nums) and p.suffix == _RELEASE):
                if v.nums[:len(p.nums)] == p.nums:
                    return True
            elif compare(p, v) == 0:
                return True
        return False
    if kind == "upper":
        return _below(v, alt[1], _pick_bound(alt[2], v))
    _, low, op, bounds = alt
    return compare(low, v) <= 0 and _below(v, op, _pick_bound(bounds, v))


def _family_matches(alt, fam):
    """Could any version in the major.minor family fam be included?"""
    low_end = Version(fam.nums, False, _RELEASE)
    if len(fam.nums) >= 2:
        next_family = Version((fam.nums[0], fam.nums[1] + 1), False, _RELEASE)
    else:
        next_family = Version((fam.nums[0] + 1,), False, _RELEASE)

    kind = alt[0]
    if kind == "points":
        for p in alt[1]:
            k = min(len(p.nums), len(fam.nums))
            if p.nums[:k] == fam.nums[:k]:
                return True
        return False
    if kind == "upper":
        return _below(low_end, alt[1], _pick_bound(alt[2], fam))
    _, low, op, bounds = alt
    start = low if compare(low, low_end) > 0 else low_end
    return (compare(start, next_family) < 0
            and _below(start, op, _pick_bound(bounds, fam)))


def check(title, search_name, version, family_only=False):
    """
    affected, not_affected or unverified for one Exploit-DB title.

    With family_only, version is treated as a major.minor family and the title
    is only not_affected when its range excludes the whole family.
    """
    alts = parse_expression(title, search_name)
    v = parse_version(version)
    if alts is None or v is None:
        return UNVERIFIED
    if family_only:
        fam = Version(v.nums[:2], False, _RELEASE)
        hit = any(_family_matches(a, fam) for a in alts)
    else:
        hit = any(_matches(a, v) for a in alts)
    return AFFECTED if hit else NOT_AFFECTED
