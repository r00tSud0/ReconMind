"""
ReconMind summary checker.

The analyst summary is written by a model, so it is checked by plain code
before it reaches a report:

    - everything before the first "### " heading is dropped (thinking text,
      introductions)
    - it is valid only if its headings are exactly the four required ones,
      in order, and each section has some text under it
    - any EDB-ID that is not in the scan results, and any CVE ID (no tool
      provides CVEs yet), is listed as an unverified reference

No AI and no I/O here, so every rule can be tested on its own.
"""

import re
from collections import namedtuple

REQUIRED_HEADINGS = (
    "### Key findings",
    "### Likely attack path",
    "### MITRE ATT&CK (preliminary)",
    "### Recommended fixes",
)

SummaryCheck = namedtuple("SummaryCheck", "valid text problems unverified_refs")

_HEADING = re.compile(r"^\s{0,3}#{1,6}(?:\s|$)")
_FIRST_SECTION = re.compile(r"^###\s", re.M)
_EDB = re.compile(r"\bEDB(?:[\s-]*ID)?[\s:#-]*(\d+)\b"
                  r"|exploit-db\.com/exploits/(\d+)", re.I)
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)


def strip_preamble(text):
    """The text from the first line starting with "### ", or "" if none."""
    match = _FIRST_SECTION.search(text or "")
    return text[match.start():].strip() if match else ""


def known_edb_ids(scan):
    """Every EDB-ID the exploit lookup returned for this scan."""
    ids = set()
    for port in (scan or {}).get("ports", []):
        for e in port.get("exploits", []) or []:
            edb = str(e.get("edb_id", "") or "").strip()
            if edb:
                ids.add(edb)
    return ids


def find_unverified_refs(text, scan):
    """EDB-IDs not in the scan results and every CVE ID, in order, no repeats."""
    known = known_edb_ids(scan)
    found = []
    for match in _EDB.finditer(text or ""):
        edb = match.group(1) or match.group(2)
        if edb not in known:
            found.append((match.start(), "EDB-" + edb))
    for match in _CVE.finditer(text or ""):
        found.append((match.start(), match.group(0).upper()))
    refs = []
    for _, ref in sorted(found):
        if ref not in refs:
            refs.append(ref)
    return refs


def _sections(text):
    """[(heading, body)] for every heading line in text."""
    sections = []
    for line in text.splitlines():
        if _HEADING.match(line):
            sections.append([line.strip(), []])
        elif sections:
            sections[-1][1].append(line)
    return [(h, "\n".join(body).strip()) for h, body in sections]


def check_summary(text, scan):
    """Strip the preamble and check the structure. Returns a SummaryCheck."""
    body = strip_preamble(text)
    problems = []
    if not body:
        problems.append("no '### ' section heading found")
    else:
        sections = _sections(body)
        headings = tuple(h for h, _ in sections)
        if headings != REQUIRED_HEADINGS:
            problems.append("headings are {h}, expected {r}".format(
                h=list(headings), r=list(REQUIRED_HEADINGS)))
        else:
            for heading, content in sections:
                if not content:
                    problems.append("section '{h}' is empty".format(h=heading))
    return SummaryCheck(not problems, body, problems, find_unverified_refs(body, scan))
