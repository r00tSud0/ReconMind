"""
Download MITRE's official Enterprise ATT&CK data and write the local lookup
table used by reconmind/core/attack_check.py.

    python3 scripts/update_attack_data.py

Keeps only attack-pattern objects and writes reconmind/data/attack_techniques.json:

    {
      "attack_version": "17.1",
      "downloaded": "2026-11-01",
      "source": "<url>",
      "techniques": {
        "T1021.004": {"name": "Remote Services: SSH", "short_name": "SSH",
                      "deprecated": false, "revoked": false},
        ...
      }
    }

Sub-techniques get the full name "Parent: Sub". Standard library only.
"""

import json
import os
import sys
import urllib.request
from datetime import date

SOURCE_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
              "master/enterprise-attack/enterprise-attack.json")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH = os.path.join(REPO_ROOT, "reconmind", "data", "attack_techniques.json")


def _attack_id(obj):
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def _attack_version(bundle):
    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection" and obj.get("x_mitre_version"):
            return str(obj["x_mitre_version"])
    return "unknown"


def build_table(bundle, downloaded=None, source=SOURCE_URL):
    """The JSON-ready table for a STIX bundle dict. Pure, no I/O."""
    raw = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        tid = _attack_id(obj)
        if not tid:
            continue
        entry = {
            "short_name": obj.get("name", ""),
            "deprecated": bool(obj.get("x_mitre_deprecated", False)),
            "revoked": bool(obj.get("revoked", False)),
        }
        current = raw.get(tid)
        # If an ID appears twice, the active entry wins.
        if current is None or (current["deprecated"] or current["revoked"]) and not (
                entry["deprecated"] or entry["revoked"]):
            raw[tid] = entry

    techniques = {}
    for tid in sorted(raw):
        entry = raw[tid]
        name = entry["short_name"]
        if "." in tid:
            parent = raw.get(tid.split(".", 1)[0])
            if parent:
                name = "{p}: {s}".format(p=parent["short_name"], s=entry["short_name"])
        techniques[tid] = {
            "name": name,
            "short_name": entry["short_name"],
            "deprecated": entry["deprecated"],
            "revoked": entry["revoked"],
        }

    return {
        "attack_version": _attack_version(bundle),
        "downloaded": downloaded or date.today().isoformat(),
        "source": source,
        "techniques": techniques,
    }


def main():
    print("Downloading", SOURCE_URL)
    with urllib.request.urlopen(SOURCE_URL, timeout=120) as resp:
        bundle = json.load(resp)
    table = build_table(bundle)
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w") as fh:
        json.dump(table, fh, indent=1, sort_keys=True)
        fh.write("\n")
    techs = table["techniques"].values()
    print("ATT&CK version {v}: {n} techniques ({d} deprecated, {r} revoked)".format(
        v=table["attack_version"], n=len(table["techniques"]),
        d=sum(t["deprecated"] for t in techs), r=sum(t["revoked"] for t in techs)))
    print("Wrote", OUT_PATH)
    return 0


if __name__ == "__main__":
    sys.exit(main())
