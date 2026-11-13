"""
ReconMind report history.

Every agent run gets its own folder, reports/<run id>/, holding:

    report.md      the Markdown report
    scan.json      the scan plan plus the structured results, without raw evidence
    evidence.json  the raw tool output (raw_xml, raw_json, raw_jsonl), kept apart

and one entry is appended to reports/index.json. Every JSON file is written
to a temp file in the same folder and then renamed over the target, so a crash
mid write never leaves a half written index. Flat report files from older
versions (reports/recon_*.md) are never touched and keep working.

Finding counts in the index cover risk flags (only when Exploit Hunt ran),
nuclei findings and testssl.sh findings. NVD CVE matches are not counted:
they match the upstream version only and are not confirmed findings.
"""

import json
import os
import re
import tempfile
from collections import namedtuple
from datetime import datetime

from reconmind.core import report as report_mod
from reconmind.tools.risky_services import flag_ports

INDEX_NAME = "index.json"
REPORT_NAME = "report.md"
SCAN_NAME = "scan.json"
EVIDENCE_NAME = "evidence.json"
EVIDENCE_KEYS = ("raw_xml", "raw_json", "raw_jsonl")
SEVERITIES = ("critical", "high", "medium", "low")
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
MAX_RUN_ID_TRIES = 100

RunRecord = namedtuple("RunRecord", "run_id folder report_path entry")


def new_run_id(target, when):
    """"<YYYYmmdd_HHMMSS>_<target>", with anything unusual in target made "_"."""
    safe = re.sub(r"[^A-Za-z0-9.]", "_", str(target)) or "unknown"
    return "{s}_{t}".format(s=when.strftime("%Y%m%d_%H%M%S"), t=safe)


def _make_run_folder(report_dir, base_id):
    """Create a new, empty run folder. Return (run id, folder path)."""
    for n in range(1, MAX_RUN_ID_TRIES + 1):
        run_id = base_id if n == 1 else "{b}_{n}".format(b=base_id, n=n)
        folder = os.path.join(report_dir, run_id)
        try:
            os.makedirs(folder)
        except FileExistsError:
            continue
        return run_id, folder
    raise RuntimeError("Could not create a new run folder for {b}.".format(b=base_id))


def split_evidence(value):
    """
    Return (clean, evidence) for a scan result. clean is a copy without any
    raw_xml, raw_json or raw_jsonl key, at any depth. evidence mirrors the
    path to every one of them, e.g. {"raw_xml": [...], "tls": {443:
    {"raw_json": {...}}}}. The input is not changed.
    """
    if isinstance(value, dict):
        clean, evidence = {}, {}
        for key, item in value.items():
            if key in EVIDENCE_KEYS:
                evidence[key] = item
                continue
            clean[key], found = split_evidence(item)
            if found:
                evidence[key] = found
        return clean, evidence
    if isinstance(value, (list, tuple)):
        clean, evidence = [], {}
        for index, item in enumerate(value):
            part, found = split_evidence(item)
            clean.append(part)
            if found:
                evidence[str(index)] = found
        return clean, evidence
    return value, {}


def finding_counts(scan, plan=None):
    """{"critical", "high", "medium", "low"} counts for one scan."""
    counts = dict.fromkeys(SEVERITIES, 0)

    def add(severity):
        key = str(severity or "").strip().lower()
        if key in counts:
            counts[key] += 1

    if plan is None or plan.has("exploits"):
        for _, flag in flag_ports(scan.get("ports") or []):
            add(flag.get("severity"))
    for key in ("nuclei", "tls"):
        for result in (scan.get(key) or {}).values():
            if isinstance(result, dict) and result.get("status") == "ok":
                for finding in result.get("findings") or []:
                    add(finding.get("severity"))
    return counts


def _write_json(path, data):
    """Write JSON to a temp file in the same folder, then rename it over path."""
    folder = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=folder, prefix="." + os.path.basename(path) + ".",
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2, default=str)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_index(report_dir=None):
    """Every index entry, oldest first. [] when there is no index yet."""
    path = os.path.join(report_dir or report_mod.REPORT_DIR, INDEX_NAME)
    if not os.path.exists(path):
        return []
    with open(path) as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise ValueError("{p} does not hold a list.".format(p=path))
    return data


def _entries_for_append(index_path, run_id):
    """
    The current entries. An index that cannot be read is moved aside to
    index.json.bad-<run id>, never overwritten, and a new list is started.
    """
    try:
        return read_index(os.path.dirname(index_path))
    except (OSError, ValueError):
        os.replace(index_path, "{p}.bad-{r}".format(p=index_path, r=run_id))
        return []


def save_run(scan, plan=None, started=None, finished=None, report_dir=None, **report_kwargs):
    """
    Save one run: its folder with report.md, scan.json and evidence.json, and
    one new entry in index.json. report_kwargs go to build_report
    (analyst_summary, unverified_refs, summary_failed, rate_limited,
    attack_check). started and finished are datetimes; they default to now.
    Return a RunRecord.
    """
    report_dir = report_dir or report_mod.REPORT_DIR
    started = started or datetime.now()
    os.makedirs(report_dir, exist_ok=True)
    target = scan.get("target", "unknown")
    run_id, folder = _make_run_folder(report_dir, new_run_id(target, started))

    report_path = report_mod.build_report(scan, plan=plan,
                                          path=os.path.join(folder, REPORT_NAME),
                                          **report_kwargs)
    clean, evidence = split_evidence(scan)
    plan_data = plan.to_dict() if plan is not None else None
    _write_json(os.path.join(folder, SCAN_NAME),
                {"run_id": run_id, "plan": plan_data, "results": clean})
    _write_json(os.path.join(folder, EVIDENCE_NAME), {"run_id": run_id, "evidence": evidence})

    finished = finished or datetime.now()
    entry = {
        "run_id": run_id,
        "target": target,
        "preset": plan.preset if plan is not None else None,
        "actions": list(plan.actions) if plan is not None else [],
        "ports_spec": plan.ports if plan is not None else None,
        "started": started.strftime(TIME_FORMAT),
        "finished": finished.strftime(TIME_FORMAT),
        "status": scan.get("status", "unknown"),
        "open_ports": len(scan.get("ports") or []),
        "findings": finding_counts(scan, plan),
    }
    index_path = os.path.join(report_dir, INDEX_NAME)
    entries = _entries_for_append(index_path, run_id)
    entries.append(entry)
    _write_json(index_path, entries)
    return RunRecord(run_id, folder, report_path, entry)
