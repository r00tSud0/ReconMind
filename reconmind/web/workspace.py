"""
The analyst's own work, kept next to the tool reports and never mixed into
them: notes about a target, and reports the analyst writes ("Your reports").

    <report_dir>/.workspace/notes/<key>.json     {"folder", "notes": [...]}
    <report_dir>/.workspace/reports/<id>.json    one analyst report

A folder is a Targets folder name: a target address or a code input's name.
Files are named by a hash of it (key), so no folder name ever becomes part of
a path. Report ids are random hex. Every write goes to a temp file that is
renamed into place, so a crash never leaves half a file.

The tool reports in <report_dir>/<run id>/ are only ever read here: a report
started from a scan copies its findings, and the scan's own files stay as the
tools wrote them.

Everything the browser sends is checked: known keys only, text only, every
field and list capped. Anything else raises WorkspaceError.
"""

import hashlib
import json
import os
import re
import secrets
import tempfile
import threading
from datetime import datetime

from reconmind.core.scan_plan import ACTIONS
from reconmind.web import runs

FOLDER = ".workspace"
MAX_FOLDER = 200
MAX_NOTE = 5000
MAX_NOTES = 500
MAX_FINDINGS = 200
REPORT_ID = re.compile(r"[0-9a-f]{16}")
NOTE_ID = re.compile(r"[0-9a-f]{12}")
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

SEVERITIES = ("critical", "high", "medium", "low", "info")
STATUSES = ("draft", "review", "final")
CLASSIFICATIONS = ("confidential", "internal", "public")
FINDING_STATUSES = ("open", "fixed", "accepted", "false_positive")
RISKS = ("critical", "high", "medium", "low", "none")

# Report fields: name -> longest text allowed.
TEXT_FIELDS = {
    "title": 200, "client": 200, "prepared_by": 120, "reviewed_by": 120, "contact": 200,
    "report_date": 40, "assessment_type": 80, "testing_started": 40, "testing_ended": 40,
    "in_scope": 2000, "out_of_scope": 2000, "tools": 1000, "method": 6000,
    "limitations": 3000, "authorization": 1000, "summary": 8000, "recommendations": 6000,
    "attack_path": 6000, "conclusion": 6000, "signed_by": 120, "signed_date": 40,
}
CHOICE_FIELDS = {"status": STATUSES, "classification": CLASSIFICATIONS, "overall_risk": RISKS}
FINDING_TEXT = {
    "title": 300, "affected": 200, "port": 60, "cves": 400, "attack": 200, "cvss": 120,
    "description": 6000, "impact": 3000, "evidence": 8000, "reproduce": 4000,
    "recommendation": 4000, "references": 2000, "fix_by": 40, "owner": 120,
}
_lock = threading.Lock()


class WorkspaceError(ValueError):
    """A request the workspace refuses; the message says why."""


def _now():
    return datetime.now().strftime(TIME_FORMAT)


def _write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".part-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        raise WorkspaceError("A saved file could not be read: " + os.path.basename(path))
    return data if isinstance(data, dict) else None


def check_folder(folder):
    if not isinstance(folder, str) or not folder.strip():
        raise WorkspaceError("Choose a target folder.")
    folder = folder.strip()
    if len(folder) > MAX_FOLDER or any(ord(c) < 32 for c in folder):
        raise WorkspaceError("That is not a target folder name.")
    return folder


def _key(folder):
    return hashlib.sha256(folder.encode("utf-8")).hexdigest()[:32]


def _text(value, limit, name):
    if value is None:
        return ""
    if not isinstance(value, str):
        raise WorkspaceError(name + " must be text.")
    value = value.replace("\r\n", "\n").replace("\x00", "")
    if len(value) > limit:
        raise WorkspaceError("{n} is too long (at most {l} characters).".format(n=name, l=limit))
    return value


class Workspace:
    def __init__(self, report_dir):
        self.report_dir = report_dir
        self.root = os.path.join(report_dir, FOLDER)

    # ---- notes -----------------------------------------------------------

    def _notes_path(self, folder):
        return os.path.join(self.root, "notes", _key(folder) + ".json")

    def notes(self, folder):
        folder = check_folder(folder)
        data = _read_json(self._notes_path(folder)) or {}
        notes = [n for n in data.get("notes", []) if isinstance(n, dict)]
        return sorted(notes, key=lambda n: str(n.get("created", "")), reverse=True)

    def save_note(self, folder, text, note_id=None):
        folder = check_folder(folder)
        text = _text(text, MAX_NOTE, "A note").strip()
        if not text:
            raise WorkspaceError("Write something in the note first.")
        with _lock:
            path = self._notes_path(folder)
            data = _read_json(path) or {}
            notes = [n for n in data.get("notes", []) if isinstance(n, dict)]
            if note_id is None:
                if len(notes) >= MAX_NOTES:
                    raise WorkspaceError("This target has {m} notes, the most it can keep. "
                                         "Delete one first.".format(m=MAX_NOTES))
                note = {"id": secrets.token_hex(6), "created": _now(), "updated": _now(),
                        "text": text}
                notes.append(note)
            else:
                note = next((n for n in notes if n.get("id") == note_id), None)
                if note is None:
                    raise WorkspaceError("That note no longer exists.")
                note.update(text=text, updated=_now())
            _write_json(path, {"folder": folder, "notes": notes})
            return note

    def delete_note(self, folder, note_id):
        folder = check_folder(folder)
        if not isinstance(note_id, str) or not NOTE_ID.fullmatch(note_id):
            raise WorkspaceError("That note no longer exists.")
        with _lock:
            path = self._notes_path(folder)
            data = _read_json(path) or {}
            notes = [n for n in data.get("notes", []) if isinstance(n, dict)]
            kept = [n for n in notes if n.get("id") != note_id]
            if len(kept) == len(notes):
                raise WorkspaceError("That note no longer exists.")
            _write_json(path, {"folder": folder, "notes": kept})

    # ---- analyst reports -------------------------------------------------

    def _report_path(self, report_id):
        if not isinstance(report_id, str) or not REPORT_ID.fullmatch(report_id):
            return None
        return os.path.join(self.root, "reports", report_id + ".json")

    def reports(self, folder):
        """Summaries of the folder's analyst reports, newest change first."""
        folder = check_folder(folder)
        found = []
        directory = os.path.join(self.root, "reports")
        if not os.path.isdir(directory):
            return found
        for name in os.listdir(directory):
            if not name.endswith(".json") or not REPORT_ID.fullmatch(name[:-5]):
                continue
            try:
                data = _read_json(os.path.join(directory, name))
            except WorkspaceError:
                continue
            if not data or data.get("folder") != folder:
                continue
            fields = data.get("fields") if isinstance(data.get("fields"), dict) else {}
            found.append({"id": data.get("id"), "title": fields.get("title", ""),
                          "status": fields.get("status", "draft"),
                          "overall_risk": fields.get("overall_risk", ""),
                          "findings": len(data.get("findings") or []),
                          "from_run": data.get("from_run"),
                          "created": data.get("created"), "updated": data.get("updated")})
        return sorted(found, key=lambda r: str(r.get("updated", "")), reverse=True)

    def report(self, report_id):
        path = self._report_path(report_id)
        data = _read_json(path) if path else None
        if not data:
            return None
        return data

    def create_report(self, folder, from_run=None):
        """A new draft. From a run, it starts with that scan's findings and facts."""
        folder = check_folder(folder)
        fields = {name: "" for name in TEXT_FIELDS}
        fields.update(status="draft", classification="confidential", overall_risk="",
                      title="Assessment of " + folder, report_date=_now()[:10],
                      authorization="Every target was checked against the lab allowlist "
                                    "before any packet was sent.")
        findings = []
        source = None
        if from_run is not None:
            if not isinstance(from_run, str) or not runs.valid_run_id(from_run):
                raise WorkspaceError("There is no scan with that id.")
            view = runs.report_view(self.report_dir, from_run)
            if view is None:
                raise WorkspaceError("There is no scan with that id.")
            source = _prefill(fields, findings, view, folder)
        report_id = secrets.token_hex(8)
        data = {"id": report_id, "folder": folder, "from_run": from_run, "source": source,
                "created": _now(), "updated": _now(), "fields": fields, "findings": findings}
        _write_json(self._report_path(report_id), data)
        return data

    def save_report(self, report_id, body):
        path = self._report_path(report_id)
        with _lock:
            data = _read_json(path) if path else None
            if not data:
                raise WorkspaceError("That report no longer exists.")
            fields = body.get("fields")
            findings = body.get("findings")
            if not isinstance(fields, dict) or not isinstance(findings, list):
                raise WorkspaceError("The report must have fields and findings.")
            data["fields"] = clean_fields(fields)
            data["findings"] = clean_findings(findings)
            data["updated"] = _now()
            _write_json(path, data)
            return data

    def delete_report(self, report_id):
        path = self._report_path(report_id)
        with _lock:
            if not path or not os.path.isfile(path):
                raise WorkspaceError("That report no longer exists.")
            os.unlink(path)


def clean_fields(fields):
    out = {}
    for name, limit in TEXT_FIELDS.items():
        out[name] = _text(fields.get(name), limit, name.replace("_", " ").capitalize())
    for name, choices in CHOICE_FIELDS.items():
        value = fields.get(name) or ""
        if value and value not in choices:
            raise WorkspaceError("{n} must be one of: {c}.".format(
                n=name.replace("_", " ").capitalize(), c=", ".join(choices)))
        out[name] = value or ("draft" if name == "status" else
                              "confidential" if name == "classification" else "")
    out["confirmed"] = fields.get("confirmed") is True
    return out


def clean_findings(findings):
    if len(findings) > MAX_FINDINGS:
        raise WorkspaceError("A report can hold at most {m} findings.".format(m=MAX_FINDINGS))
    out = []
    for i, f in enumerate(findings, 1):
        if not isinstance(f, dict):
            raise WorkspaceError("Finding {i} is not valid.".format(i=i))
        item = {name: _text(f.get(name), limit, "Finding {i} {n}".format(i=i, n=name))
                for name, limit in FINDING_TEXT.items()}
        severity = f.get("severity") or "medium"
        if severity not in SEVERITIES:
            raise WorkspaceError("Finding {i} has an unknown severity.".format(i=i))
        status = f.get("status") or "open"
        if status not in FINDING_STATUSES:
            raise WorkspaceError("Finding {i} has an unknown status.".format(i=i))
        item.update(severity=severity, status=status)
        out.append(item)
    return out


def _evidence_text(value):
    if isinstance(value, (list, tuple)):
        return "\n".join(str(v) for v in value if v is not None)
    return str(value or "")


FIX_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180, "info": 365}


def _prefill(fields, findings, view, folder):
    """Copy a scan's facts and findings into a new report. Returns its source line."""
    entry = view.get("entry") if isinstance(view.get("entry"), dict) else {}
    scan = view.get("scan") if isinstance(view.get("scan"), dict) else {}
    started = str(entry.get("started") or "")
    fields["testing_started"] = started[:16].replace("T", " ")
    fields["testing_ended"] = str(entry.get("finished") or "")[:16].replace("T", " ")
    if view.get("kind") == "code":
        fields["assessment_type"] = "Source code review"
        fields["in_scope"] = "The source code in " + folder + "."
    else:
        fields["assessment_type"] = "Vulnerability assessment"
        ports = entry.get("ports_spec") or "the scanned ports"
        fields["in_scope"] = "{t}, TCP ports: {p}.".format(t=folder, p=ports)
        fields["out_of_scope"] = ("Every network outside the lab allowlist. Denial of service, "
                                  "password guessing and social engineering.")
    tools = set()
    plan = scan.get("plan") if isinstance(scan.get("plan"), dict) else {}
    chosen = plan.get("actions") or entry.get("actions") or []
    for action in ACTIONS:
        if action.id in chosen:
            tools.update(action.tools)
    for f in view.get("findings") or []:
        if isinstance(f, dict) and isinstance(f.get("source"), str) and f["source"]:
            tools.add(f["source"])
    fields["tools"] = ", ".join(sorted(tools))
    summary = view.get("summary") if isinstance(view.get("summary"), dict) else {}
    if isinstance(summary.get("text"), str):
        fields["summary"] = summary["text"][:TEXT_FIELDS["summary"]]
    worst = None
    for f in view.get("findings") or []:
        if not isinstance(f, dict) or len(findings) >= MAX_FINDINGS:
            continue
        severity = f.get("severity") if f.get("severity") in SEVERITIES else "info"
        if worst is None or SEVERITIES.index(severity) < SEVERITIES.index(worst):
            worst = severity
        ids = [i for i in (f.get("ids") or []) if isinstance(i, str)]
        port = f.get("port")
        findings.append({
            "title": str(f.get("title") or "")[:300], "severity": severity, "status": "open",
            "affected": folder, "port": "" if port is None else str(port)[:60],
            "cves": ", ".join(i for i in ids if i.upper().startswith("CVE"))[:400],
            "attack": ", ".join(i for i in ids if i.upper().startswith("T1"))[:200],
            "cvss": "", "description": "", "impact": "",
            "evidence": _evidence_text(f.get("evidence"))[:8000],
            "reproduce": "", "recommendation": "", "references": "",
            "fix_by": "{d} days".format(d=FIX_DAYS[severity]), "owner": "",
        })
    fields["overall_risk"] = worst if worst in RISKS else ("none" if not findings else "low")
    title = entry.get("label") or ("Scan " + started[:16].replace("T", " "))
    return "{k} scan, {w}".format(k=str(entry.get("preset") or view.get("kind") or "").capitalize()
                                  or "Tool", w=started[:16].replace("T", " ")) if started else str(title)


def report_markdown(data):
    """The analyst report as Markdown, for Export .md."""
    f = data.get("fields") or {}
    lines = ["# " + (f.get("title") or "Assessment"), ""]
    meta = [("Classification", f.get("classification", "").capitalize()),
            ("Status", {"review": "In review"}.get(f.get("status"), f.get("status", "").capitalize())),
            ("Client or organization", f.get("client")), ("Report date", f.get("report_date")),
            ("Prepared by", f.get("prepared_by")), ("Reviewed by", f.get("reviewed_by")),
            ("Contact", f.get("contact"))]
    for label, value in meta:
        if value:
            lines.append("**{l}:** {v}  ".format(l=label, v=value))
    sections = [
        ("Scope and method", [("Assessment type", "assessment_type"), ("Testing started", "testing_started"),
                              ("Testing ended", "testing_ended"), ("In scope", "in_scope"),
                              ("Out of scope", "out_of_scope"), ("Tools used", "tools"),
                              ("Methodology", "method"), ("Limitations", "limitations"),
                              ("Authorization", "authorization")]),
        ("Executive summary", [("Overall risk", "overall_risk"), ("Summary", "summary"),
                               ("Top recommendations", "recommendations")]),
    ]
    for title, items in sections:
        lines += ["", "## " + title, ""]
        for label, key in items:
            if f.get(key):
                value = f[key].capitalize() if key == "overall_risk" else f[key]
                lines += ["**" + label + "**", "", value, ""]
    findings = data.get("findings") or []
    lines += ["", "## Findings", ""]
    if not findings:
        lines.append("No findings.")
    for i, item in enumerate(findings, 1):
        lines += ["", "### F{i:02d} {t}".format(i=i, t=item.get("title") or "Untitled"), "",
                  "**Severity:** {s}  ".format(s=item.get("severity", "").capitalize()),
                  "**Status:** {s}  ".format(s=item.get("status", "").replace("_", " ").capitalize())]
        for label, key in (("CVSS", "cvss"), ("Affected host", "affected"), ("Port and service", "port"),
                           ("CVE IDs", "cves"), ("ATT&CK technique", "attack")):
            if item.get(key):
                lines.append("**{l}:** {v}  ".format(l=label, v=item[key]))
        for label, key in (("Description", "description"), ("Impact", "impact"),
                           ("Steps to reproduce", "reproduce"), ("Recommendation", "recommendation"),
                           ("References", "references")):
            if item.get(key):
                lines += ["", "**" + label + "**", "", item[key]]
        if item.get("evidence"):
            lines += ["", "**Evidence**", "", "```", item["evidence"].replace("```", "'''"), "```"]
    if findings:
        lines += ["", "## Remediation plan", "", "| ID | Finding | Severity | Fix by | Owner |",
                  "| --- | --- | --- | --- | --- |"]
        for i, item in enumerate(findings, 1):
            cells = ["F{i:02d}".format(i=i), item.get("title", ""), item.get("severity", "").capitalize(),
                     item.get("fix_by", ""), item.get("owner", "")]
            lines.append("| " + " | ".join(c.replace("|", "/").replace("\n", " ") for c in cells) + " |")
    for title, key in (("Attack path", "attack_path"), ("Conclusion", "conclusion")):
        if f.get(key):
            lines += ["", "## " + title, "", f[key]]
    lines += ["", "## Sign off", ""]
    if f.get("signed_by"):
        lines.append("**Analyst:** {a}  ".format(a=f["signed_by"]))
    if f.get("signed_date"):
        lines.append("**Date:** {d}  ".format(d=f["signed_date"]))
    if f.get("confirmed"):
        lines.append("The analyst confirms these findings are accurate and were found within "
                     "the authorized scope.")
    if data.get("source"):
        lines += ["", "_Started from: {s}. That tool report is unchanged._".format(s=data["source"])]
    return "\n".join(lines).rstrip() + "\n"
