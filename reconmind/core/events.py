"""
ReconMind progress events.

emit(kind, **data) appends one JSON line to the file named by the environment
variable RECONMIND_EVENTS:

    {"time": "2026-11-15T10:00:00", "kind": "step", "tool": "nmap_scan", ...}

Each line is written and flushed at once, so a reader (the web app's Live run
screen) can follow a run while it is still going. When RECONMIND_EVENTS is
unset or empty, emit does nothing.

emit never raises. A progress line is never worth a scan: an unwritable path,
a value JSON cannot hold or any other problem is silently dropped.
"""

import json
import os
from datetime import datetime

ENV_VAR = "RECONMIND_EVENTS"
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"


def events_path():
    """The events file for this process, or None when events are off."""
    try:
        return os.environ.get(ENV_VAR) or None
    except Exception:  # never raise, whatever the environment holds
        return None


def emit(kind, **data):
    """Append one event line when RECONMIND_EVENTS is set. Never raises."""
    try:
        path = events_path()
        if not path:
            return
        record = {"time": datetime.now().strftime(TIME_FORMAT), "kind": str(kind)}
        for key, value in data.items():
            if key not in record:
                record[key] = value
        line = json.dumps(record, default=str)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
    except Exception:  # a progress line must never stop a run
        pass
