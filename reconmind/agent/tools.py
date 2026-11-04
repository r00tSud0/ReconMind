"""
ReconMind agent toolbox.

This is the only door between the LLM brain and the real security tools. The
model never runs a command itself. It can only ask for one of the tools
described in TOOL_SPECS, and every request comes through ToolBox.call(), which:

  1. checks the request against the scope lock (the agent may only touch the
     one target the human gave it on the command line),
  2. hands the request to the real tool, which runs the authorization gate
     again before anything is launched,
  3. returns a compact JSON observation for the model to read, and
  4. keeps the structured results so the report is built from real tool
     output, not from whatever the model claims it saw.

Adding a tool later means adding one spec and one handler here. The agent loop
does not change.
"""

import json

from reconmind.tools.nmap_scan import run_nmap
from reconmind.tools.exploit_lookup import (
    STATUS_FAILED, STATUS_NO_PRODUCT, lookup_port, primary_label, search_exploits)
from reconmind.tools.risky_services import flag_port
from reconmind.tools.version_normalizer import planned_queries

# How many titles each port shows in the compact nmap_scan summary. The full
# list comes from exploit_lookup and is always stored for the report.
TOP_MATCHES_IN_SUMMARY = 3

# What the model is told about each weaker match label.
MATCH_NOTES = {
    "version_family": "Matched on major.minor only; the patch level is not "
                      "confirmed. Treat these matches as unconfirmed.",
    "product_only": "nmap gave no usable version; matched on product name "
                    "only. Treat these matches as unconfirmed.",
    "unverified": "The title's version range could not be checked against the "
                  "scanned version. Treat these matches as unconfirmed.",
}

LOOKUP_FAILED_NOTE = ("The exploit lookup failed, so this service was not "
                      "checked. This does not mean there are no exploits.")


# Tool descriptions in the JSON schema format the LLM API expects.
TOOL_SPECS = [
    {
        "name": "nmap_scan",
        "description": (
            "Run an nmap service and version scan (-sV) against the authorized "
            "target. Returns every open port with its service, product and "
            "version. The Exploit-DB lookup then runs automatically for every "
            "port with a product, and each port carries a compact summary: "
            "exploit_label, match_count and the top 3 titles with EDB-IDs. "
            "Ports that are risky just by being exposed carry a risk flag "
            "with severity and reason. Run this first. Only the target given "
            "by the operator is allowed."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "IPv4 address of the authorized target.",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "exploit_lookup",
        "description": (
            "Return the full Exploit-DB (searchsploit) results for one port. "
            "nmap_scan already ran the lookup for every port, so this only "
            "returns the stored list, without searching again. Use it when the "
            "top 3 titles in the nmap_scan summary are not enough. Each match "
            "is labeled exact_version (full version matched), version_family "
            "(major.minor only, patch level not confirmed), product_only "
            "(version unknown, unconfirmed) or unverified (version range could "
            "not be checked, unconfirmed). match lookup_failed means the "
            "service was not checked, not that it has no exploits."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "port": {
                    "type": "integer",
                    "description": "Port number the service was found on.",
                },
            },
            "required": ["port"],
        },
    },
]


class ToolBox:
    """Holds the scope lock and the results gathered during one agent run."""

    def __init__(self, target, all_ports=False):
        self.target = str(target).strip()
        # Passed straight through to run_nmap. Default False, so the agent and
        # brain.py scan exactly as before; only callers that ask for a full
        # sweep set it.
        self.all_ports = all_ports
        # Same shape the report builder already reads.
        self.scan = {"target": self.target, "status": "not-run", "ports": []}
        self.calls = []  # (tool name, input) history, for the trace and tests

    # ---- dispatch -------------------------------------------------------

    def call(self, name, args):
        """
        Run one tool request from the model. Always returns
        (observation_text, is_error). Never raises, so a bad request from the
        model becomes an observation it can react to instead of a crash.
        """
        self.calls.append((name, dict(args or {})))
        handler = {
            "nmap_scan": self._nmap_scan,
            "exploit_lookup": self._exploit_lookup,
        }.get(name)

        if handler is None:
            return self._err("Unknown tool '{n}'.".format(n=name))
        try:
            return handler(**(args or {}))
        except TypeError as exc:
            return self._err("Bad arguments for {n}: {e}".format(n=name, e=exc))
        except Exception as exc:  # tool crashed, report it to the model
            return self._err("{n} failed: {e}".format(n=name, e=exc))

    # ---- handlers -------------------------------------------------------

    def _nmap_scan(self, target):
        # Scope lock: the model may only scan the target the human chose.
        if str(target).strip() != self.target:
            return self._err(
                "Refused: {t} is outside this run's scope. The only authorized "
                "target is {s}.".format(t=target, s=self.target))

        # run_nmap asks the authorization gate again before nmap starts.
        result = run_nmap(self.target, all_ports=self.all_ports)
        self.scan = result

        if result["status"] == "refused":
            return self._err(
                "Refused by the authorization gate: {t} is not on the "
                "allowlist. No scan was run. Do not retry.".format(t=self.target))
        if result["status"] != "ok":
            return self._err("Scan did not run: status={s}".format(s=result["status"]))

        # Completeness: every open port is looked up, not just the ones the
        # model would have picked.
        for port in result["ports"]:
            self._lookup_port(port)

        observation = {
            "target": result["target"],
            "open_ports": [self._port_summary(p) for p in result["ports"]],
        }
        return json.dumps(observation), False

    def _exploit_lookup(self, port, product=None, version=None):
        # product and version from the model are accepted but ignored: the
        # results always come from what nmap recorded for the port.
        if self.scan.get("status") != "ok":
            return self._err("Run nmap_scan first; there are no scan results yet.")

        match = next((p for p in self.scan["ports"] if p.get("port") == int(port)), None)
        if match is None:
            return self._err("Port {p} was not found open in the scan.".format(p=port))

        # Normally nmap_scan already looked the port up. Search only if not.
        if "exploit_status" not in match:
            self._lookup_port(match)

        status = match.get("exploit_status")
        if status == STATUS_NO_PRODUCT:
            observation = {
                "port": int(port),
                "match": "none",
                "note": "nmap recorded no product for port {p}; nothing to "
                        "search.".format(p=port),
            }
            return json.dumps(observation), False

        product = (match.get("product") or "").strip()
        version = (match.get("version") or "").strip()
        exploits = match.get("exploits", [])
        observation = {"port": int(port), "product": product, "version": version}

        if status == STATUS_FAILED:
            observation["match"] = STATUS_FAILED
            observation["error"] = match.get("lookup_error", "")
            observation["note"] = LOOKUP_FAILED_NOTE
            observation["queries_tried"] = self._queries_tried(match)
        elif exploits:
            label = primary_label(exploits)
            observation["match"] = label
            observation["query"] = exploits[0].get("query")
            if label in MATCH_NOTES:
                observation["note"] = MATCH_NOTES[label]
            if label != "unverified" and any(e.get("match") == "unverified" for e in exploits):
                observation["unverified_note"] = MATCH_NOTES["unverified"]
        else:
            observation["match"] = "none"
            observation["queries_tried"] = self._queries_tried(match)
        observation["total_matches"] = len(exploits)
        observation["exploits"] = exploits
        return json.dumps(observation), False

    # ---- lookup helpers -------------------------------------------------

    @staticmethod
    def _lookup_port(port):
        # search_exploits is looked up here at call time, so tests can
        # replace this module's reference with a fake.
        lookup_port(port, search=search_exploits)

    @staticmethod
    def _queries_tried(port):
        return port.get("queries_tried") or [
            q for q, _ in planned_queries(port.get("product", ""), port.get("version", ""))]

    @staticmethod
    def _port_summary(port):
        """Compact per port line for the nmap_scan observation."""
        summary = {k: port.get(k, "") for k in ("port", "protocol", "service", "product", "version")}
        status = port.get("exploit_status")
        exploits = port.get("exploits", [])
        if status in (STATUS_FAILED, STATUS_NO_PRODUCT):
            summary["exploit_label"] = status
        elif exploits:
            summary["exploit_label"] = primary_label(exploits)
        else:
            summary["exploit_label"] = "none"
        if status == STATUS_FAILED:
            summary["lookup_error"] = port.get("lookup_error", "")
        summary["match_count"] = len(exploits)
        summary["top_matches"] = [
            {"title": e.get("title", ""), "edb_id": e.get("edb_id", ""), "match": e.get("match")}
            for e in exploits[:TOP_MATCHES_IN_SUMMARY]
        ]
        risk = flag_port(port)
        if risk:
            summary["risk"] = risk
        return summary

    # ---- helpers --------------------------------------------------------

    @staticmethod
    def _err(message):
        return json.dumps({"error": message}), True
