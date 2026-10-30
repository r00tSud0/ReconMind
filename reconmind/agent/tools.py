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
from reconmind.tools.exploit_lookup import search_exploits

# How many exploit titles one lookup hands back to the model. Keeps the
# context small; the full list is still stored for the report.
MAX_EXPLOITS_TO_MODEL = 8


# Tool descriptions in the JSON schema format the LLM API expects.
TOOL_SPECS = [
    {
        "name": "nmap_scan",
        "description": (
            "Run an nmap service and version scan (-sV) against the authorized "
            "target. Returns every open port with its service, product and "
            "version. Run this first; other tools need its results. Only the "
            "target given by the operator is allowed."
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
            "Search the offline Exploit-DB database (searchsploit) for public "
            "exploits matching one service product and version found by "
            "nmap_scan. Call it once per interesting service. Use the product "
            "name exactly as nmap reported it."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "port": {
                    "type": "integer",
                    "description": "Port number the service was found on.",
                },
                "product": {
                    "type": "string",
                    "description": "Product name from nmap, e.g. 'vsftpd'.",
                },
                "version": {
                    "type": "string",
                    "description": "Version string from nmap, e.g. '2.3.4'. "
                                   "Empty string if nmap gave none.",
                },
            },
            "required": ["port", "product"],
        },
    },
]


class ToolBox:
    """Holds the scope lock and the results gathered during one agent run."""

    def __init__(self, target):
        self.target = str(target).strip()
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
        result = run_nmap(self.target)
        self.scan = result

        if result["status"] == "refused":
            return self._err(
                "Refused by the authorization gate: {t} is not on the "
                "allowlist. No scan was run. Do not retry.".format(t=self.target))
        if result["status"] != "ok":
            return self._err("Scan did not run: status={s}".format(s=result["status"]))

        observation = {
            "target": result["target"],
            "open_ports": [
                {k: p.get(k, "") for k in ("port", "protocol", "service", "product", "version")}
                for p in result["ports"]
            ],
        }
        return json.dumps(observation), False

    def _exploit_lookup(self, port, product, version=""):
        if self.scan.get("status") != "ok":
            return self._err("Run nmap_scan first; there are no scan results yet.")

        match = next((p for p in self.scan["ports"] if p.get("port") == int(port)), None)
        if match is None:
            return self._err("Port {p} was not found open in the scan.".format(p=port))

        exploits = search_exploits(product, version)
        match["exploits"] = exploits  # stored in full for the report

        observation = {
            "port": int(port),
            "query": "{p} {v}".format(p=product, v=version).strip(),
            "total_matches": len(exploits),
            "exploits": exploits[:MAX_EXPLOITS_TO_MODEL],
        }
        return json.dumps(observation), False

    # ---- helpers --------------------------------------------------------

    @staticmethod
    def _err(message):
        return json.dumps({"error": message}), True
