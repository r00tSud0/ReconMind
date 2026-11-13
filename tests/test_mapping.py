"""
Offline tests for the hybrid ATT&CK mapping, with a fake predictor (no torch,
no transformers, no model files), plus the import rules: reconmind/ never
imports evaluation/, and torch and transformers are imported only inside the
model loader.

    python3 -m unittest discover -s tests -v
"""

import ast
import json
import os
import tempfile
import unittest

from reconmind.ai import attack_mapper
from reconmind.ai.finding_text import finding_text
from reconmind.ai.mapping import SOURCE_MODEL, SOURCE_MODEL_LOW, SOURCE_RULE, build_mapping
from reconmind.core.attack_check import SKIPPED_MISSING

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECONMIND_DIR = os.path.join(REPO_ROOT, "reconmind")

ACTIVE = {
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1190": "Exploit Public-Facing Application",
    "T1059": "Command and Scripting Interpreter",
    "T1021": "Remote Services",
    "T1040": "Network Sniffing",
    "T1021.005": "Remote Services: VNC",
    "T1113": "Screen Capture",
    "T1056.001": "Input Capture: Keylogging",
    "T1135": "Network Share Discovery",
    "T1039": "Data from Network Shared Drive",
    "T1005": "Data from Local System",
    "T1499.004": "Endpoint Denial of Service: Application or System Exploitation",
}


def write_techniques(path, leave_out=()):
    techniques = {tid: {"name": name, "short_name": name.split(": ")[-1],
                        "deprecated": False, "revoked": False}
                  for tid, name in ACTIVE.items() if tid not in leave_out}
    techniques["T1086"] = {"name": "PowerShell", "short_name": "PowerShell",
                           "deprecated": True, "revoked": False}
    techniques["T1173"] = {"name": "Dynamic Data Exchange", "short_name": "Dynamic Data Exchange",
                           "deprecated": False, "revoked": True}
    with open(path, "w") as fh:
        json.dump({"attack_version": "test", "techniques": techniques}, fh)


def port(num, service, product="", version=""):
    return {"port": num, "protocol": "tcp", "service": service, "product": product,
            "version": version}


def scan_with(*ports, **extra):
    return dict({"target": "10.10.1.100", "status": "ok", "ports": list(ports)}, **extra)


class FakePredictor:
    """Stands in for attack_mapper.Predictor. hits maps a word in the text to its hits."""

    def __init__(self, hits=None, status="ok", threshold=0.85, run_name="run3",
                 sha256="0123456789abcdef" * 4, error=""):
        self.hits = hits or {}
        self.status = status
        self.threshold = threshold
        self.run_name = run_name
        self.sha256 = sha256
        self.error = error
        self.texts = []

    def predict(self, texts):
        if self.status != "ok":
            raise AssertionError("predict() must not be called when the model is unavailable")
        self.texts.extend(texts)
        return [next((h for word, h in self.hits.items() if word in t), []) for t in texts]


FTP = port(21, "ftp", "vsftpd", "2.3.4")
TELNET = port(23, "telnet", "Linux telnetd")
SSH = port(22, "ssh", "OpenSSH", "4.7p1")

# Every rule in the risky services table, with LABELING.md version 2's IDs.
RULE_PORTS = (
    (port(1524, "bindshell", "Metasploitable root shell"), ["T1059.004"]),
    (port(3632, "distccd", "distccd", "v1"), ["T1190", "T1059"]),
    (port(8787, "drb", "Ruby DRb RMI"), ["T1190", "T1059"]),
    (TELNET, ["T1021", "T1040"]),
    (port(512, "exec", "netkit-rsh rexecd"), ["T1021", "T1040"]),
    (port(513, "login", "OpenBSD or Solaris rlogind"), ["T1021", "T1040"]),
    (port(514, "shell", "Netkit rshd"), ["T1021", "T1040"]),
    (port(5900, "vnc", "VNC"), ["T1021.005"]),
    (port(6000, "X11"), ["T1113", "T1056.001"]),
    (port(2049, "nfs"), ["T1135", "T1039"]),
    (port(1099, "java-rmi", "GNU Classpath grmiregistry"), ["T1190"]),
)


class MappingTests(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "attack_techniques.json")
        write_techniques(self.path)

    def tearDown(self):
        self._tmp.cleanup()

    def build(self, scan, predictor, path=None):
        return build_mapping(scan, predictor, path=path or self.path)

    def only_port(self, mapping):
        self.assertEqual(len(mapping["ports"]), 1)
        return mapping["ports"][0]

    def test_rule_mappings_from_the_table(self):
        mapping = self.build(scan_with(*[p for p, _ in RULE_PORTS]),
                             FakePredictor(status="not-installed"))
        for (p, expected), mapped in zip(RULE_PORTS, mapping["ports"]):
            with self.subTest(service=p["service"]):
                self.assertEqual(mapped["port"], p["port"])
                self.assertEqual([t["id"] for t in mapped["techniques"]], expected)
                for t in mapped["techniques"]:
                    self.assertEqual(t["sources"], [SOURCE_RULE])
                    self.assertEqual(t["confidence"], 1.0)
                    self.assertEqual(t["name"], ACTIVE[t["id"]])
                self.assertEqual(mapped["lower_confidence"], [])
                self.assertEqual(mapped["dropped"], [])

    def test_ordinary_port_gets_no_rule_mapping(self):
        mapped = self.only_port(self.build(scan_with(SSH), FakePredictor(status="not-installed")))
        self.assertEqual(mapped["techniques"], [])

    def test_model_threshold_and_lower_confidence_band(self):
        hits = {"vsftpd": [("T1190", 0.91), ("T1059", 0.85), ("T1005", 0.84),
                           ("T1499.004", 0.50), ("T1068", 0.49)]}
        mapped = self.only_port(self.build(scan_with(FTP), FakePredictor(hits)))
        self.assertEqual([(t["id"], t["sources"], t["confidence"]) for t in mapped["techniques"]],
                         [("T1190", [SOURCE_MODEL], 0.91), ("T1059", [SOURCE_MODEL], 0.85)])
        self.assertEqual([(t["id"], t["source"], t["confidence"])
                          for t in mapped["lower_confidence"]],
                         [("T1005", SOURCE_MODEL_LOW, 0.84),
                          ("T1499.004", SOURCE_MODEL_LOW, 0.50)])
        self.assertEqual(mapped["dropped"], [])  # below 0.50 is ignored, not checked

    def test_the_model_reads_the_finding_text(self):
        predictor = FakePredictor()
        mapping = self.build(scan_with(FTP, TELNET), predictor)
        expected = [finding_text(FTP), finding_text(TELNET)]
        self.assertEqual(predictor.texts, expected)
        self.assertEqual([p["text"] for p in mapping["ports"]], expected)

    def test_unknown_revoked_and_deprecated_ids_are_dropped(self):
        hits = {"vsftpd": [("T9999", 0.95), ("T1086", 0.95), ("T1173", 0.60)]}
        mapped = self.only_port(self.build(scan_with(FTP), FakePredictor(hits)))
        self.assertEqual(mapped["techniques"], [])
        self.assertEqual(mapped["lower_confidence"], [])
        self.assertEqual(mapped["dropped"], [
            {"id": "T9999", "source": SOURCE_MODEL, "reason": "unknown_id"},
            {"id": "T1086", "source": SOURCE_MODEL, "reason": "deprecated"},
            {"id": "T1173", "source": SOURCE_MODEL_LOW, "reason": "revoked"},
        ])

    def test_rule_ids_are_checked_too(self):
        path = os.path.join(self._tmp.name, "no_sniffing.json")
        write_techniques(path, leave_out=("T1040",))
        mapped = self.only_port(self.build(scan_with(TELNET),
                                           FakePredictor(status="not-installed"), path))
        self.assertEqual([t["id"] for t in mapped["techniques"]], ["T1021"])
        self.assertEqual(mapped["dropped"],
                         [{"id": "T1040", "source": SOURCE_RULE, "reason": "unknown_id"}])

    def test_missing_mitre_data_drops_every_id(self):
        mapping = self.build(scan_with(TELNET), FakePredictor({"telnet": [("T1190", 0.9)]}),
                             path=os.path.join(self._tmp.name, "nope.json"))
        self.assertEqual(mapping["mitre_check"], SKIPPED_MISSING)
        mapped = self.only_port(mapping)
        self.assertEqual(mapped["techniques"], [])
        self.assertEqual([(d["id"], d["reason"]) for d in mapped["dropped"]],
                         [("T1021", SKIPPED_MISSING), ("T1040", SKIPPED_MISSING),
                          ("T1190", SKIPPED_MISSING)])

    def test_rule_and_model_merge_into_one_entry(self):
        hits = {"telnet": [("T1021", 0.95), ("T1040", 0.70)]}
        mapped = self.only_port(self.build(scan_with(TELNET), FakePredictor(hits)))
        self.assertEqual(mapped["techniques"], [
            {"id": "T1021", "name": "Remote Services", "sources": [SOURCE_RULE, SOURCE_MODEL],
             "confidence": 1.0, "model_probability": 0.95},
            {"id": "T1040", "name": "Network Sniffing",
             "sources": [SOURCE_RULE, SOURCE_MODEL_LOW], "confidence": 1.0,
             "model_probability": 0.70},
        ])
        self.assertEqual(mapped["lower_confidence"], [])

    def test_model_fields_are_recorded(self):
        mapping = self.build(scan_with(FTP), FakePredictor())
        self.assertEqual((mapping["status"], mapping["run_name"], mapping["threshold"],
                          mapping["model_sha256"]),
                         ("ok", "run3", 0.85, "0123456789abcdef" * 4))
        self.assertIsNone(mapping["mitre_check"])

    def test_not_installed_still_applies_rules(self):
        predictor = attack_mapper.Predictor("not-installed", "x", error="no torch",
                                            run_name="run3", threshold=0.85, sha256="ab" * 32)
        mapping = self.build(scan_with(TELNET, FTP), predictor)
        self.assertEqual(mapping["status"], "not-installed")
        self.assertEqual(mapping["error"], "no torch")
        self.assertEqual([t["id"] for t in mapping["ports"][0]["techniques"]], ["T1021", "T1040"])
        self.assertEqual(mapping["ports"][1]["techniques"], [])

    def test_model_missing_still_applies_rules(self):
        attack_mapper.clear_cache()
        try:
            predictor = attack_mapper.load(os.path.join(self._tmp.name, "no_model_here"))
        finally:
            attack_mapper.clear_cache()
        self.assertEqual(predictor.status, "model-missing")
        mapping = self.build(scan_with(TELNET), predictor)
        self.assertEqual(mapping["status"], "model-missing")
        self.assertEqual([t["id"] for t in mapping["ports"][0]["techniques"]], ["T1021", "T1040"])

    def test_only_confirmed_open_ports_are_mapped(self):
        scan = scan_with(FTP, unconfirmed_ports=[{"port": 23, "protocol": "tcp"}])
        mapping = self.build(scan, FakePredictor())
        self.assertEqual([p["port"] for p in mapping["ports"]], [21])

    def test_no_ports_means_no_prediction(self):
        mapping = self.build(scan_with(), FakePredictor(status="ok", hits=None))
        self.assertEqual(mapping["ports"], [])


def python_files(folder):
    for root, _, names in os.walk(folder):
        for name in names:
            if name.endswith(".py"):
                yield os.path.join(root, name)


def imported_modules(tree):
    """[(module name, line)] for every import statement in a parsed file."""
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend((alias.name, node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.append((node.module, node.lineno))
    return found


def parse(path):
    with open(path) as fh:
        return ast.parse(fh.read(), filename=path)


class ImportRuleTests(unittest.TestCase):

    def test_reconmind_never_imports_evaluation(self):
        for path in python_files(RECONMIND_DIR):
            for module, line in imported_modules(parse(path)):
                with self.subTest(path=path, line=line):
                    self.assertNotEqual(module.split(".")[0], "evaluation")

    def test_torch_and_transformers_only_inside_the_loader(self):
        loader = os.path.join(RECONMIND_DIR, "ai", "attack_mapper.py")
        backend = next(node for node in parse(loader).body
                       if isinstance(node, ast.FunctionDef) and node.name == "_import_backend")
        allowed = range(backend.lineno, backend.end_lineno + 1)
        for path in python_files(RECONMIND_DIR):
            for module, line in imported_modules(parse(path)):
                if module.split(".")[0] not in ("torch", "transformers", "safetensors"):
                    continue
                with self.subTest(path=path, line=line):
                    self.assertEqual(os.path.abspath(path), os.path.abspath(loader))
                    self.assertIn(line, allowed)


if __name__ == "__main__":
    unittest.main()
