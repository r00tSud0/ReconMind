"""
ReconMind hybrid ATT&CK mapping.

Maps every confirmed open port to MITRE ATT&CK techniques in two ways:

    rule    the techniques of the port's risk flag (risky_services.py,
            LABELING.md version 2), confidence 1.0
    model   the fine tuned SciBERT mapper (attack_mapper.py) reading the
            port's finding text (finding_text.py). A technique at or above
            the model's threshold is a mapping. One from 0.50 up to the
            threshold is a lower confidence suggestion: kept apart and never
            counted as a mapping.

A technique given by both a rule and the model is one entry with both
sources. Every ID is checked against MITRE's ATT&CK data with the
attack_check helpers. An unknown, revoked or deprecated ID is dropped and
listed with the reason. If the MITRE data file is missing or unreadable no ID
can be checked, so every ID is dropped with that message as the reason.

When the model is unavailable (any status but ok) only rule mappings are made.
The predictor is passed in, so tests use a fake one and need no torch.
"""

from reconmind.ai.attack_mapper import STATUS_MODEL_MISSING, STATUS_OK, SUGGESTION_FLOOR
from reconmind.ai.finding_text import finding_text
from reconmind.core.attack_check import DATA_PATH, classify, load_techniques
from reconmind.tools.risky_services import attack_techniques

SOURCE_RULE = "rule"
SOURCE_MODEL = "model"
SOURCE_MODEL_LOW = "model, lower confidence"
RULE_CONFIDENCE = 1.0
DROPPED_RESULTS = ("unknown_id", "revoked", "deprecated")


def _check(technique_id, techniques, skipped):
    """(official name, None) for an active ID, or (None, reason) to drop it."""
    if techniques is None:
        return None, skipped
    official, result = classify(technique_id, "", techniques)
    if result in DROPPED_RESULTS:
        return None, result
    return official, None


def _map_port(port, text, hits, threshold, techniques, skipped):
    """The mapping for one port: confirmed techniques, suggestions, dropped IDs."""
    confirmed = {}  # ID to entry, in the order found
    lower, dropped = [], []

    def checked(technique_id, source):
        name, reason = _check(technique_id, techniques, skipped)
        if reason:
            dropped.append({"id": technique_id, "source": source, "reason": reason})
        return name

    for technique_id in attack_techniques(port):
        name = checked(technique_id, SOURCE_RULE)
        if name is not None and technique_id not in confirmed:
            confirmed[technique_id] = {"id": technique_id, "name": name,
                                       "sources": [SOURCE_RULE],
                                       "confidence": RULE_CONFIDENCE}

    for technique_id, probability in hits:
        if probability < SUGGESTION_FLOOR:
            continue
        source = SOURCE_MODEL if probability >= threshold else SOURCE_MODEL_LOW
        name = checked(technique_id, source)
        if name is None:
            continue
        entry = confirmed.get(technique_id)
        if entry is not None:
            # Also given by a rule: one entry with both sources.
            entry["sources"].append(source)
            entry["model_probability"] = probability
        elif source == SOURCE_MODEL:
            confirmed[technique_id] = {"id": technique_id, "name": name,
                                       "sources": [SOURCE_MODEL], "confidence": probability}
        else:
            lower.append({"id": technique_id, "name": name, "source": SOURCE_MODEL_LOW,
                          "confidence": probability})

    return {
        "port": port.get("port"),
        "protocol": port.get("protocol") or "tcp",
        "service": port.get("service") or "",
        "text": text,
        "techniques": list(confirmed.values()),
        "lower_confidence": lower,
        "dropped": dropped,
    }


def build_mapping(scan, predictor, path=DATA_PATH):
    """
    The ATT&CK mapping for every confirmed open port in scan["ports"]:

        {"status", "error", "run_name", "threshold", "model_sha256",
         "mitre_check", "ports": [{"port", "protocol", "service", "text",
         "techniques", "lower_confidence", "dropped"}]}

    status is the predictor's status. mitre_check is None, or the message
    saying the MITRE data could not be read.
    """
    ports = (scan or {}).get("ports") or []
    techniques, skipped = load_techniques(path)
    status = getattr(predictor, "status", None) or STATUS_MODEL_MISSING
    texts = [finding_text(p) for p in ports]
    if status == STATUS_OK and texts:
        predictions = predictor.predict(texts)
    else:
        predictions = [[] for _ in texts]
    threshold = getattr(predictor, "threshold", None)
    return {
        "status": status,
        "error": getattr(predictor, "error", "") or "",
        "run_name": getattr(predictor, "run_name", "") or "",
        "threshold": threshold,
        "model_sha256": getattr(predictor, "sha256", "") or "",
        "mitre_check": skipped,
        "ports": [_map_port(port, text, hits, threshold, techniques, skipped)
                  for port, text, hits in zip(ports, texts, predictions)],
    }
