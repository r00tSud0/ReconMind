"""
ReconMind finding text.

Turn one scanned port dict into a single plain English sentence describing what
is open there. The ATT&CK mapper reads this exact text later, so it must be
deterministic: it is built only from the facts nmap and the exploit lookup
already recorded on the port, never from any model output.

The sentence has up to three parts:

    Port {port}/{protocol} is open running {service}: {product} {version}.
     Risk: {reason}
     Known exploits (Exploit-DB): {title} (EDB-{id}); ...

A missing product or version simply drops that word, with no extra spaces. The
risk part is added only when risky_services flags the port. The exploit part
lists at most three titles and only the confirmed matches (exact_version first,
then version_family); product_only and unverified matches are left out because
their version was never pinned down, and a port whose lookup failed has no
exploit entries, so it adds nothing.
"""

from reconmind.tools.risky_services import flag_port

# Only confirmed matches go in the text, exact_version ahead of version_family.
CONFIRMED_LABELS = ("exact_version", "version_family")
MAX_TITLES = 3


def _service_line(port):
    """The first sentence, built from service, product and version only."""
    service = (port.get("service") or "unknown").strip() or "unknown"
    product = (port.get("product") or "").strip()
    version = (port.get("version") or "").strip()
    facts = " ".join(part for part in (product, version) if part)
    line = "Port {port}/{protocol} is open running {service}:".format(
        port=port.get("port"), protocol=port.get("protocol"), service=service)
    if facts:
        line += " " + facts
    return line + "."


def _confirmed_exploits(port):
    """Confirmed matches for the port, exact_version first, capped at three."""
    exploits = [e for e in (port.get("exploits") or [])
                if e.get("match") in CONFIRMED_LABELS]
    # Stable sort keeps the original order within each label.
    exploits.sort(key=lambda e: CONFIRMED_LABELS.index(e.get("match")))
    return exploits[:MAX_TITLES]


def finding_text(port):
    """One deterministic plain English sentence for an open port, facts only."""
    text = _service_line(port)

    risk = flag_port(port)
    if risk:
        text += " Risk: {reason}".format(reason=risk["reason"])

    exploits = _confirmed_exploits(port)
    if exploits:
        titles = "; ".join("{title} (EDB-{id})".format(
            title=(e.get("title") or "").strip(),
            id=(e.get("edb_id") or "").strip()) for e in exploits)
        text += " Known exploits (Exploit-DB): {titles}.".format(titles=titles)

    return text
