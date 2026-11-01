"""
ReconMind version normalizer.

searchsploit ANDs every word of a query, so an nmap version string carrying
packaging detail ("4.7p1 Debian 8ubuntu1") matches nothing. These plain rules
turn nmap's product and version into the queries Exploit-DB can actually
match, and label each query with how strong a match it would be:

    exact_version   product + the full cleaned version
    version_family  product + major.minor only, patch level not confirmed
    product_only    nmap gave no usable version, unconfirmed

No AI and no I/O here, so every rule can be tested on its own.
"""

import re

# nmap product name (lowercase) -> (Exploit-DB search name, title exclusions).
# Exclusions drop titles that share the search name but are another product.
PRODUCTS = {
    "apache httpd": ("Apache", ["Tomcat", "Struts", "Solr", "ActiveMQ", "Axis",
                                "OFBiz", "CouchDB", "Spark", "Kafka", "OpenOffice",
                                "CXF"]),
    "postgresql db": ("PostgreSQL", []),
    "samba smbd": ("Samba", []),
    "postfix smtpd": ("Postfix", []),
    "distccd": ("distcc", []),
    "isc bind": ("BIND", []),
}

_RANGE = re.compile(r"\s+-\s+")
_LEADING = re.compile(r"\d+(?:\.\d+)*")
_WILDCARD = re.compile(r"(?:^|\.)[xX*](?:\.|\s|$)")


def normalize_product(product):
    """Map an nmap product name to its Exploit-DB name. Unknown names pass through."""
    product = (product or "").strip()
    entry = PRODUCTS.get(product.lower())
    return entry[0] if entry else product


def excluded_terms(product):
    """Title words that mean a search hit belongs to a different product."""
    entry = PRODUCTS.get((product or "").strip().lower())
    return list(entry[1]) if entry else []


def normalize_version(version):
    """
    Return (clean, family, is_range), or None when the version is unknown.

    clean is the leading numeric part ("4.7p1 Debian 8ubuntu1" -> "4.7",
    "5.0.51a-3ubuntu5" -> "5.0.51"), family its major.minor (None for a bare
    major), and is_range says nmap gave a range, whose lowest bound is used.
    """
    version = (version or "").strip()
    parts = _RANGE.split(version, maxsplit=1)
    is_range = len(parts) == 2
    version = parts[0].strip()

    if not version or _WILDCARD.search(version):
        return None
    match = _LEADING.match(version)
    if match is None:
        return None

    clean = match.group(0)
    numbers = clean.split(".")
    family = ".".join(numbers[:2]) if len(numbers) >= 2 else None
    return clean, family, is_range


def planned_queries(product, version):
    """
    The searches to try, in order, as [(query, label)]. A known version never
    falls back to a product_only search.
    """
    name = normalize_product(product)
    if not name:
        return []

    parsed = normalize_version(version)
    if parsed is None:
        return [(name, "product_only")]

    clean, family, is_range = parsed
    # A range never pinned the patch level, so only the family is known.
    if is_range:
        return [("{n} {v}".format(n=name, v=family or clean), "version_family")]

    queries = [("{n} {v}".format(n=name, v=clean), "exact_version")]
    if family and family != clean:
        queries.append(("{n} {v}".format(n=name, v=family), "version_family"))
    return queries
