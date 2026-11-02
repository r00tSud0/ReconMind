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

# nmap product name (lowercase) -> how to search Exploit-DB for it.
#   search          the Exploit-DB search name
#   exclude         title words that mean a hit is another product
#   title_prefixes  a product_only title must start with one of these
#                   (default: the search name)
#   version_known   False when nmap's version is not the product's own
#                   version, so it is treated as unknown (default: True)
PRODUCTS = {
    "apache httpd": {
        "search": "Apache",
        "exclude": ["Tomcat", "Struts", "Solr", "ActiveMQ", "Axis", "OFBiz",
                    "CouchDB", "Spark", "Kafka", "OpenOffice", "CXF"],
    },
    "postgresql db": {"search": "PostgreSQL"},
    "samba smbd": {"search": "Samba"},
    "postfix smtpd": {"search": "Postfix"},
    "distccd": {"search": "distcc"},
    "isc bind": {"search": "BIND"},
    # nmap reports the Coyote connector version here, not Tomcat's.
    "apache tomcat/coyote jsp engine": {
        "search": "Tomcat",
        "title_prefixes": ["Tomcat", "Apache Tomcat"],
        "version_known": False,
    },
}

_RANGE = re.compile(r"\s+-\s+")
_LEADING = re.compile(r"\d+(?:\.\d+)*")
_WILDCARD = re.compile(r"(?:^|\.)[xX*](?:\.|\s|$)")


def _entry(product):
    return PRODUCTS.get((product or "").strip().lower())


def normalize_product(product):
    """Map an nmap product name to its Exploit-DB name. Unknown names pass through."""
    entry = _entry(product)
    return entry["search"] if entry else (product or "").strip()


def excluded_terms(product):
    """Title words that mean a search hit belongs to a different product."""
    entry = _entry(product)
    return list(entry.get("exclude", [])) if entry else []


def title_prefixes(product):
    """Allowed starts for a product_only title. Default: the search name."""
    entry = _entry(product)
    if entry and entry.get("title_prefixes"):
        return list(entry["title_prefixes"])
    name = normalize_product(product)
    return [name] if name else []


def usable_version(product, version):
    """
    normalize_version(version), or None when nmap's version for this product
    is not the product's own version and must be treated as unknown.
    """
    entry = _entry(product)
    if entry and entry.get("version_known") is False:
        return None
    return normalize_version(version)


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

    parsed = usable_version(product, version)
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
