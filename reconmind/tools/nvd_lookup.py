"""
ReconMind NVD CVE lookup (Stage 2, known CVEs).

Looks up the CVEs that NVD lists for each versioned product found in a scan,
using the NVD CPE and CVE APIs 2.0 and the standard library only.

Privacy rule: only CPE strings ever leave the machine. The target address,
ports, banners and every other scan detail stay local. lookup_targets reads
each port's "cpe" list, product and version (the version only to complete a
versionless CPE, and only its leading upstream number is kept) and
whatweb's PHP versions. CVE request URLs carry only cpeName, resultsPerPage
and startIndex; CPE dictionary request URLs carry only cpeMatchString,
resultsPerPage and startIndex. The only header sent is apiKey, when
NVD_API_KEY is set.

Where the CPEs come from:
    - nmap writes CPE 2.2 (cpe:/a:vendor:product:version). Each one is
      converted to CPE 2.3.
    - When nmap's application CPE has no version but the port has one (also
      a version filled in by smb-os-discovery or irc-info), the CPE is built
      from nmap's vendor and product plus the leading upstream version of
      the port version: Samba 3.0.20-Debian gives version 3.0.20. The
      product records "version_from": "nmap port version". This is only
      done when the port carries exactly one application CPE, so the version
      cannot land on the wrong product, and never for an OS CPE. Any other
      CPE without a version is skipped and reported as skipped, because NVD
      would answer for every version of the product.
    - whatweb's PHP component, the only explicit mapping: PHP 5.2.4-2ubuntu5.10
      becomes cpe:2.3:a:php:php:5.2.4:*:*:*:*:*:*:*, using only the leading
      upstream version. Nothing else is guessed.

Official names: nmap's vendor names do not always match NVD's (nmap says
vsftpd, NVD says vsftpd_project), and the CVE API only answers for exact
dictionary names. So before any CVE query, every candidate is looked up in
NVD's CPE dictionary with cpeMatchString=cpe:2.3:<part>:*:<product>:<version>.
Deprecated names are dropped, and so is every name whose product or version
differs. The remaining fields must agree too: a field the candidate leaves
open ("*") only matches a dictionary name that leaves it open, so OpenSSH
4.7p1 (version 4.7, update p1) only matches 4.7:p1. One name left: it is
used. Several: the one with the scan's vendor is used, and if there is no
single such name the product is skipped with the names listed. None: the
original CPE is kept. Each product records "resolved_from" (the CPE before
resolution) and "cpe_resolution".

NVD's rate limit is respected: 6 seconds between requests without an API key,
1 second with one, across CPE and CVE requests alike. Each request has a 30
second timeout and one retry, after 30 seconds, on HTTP 403, 429 or 503.
Answers of both APIs are cached as JSON under ~/.cache/reconmind/nvd/ and
reused for 24 hours.

Every value taken from NVD (IDs, dates, descriptions, scores, severities,
vectors, CWE IDs, CISA KEV dates) is kept exactly as NVD wrote it. A failure
never raises: it becomes a status on that product.
"""

import hashlib
import http.client
import json
import os
import re
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlencode
from urllib.request import Request, urlopen

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
RESULTS_PER_PAGE = 2000
CPE_RESULTS_PER_PAGE = 10000
REQUEST_TIMEOUT = 30
RETRY_CODES = (403, 429, 503)
RETRY_WAIT = 30
WAIT_NO_KEY = 6
WAIT_WITH_KEY = 1
API_KEY_ENV = "NVD_API_KEY"

CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "reconmind", "nvd")
CACHE_MAX_AGE = 24 * 60 * 60

STATUS_OK = "ok"
STATUS_NO_CPE = "no-cpe"
STATUS_NETWORK_ERROR = "network-error"
STATUS_RATE_LIMITED = "rate-limited"
STATUS_BAD_RESPONSE = "bad-response"

# NVD severities, most severe first. A CVE with no CVSS metric counts as
# UNSCORED.
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")
UNSCORED = "UNSCORED"

# Preferred CVSS metric first. The label says which one was used.
METRIC_FIELDS = (("cvssMetricV31", "v3.1"), ("cvssMetricV30", "v3.0"), ("cvssMetricV2", "v2"))

PATCH_NOTE = ("NVD matches the upstream version. Linux distributions often fix CVEs "
              "without changing the version number, so some of these may already be "
              "patched on the target.")

RANGE_NOTE = ("NVD version ranges sometimes have no lower bound, so CVEs for newer code "
              "can be listed against older versions. Confirm high impact CVEs against "
              "the vendor advisory.")

NO_RESULTS_NOTE = ("NVD returned no CVEs for this exact product ID. This does not mean "
                   "the product has no known vulnerabilities.")

REASON_NO_VERSION = "no version in the CPE"
REASON_NOT_CPE = "not a CPE 2.2 string"
REASON_TOO_MANY_FIELDS = "more fields than CPE 2.2 allows"
REASON_PHP_NO_VERSION = "no upstream version in the PHP version"
REASON_VERSION_RANGE = "no version in the CPE, and nmap's port version is a range"
REASON_AMBIGUOUS_OTHER_VENDOR = ("several NVD CPE names match and none has the vendor "
                                 "{v}: {c}")
REASON_AMBIGUOUS_SAME_VENDOR = "several NVD CPE names match with the vendor {v}: {c}"

VERSION_FROM_PORT = "nmap port version"

# cpe_resolution values.
RESOLVED = "nvd-dictionary"
NOT_IN_DICTIONARY = "not-in-dictionary"
RESOLUTION_FAILED = "lookup-failed"

_UPSTREAM_VERSION = re.compile(r"\d+(?:\.\d+)*")
# nmap -sV writes a vague version such as "3.X - 4.X" when it cannot tell.
_VERSION_RANGE = re.compile(r"\d\.[xX*]|\s-\s")
# nmap writes OpenSSH versions as 4.7p1; NVD's dictionary stores version 4.7
# with update p1. Used for the openbsd:openssh CPE only.
_OPENSSH_PORTABLE = re.compile(r"^(\d+\.\d+)(p\d+)$")
# CPE 2.3 formatted strings leave letters, digits, "_", "-" and "." as they
# are and escape every other character with a backslash.
_NEEDS_ESCAPE = re.compile(r"[^A-Za-z0-9_.\-]")


def _sleep(seconds):
    time.sleep(seconds)


def _now():
    return time.time()


# ---- CPE handling -------------------------------------------------------

def _cpe23_value(value):
    """One CPE 2.2 field as a CPE 2.3 value: empty is "*", "-" stays "-"."""
    value = unquote(value or "")
    if value in ("", "*"):
        return "*"
    if value == "-":
        return "-"
    return _NEEDS_ESCAPE.sub(lambda m: "\\" + m.group(0), value)


def cpe22_to_23(cpe):
    """
    Convert one CPE 2.2 URI (cpe:/a:vendor:product:version...) to a CPE 2.3
    formatted string. Return (cpe23, "") or ("", reason). A CPE with no
    version is refused with REASON_NO_VERSION.
    """
    text = str(cpe or "").strip()
    if not text.lower().startswith("cpe:/"):
        return "", REASON_NOT_CPE
    fields = text[5:].split(":")
    if len(fields) > 7:
        return "", REASON_TOO_MANY_FIELDS
    part, vendor, product, version, update, edition, language = (fields + [""] * 7)[:7]
    if part.lower() not in ("a", "o", "h") or not vendor or not product:
        return "", REASON_NOT_CPE
    if unquote(version) in ("", "*", "-"):
        return "", REASON_NO_VERSION
    # The one product specific rule: openbsd:openssh 4.7p1 becomes version
    # 4.7, update p1, as NVD's dictionary names it. No other product.
    portable = _OPENSSH_PORTABLE.match(unquote(version))
    if (part.lower() == "a" and unquote(vendor).lower() == "openbsd"
            and unquote(product).lower() == "openssh" and not update and portable):
        version, update = portable.group(1), portable.group(2)
    # CPE 2.2 packs the extended 2.3 fields into edition as
    # ~edition~sw_edition~target_sw~target_hw~other.
    if edition.startswith("~"):
        extended = (edition[1:].split("~") + [""] * 5)[:5]
    else:
        extended = [edition, "", "", "", ""]
    edition, sw_edition, target_sw, target_hw, other = extended
    values = [vendor, product, version, update, edition, language,
              sw_edition, target_sw, target_hw, other]
    return "cpe:2.3:" + part.lower() + ":" + ":".join(_cpe23_value(v) for v in values), ""


def php_cpe(version):
    """cpe:2.3:a:php:php:<upstream version> for a whatweb PHP version, or ""."""
    match = _UPSTREAM_VERSION.match(str(version or "").strip())
    if not match:
        return ""
    return "cpe:2.3:a:php:php:{v}:*:*:*:*:*:*:*".format(v=match.group(0))


def port_version_cpe(cpe, version):
    """
    Complete nmap's versionless application CPE 2.2 with the leading upstream
    version of the port's version (3.0.20 from 3.0.20-Debian, as for PHP).
    Return (cpe23, "") or ("", reason). OpenSSH keeps its 4.7p1 form so
    cpe22_to_23 splits it into version and update as usual.
    """
    text = str(cpe or "").strip()
    fields = text[5:].split(":") if text.lower().startswith("cpe:/") else []
    if len(fields) < 3 or fields[0].lower() != "a":
        return "", REASON_NO_VERSION
    version = str(version or "").strip()
    if _VERSION_RANGE.search(version):
        return "", REASON_VERSION_RANGE
    match = _UPSTREAM_VERSION.match(version)
    if not match:
        return "", REASON_NO_VERSION
    upstream = match.group(0)
    first_word = version.split()[0]
    if (unquote(fields[1]).lower() == "openbsd" and unquote(fields[2]).lower() == "openssh"
            and _OPENSSH_PORTABLE.match(first_word)):
        upstream = first_word
    fields = (fields + [""])[:max(len(fields), 4)]
    fields[3] = upstream
    return cpe22_to_23("cpe:/" + ":".join(fields))


def _cpe23_fields(name):
    """
    The 11 fields of a CPE 2.3 formatted string (part through other), split
    on unescaped colons and kept in their escaped form. Missing trailing
    fields count as "*". None when it is not a CPE 2.3 string.
    """
    fields, current, escaped = [], "", False
    for ch in str(name or ""):
        if escaped:
            current, escaped = current + ch, False
        elif ch == "\\":
            current, escaped = current + ch, True
        elif ch == ":":
            fields.append(current)
            current = ""
        else:
            current += ch
    fields.append(current)
    if len(fields) < 6 or len(fields) > 13 or fields[0].lower() != "cpe" or fields[1] != "2.3":
        return None
    return (fields[2:] + ["*"] * 11)[:11]


def _open_field(value):
    return value in ("", "*", "-")


def _same_name(mine, theirs):
    """Part, product, version and every later field agree; the vendor may differ."""
    for index, (a, b) in enumerate(zip(mine, theirs)):
        if index == 1:
            continue
        if index in (0, 2, 3):
            if a.lower() != b.lower():
                return False
        elif _open_field(a) != _open_field(b) or (not _open_field(a) and a.lower() != b.lower()):
            return False
    return True


def cpe_match_string(cpe):
    """cpe:2.3:<part>:*:<product>:<version> for one CPE 2.3 string, or ""."""
    fields = _cpe23_fields(cpe)
    if not fields or _open_field(fields[2]) or _open_field(fields[3]):
        return ""
    return "cpe:2.3:{p}:*:{n}:{v}".format(p=fields[0], n=fields[2], v=fields[3])


def choose_cpe(cpe, names):
    """
    Pick the NVD dictionary name for one CPE 2.3 string from the names NVD's
    CPE API returned ([{"cpeName", "deprecated"}]). Return one of:
        {"outcome": "resolved", "cpe": name}
        {"outcome": "none", "cpe": cpe}               no name fits, keep cpe
        {"outcome": "ambiguous", "candidates": [...], "reason": text}
    """
    mine = _cpe23_fields(cpe)
    if not mine:
        return {"outcome": "none", "cpe": cpe}
    matches = []
    for entry in names or []:
        if not isinstance(entry, dict) or entry.get("deprecated"):
            continue
        name = entry.get("cpeName")
        theirs = _cpe23_fields(name)
        if theirs and _same_name(mine, theirs) and name not in matches:
            matches.append(name)
    if not matches:
        return {"outcome": "none", "cpe": cpe}
    if len(matches) == 1:
        return {"outcome": "resolved", "cpe": matches[0]}
    vendor = mine[1]
    same_vendor = [m for m in matches if _cpe23_fields(m)[1].lower() == vendor.lower()]
    if len(same_vendor) == 1:
        return {"outcome": "resolved", "cpe": same_vendor[0]}
    if same_vendor:
        reason = REASON_AMBIGUOUS_SAME_VENDOR.format(v=vendor, c=", ".join(same_vendor))
        return {"outcome": "ambiguous", "candidates": same_vendor, "reason": reason}
    reason = REASON_AMBIGUOUS_OTHER_VENDOR.format(v=vendor, c=", ".join(matches))
    return {"outcome": "ambiguous", "candidates": matches, "reason": reason}


def lookup_targets(ports, web=None):
    """
    Return (products, skipped) for a scan's open ports and whatweb results.

    products: [{"product", "cpe", "source", "from", "ports"}], one per
    distinct CPE 2.3 string, plus "version_from" when the version came from
    the port rather than the CPE. skipped: [{"cpe", "ports", "reason"}], one
    per distinct CPE or PHP version that was not looked up. Only CPE values,
    port products and versions and PHP versions are read; the target address
    is never touched.
    """
    products, by_cpe = [], {}
    skipped, skipped_by = [], {}

    def add(cpe23, label, source, raw, port_label, version_from=""):
        item = by_cpe.get(cpe23)
        if item is None:
            item = {"product": label, "cpe": cpe23, "source": [], "from": [], "ports": []}
            by_cpe[cpe23] = item
            products.append(item)
        if version_from:
            item["version_from"] = version_from
        for key, value in (("source", source), ("from", raw), ("ports", port_label)):
            if value not in item[key]:
                item[key].append(value)

    def skip(raw, port_label, reason):
        item = skipped_by.get(raw)
        if item is None:
            item = {"cpe": raw, "ports": [], "reason": reason}
            skipped_by[raw] = item
            skipped.append(item)
        if port_label not in item["ports"]:
            item["ports"].append(port_label)

    for port in ports or []:
        port_label = "{p}/{t}".format(p=port.get("port", ""), t=port.get("protocol") or "tcp")
        label = " ".join(str(x) for x in (port.get("product"), port.get("version")) if x)
        raws = port.get("cpe") or []
        # The port version belongs to the port's application, so it is only
        # used when there is exactly one application CPE to give it to.
        apps = [r for r in raws if str(r or "").strip().lower().startswith("cpe:/a:")]
        for raw in raws:
            cpe23, reason = cpe22_to_23(raw)
            version_from = ""
            if not cpe23 and reason == REASON_NO_VERSION and apps == [raw]:
                cpe23, why = port_version_cpe(raw, port.get("version"))
                if cpe23:
                    version_from = VERSION_FROM_PORT
                else:
                    reason = why or reason
            if cpe23:
                add(cpe23, label or cpe23, "nmap", raw, port_label, version_from)
            else:
                skip(raw, port_label, reason)

    for number, result in (web or {}).items():
        if not isinstance(result, dict) or result.get("status") != "ok":
            continue
        port_label = "{p}/tcp".format(p=number)
        for component in result.get("components") or []:
            if str(component.get("name", "")).lower() != "php":
                continue
            for version in component.get("versions") or []:
                raw = "PHP {v}".format(v=version)
                cpe23 = php_cpe(version)
                if cpe23:
                    add(cpe23, raw, "whatweb", raw, port_label)
                else:
                    skip(raw, port_label, REASON_PHP_NO_VERSION)
    return products, skipped


# ---- NVD answer parsing -------------------------------------------------

class _BadResponse(Exception):
    pass


def _cvss(metrics):
    """The preferred CVSS metric: v3.1, then v3.0, then v2. Primary entry first."""
    metrics = metrics if isinstance(metrics, dict) else {}
    for field, label in METRIC_FIELDS:
        entries = [m for m in metrics.get(field) or [] if isinstance(m, dict)]
        if not entries:
            continue
        metric = next((m for m in entries if m.get("type") == "Primary"), entries[0])
        data = metric.get("cvssData") if isinstance(metric.get("cvssData"), dict) else {}
        # v3 keeps baseSeverity inside cvssData, v2 keeps it next to it.
        return {"cvss_score": data.get("baseScore"),
                "cvss_severity": data.get("baseSeverity") or metric.get("baseSeverity") or "",
                "cvss_vector": data.get("vectorString", ""), "cvss_version": label}
    return {"cvss_score": None, "cvss_severity": "", "cvss_vector": "", "cvss_version": ""}


def _english(entries):
    return next((d.get("value", "") for d in entries or []
                 if isinstance(d, dict) and d.get("lang") == "en"), "")


def _cwe_ids(weaknesses):
    found = []
    for weakness in weaknesses or []:
        if not isinstance(weakness, dict):
            continue
        for d in weakness.get("description") or []:
            if not isinstance(d, dict) or d.get("lang") != "en":
                continue
            value = d.get("value", "")
            if value and value not in found:
                found.append(value)
    return found


def parse_cve(item):
    """One NVD vulnerability entry as a flat dict, or None if it has no ID."""
    cve = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict) or not cve.get("id"):
        return None
    kev_added = cve.get("cisaExploitAdd") or ""
    parsed = {"id": cve["id"], "published": cve.get("published", ""),
              "description": _english(cve.get("descriptions"))}
    parsed.update(_cvss(cve.get("metrics")))
    parsed.update({"cwe": _cwe_ids(cve.get("weaknesses")), "kev": bool(kev_added),
                   "kev_added": kev_added})
    return parsed


def _page_items(body, list_field):
    """Return (total_results, items of list_field) for one NVD answer."""
    try:
        data = json.loads(body.decode("utf-8") if isinstance(body, bytes) else body)
    except (ValueError, UnicodeDecodeError) as exc:
        raise _BadResponse("NVD answer is not valid JSON: {e}".format(e=exc))
    if not isinstance(data, dict):
        raise _BadResponse("NVD answer is not a JSON object.")
    total, items = data.get("totalResults"), data.get(list_field)
    if not isinstance(total, int) or isinstance(total, bool) or not isinstance(items, list):
        raise _BadResponse("NVD answer has no totalResults or {f} list.".format(f=list_field))
    return total, items


def parse_page(body):
    """Return (total_results, vulnerability items) for one NVD CVE answer."""
    return _page_items(body, "vulnerabilities")


def parse_cpe_page(body):
    """
    Return (total_results, item count, names) for one NVD CPE answer, names
    being [{"cpeName", "deprecated"}] exactly as NVD wrote them.
    """
    total, items = _page_items(body, "products")
    names = []
    for item in items:
        cpe = item.get("cpe") if isinstance(item, dict) else None
        if isinstance(cpe, dict) and isinstance(cpe.get("cpeName"), str) and cpe["cpeName"]:
            names.append({"cpeName": cpe["cpeName"], "deprecated": bool(cpe.get("deprecated"))})
    return total, len(items), names


# ---- requests -----------------------------------------------------------

class _Pacer:
    """Waits the rate limit gap before every real request but the first."""

    def __init__(self, gap):
        self.gap = gap
        self.used = False

    def wait(self):
        if self.used:
            _sleep(self.gap)
        self.used = True


def _fetch_page(cpe, start, api_key, pacer):
    """One NVD CVE request. Returns the body."""
    return _get(NVD_URL, {"cpeName": cpe, "resultsPerPage": RESULTS_PER_PAGE,
                          "startIndex": start}, api_key, pacer)


def _fetch_cpe_page(match, start, api_key, pacer):
    """One NVD CPE dictionary request. Returns the body."""
    return _get(CPE_URL, {"cpeMatchString": match, "resultsPerPage": CPE_RESULTS_PER_PAGE,
                          "startIndex": start}, api_key, pacer)


def _get(base, params, api_key, pacer):
    """One NVD request, with one retry on 403, 429 or 503. Returns the body."""
    url = base + "?" + urlencode(params)
    headers = {"apiKey": api_key} if api_key else {}
    for attempt in (1, 2):
        pacer.wait()
        try:
            with urlopen(Request(url, headers=headers), timeout=REQUEST_TIMEOUT) as response:
                return response.read()
        except HTTPError as exc:
            if attempt == 1 and exc.code in RETRY_CODES:
                _sleep(RETRY_WAIT)
                continue
            raise
    raise AssertionError("unreachable")


def _query(cpe, api_key, pacer):
    """Every CVE NVD lists for one CPE, following pagination. Returns (total, cves)."""
    cves, start = [], 0
    while True:
        total, items = parse_page(_fetch_page(cpe, start, api_key, pacer))
        for item in items:
            parsed = parse_cve(item)
            if parsed:
                cves.append(parsed)
        start += len(items)
        if not items or start >= total:
            return total, cves


def _query_cpes(match, api_key, pacer):
    """Every dictionary name NVD lists for one cpeMatchString, following pagination."""
    names, start = [], 0
    while True:
        total, count, page_names = parse_cpe_page(_fetch_cpe_page(match, start, api_key, pacer))
        names.extend(page_names)
        start += count
        if not count or start >= total:
            return names


def _error(exc):
    """(status, message) for an exception raised by an NVD request."""
    if isinstance(exc, HTTPError):
        if exc.code in (403, 429):
            return STATUS_RATE_LIMITED, ("NVD refused the request (HTTP {c}) after one "
                                         "retry.".format(c=exc.code))
        status = STATUS_NETWORK_ERROR if exc.code >= 500 else STATUS_BAD_RESPONSE
        return status, "NVD answered HTTP {c}.".format(c=exc.code)
    if isinstance(exc, _BadResponse):
        return STATUS_BAD_RESPONSE, str(exc)
    reason = getattr(exc, "reason", None) or exc
    return STATUS_NETWORK_ERROR, "NVD could not be reached: {e}".format(e=reason)


_REQUEST_ERRORS = (_BadResponse, URLError, OSError, http.client.HTTPException)


# ---- cache --------------------------------------------------------------

# CPE dictionary answers are keyed apart from CVE answers, which keep the
# bare CPE as their key.
_CPE_CACHE_KEY = "cpeMatchString="


def _cache_path(key, cache_dir):
    return os.path.join(cache_dir, hashlib.sha256(key.encode("utf-8")).hexdigest() + ".json")


def _load_cache(key, cache_dir, now, valid):
    """The cached entry for key if valid(entry) and it is under 24 hours old."""
    try:
        with open(_cache_path(key, cache_dir)) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not valid(data):
        return None
    fetched = data.get("fetched_epoch")
    if not isinstance(fetched, (int, float)):
        return None
    if not 0 <= now - fetched < CACHE_MAX_AGE:
        return None
    return data


def _read_cache(cpe, cache_dir, now):
    """The cached CVE answer for cpe if it is under 24 hours old, else None."""
    return _load_cache(cpe, cache_dir, now,
                       lambda d: d.get("cpe") == cpe and isinstance(d.get("cves"), list))


def _read_cpe_cache(match, cache_dir, now):
    """The cached CPE dictionary answer for match if under 24 hours old, else None."""
    return _load_cache(_CPE_CACHE_KEY + match, cache_dir, now,
                       lambda d: d.get("match") == match and isinstance(d.get("names"), list))


def _write_cache(entry, cache_dir, key=None):
    """Best effort: a cache that cannot be written only costs a fresh query."""
    path = _cache_path(key or entry["cpe"], cache_dir)
    try:
        os.makedirs(cache_dir, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(entry, fh)
        os.replace(tmp, path)
    except OSError:
        pass


# ---- lookups ------------------------------------------------------------

def _failure(cpe, status, error):
    return {"cpe": cpe, "status": status, "fetched_at": "", "from_cache": False,
            "total_results": 0, "cves": [], "error": error}


def lookup_cpe(cpe, api_key="", pacer=None, cache_dir=None):
    """
    Return {"cpe", "status", "fetched_at", "from_cache", "total_results",
    "cves"} for one CPE 2.3 string, plus "error" when status is not "ok".
    Never raises.
    """
    cache_dir = cache_dir or CACHE_DIR
    pacer = pacer or _Pacer(WAIT_WITH_KEY if api_key else WAIT_NO_KEY)
    now = _now()
    cached = _read_cache(cpe, cache_dir, now)
    if cached:
        return {"cpe": cpe, "status": STATUS_OK, "fetched_at": cached.get("fetched_at", ""),
                "from_cache": True, "total_results": cached.get("total_results", 0),
                "cves": cached["cves"]}
    try:
        total, cves = _query(cpe, api_key, pacer)
    except _REQUEST_ERRORS as exc:
        status, error = _error(exc)
        return _failure(cpe, status, error)
    fetched = _now()
    entry = {"cpe": cpe, "fetched_at": _stamp(fetched),
             "fetched_epoch": fetched, "total_results": total, "cves": cves}
    _write_cache(entry, cache_dir)
    return {"cpe": cpe, "status": STATUS_OK, "fetched_at": entry["fetched_at"],
            "from_cache": False, "total_results": total, "cves": cves}


def _stamp(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def resolve_cpe(cpe, api_key="", pacer=None, cache_dir=None):
    """
    Look one CPE 2.3 string up in NVD's CPE dictionary. Return {"match",
    "status", "from_cache", "names": [{"cpeName", "deprecated"}]}, plus
    "error" when status is not "ok". A CPE with no product or version to
    match on gets status "ok" and no names. Never raises.
    """
    match = cpe_match_string(cpe)
    if not match:
        return {"match": "", "status": STATUS_OK, "from_cache": False, "names": []}
    cache_dir = cache_dir or CACHE_DIR
    pacer = pacer or _Pacer(WAIT_WITH_KEY if api_key else WAIT_NO_KEY)
    cached = _read_cpe_cache(match, cache_dir, _now())
    if cached:
        return {"match": match, "status": STATUS_OK, "from_cache": True,
                "names": cached["names"]}
    try:
        names = _query_cpes(match, api_key, pacer)
    except _REQUEST_ERRORS as exc:
        status, error = _error(exc)
        return {"match": match, "status": status, "from_cache": False, "names": [],
                "error": error}
    fetched = _now()
    _write_cache({"match": match, "fetched_at": _stamp(fetched), "fetched_epoch": fetched,
                  "names": names}, cache_dir, key=_CPE_CACHE_KEY + match)
    return {"match": match, "status": STATUS_OK, "from_cache": False, "names": names}


def run_cve_lookup(products, skipped=(), api_key=None, cache_dir=None):
    """
    Resolve every product from lookup_targets to its NVD dictionary name,
    then look up its CVEs. Return:
        {"status", "api_key_used", "products": [{"product", "cpe", "source",
         "from", "ports", "resolved_from", "cpe_resolution", "status",
         "fetched_at", "from_cache", "total_results", "cves": [...]}],
         "skipped": [...]}
    "cpe" is the name the CVEs were looked up with and "resolved_from" the
    CPE before resolution. cpe_resolution is "nvd-dictionary", or
    "not-in-dictionary" when nothing fit and the CPE was kept, or
    "lookup-failed" (with "resolution_error") when the dictionary could not
    be read and the CPE was kept. A product with several fitting names and
    no single one with its own vendor is moved to skipped with the names in
    "candidates" and in the reason.

    status is "no-cpe" when there is nothing to look up, otherwise "ok";
    each product carries its own status. api_key defaults to NVD_API_KEY
    from the environment. The key itself is never stored in the result.
    """
    if api_key is None:
        api_key = os.environ.get(API_KEY_ENV, "").strip()
    result = {"status": STATUS_OK, "api_key_used": bool(api_key), "products": [],
              "skipped": [dict(s) for s in skipped]}
    if not products:
        result["status"] = STATUS_NO_CPE
        result["error"] = "No open port has a CPE with a version, so nothing was looked up."
        return result
    pacer = _Pacer(WAIT_WITH_KEY if api_key else WAIT_NO_KEY)
    # Every name is resolved before the first CVE query.
    resolved = []
    for product in products:
        item = dict(product)
        item["resolved_from"] = product["cpe"]
        answer = resolve_cpe(product["cpe"], api_key, pacer, cache_dir)
        if answer["status"] != STATUS_OK:
            item["cpe_resolution"] = RESOLUTION_FAILED
            item["resolution_error"] = answer.get("error", "")
            resolved.append(item)
            continue
        choice = choose_cpe(product["cpe"], answer["names"])
        if choice["outcome"] == "ambiguous":
            result["skipped"].append({"cpe": product["cpe"],
                                      "ports": list(product.get("ports") or []),
                                      "reason": choice["reason"],
                                      "candidates": choice["candidates"]})
            continue
        item["cpe"] = choice["cpe"]
        item["cpe_resolution"] = RESOLVED if choice["outcome"] == "resolved" else NOT_IN_DICTIONARY
        resolved.append(item)
    for item in resolved:
        item.update(lookup_cpe(item["cpe"], api_key, pacer, cache_dir))
        result["products"].append(item)
    return result


# ---- helpers shared by the agent tool and the report --------------------

def severity_counts(cves):
    """{CRITICAL, HIGH, MEDIUM, LOW, NONE, UNSCORED: count}."""
    counts = {s: 0 for s in SEVERITIES + (UNSCORED,)}
    for c in cves or []:
        severity = str(c.get("cvss_severity") or "").upper()
        counts[severity if severity in SEVERITIES else UNSCORED] += 1
    return counts


def _score_key(cve):
    score = cve.get("cvss_score")
    if isinstance(score, (int, float)) and not isinstance(score, bool):
        return (0, -score, str(cve.get("id", "")))
    return (1, 0, str(cve.get("id", "")))


def by_score(cves):
    """Highest CVSS score first, unscored last, ties by CVE ID."""
    return sorted(cves or [], key=_score_key)


def top_cves(cves, count):
    return by_score(cves)[:count]


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: python3 -m reconmind.tools.nvd_lookup <cpe 2.2 or 2.3> [...]")
        sys.exit(1)
    wanted, skipped_cpes = [], []
    for arg in sys.argv[1:]:
        converted, why = (arg, "") if arg.startswith("cpe:2.3:") else cpe22_to_23(arg)
        if converted:
            wanted.append({"product": arg, "cpe": converted, "source": ["cli"],
                           "from": [arg], "ports": []})
        else:
            skipped_cpes.append({"cpe": arg, "ports": [], "reason": why})
    out = run_cve_lookup(wanted, skipped_cpes)
    for s in out["skipped"]:
        print("skipped:", s["cpe"], "(" + s["reason"] + ")")
    for p in out["products"]:
        print(p["cpe"], " status:", p["status"], " CVEs:", p["total_results"],
              " cached" if p["from_cache"] else "")
        for c in top_cves(p["cves"], 5):
            print("  {i}  {s} {v} ({c})".format(i=c["id"], s=c["cvss_score"],
                                                v=c["cvss_severity"], c=c["cvss_version"]))
