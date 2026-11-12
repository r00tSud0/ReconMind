"""
ReconMind NVD CVE lookup (Stage 2, known CVEs).

Looks up the CVEs that NVD lists for each versioned product found in a scan,
using the NVD CVE API 2.0 and the standard library only.

Privacy rule: only CPE strings ever leave the machine. The target address,
ports, banners and every other scan detail stay local. lookup_targets reads
nothing but each port's "cpe" list and whatweb's PHP versions, and the
request URL carries only cpeName, resultsPerPage and startIndex. The only
header sent is apiKey, when NVD_API_KEY is set.

Where the CPEs come from:
    - nmap writes CPE 2.2 (cpe:/a:vendor:product:version). Each one is
      converted to CPE 2.3. A CPE without a version is skipped and reported
      as skipped, because NVD would answer for every version of the product.
    - whatweb's PHP component, the only explicit mapping: PHP 5.2.4-2ubuntu5.10
      becomes cpe:2.3:a:php:php:5.2.4:*:*:*:*:*:*:*, using only the leading
      upstream version. Nothing else is guessed.

NVD's rate limit is respected: 6 seconds between requests without an API key,
1 second with one. Each request has a 30 second timeout and one retry, after
30 seconds, on HTTP 403, 429 or 503. Answers are cached per CPE as JSON under
~/.cache/reconmind/nvd/ and reused for 24 hours.

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
RESULTS_PER_PAGE = 2000
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

NO_RESULTS_NOTE = ("NVD returned no CVEs for this exact product ID. This does not mean "
                   "the product has no known vulnerabilities.")

REASON_NO_VERSION = "no version in the CPE"
REASON_NOT_CPE = "not a CPE 2.2 string"
REASON_TOO_MANY_FIELDS = "more fields than CPE 2.2 allows"
REASON_PHP_NO_VERSION = "no upstream version in the PHP version"

_UPSTREAM_VERSION = re.compile(r"\d+(?:\.\d+)*")
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


def lookup_targets(ports, web=None):
    """
    Return (products, skipped) for a scan's open ports and whatweb results.

    products: [{"product", "cpe", "source", "from", "ports"}], one per
    distinct CPE 2.3 string. skipped: [{"cpe", "ports", "reason"}], one per
    distinct CPE or PHP version that was not looked up. Only CPE values and
    PHP versions are read; the target address is never touched.
    """
    products, by_cpe = [], {}
    skipped, skipped_by = [], {}

    def add(cpe23, label, source, raw, port_label):
        item = by_cpe.get(cpe23)
        if item is None:
            item = {"product": label, "cpe": cpe23, "source": [], "from": [], "ports": []}
            by_cpe[cpe23] = item
            products.append(item)
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
        for raw in port.get("cpe") or []:
            cpe23, reason = cpe22_to_23(raw)
            if cpe23:
                add(cpe23, label or cpe23, "nmap", raw, port_label)
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


def parse_page(body):
    """Return (total_results, vulnerability items) for one NVD answer."""
    try:
        data = json.loads(body.decode("utf-8") if isinstance(body, bytes) else body)
    except (ValueError, UnicodeDecodeError) as exc:
        raise _BadResponse("NVD answer is not valid JSON: {e}".format(e=exc))
    if not isinstance(data, dict):
        raise _BadResponse("NVD answer is not a JSON object.")
    total, items = data.get("totalResults"), data.get("vulnerabilities")
    if not isinstance(total, int) or isinstance(total, bool) or not isinstance(items, list):
        raise _BadResponse("NVD answer has no totalResults or vulnerabilities list.")
    return total, items


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
    """One NVD request, with one retry on 403, 429 or 503. Returns the body."""
    url = NVD_URL + "?" + urlencode({"cpeName": cpe, "resultsPerPage": RESULTS_PER_PAGE,
                                     "startIndex": start})
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


# ---- cache --------------------------------------------------------------

def _cache_path(cpe, cache_dir):
    return os.path.join(cache_dir, hashlib.sha256(cpe.encode("utf-8")).hexdigest() + ".json")


def _read_cache(cpe, cache_dir, now):
    """The cached answer for cpe if it is under 24 hours old, else None."""
    try:
        with open(_cache_path(cpe, cache_dir)) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("cpe") != cpe:
        return None
    fetched = data.get("fetched_epoch")
    if not isinstance(fetched, (int, float)) or not isinstance(data.get("cves"), list):
        return None
    if not 0 <= now - fetched < CACHE_MAX_AGE:
        return None
    return data


def _write_cache(entry, cache_dir):
    """Best effort: a cache that cannot be written only costs a fresh query."""
    path = _cache_path(entry["cpe"], cache_dir)
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
    except HTTPError as exc:
        if exc.code in (403, 429):
            return _failure(cpe, STATUS_RATE_LIMITED,
                            "NVD refused the request (HTTP {c}) after one retry.".format(
                                c=exc.code))
        status = STATUS_NETWORK_ERROR if exc.code >= 500 else STATUS_BAD_RESPONSE
        return _failure(cpe, status, "NVD answered HTTP {c}.".format(c=exc.code))
    except _BadResponse as exc:
        return _failure(cpe, STATUS_BAD_RESPONSE, str(exc))
    except (URLError, OSError, http.client.HTTPException) as exc:
        reason = getattr(exc, "reason", None) or exc
        return _failure(cpe, STATUS_NETWORK_ERROR,
                        "NVD could not be reached: {e}".format(e=reason))
    fetched = _now()
    entry = {"cpe": cpe, "fetched_at": datetime.fromtimestamp(fetched, timezone.utc).strftime(
                 "%Y-%m-%dT%H:%M:%SZ"),
             "fetched_epoch": fetched, "total_results": total, "cves": cves}
    _write_cache(entry, cache_dir)
    return {"cpe": cpe, "status": STATUS_OK, "fetched_at": entry["fetched_at"],
            "from_cache": False, "total_results": total, "cves": cves}


def run_cve_lookup(products, skipped=(), api_key=None, cache_dir=None):
    """
    Look up every product from lookup_targets and return:
        {"status", "api_key_used", "products": [{"product", "cpe", "source",
         "from", "ports", "status", "fetched_at", "from_cache",
         "total_results", "cves": [...]}], "skipped": [...]}
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
    for product in products:
        answer = lookup_cpe(product["cpe"], api_key, pacer, cache_dir)
        item = dict(product)
        item.update(answer)
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
