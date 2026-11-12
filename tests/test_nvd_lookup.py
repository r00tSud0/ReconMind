"""
Offline tests for the NVD CVE lookup module. urllib's urlopen is replaced by
a fake that serves a small NVD API 2.0 fixture, time.sleep and the clock are
mocked, and the cache lives in a temp directory, so nothing reaches NVD and
no test waits.

The fixture follows NVD's API 2.0 answer shape, trimmed for the tests.
"""

import json
import os
import tempfile
import unittest
from unittest import mock
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit

from reconmind.tools import nvd_lookup

TARGET = "10.10.1.100"
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "nvd_php_5.2.4.json")
with open(FIXTURE, "rb") as _fh:
    FIXTURE_BYTES = _fh.read()
VULNS = json.loads(FIXTURE_BYTES)["vulnerabilities"]

PHP_CPE = "cpe:2.3:a:php:php:5.2.4:*:*:*:*:*:*:*"
APACHE_CPE = "cpe:2.3:a:apache:http_server:2.2.8:*:*:*:*:*:*:*"
NOW = 1800000000.0


def page(vulns, total, start=0):
    """One NVD API 2.0 answer holding the given vulnerability entries."""
    return json.dumps({"resultsPerPage": len(vulns), "startIndex": start,
                       "totalResults": total, "format": "NVD_CVE", "version": "2.0",
                       "timestamp": "2026-11-12T15:04:11.873",
                       "vulnerabilities": vulns}).encode("utf-8")


def http_error(code):
    return HTTPError(nvd_lookup.NVD_URL, code, "error", {}, None)


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeNVD:
    """Stands in for urlopen. Serves the answers in order; an exception is raised."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.requests = []

    def __call__(self, request, timeout=None):
        self.requests.append((request, timeout))
        if not self.answers:
            raise AssertionError("unexpected NVD request: " + request.full_url)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return FakeResponse(answer)

    def query(self, n):
        return parse_qs(urlsplit(self.requests[n][0].full_url).query)


def product(cpe, label="PHP 5.2.4", ports=("80/tcp",)):
    return {"product": label, "cpe": cpe, "source": ["whatweb"], "from": [label],
            "ports": list(ports)}


class NVDTestCase(unittest.TestCase):
    """Temp cache, mocked sleep and clock, no NVD_API_KEY in the environment."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.cache_dir = self._tmp.name
        self.sleeps = []
        self.now = NOW
        patches = [
            mock.patch.object(nvd_lookup, "CACHE_DIR", self.cache_dir),
            mock.patch.object(nvd_lookup, "_sleep", self.sleeps.append),
            mock.patch.object(nvd_lookup, "_now", lambda: self.now),
            mock.patch.dict(os.environ),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        os.environ.pop("NVD_API_KEY", None)
        self.addCleanup(self._tmp.cleanup)

    def fake(self, *answers):
        fake = FakeNVD(*answers)
        p = mock.patch.object(nvd_lookup, "urlopen", fake)
        p.start()
        self.addCleanup(p.stop)
        return fake


class CpeConversionTests(unittest.TestCase):

    def test_application_cpe(self):
        self.assertEqual(nvd_lookup.cpe22_to_23("cpe:/a:apache:http_server:2.2.8"),
                         (APACHE_CPE, ""))

    def test_openssh_portable_version_split_into_version_and_update(self):
        self.assertEqual(nvd_lookup.cpe22_to_23("cpe:/a:openbsd:openssh:4.7p1"),
                         ("cpe:2.3:a:openbsd:openssh:4.7:p1:*:*:*:*:*:*", ""))
        self.assertEqual(nvd_lookup.cpe22_to_23("cpe:/a:openbsd:openssh:10.12p3"),
                         ("cpe:2.3:a:openbsd:openssh:10.12:p3:*:*:*:*:*:*", ""))

    def test_openssh_split_only_for_the_exact_pattern(self):
        # No p suffix, a third version part, or an update already given: unchanged.
        self.assertEqual(nvd_lookup.cpe22_to_23("cpe:/a:openbsd:openssh:7.4"),
                         ("cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*", ""))
        self.assertEqual(nvd_lookup.cpe22_to_23("cpe:/a:openbsd:openssh:4.7.1p1"),
                         ("cpe:2.3:a:openbsd:openssh:4.7.1p1:*:*:*:*:*:*:*", ""))
        self.assertEqual(nvd_lookup.cpe22_to_23("cpe:/a:openbsd:openssh:4.7p1:beta"),
                         ("cpe:2.3:a:openbsd:openssh:4.7p1:beta:*:*:*:*:*:*", ""))

    def test_no_other_product_gets_the_openssh_split(self):
        for cpe, expected in (
                ("cpe:/a:vendor:product:4.7p1", "cpe:2.3:a:vendor:product:4.7p1:*:*:*:*:*:*:*"),
                ("cpe:/a:openbsd:openbgpd:4.7p1", "cpe:2.3:a:openbsd:openbgpd:4.7p1:*:*:*:*:*:*:*"),
                ("cpe:/a:other:openssh:4.7p1", "cpe:2.3:a:other:openssh:4.7p1:*:*:*:*:*:*:*"),
                ("cpe:/o:openbsd:openssh:4.7p1", "cpe:2.3:o:openbsd:openssh:4.7p1:*:*:*:*:*:*:*")):
            with self.subTest(cpe=cpe):
                self.assertEqual(nvd_lookup.cpe22_to_23(cpe), (expected, ""))

    def test_operating_system_cpe_and_update_field(self):
        self.assertEqual(nvd_lookup.cpe22_to_23("cpe:/o:canonical:ubuntu_linux:8.04"),
                         ("cpe:2.3:o:canonical:ubuntu_linux:8.04:*:*:*:*:*:*:*", ""))
        self.assertEqual(nvd_lookup.cpe22_to_23("cpe:/a:openbsd:openssh:4.7:p1"),
                         ("cpe:2.3:a:openbsd:openssh:4.7:p1:*:*:*:*:*:*", ""))

    def test_versionless_cpe_is_skipped_with_reason(self):
        for cpe in ("cpe:/o:linux:linux_kernel", "cpe:/a:samba:samba", "cpe:/a:samba:samba:",
                    "cpe:/a:samba:samba:-"):
            self.assertEqual(nvd_lookup.cpe22_to_23(cpe), ("", nvd_lookup.REASON_NO_VERSION))

    def test_not_a_cpe_22_string(self):
        for cpe in ("", None, "cpe:2.3:a:php:php:5.2.4", "apache 2.2.8", "cpe:/x:a:b:1",
                    "cpe:/a::product:1"):
            self.assertEqual(nvd_lookup.cpe22_to_23(cpe), ("", nvd_lookup.REASON_NOT_CPE))

    def test_too_many_fields(self):
        self.assertEqual(nvd_lookup.cpe22_to_23("cpe:/a:v:p:1:u:e:l:extra"),
                         ("", nvd_lookup.REASON_TOO_MANY_FIELDS))

    def test_percent_decoding_and_escaping(self):
        self.assertEqual(nvd_lookup.cpe22_to_23("cpe:/a:vendor:prod%7eone:1.0%2b"),
                         ("cpe:2.3:a:vendor:prod\\~one:1.0\\+:*:*:*:*:*:*:*", ""))

    def test_packed_edition_is_unpacked(self):
        self.assertEqual(nvd_lookup.cpe22_to_23("cpe:/a:v:p:1.0:u1:~ed~sw~tsw~thw~oth:en"),
                         ("cpe:2.3:a:v:p:1.0:u1:ed:en:sw:tsw:thw:oth", ""))


class PhpMappingTests(unittest.TestCase):

    def test_leading_upstream_version_only(self):
        self.assertEqual(nvd_lookup.php_cpe("5.2.4-2ubuntu5.10"), PHP_CPE)
        self.assertEqual(nvd_lookup.php_cpe("5.2.4"), PHP_CPE)
        self.assertEqual(nvd_lookup.php_cpe(" 7.4.3 "), "cpe:2.3:a:php:php:7.4.3:*:*:*:*:*:*:*")

    def test_no_numeric_version_gives_nothing(self):
        for version in ("", None, "unknown", "v5"):
            self.assertEqual(nvd_lookup.php_cpe(version), "")


class LookupTargetsTests(unittest.TestCase):

    PORTS = [
        {"port": 22, "protocol": "tcp", "product": "OpenSSH", "version": "4.7p1 Debian 8ubuntu1",
         "cpe": ["cpe:/a:openbsd:openssh:4.7p1", "cpe:/o:linux:linux_kernel"]},
        {"port": 80, "protocol": "tcp", "product": "Apache httpd", "version": "2.2.8",
         "cpe": ["cpe:/a:apache:http_server:2.2.8", "cpe:/o:linux:linux_kernel"]},
        {"port": 443, "protocol": "tcp", "product": "Apache httpd", "version": "2.2.8",
         "cpe": ["cpe:/a:apache:http_server:2.2.8"]},
        {"port": 3306, "protocol": "tcp", "product": "MySQL", "version": "5.0.51a"},
    ]
    WEB = {
        80: {"status": "ok", "url": "http://" + TARGET + ":80", "components": [
            {"name": "Apache", "versions": ["2.2.8"], "strings": ["Ubuntu"]},
            {"name": "PHP", "versions": ["5.2.4-2ubuntu5.10"], "strings": []}]},
        "443": {"status": "ok", "url": "https://" + TARGET + ":443", "components": [
            {"name": "PHP", "versions": ["5.2.4-2ubuntu5.10", "unknown"], "strings": []}]},
        8080: {"status": "timeout", "components": [{"name": "PHP", "versions": ["7.0.1"]}]},
    }

    def test_versioned_cpes_become_products_merged_by_cpe(self):
        products, _ = nvd_lookup.lookup_targets(self.PORTS)
        self.assertEqual([p["cpe"] for p in products],
                         ["cpe:2.3:a:openbsd:openssh:4.7:p1:*:*:*:*:*:*", APACHE_CPE])
        apache = products[1]
        self.assertEqual(apache["product"], "Apache httpd 2.2.8")
        self.assertEqual(apache["ports"], ["80/tcp", "443/tcp"])
        self.assertEqual(apache["from"], ["cpe:/a:apache:http_server:2.2.8"])
        self.assertEqual(apache["source"], ["nmap"])

    def test_versionless_cpes_are_skipped_and_said_so(self):
        _, skipped = nvd_lookup.lookup_targets(self.PORTS)
        self.assertEqual(skipped, [{"cpe": "cpe:/o:linux:linux_kernel",
                                    "ports": ["22/tcp", "80/tcp"],
                                    "reason": nvd_lookup.REASON_NO_VERSION}])

    def test_php_from_whatweb_only(self):
        products, skipped = nvd_lookup.lookup_targets([], self.WEB)
        self.assertEqual(len(products), 1)
        php = products[0]
        self.assertEqual(php["cpe"], PHP_CPE)
        self.assertEqual(php["product"], "PHP 5.2.4-2ubuntu5.10")
        self.assertEqual(php["ports"], ["80/tcp", "443/tcp"])  # failed port 8080 ignored
        self.assertEqual(php["source"], ["whatweb"])
        self.assertEqual(skipped, [{"cpe": "PHP unknown", "ports": ["443/tcp"],
                                    "reason": nvd_lookup.REASON_PHP_NO_VERSION}])

    def test_no_web_results(self):
        self.assertEqual(nvd_lookup.lookup_targets([], None), ([], []))

    def test_target_address_never_in_products(self):
        products, skipped = nvd_lookup.lookup_targets(self.PORTS, self.WEB)
        self.assertNotIn(TARGET, json.dumps([products, skipped]))


class ParseTests(unittest.TestCase):

    def test_v31_preferred_over_v2(self):
        cve = nvd_lookup.parse_cve(VULNS[0])
        self.assertEqual(cve["id"], "CVE-2012-1823")
        self.assertEqual(cve["cvss_score"], 9.8)
        self.assertEqual(cve["cvss_severity"], "CRITICAL")
        self.assertEqual(cve["cvss_vector"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(cve["cvss_version"], "v3.1")

    def test_v30_used_and_primary_entry_preferred(self):
        cve = nvd_lookup.parse_cve(VULNS[1])
        self.assertEqual((cve["cvss_score"], cve["cvss_severity"], cve["cvss_version"]),
                         (7.5, "HIGH", "v3.0"))
        self.assertEqual(cve["cvss_vector"], "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")

    def test_v2_fallback_reads_severity_beside_cvss_data(self):
        cve = nvd_lookup.parse_cve(VULNS[2])
        self.assertEqual((cve["cvss_score"], cve["cvss_severity"], cve["cvss_version"]),
                         (10.0, "HIGH", "v2"))
        self.assertEqual(cve["cvss_vector"], "AV:N/AC:L/Au:N/C:C/I:C/A:C")

    def test_no_metrics(self):
        cve = nvd_lookup.parse_cve({"cve": {"id": "CVE-2026-0001", "metrics": {}}})
        self.assertEqual((cve["cvss_score"], cve["cvss_severity"], cve["cvss_vector"],
                          cve["cvss_version"]), (None, "", "", ""))
        self.assertEqual(cve["description"], "")
        self.assertEqual(cve["cwe"], [])

    def test_first_english_description_exactly_as_written(self):
        cve = nvd_lookup.parse_cve(VULNS[0])
        self.assertTrue(cve["description"].startswith("sapi/cgi/cgi_main.c in PHP before 5.3.12"))
        self.assertTrue(cve["description"].endswith("for the 'd' case."))

    def test_published_date_exactly_as_written(self):
        self.assertEqual(nvd_lookup.parse_cve(VULNS[0])["published"], "2012-05-11T10:15:05.110")

    def test_cwe_ids_in_order_without_repeats(self):
        self.assertEqual(nvd_lookup.parse_cve(VULNS[0])["cwe"], ["CWE-20"])
        self.assertEqual(nvd_lookup.parse_cve(VULNS[1])["cwe"], ["CWE-502", "CWE-835"])
        self.assertEqual(nvd_lookup.parse_cve(VULNS[2])["cwe"], ["NVD-CWE-Other"])

    def test_cisa_kev_flag_and_date(self):
        kev = nvd_lookup.parse_cve(VULNS[0])
        self.assertTrue(kev["kev"])
        self.assertEqual(kev["kev_added"], "2022-03-25")
        plain = nvd_lookup.parse_cve(VULNS[1])
        self.assertFalse(plain["kev"])
        self.assertEqual(plain["kev_added"], "")

    def test_entry_without_id_is_dropped(self):
        self.assertIsNone(nvd_lookup.parse_cve({"cve": {}}))
        self.assertIsNone(nvd_lookup.parse_cve("not a dict"))

    def test_severity_counts_and_score_order(self):
        cves = [nvd_lookup.parse_cve(v) for v in VULNS]
        cves.append(nvd_lookup.parse_cve({"cve": {"id": "CVE-2026-0001"}}))
        self.assertEqual(nvd_lookup.severity_counts(cves),
                         {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 0, "NONE": 0,
                          "UNSCORED": 1})
        self.assertEqual([c["id"] for c in nvd_lookup.by_score(cves)],
                         ["CVE-2008-2050", "CVE-2012-1823", "CVE-2016-7478", "CVE-2026-0001"])
        self.assertEqual(len(nvd_lookup.top_cves(cves, 2)), 2)


class QueryTests(NVDTestCase):

    def test_single_page(self):
        fake = self.fake(FIXTURE_BYTES)
        result = nvd_lookup.lookup_cpe(PHP_CPE)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["total_results"], 3)
        self.assertEqual([c["id"] for c in result["cves"]],
                         ["CVE-2012-1823", "CVE-2016-7478", "CVE-2008-2050"])
        self.assertFalse(result["from_cache"])
        self.assertEqual(result["fetched_at"], "2027-01-15T08:00:00Z")
        request, timeout = fake.requests[0]
        self.assertTrue(request.full_url.startswith(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?"))
        self.assertEqual(fake.query(0), {"cpeName": [PHP_CPE], "resultsPerPage": ["2000"],
                                         "startIndex": ["0"]})
        self.assertEqual(timeout, 30)
        self.assertEqual(self.sleeps, [])

    def test_pagination_is_followed(self):
        fake = self.fake(page(VULNS[:2], total=3, start=0), page(VULNS[2:], total=3, start=2))
        result = nvd_lookup.lookup_cpe(PHP_CPE)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(result["cves"]), 3)
        self.assertEqual([fake.query(n)["startIndex"] for n in range(2)], [["0"], ["2"]])
        self.assertEqual(self.sleeps, [6])  # the rate limit gap applies to every page

    def test_empty_page_stops_pagination(self):
        fake = self.fake(page([], total=5))
        result = nvd_lookup.lookup_cpe(PHP_CPE)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(fake.requests), 1)

    def test_api_key_header_when_given(self):
        fake = self.fake(FIXTURE_BYTES)
        nvd_lookup.lookup_cpe(PHP_CPE, api_key="secret-key")
        self.assertEqual(fake.requests[0][0].get_header("Apikey"), "secret-key")

    def test_no_api_key_header_without_key(self):
        fake = self.fake(FIXTURE_BYTES)
        nvd_lookup.lookup_cpe(PHP_CPE)
        self.assertIsNone(fake.requests[0][0].get_header("Apikey"))
        self.assertEqual(fake.requests[0][0].header_items(), [])

    def test_api_key_read_from_environment_and_never_stored(self):
        os.environ["NVD_API_KEY"] = "env-key"
        fake = self.fake(FIXTURE_BYTES)
        result = nvd_lookup.run_cve_lookup([product(PHP_CPE)])
        self.assertEqual(fake.requests[0][0].get_header("Apikey"), "env-key")
        self.assertTrue(result["api_key_used"])
        self.assertNotIn("env-key", json.dumps(result))
        with open(os.path.join(self.cache_dir, os.listdir(self.cache_dir)[0])) as fh:
            self.assertNotIn("env-key", fh.read())

    def test_wait_six_seconds_between_requests_without_key(self):
        self.fake(FIXTURE_BYTES, FIXTURE_BYTES, FIXTURE_BYTES)
        nvd_lookup.run_cve_lookup([product(PHP_CPE), product(APACHE_CPE),
                                   product("cpe:2.3:a:openbsd:openssh:4.7p1:*:*:*:*:*:*:*")])
        self.assertEqual(self.sleeps, [6, 6])

    def test_wait_one_second_between_requests_with_key(self):
        self.fake(FIXTURE_BYTES, FIXTURE_BYTES)
        nvd_lookup.run_cve_lookup([product(PHP_CPE), product(APACHE_CPE)], api_key="k")
        self.assertEqual(self.sleeps, [1])


class CacheTests(NVDTestCase):

    def test_answer_is_cached_with_fetch_time(self):
        self.fake(FIXTURE_BYTES)
        nvd_lookup.lookup_cpe(PHP_CPE)
        files = os.listdir(self.cache_dir)
        self.assertEqual(len(files), 1)
        with open(os.path.join(self.cache_dir, files[0])) as fh:
            entry = json.load(fh)
        self.assertEqual(entry["cpe"], PHP_CPE)
        self.assertEqual(entry["fetched_at"], "2027-01-15T08:00:00Z")
        self.assertEqual(entry["fetched_epoch"], NOW)
        self.assertEqual(entry["total_results"], 3)
        self.assertEqual(len(entry["cves"]), 3)

    def test_cache_reused_within_24_hours(self):
        fake = self.fake(FIXTURE_BYTES)
        first = nvd_lookup.lookup_cpe(PHP_CPE)
        self.now = NOW + 24 * 3600 - 1
        second = nvd_lookup.lookup_cpe(PHP_CPE)
        self.assertEqual(len(fake.requests), 1)
        self.assertTrue(second["from_cache"])
        self.assertEqual(second["fetched_at"], first["fetched_at"])
        self.assertEqual(second["cves"], first["cves"])

    def test_cache_expires_after_24_hours(self):
        fake = self.fake(FIXTURE_BYTES, page(VULNS[:1], total=1))
        nvd_lookup.lookup_cpe(PHP_CPE)
        self.now = NOW + 24 * 3600
        again = nvd_lookup.lookup_cpe(PHP_CPE)
        self.assertEqual(len(fake.requests), 2)
        self.assertFalse(again["from_cache"])
        self.assertEqual(len(again["cves"]), 1)

    def test_cached_answers_need_no_wait(self):
        self.fake(FIXTURE_BYTES, FIXTURE_BYTES)
        nvd_lookup.run_cve_lookup([product(PHP_CPE), product(APACHE_CPE)])
        del self.sleeps[:]
        result = nvd_lookup.run_cve_lookup([product(PHP_CPE), product(APACHE_CPE)])
        self.assertEqual(self.sleeps, [])
        self.assertTrue(all(p["from_cache"] for p in result["products"]))

    def test_corrupt_cache_is_fetched_again(self):
        fake = self.fake(FIXTURE_BYTES, FIXTURE_BYTES)
        nvd_lookup.lookup_cpe(PHP_CPE)
        path = os.path.join(self.cache_dir, os.listdir(self.cache_dir)[0])
        with open(path, "w") as fh:
            fh.write("{not json")
        result = nvd_lookup.lookup_cpe(PHP_CPE)
        self.assertEqual(len(fake.requests), 2)
        self.assertEqual(result["status"], "ok")

    def test_failures_are_not_cached(self):
        fake = self.fake(URLError("down"), FIXTURE_BYTES)
        self.assertEqual(nvd_lookup.lookup_cpe(PHP_CPE)["status"], "network-error")
        self.assertEqual(os.listdir(self.cache_dir), [])
        self.assertEqual(nvd_lookup.lookup_cpe(PHP_CPE)["status"], "ok")
        self.assertEqual(len(fake.requests), 2)

    def test_unwritable_cache_does_not_fail_the_lookup(self):
        self.fake(FIXTURE_BYTES)
        with mock.patch.object(nvd_lookup.os, "makedirs", side_effect=OSError("read only")):
            result = nvd_lookup.lookup_cpe(PHP_CPE)
        self.assertEqual(result["status"], "ok")


class FailureTests(NVDTestCase):

    def test_rate_limited_after_one_retry(self):
        for code in (403, 429):
            with self.subTest(code=code):
                del self.sleeps[:]
                fake = self.fake(http_error(code), http_error(code))
                result = nvd_lookup.lookup_cpe(PHP_CPE)
                self.assertEqual(result["status"], "rate-limited")
                self.assertEqual(len(fake.requests), 2)
                self.assertIn(30, self.sleeps)
                self.assertEqual(result["cves"], [])
                self.assertIn(str(code), result["error"])

    def test_retry_succeeds(self):
        fake = self.fake(http_error(429), FIXTURE_BYTES)
        result = nvd_lookup.lookup_cpe(PHP_CPE)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(fake.requests), 2)
        self.assertEqual(self.sleeps[0], 30)

    def test_503_twice_is_network_error(self):
        fake = self.fake(http_error(503), http_error(503))
        self.assertEqual(nvd_lookup.lookup_cpe(PHP_CPE)["status"], "network-error")
        self.assertEqual(len(fake.requests), 2)

    def test_500_is_network_error_without_retry(self):
        fake = self.fake(http_error(500))
        self.assertEqual(nvd_lookup.lookup_cpe(PHP_CPE)["status"], "network-error")
        self.assertEqual(len(fake.requests), 1)
        self.assertNotIn(30, self.sleeps)

    def test_404_is_bad_response(self):
        self.fake(http_error(404))
        self.assertEqual(nvd_lookup.lookup_cpe(PHP_CPE)["status"], "bad-response")

    def test_unreachable_or_timeout_is_network_error(self):
        for error in (URLError("Name or service not known"), TimeoutError("timed out"),
                      ConnectionResetError("reset")):
            with self.subTest(error=error):
                self.fake(error)
                result = nvd_lookup.lookup_cpe(PHP_CPE)
                self.assertEqual(result["status"], "network-error")
                self.assertIn("NVD could not be reached", result["error"])

    def test_bad_json_or_wrong_shape_is_bad_response(self):
        for body in (b"<html>Service Unavailable</html>", b"[]", b'{"totalResults": 1}',
                     b'{"totalResults": "1", "vulnerabilities": []}', b"\xff\xfe"):
            with self.subTest(body=body):
                self.fake(body)
                self.assertEqual(nvd_lookup.lookup_cpe(PHP_CPE)["status"], "bad-response")

    def test_one_failure_does_not_stop_the_run(self):
        self.fake(http_error(500), FIXTURE_BYTES)
        result = nvd_lookup.run_cve_lookup([product(APACHE_CPE), product(PHP_CPE)])
        self.assertEqual(result["status"], "ok")
        self.assertEqual([p["status"] for p in result["products"]], ["network-error", "ok"])
        self.assertEqual(result["products"][1]["total_results"], 3)

    def test_no_cpe_makes_no_request(self):
        fake = self.fake()
        skipped = [{"cpe": "cpe:/o:linux:linux_kernel", "ports": ["22/tcp"],
                    "reason": nvd_lookup.REASON_NO_VERSION}]
        result = nvd_lookup.run_cve_lookup([], skipped)
        self.assertEqual(result["status"], "no-cpe")
        self.assertEqual(result["skipped"], skipped)
        self.assertIn("nothing was looked up", result["error"])
        self.assertEqual(fake.requests, [])


class PrivacyTests(NVDTestCase):

    def test_target_and_scan_details_never_leave_the_machine(self):
        os.environ["NVD_API_KEY"] = "k"
        ports = [
            {"port": 80, "protocol": "tcp", "service": "http", "product": "Apache httpd",
             "version": "2.2.8 ((Ubuntu) DAV/2)", "reason": "syn-ack",
             "cpe": ["cpe:/a:apache:http_server:2.2.8"]},
            {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH",
             "version": "4.7p1 Debian 8ubuntu1", "cpe": ["cpe:/a:openbsd:openssh:4.7p1"]},
        ]
        web = {80: {"status": "ok", "url": "http://{t}:80/".format(t=TARGET),
                    "components": [{"name": "PHP", "versions": ["5.2.4-2ubuntu5.10"]},
                                   {"name": "IP", "strings": [TARGET]}]}}
        fake = self.fake(FIXTURE_BYTES, FIXTURE_BYTES, FIXTURE_BYTES)
        products, skipped = nvd_lookup.lookup_targets(ports, web)
        nvd_lookup.run_cve_lookup(products, skipped)
        self.assertEqual(len(fake.requests), 3)
        sent_cpes = set()
        for request, _ in fake.requests:
            sent = request.full_url + " " + json.dumps(request.header_items())
            for detail in (TARGET, "10.10.1", "syn-ack", "Ubuntu", "DAV", "Debian", ":80"):
                self.assertNotIn(detail, sent)
            query = parse_qs(urlsplit(request.full_url).query)
            self.assertEqual(set(query), {"cpeName", "resultsPerPage", "startIndex"})
            sent_cpes.add(query["cpeName"][0])
            self.assertEqual([k for k, _ in request.header_items()], ["Apikey"])
            self.assertEqual(urlsplit(request.full_url).netloc, "services.nvd.nist.gov")
        self.assertEqual(sent_cpes, {APACHE_CPE, PHP_CPE,
                                     "cpe:2.3:a:openbsd:openssh:4.7:p1:*:*:*:*:*:*"})


if __name__ == "__main__":
    unittest.main()
