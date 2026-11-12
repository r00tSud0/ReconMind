"""
Offline tests for the cve_lookup agent tool, its prompt rule and the report's
Known CVEs (NVD) section. urllib's urlopen is replaced by the fake NVD from
test_nvd_lookup, so nothing reaches NVD and no test waits.
"""

import copy
import json
import os
import tempfile
import unittest

from reconmind.agent import prompts, tools as toolmod
from reconmind.core.report import build_report
from reconmind.tools import nvd_lookup

from tests.test_nvd_lookup import (
    APACHE_CPE, FIXTURE_BYTES, PHP_CPE, TARGET, VULNS, NVDTestCase, http_error, page)

PATCH_NOTE = ("NVD matches the upstream version. Linux distributions often fix CVEs "
              "without changing the version number, so some of these may already be "
              "patched on the target.")

SCAN = {
    "target": TARGET, "status": "ok",
    "ports": [
        {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH",
         "version": "4.7p1 Debian 8ubuntu1", "tunnel": "",
         "cpe": ["cpe:/a:openbsd:openssh:4.7p1", "cpe:/o:linux:linux_kernel"]},
        {"port": 80, "protocol": "tcp", "service": "http", "product": "Apache httpd",
         "version": "2.2.8", "tunnel": "",
         "cpe": ["cpe:/a:apache:http_server:2.2.8", "cpe:/o:linux:linux_kernel"]},
    ],
    "web": {80: {"status": "ok", "url": "http://10.10.1.100:80", "http_status": 200,
                 "components": [{"name": "PHP", "versions": ["5.2.4-2ubuntu5.10"],
                                 "strings": []}]}},
}
OPENSSH_CPE = "cpe:2.3:a:openbsd:openssh:4.7:p1:*:*:*:*:*:*"
NO_RESULTS = ("NVD returned no CVEs for this exact product ID. This does not mean the "
              "product has no known vulnerabilities.")


def many_cves(count):
    """count NVD entries with falling v3.1 scores, none in CISA KEV."""
    vulns = []
    for n in range(count):
        score = round(9.0 - n * 0.5, 1)
        vulns.append({"cve": {
            "id": "CVE-2020-{n:04d}".format(n=1000 + n), "published": "2020-01-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "Issue number {n}.".format(n=n)}],
            "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
                "version": "3.1", "baseScore": score,
                "baseSeverity": "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}})
    return vulns


class CveLookupToolTests(NVDTestCase):

    def toolbox(self, scan=SCAN):
        tb = toolmod.ToolBox(TARGET)
        tb.scan = copy.deepcopy(scan)
        return tb

    def test_requires_nmap_scan_first(self):
        fake = self.fake()
        obs, is_error = toolmod.ToolBox(TARGET).call("cve_lookup", {})
        self.assertTrue(is_error)
        self.assertIn("Run nmap_scan first", obs)
        self.assertEqual(fake.requests, [])

    def test_spec_takes_no_inputs(self):
        spec = next(s for s in toolmod.TOOL_SPECS if s["name"] == "cve_lookup")
        self.assertEqual(spec["input_schema"], {"type": "object", "properties": {},
                                                "required": []})
        self.assertIn("Run nmap_scan first", spec["description"])

    def test_looks_up_nmap_cpes_and_php_and_stores_results(self):
        fake = self.fake(FIXTURE_BYTES, page(VULNS[1:2], total=1), page([], total=0))
        tb = self.toolbox()
        obs, is_error = tb.call("cve_lookup", {})
        self.assertFalse(is_error)
        nvd = tb.scan["nvd"]
        self.assertEqual(nvd["status"], "ok")
        self.assertEqual([p["cpe"] for p in nvd["products"]],
                         [OPENSSH_CPE, APACHE_CPE, PHP_CPE])
        self.assertEqual([p["status"] for p in nvd["products"]], ["ok", "ok", "ok"])
        self.assertEqual(len(nvd["products"][0]["cves"]), 3)
        self.assertEqual(nvd["skipped"][0]["cpe"], "cpe:/o:linux:linux_kernel")
        self.assertEqual(len(fake.requests), 3)

    def test_compact_observation(self):
        self.fake(FIXTURE_BYTES, page([], total=0), page([], total=0))
        obs, _ = self.toolbox().call("cve_lookup", {})
        data = json.loads(obs)
        self.assertEqual(data["note"], PATCH_NOTE)
        self.assertEqual(data["skipped"], [{"cpe": "cpe:/o:linux:linux_kernel",
                                            "ports": ["22/tcp", "80/tcp"],
                                            "reason": "no version in the CPE"}])
        first = data["products"][0]
        self.assertEqual(first["cpe"], OPENSSH_CPE)
        self.assertEqual(first["product"], "OpenSSH 4.7p1 Debian 8ubuntu1")
        self.assertEqual(first["ports"], ["22/tcp"])
        self.assertEqual(first["cve_count"], 3)
        self.assertEqual(first["severity_counts"],
                         {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 0, "NONE": 0,
                          "UNSCORED": 0})
        self.assertEqual(first["cisa_kev"], [{"id": "CVE-2012-1823", "score": 9.8,
                                              "severity": "CRITICAL",
                                              "kev_added": "2022-03-25"}])
        self.assertEqual(first["top_cvss"], [
            {"id": "CVE-2008-2050", "score": 10.0, "severity": "HIGH"},
            {"id": "CVE-2012-1823", "score": 9.8, "severity": "CRITICAL"},
            {"id": "CVE-2016-7478", "score": 7.5, "severity": "HIGH"}])
        # Descriptions, vectors and CWE IDs stay in the stored results.
        self.assertNotIn("sapi/cgi", obs)
        self.assertNotIn("CVSS:3.1/", obs)
        self.assertNotIn("CWE-20", obs)

    def test_zero_results_say_so_never_a_bare_count(self):
        self.fake(FIXTURE_BYTES, page([], total=0), page([], total=0))
        data = json.loads(self.toolbox().call("cve_lookup", {})[0])
        apache, php = data["products"][1], data["products"][2]
        for item in (apache, php):
            self.assertEqual(item["status"], "ok")
            self.assertEqual(item["note"], NO_RESULTS)
            for key in ("cve_count", "severity_counts", "cisa_kev", "top_cvss"):
                self.assertNotIn(key, item)
        self.assertNotIn("note", data["products"][0])

    def test_top_five_by_cvss_only(self):
        self.fake(page(many_cves(8), total=8), page([], total=0), page([], total=0))
        data = json.loads(self.toolbox().call("cve_lookup", {})[0])
        top = data["products"][0]["top_cvss"]
        self.assertEqual(len(top), 5)
        self.assertEqual([t["score"] for t in top], [9.0, 8.5, 8.0, 7.5, 7.0])
        self.assertEqual(data["products"][0]["cve_count"], 8)

    def test_failed_product_is_reported_not_raised(self):
        self.fake(http_error(429), http_error(429), FIXTURE_BYTES, FIXTURE_BYTES)
        obs, is_error = self.toolbox().call("cve_lookup", {})
        self.assertFalse(is_error)
        first = json.loads(obs)["products"][0]
        self.assertEqual(first["status"], "rate-limited")
        self.assertIn("does not mean it has no CVEs", first["note"])

    def test_no_cpe(self):
        scan = copy.deepcopy(SCAN)
        for p in scan["ports"]:
            p["cpe"] = []
        scan["web"] = {}
        fake = self.fake()
        tb = self.toolbox(scan)
        obs, is_error = tb.call("cve_lookup", {})
        self.assertFalse(is_error)
        self.assertEqual(json.loads(obs)["status"], "no-cpe")
        self.assertEqual(tb.scan["nvd"]["status"], "no-cpe")
        self.assertEqual(fake.requests, [])

    def test_target_never_sent(self):
        fake = self.fake(FIXTURE_BYTES, FIXTURE_BYTES, FIXTURE_BYTES)
        self.toolbox().call("cve_lookup", {})
        for request, _ in fake.requests:
            self.assertNotIn(TARGET, request.full_url)
            self.assertNotIn(TARGET, json.dumps(request.header_items()))


class PromptTests(unittest.TestCase):

    def test_rule_calls_cve_lookup_once_after_web_tools(self):
        self.assertIn("Call cve_lookup once, after the web tools", prompts.SYSTEM_PROMPT)


def nvd_result(cves, status="ok"):
    return {"status": "ok", "api_key_used": False, "products": [
        {"product": "PHP 5.2.4-2ubuntu5.10", "cpe": PHP_CPE, "source": ["whatweb"],
         "from": ["PHP 5.2.4-2ubuntu5.10"], "ports": ["80/tcp"], "status": status,
         "fetched_at": "2026-11-12T15:04:11Z", "from_cache": True,
         "total_results": len(cves), "cves": cves}],
        "skipped": [{"cpe": "cpe:/o:linux:linux_kernel", "ports": ["22/tcp", "80/tcp"],
                     "reason": "no version in the CPE"}]}


PARSED = [nvd_lookup.parse_cve(v) for v in VULNS]


class CveReportTests(unittest.TestCase):

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def report(self, nvd=None, nuclei=None, scan=SCAN):
        scan = copy.deepcopy(scan)
        if nvd is not None:
            scan["nvd"] = nvd
        if nuclei is not None:
            scan["nuclei"] = nuclei
        with open(build_report(scan)) as fh:
            return fh.read()

    @staticmethod
    def cve_lines(report):
        section = report.split("## Known CVEs (NVD)")[1].split("\n## ")[0]
        return [line for line in section.splitlines() if line.startswith("- CVE-")]

    def test_section_with_patch_note_cpe_counts_and_skipped(self):
        report = self.report(nvd_result(PARSED))
        self.assertIn("## Known CVEs (NVD)", report)
        self.assertIn(PATCH_NOTE, report)
        self.assertIn("**PHP 5.2.4-2ubuntu5.10** (80/tcp)", report)
        self.assertIn("CPE: `{c}`".format(c=PHP_CPE), report)
        self.assertIn("NVD data fetched: 2026-11-12T15:04:11Z (from cache)", report)
        self.assertIn("By severity: CRITICAL 1, HIGH 2, MEDIUM 0, LOW 0 (3 total)", report)
        self.assertIn("**Skipped, no version:** cpe:/o:linux:linux_kernel on 22/tcp, 80/tcp "
                      "(no version in the CPE).", report)

    def test_order_without_nuclei_is_kev_then_cvss(self):
        lines = self.cve_lines(self.report(nvd_result(PARSED)))
        self.assertEqual([l.split(":")[0] for l in lines],
                         ["- CVE-2012-1823", "- CVE-2008-2050", "- CVE-2016-7478"])
        self.assertNotIn("confirmed live by nuclei", "\n".join(lines))

    def test_nuclei_confirmed_first_case_insensitive(self):
        nuclei = {80: {"status": "ok", "findings": [
            {"template_id": "x", "severity": "high", "cve": ["cve-2016-7478"]}]}}
        lines = self.cve_lines(self.report(nvd_result(PARSED), nuclei))
        self.assertTrue(lines[0].startswith(
            "- CVE-2016-7478 (confirmed live by nuclei): CVSS 7.5 HIGH (v3.0), CISA KEV no. "
            "Zend/zend_exceptions.c in PHP"))
        self.assertTrue(lines[1].startswith(
            "- CVE-2012-1823: CVSS 9.8 CRITICAL (v3.1), CISA KEV yes (added 2022-03-25). "
            "sapi/cgi/cgi_main.c"))
        self.assertTrue(lines[2].startswith("- CVE-2008-2050: CVSS 10.0 HIGH (v2), CISA KEV no."))
        self.assertEqual(sum("confirmed live by nuclei" in l for l in lines), 1)

    def test_nuclei_string_port_keys_and_failed_runs(self):
        nuclei = {"80": {"status": "ok", "findings": [{"cve": ["CVE-2008-2050"]}]},
                  443: {"status": "timeout", "findings": [{"cve": ["CVE-2016-7478"]}]}}
        lines = self.cve_lines(self.report(nvd_result(PARSED), nuclei))
        self.assertTrue(lines[0].startswith("- CVE-2008-2050 (confirmed live by nuclei)"))
        self.assertNotIn("confirmed", lines[2])

    def test_ten_shown_and_rest_counted(self):
        cves = [nvd_lookup.parse_cve(v) for v in many_cves(12)] + PARSED
        report = self.report(nvd_result(cves))
        lines = self.cve_lines(report)
        self.assertEqual(len(lines), 10)
        self.assertTrue(lines[0].startswith("- CVE-2012-1823"))  # KEV before higher scores
        self.assertIn("...and 5 more stored in the scan data.", report)

    def test_short_description(self):
        lines = self.cve_lines(self.report(nvd_result(PARSED)))
        self.assertTrue(lines[0].endswith("..."))
        self.assertNotIn("php_getopt", lines[0])

    def test_unscored_cve(self):
        cve = nvd_lookup.parse_cve({"cve": {"id": "CVE-2026-0001"}})
        lines = self.cve_lines(self.report(nvd_result([cve])))
        self.assertEqual(lines, ["- CVE-2026-0001: no CVSS score, CISA KEV no"])

    def test_failed_product_line(self):
        report = self.report(nvd_result([], status="rate-limited"))
        self.assertIn("_NVD lookup failed (status rate-limited), so this product was not "
                      "checked. This does not mean it has no CVEs._", report)
        self.assertIn(PATCH_NOTE, report)

    def test_zero_results_say_so_never_a_bare_count(self):
        report = self.report(nvd_result([]))
        self.assertIn("_" + NO_RESULTS + "_", report)
        section = report.split("## Known CVEs (NVD)")[1].split("\n## ")[0]
        self.assertNotIn("By severity", section)
        self.assertNotIn("0 total", section)
        self.assertEqual(self.cve_lines(report), [])

    def test_no_cpe_status(self):
        nvd = {"status": "no-cpe", "products": [], "skipped": []}
        report = self.report(nvd)
        self.assertIn("_No open port has a CPE with a version, so nothing was looked up._",
                      report)
        self.assertIn(PATCH_NOTE, report)

    def test_not_checked_when_lookup_never_ran(self):
        report = self.report()
        self.assertIn("**Not checked:** open ports carry CPEs, but cve_lookup did not run, "
                      "so no CVEs were looked up.", report)
        self.assertNotIn(PATCH_NOTE, report)

    def test_no_section_without_cpes_or_results(self):
        scan = copy.deepcopy(SCAN)
        for p in scan["ports"]:
            del p["cpe"]
        self.assertNotIn("Known CVEs", self.report(scan=scan))

    def test_section_after_exploits_before_web(self):
        scan = copy.deepcopy(SCAN)
        scan["ports"][1]["exploits"] = [{"title": "Apache Something", "edb_id": "1",
                                         "match": "exact_version", "query": "Apache 2.2.8"}]
        report = self.report(nvd_result(PARSED), scan=scan)
        self.assertLess(report.index("## Known exploits (Exploit-DB)"),
                        report.index("## Known CVEs (NVD)"))
        self.assertLess(report.index("## Known CVEs (NVD)"),
                        report.index("## Web technology (whatweb)"))

    def test_no_em_dashes_or_dash_separators_in_our_text(self):
        report = self.report(nvd_result(PARSED), {80: {"status": "ok", "findings": [
            {"cve": ["CVE-2012-1823"]}]}})
        # The fixture's NVD descriptions hold no dashes, so the whole section is checked.
        section = report.split("## Known CVEs (NVD)")[1].split("\n## ")[0]
        self.assertNotIn("—", section)
        self.assertNotIn("–", section)
        self.assertNotIn(" - ", section)


if __name__ == "__main__":
    unittest.main()
