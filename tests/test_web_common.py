"""
Offline tests for the shared web helpers: which nmap ports count as web
services, when HTTPS is used, how URLs are built, and nmap recording the
tunnel field those choices rely on.
"""

import unittest

from reconmind.tools import web_common


class HelperTests(unittest.TestCase):

    def test_is_web_service(self):
        for name in ("http", "https", "ssl/http", "http-proxy", "http-alt", "HTTP"):
            self.assertTrue(web_common.is_web_service({"service": name}), name)
        for name in ("ssh", "ftp", "ssl", "", None):
            self.assertFalse(web_common.is_web_service({"service": name}), name)

    def test_wants_https(self):
        self.assertTrue(web_common.wants_https({"service": "http", "tunnel": "ssl"}))
        self.assertTrue(web_common.wants_https({"service": "ssl/http"}))
        self.assertTrue(web_common.wants_https({"service": "https"}))
        self.assertFalse(web_common.wants_https({"service": "http", "tunnel": ""}))
        self.assertFalse(web_common.wants_https({"service": "http-proxy"}))

    def test_build_url(self):
        self.assertEqual(web_common.build_url("10.10.1.100", 80), "http://10.10.1.100:80")
        self.assertEqual(web_common.build_url(" 10.10.1.100 ", "8443", use_https=True),
                         "https://10.10.1.100:8443")
        self.assertEqual(web_common.build_url("fe80::1", 80), "http://[fe80::1]:80")

    def test_nmap_records_tunnel(self):
        from reconmind.tools import nmap_scan
        xml = """<?xml version="1.0"?>
<nmaprun><host><ports>
  <port protocol="tcp" portid="443"><state state="open"/>
    <service name="http" product="Apache httpd" tunnel="ssl"/></port>
  <port protocol="tcp" portid="80"><state state="open"/>
    <service name="http" product="Apache httpd"/></port>
</ports></host></nmaprun>"""
        ports = {p["port"]: p for p in nmap_scan._parse_nmap_xml(xml)}
        self.assertEqual(ports[443]["tunnel"], "ssl")
        self.assertEqual(ports[80]["tunnel"], "")


if __name__ == "__main__":
    unittest.main()
