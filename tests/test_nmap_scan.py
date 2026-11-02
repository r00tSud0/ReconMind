"""
Offline tests for the nmap wrapper: XML parsing with smb-os-discovery output,
the scan flags, and the authorization gate running before nmap.
"""

import unittest
from unittest import mock

from reconmind.tools import nmap_scan

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -Pn -sV --script smb-os-discovery -T4 10.10.1.100">
  <host>
    <address addr="10.10.1.100" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="4.7p1 Debian 8ubuntu1"/>
      </port>
      <port protocol="tcp" portid="139">
        <state state="open"/>
        <service name="netbios-ssn" product="Samba smbd" version="3.X - 4.X"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="netbios-ssn" product="Samba smbd" version="3.X - 4.X"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="closed"/>
        <service name="mysql"/>
      </port>
    </ports>
    <hostscript>
      <script id="smb-os-discovery" output="&#xa;  OS: Unix (Samba 3.0.20-Debian)&#xa;  Computer name: metasploitable&#xa;">
        <elem key="os">Unix</elem>
        <elem key="lanmanager">Samba 3.0.20-Debian</elem>
        <elem key="server">METASPLOITABLE</elem>
      </script>
    </hostscript>
  </host>
</nmaprun>
"""


class ParseTests(unittest.TestCase):

    def test_smb_os_discovery_fills_samba_ports(self):
        ports = {p["port"]: p for p in nmap_scan._parse_nmap_xml(SAMPLE_XML)}
        self.assertEqual(sorted(ports), [22, 139, 445])  # closed 3306 dropped
        for port in (139, 445):
            self.assertEqual(ports[port]["product"], "Samba smbd")
            self.assertEqual(ports[port]["version"], "3.0.20-Debian")
        self.assertEqual(ports[22]["version"], "4.7p1 Debian 8ubuntu1")

    def test_text_output_fallback(self):
        xml = SAMPLE_XML.replace('<elem key="lanmanager">Samba 3.0.20-Debian</elem>', "")
        ports = {p["port"]: p for p in nmap_scan._parse_nmap_xml(xml)}
        self.assertEqual(ports[445]["version"], "3.0.20-Debian")

    def test_without_script_output_versions_are_unchanged(self):
        start = SAMPLE_XML.index("<hostscript>")
        end = SAMPLE_XML.index("</hostscript>") + len("</hostscript>")
        ports = {p["port"]: p for p in nmap_scan._parse_nmap_xml(SAMPLE_XML[:start] + SAMPLE_XML[end:])}
        self.assertEqual(ports[445]["version"], "3.X - 4.X")

    def test_non_samba_smb_port_untouched(self):
        xml = SAMPLE_XML.replace(
            '<service name="netbios-ssn" product="Samba smbd" version="3.X - 4.X"/>\n      </port>\n      <port protocol="tcp" portid="3306">',
            '<service name="microsoft-ds" product="Microsoft Windows 7 microsoft-ds"/>\n      </port>\n      <port protocol="tcp" portid="3306">')
        ports = {p["port"]: p for p in nmap_scan._parse_nmap_xml(xml)}
        self.assertEqual(ports[445]["product"], "Microsoft Windows 7 microsoft-ds")
        self.assertEqual(ports[139]["version"], "3.0.20-Debian")


IRC_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -Pn -sV --script smb-os-discovery,irc-info -T4 10.10.1.100">
  <host>
    <address addr="10.10.1.100" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="6667">
        <state state="open"/>
        <service name="irc" product="UnrealIRCd"/>
        <script id="irc-info" output="&#xa;  users: 1&#xa;  servers: 1&#xa;  lusers: 1&#xa;  lservers: 0&#xa;  server: irc.Metasploitable.LAN&#xa;  version: Unreal3.2.8.1. irc.Metasploitable.LAN &#xa;  uptime: 0 days, 0:12:34&#xa;  source ident: nmap&#xa;">
          <elem key="users">1</elem>
          <elem key="server">irc.Metasploitable.LAN</elem>
          <elem key="version">Unreal3.2.8.1. irc.Metasploitable.LAN </elem>
        </script>
      </port>
      <port protocol="tcp" portid="6697">
        <state state="open"/>
        <service name="irc" product="UnrealIRCd"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class IrcInfoTests(unittest.TestCase):

    def test_irc_info_fills_unrealircd_version(self):
        ports = {p["port"]: p for p in nmap_scan._parse_nmap_xml(IRC_XML)}
        self.assertEqual(ports[6667]["product"], "UnrealIRCd")
        self.assertEqual(ports[6667]["version"], "3.2.8.1")

    def test_irc_info_text_output_fallback(self):
        xml = IRC_XML.replace('<elem key="version">Unreal3.2.8.1. irc.Metasploitable.LAN </elem>', "")
        ports = {p["port"]: p for p in nmap_scan._parse_nmap_xml(xml)}
        self.assertEqual(ports[6667]["version"], "3.2.8.1")

    def test_port_without_script_output_is_untouched(self):
        ports = {p["port"]: p for p in nmap_scan._parse_nmap_xml(IRC_XML)}
        self.assertEqual(ports[6697]["product"], "UnrealIRCd")
        self.assertIsNone(ports[6697]["version"])

    def test_empty_script_output_is_untouched(self):
        start = IRC_XML.index("<script")
        end = IRC_XML.index("</script>") + len("</script>")
        xml = IRC_XML[:start] + '<script id="irc-info" output=""/>' + IRC_XML[end:]
        ports = {p["port"]: p for p in nmap_scan._parse_nmap_xml(xml)}
        self.assertIsNone(ports[6667]["version"])


class RunTests(unittest.TestCase):

    def test_flags_name_only_safe_discovery_scripts(self):
        flags = nmap_scan.NMAP_FLAGS
        self.assertEqual(flags[flags.index("--script") + 1], "smb-os-discovery,irc-info")
        self.assertEqual(sum(1 for f in flags if f.startswith("--script")), 1)

    def test_gate_refusal_never_runs_nmap(self):
        with mock.patch.object(nmap_scan, "is_authorized", return_value=False), \
             mock.patch.object(nmap_scan.subprocess, "run") as run, \
             mock.patch.object(nmap_scan.shutil, "which") as which:
            result = nmap_scan.run_nmap("10.10.1.100")
        self.assertEqual(result["status"], "refused")
        run.assert_not_called()
        which.assert_not_called()


if __name__ == "__main__":
    unittest.main()
