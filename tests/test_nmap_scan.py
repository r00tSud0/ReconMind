"""
Offline tests for the nmap wrapper: XML parsing with smb-os-discovery output,
the scan flags, the one pass and two pass modes, port state counts, scan info,
and the authorization gate running before nmap. subprocess.run is replaced by
a fake that writes canned XML, so nmap never runs.
"""

import shlex
import unittest
from datetime import datetime
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


TARGET = "10.10.1.100"
START = 1762250000

# Default single pass on the top 1000 ports: two open, 997 closed folded into
# extraports, one closed port listed on its own.
DEFAULT_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94" start="{start}" startstr="Tue Nov  4 10:00:00 2025">
  <host>
    <address addr="10.10.1.100" addrtype="ipv4"/>
    <ports>
      <extraports state="closed" count="997">
        <extrareasons reason="reset" count="997"/>
      </extraports>
      <port protocol="tcp" portid="21">
        <state state="open" reason="syn-ack"/>
        <service name="ftp" product="vsftpd" version="2.3.4"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="4.7p1"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="closed" reason="reset"/>
        <service name="mysql"/>
      </port>
    </ports>
  </host>
  <runstats><finished elapsed="12.50"/></runstats>
</nmaprun>
""".format(start=START)

# Pass 1 over all 65535 ports behind a firewall: 65532 filtered, two open,
# one closed.
DISCOVERY_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94" start="{start}">
  <host>
    <address addr="10.10.1.100" addrtype="ipv4"/>
    <ports>
      <extraports state="filtered" count="65532">
        <extrareasons reason="no-response" count="65530"/>
        <extrareasons reason="admin-prohibited" count="2"/>
      </extraports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open" reason="syn-ack"/>
        <service name="http-proxy"/>
      </port>
      <port protocol="tcp" portid="113">
        <state state="closed" reason="reset"/>
        <service name="ident"/>
      </port>
    </ports>
  </host>
  <runstats><finished elapsed="61.20"/></runstats>
</nmaprun>
""".format(start=START)

DETAIL_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94" start="{start}">
  <host>
    <address addr="10.10.1.100" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="4.7p1"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache Tomcat" version="5.5"/>
      </port>
    </ports>
  </host>
  <runstats><finished elapsed="20.50"/></runstats>
</nmaprun>
""".format(start=START + 62)

# Pass 1 that found nothing open.
ALL_FILTERED_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94" start="{start}">
  <host>
    <address addr="10.10.1.100" addrtype="ipv4"/>
    <ports>
      <extraports state="filtered" count="65535">
        <extrareasons reason="no-response" count="65535"/>
      </extraports>
    </ports>
  </host>
  <runstats><finished elapsed="70.00"/></runstats>
</nmaprun>
""".format(start=START)


def fake_nmap(*xml_runs):
    """Stand in for subprocess.run: writes the next canned XML into the -oX file."""
    outputs = list(xml_runs)

    def run(cmd, **kwargs):
        with open(cmd[cmd.index("-oX") + 1], "w") as fh:
            fh.write(outputs.pop(0))
        return mock.Mock(returncode=0)

    return mock.Mock(side_effect=run)


def states_by_name(port_states):
    return {s["state"]: s for s in port_states}


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


class ScanModeTests(unittest.TestCase):
    """Default is one pass on the top 1000 ports; all_ports is two passes."""

    def _run(self, *xml_runs, **kwargs):
        run = fake_nmap(*xml_runs)
        with mock.patch.object(nmap_scan, "is_authorized", return_value=True), \
             mock.patch.object(nmap_scan.shutil, "which", return_value="/usr/bin/nmap"), \
             mock.patch.object(nmap_scan, "_source_ip", return_value="10.10.1.5"), \
             mock.patch.object(nmap_scan.subprocess, "run", run):
            result = nmap_scan.run_nmap(TARGET, **kwargs)
        return run, result

    @staticmethod
    def _cmds(run):
        return [c.args[0] for c in run.call_args_list]

    def test_default_is_one_pass_with_reason_and_300_timeout(self):
        run, result = self._run(DEFAULT_XML)
        self.assertEqual(run.call_count, 1)
        cmd = run.call_args.args[0]
        tmp_name = cmd[cmd.index("-oX") + 1]
        self.assertEqual(
            cmd, ["nmap"] + nmap_scan.NMAP_FLAGS + ["--reason", "-oX", tmp_name, TARGET])
        self.assertNotIn("-p-", cmd)
        self.assertNotIn("-p", cmd)
        self.assertEqual(run.call_args.kwargs["timeout"], 300)
        self.assertEqual(result["status"], "ok")
        self.assertEqual([p["port"] for p in result["ports"]], [21, 22])

    def test_all_ports_pass_1_is_discovery_only(self):
        run, _ = self._run(DISCOVERY_XML, DETAIL_XML, all_ports=True)
        self.assertEqual(run.call_count, 2)
        first = run.call_args_list[0]
        cmd = first.args[0]
        tmp_name = cmd[cmd.index("-oX") + 1]
        self.assertEqual(cmd, ["nmap", "-Pn", "-p-", "--min-rate", "1000", "--max-retries",
                               "2", "-T4", "--reason", "-oX", tmp_name, TARGET])
        self.assertNotIn("-sV", cmd)
        self.assertNotIn("--script", cmd)
        self.assertEqual(first.kwargs["timeout"], 600)

    def test_all_ports_pass_2_scans_only_open_ports(self):
        run, result = self._run(DISCOVERY_XML, DETAIL_XML, all_ports=True)
        second = run.call_args_list[1]
        cmd = second.args[0]
        self.assertEqual(cmd[1:1 + len(nmap_scan.NMAP_FLAGS)], nmap_scan.NMAP_FLAGS)
        self.assertIn("--reason", cmd)
        self.assertEqual(cmd[cmd.index("-p") + 1], "22,8080")  # 113 was closed
        self.assertNotIn("-p-", cmd)
        self.assertEqual(cmd[-1], TARGET)
        self.assertEqual(second.kwargs["timeout"], 300)
        ports = {p["port"]: p for p in result["ports"]}
        self.assertEqual(ports[8080]["product"], "Apache Tomcat")  # detail from pass 2

    def test_all_ports_states_come_from_pass_1(self):
        _, result = self._run(DISCOVERY_XML, DETAIL_XML, all_ports=True)
        states = states_by_name(result["port_states"])
        self.assertEqual(states["filtered"]["count"], 65532)
        self.assertEqual(states["closed"]["count"], 1)
        self.assertEqual(states["open"]["count"], 2)
        self.assertEqual(sum(s["count"] for s in result["port_states"]), 65535)

    def test_no_open_ports_skips_pass_2(self):
        run, result = self._run(ALL_FILTERED_XML, all_ports=True)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["ports"], [])
        self.assertEqual(len(result["scan_info"]["commands"]), 1)
        self.assertEqual(states_by_name(result["port_states"])["filtered"]["count"], 65535)
        self.assertEqual(states_by_name(result["port_states"])["open"]["count"], 0)

    def test_scan_info_default(self):
        run, result = self._run(DEFAULT_XML)
        info = result["scan_info"]
        self.assertEqual(info["source_ip"], "10.10.1.5")
        self.assertEqual(info["nmap_version"], "7.94")
        self.assertEqual(info["mode"], "top 1000 ports")
        self.assertEqual(info["commands"], [shlex.join(run.call_args.args[0])])
        self.assertEqual(info["started"],
                         datetime.fromtimestamp(START).strftime("%Y-%m-%d %H:%M:%S"))
        self.assertEqual(info["elapsed_seconds"], 12.5)

    def test_scan_info_two_pass(self):
        run, result = self._run(DISCOVERY_XML, DETAIL_XML, all_ports=True)
        info = result["scan_info"]
        self.assertEqual(info["mode"], "all 65535 ports, two pass")
        self.assertEqual(info["commands"], [shlex.join(c) for c in self._cmds(run)])
        self.assertEqual(info["elapsed_seconds"], 81.7)  # both passes
        self.assertEqual(info["started"],
                         datetime.fromtimestamp(START).strftime("%Y-%m-%d %H:%M:%S"))

    def test_no_udp_or_evasion_flags_in_any_pass(self):
        run_default, _ = self._run(DEFAULT_XML)
        run_all, _ = self._run(DISCOVERY_XML, DETAIL_XML, all_ports=True)
        banned = {"-sU", "-D", "-f", "--mtu", "-g", "--source-port", "-S",
                  "--spoof-mac", "--data-length", "--badsum"}
        for cmd in self._cmds(run_default) + self._cmds(run_all):
            self.assertFalse(banned & set(cmd), cmd)

    def test_refused_target_never_reaches_subprocess_in_either_mode(self):
        for all_ports in (False, True):
            with mock.patch.object(nmap_scan, "is_authorized", return_value=False), \
                 mock.patch.object(nmap_scan.shutil, "which") as which, \
                 mock.patch.object(nmap_scan, "_source_ip") as source_ip, \
                 mock.patch.object(nmap_scan.subprocess, "run") as run:
                result = nmap_scan.run_nmap("8.8.8.8", all_ports=all_ports)
            run.assert_not_called()
            which.assert_not_called()
            source_ip.assert_not_called()
            self.assertEqual(result["status"], "refused")


class PortStateTests(unittest.TestCase):

    def test_extraports_and_reasons_parsed(self):
        states = states_by_name(nmap_scan._parse_port_states(DISCOVERY_XML))
        self.assertEqual(states["filtered"],
                         {"state": "filtered", "count": 65532,
                          "reasons": {"no-response": 65530, "admin-prohibited": 2}})
        self.assertEqual(states["closed"],
                         {"state": "closed", "count": 1, "reasons": {"reset": 1}})
        self.assertEqual(states["open"],
                         {"state": "open", "count": 2, "reasons": {"syn-ack": 2}})

    def test_listed_closed_ports_add_to_extraports(self):
        states = states_by_name(nmap_scan._parse_port_states(DEFAULT_XML))
        self.assertEqual(states["closed"]["count"], 998)  # 997 folded plus 3306
        self.assertEqual(states["closed"]["reasons"], {"reset": 998})
        self.assertNotIn("filtered", states)

    def test_largest_count_first_and_open_always_present(self):
        port_states = nmap_scan._parse_port_states(ALL_FILTERED_XML)
        self.assertEqual(port_states[0]["state"], "filtered")
        self.assertEqual(states_by_name(port_states)["open"]["count"], 0)

    def test_open_port_carries_reason(self):
        ports = {p["port"]: p for p in nmap_scan._parse_nmap_xml(DETAIL_XML)}
        self.assertEqual(ports[22]["reason"], "syn-ack")

    def test_missing_reason_is_empty(self):
        ports = {p["port"]: p for p in nmap_scan._parse_nmap_xml(SAMPLE_XML)}
        self.assertEqual(ports[22]["reason"], "")


class SourceIpTests(unittest.TestCase):

    def test_udp_connect_only_no_data_sent(self):
        sock = mock.MagicMock()
        sock.__enter__.return_value = sock
        sock.getsockname.return_value = ("10.10.1.5", 40000)
        with mock.patch.object(nmap_scan.socket, "socket", return_value=sock) as make:
            self.assertEqual(nmap_scan._source_ip(TARGET), "10.10.1.5")
        make.assert_called_once_with(nmap_scan.socket.AF_INET, nmap_scan.socket.SOCK_DGRAM)
        sock.connect.assert_called_once_with((TARGET, 9))
        sock.send.assert_not_called()
        sock.sendto.assert_not_called()

    def test_failure_gives_unknown(self):
        with mock.patch.object(nmap_scan.socket, "socket", side_effect=OSError("no route")):
            self.assertEqual(nmap_scan._source_ip(TARGET), "unknown")


if __name__ == "__main__":
    unittest.main()
