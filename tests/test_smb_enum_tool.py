"""
Offline tests for the smb_enum agent tool and the report's SMB section:
smb_enum needs nmap_scan first and port 139 or 445 open, takes no inputs,
stores its result in scan["smb"] and returns a compact observation without
the raw JSON. The report shows the null session result, domain, OS, every
username, the shares table and the password policy, or a not checked line.
run_enum4linux is replaced by a mock, so enum4linux-ng never runs.
"""

import copy
import json
import os
import tempfile
import unittest
from unittest import mock

from reconmind.agent import prompts, tools as toolmod
from reconmind.core import report as reportmod
from reconmind.core.report import build_report
from reconmind.tools import smb_enum

TARGET = "10.10.1.100"
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "enum4linux_ng.json")
with open(FIXTURE) as _fh:
    FIXTURE_JSON = _fh.read()
FIXTURE_DATA = json.loads(FIXTURE_JSON)

RAW_MARKER = "RAW_JSON_MARKER_do_not_send"
# Only in the raw JSON, never in a parsed field.
RAW_ONLY = ("kxwyrzfh", "No printers returned", "NULL SID", "SMB signing required")


def ok_result():
    """What run_enum4linux returns for the fixture, built by the real parser."""
    return {
        "status": "ok", "target": TARGET,
        "command": "enum4linux-ng -A -oJ /tmp/x/enum4linux_ng {t}".format(t=TARGET),
        "null_session": smb_enum._null_session(FIXTURE_DATA),
        "domain": smb_enum._domain(FIXTURE_DATA),
        "os": smb_enum._os(FIXTURE_DATA),
        "users": smb_enum._users(FIXTURE_DATA),
        "groups": smb_enum._groups(FIXTURE_DATA),
        "shares": smb_enum._shares(FIXTURE_DATA),
        "policy": smb_enum._policy(FIXTURE_DATA),
        "raw_json": FIXTURE_JSON + RAW_MARKER,
    }


SCAN = {
    "target": TARGET, "status": "ok",
    "ports": [
        {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH",
         "version": "4.7p1", "tunnel": ""},
        {"port": 139, "protocol": "tcp", "service": "netbios-ssn", "product": "Samba smbd",
         "version": "3.X - 4.X", "tunnel": ""},
        {"port": 443, "protocol": "tcp", "service": "http", "product": "Apache httpd",
         "version": "2.2.8", "tunnel": "ssl"},
        {"port": 445, "protocol": "tcp", "service": "netbios-ssn", "product": "Samba smbd",
         "version": "3.0.20-Debian", "tunnel": ""},
    ],
}
NO_SMB_PORTS = [p for p in SCAN["ports"] if p["port"] not in (139, 445)]


def toolbox(ports=None):
    tb = toolmod.ToolBox(TARGET)
    tb.scan = copy.deepcopy(SCAN)
    if ports is not None:
        tb.scan["ports"] = copy.deepcopy(ports)
    return tb


class SmbEnumToolTests(unittest.TestCase):

    def test_requires_nmap_scan_first(self):
        tb = toolmod.ToolBox(TARGET)
        with mock.patch.object(toolmod, "run_enum4linux") as run:
            obs, is_error = tb.call("smb_enum", {})
        self.assertTrue(is_error)
        self.assertIn("Run nmap_scan first", obs)
        run.assert_not_called()
        self.assertNotIn("smb", tb.scan)

    def test_refused_without_139_or_445(self):
        tb = toolbox(NO_SMB_PORTS)
        with mock.patch.object(toolmod, "run_enum4linux") as run:
            obs, is_error = tb.call("smb_enum", {})
        self.assertTrue(is_error)
        message = json.loads(obs)["error"]
        self.assertIn("only allowed when port 139 or 445 is open", message)
        self.assertIn("SMB was not enumerated", message)
        run.assert_not_called()
        self.assertNotIn("smb", tb.scan)

    def test_runs_with_only_139_or_only_445(self):
        for keep in (139, 445):
            ports = NO_SMB_PORTS + [p for p in SCAN["ports"] if p["port"] == keep]
            tb = toolbox(ports)
            with mock.patch.object(toolmod, "run_enum4linux", return_value=ok_result()) as run:
                obs, is_error = tb.call("smb_enum", {})
            self.assertFalse(is_error, obs)
            run.assert_called_once_with(TARGET)
            self.assertEqual(json.loads(obs)["smb_ports"], [keep])

    def test_takes_no_inputs(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_enum4linux", return_value=ok_result()) as run:
            obs, is_error = tb.call("smb_enum", {"target": "10.10.1.200"})
        self.assertTrue(is_error)
        run.assert_not_called()

    def test_stores_result(self):
        tb = toolbox()
        result = ok_result()
        with mock.patch.object(toolmod, "run_enum4linux", return_value=result):
            tb.call("smb_enum", {})
        self.assertEqual(tb.scan["smb"], result)
        self.assertIn(RAW_MARKER, tb.scan["smb"]["raw_json"])

    def test_compact_observation(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_enum4linux", return_value=ok_result()):
            obs, is_error = tb.call("smb_enum", {})
        self.assertFalse(is_error)
        data = json.loads(obs)
        self.assertEqual(data["smb_ports"], [139, 445])
        self.assertIs(data["null_session"], True)
        self.assertEqual(data["domain"], "WORKGROUP")
        self.assertEqual(data["os"]["OS"], "Linux/Unix (Samba 3.0.20-Debian)")
        self.assertEqual(data["user_count"], 25)
        self.assertEqual(len(data["usernames"]), 20)
        self.assertEqual(data["usernames"][:3], ["msfadmin", "games", "nobody"])
        self.assertNotIn("gnats", data["usernames"])  # user 22 of 25
        self.assertEqual(data["group_count"], 3)
        self.assertNotIn("groups", data)
        self.assertEqual(len(data["shares"]), 5)
        self.assertEqual(data["shares"][1], {"name": "tmp", "type": "Disk",
                                             "comment": "oh noes!", "mapping": "ok",
                                             "listing": "ok"})
        policy = data["password_policy"]
        self.assertEqual(policy["Minimum password length"], 5)
        self.assertIsNone(policy["Lockout threshold"])
        self.assertEqual(policy["Lockout duration"], "30 minutes")
        self.assertEqual(policy["Password properties"][0], {"DOMAIN_PASSWORD_COMPLEX": False})

    def test_observation_leaves_out_raw_json_and_command(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_enum4linux", return_value=ok_result()):
            obs, _ = tb.call("smb_enum", {})
        data = json.loads(obs)
        self.assertNotIn("raw_json", data)
        self.assertNotIn("command", data)
        self.assertNotIn(RAW_MARKER, obs)
        for text in RAW_ONLY:
            self.assertNotIn(text, obs)

    def test_missing_binary_is_an_error_observation(self):
        tb = toolbox()
        result = smb_enum._result("enum4linux-ng-not-found", TARGET,
                                  error="enum4linux-ng is not installed on this machine.")
        with mock.patch.object(toolmod, "run_enum4linux", return_value=result):
            obs, is_error = tb.call("smb_enum", {})
        self.assertTrue(is_error)
        self.assertIn("enum4linux-ng is not installed", obs)
        self.assertEqual(tb.scan["smb"]["status"], "enum4linux-ng-not-found")

    def test_failed_run_says_not_checked(self):
        tb = toolbox()
        result = smb_enum._result("timeout", TARGET, "enum4linux-ng ...",
                                  error="enum4linux-ng did not finish within 600 seconds.")
        with mock.patch.object(toolmod, "run_enum4linux", return_value=result):
            obs, is_error = tb.call("smb_enum", {})
        self.assertTrue(is_error)
        message = json.loads(obs)["error"]
        self.assertIn("status=timeout", message)
        self.assertIn("SMB was not checked.", message)
        self.assertNotIn(" - ", message)

    def test_gate_refusal_is_reported(self):
        tb = toolbox()
        with mock.patch.object(toolmod, "run_enum4linux",
                               return_value=smb_enum._result("refused")):
            obs, is_error = tb.call("smb_enum", {})
        self.assertTrue(is_error)
        self.assertIn("authorization gate", obs)


class SpecAndPromptTests(unittest.TestCase):

    def spec(self):
        return next(s for s in toolmod.TOOL_SPECS if s["name"] == "smb_enum")

    def test_tool_spec(self):
        spec = self.spec()
        self.assertIn("enum4linux-ng", spec["description"])
        self.assertIn("139 or 445", spec["description"])
        self.assertEqual(spec["input_schema"]["properties"], {})
        self.assertEqual(spec["input_schema"]["required"], [])

    def test_prompt_rule(self):
        self.assertIn("After nmap_scan, if port 139 or 445 is open, call smb_enum once.",
                      prompts.SYSTEM_PROMPT)

    def test_new_text_has_no_dash_separators(self):
        for text in (self.spec()["description"], prompts.SYSTEM_PROMPT):
            self.assertNotIn("—", text)
            self.assertNotIn(" - ", text)


# ---- report ---------------------------------------------------------------

SMB_HEAD = "## SMB enumeration (enum4linux-ng)"
SMB_SCAN = dict(copy.deepcopy(SCAN), smb=ok_result())


def read_report(scan):
    with open(build_report(scan)) as fh:
        return fh.read()


def smb_part(report):
    return report.split(SMB_HEAD)[1].split("## Notes")[0]


class SmbReportTests(unittest.TestCase):

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def test_section_after_tls_before_notes(self):
        report = read_report(SMB_SCAN)
        self.assertLess(report.index("## TLS checks (testssl.sh)"), report.index(SMB_HEAD))
        self.assertLess(report.index(SMB_HEAD), report.index("## Notes"))

    def test_session_domain_os_and_users(self):
        section = smb_part(read_report(SMB_SCAN))
        self.assertIn("**Null session allowed:** yes\n", section)
        self.assertIn("**Domain or workgroup:** WORKGROUP\n", section)
        self.assertIn("**OS:** OS: Linux/Unix (Samba 3.0.20-Debian); OS version: 4.9; "
                      "Native OS: Unix; Native LAN manager: Samba 3.0.20-Debian\n", section)
        users = smb_enum._users(FIXTURE_DATA)
        self.assertIn("**Users (25):** " + ", ".join(u["username"] for u in users) + "\n",
                      section)
        self.assertIn("tomcat55", section)  # every username, not just 20

    def test_shares_table(self):
        section = smb_part(read_report(SMB_SCAN))
        self.assertIn("| Name | Type | Comment | Mapping | Listing |\n"
                      "|------|------|---------|---------|---------|\n"
                      "| print$ | Disk | Printer Drivers | denied | n/a |\n"
                      "| tmp | Disk | oh noes! | ok | ok |\n"
                      "| opt | Disk |  | denied | n/a |\n"
                      "| IPC$ | IPC | IPC Service (metasploitable server (Samba 3.0.20-Debian)) "
                      "| ok | not supported |\n", section)

    def test_password_policy(self):
        section = smb_part(read_report(SMB_SCAN))
        self.assertIn("Password policy:\n"
                      "- Password history length: None\n"
                      "- Minimum password length: 5\n"
                      "- Maximum password age: not set\n"
                      "- Password properties: DOMAIN_PASSWORD_COMPLEX: false, ", section)
        self.assertIn("- Lockout threshold: None\n", section)
        self.assertIn("- Force logoff time: not set\n", section)

    def test_raw_json_never_printed(self):
        report = read_report(SMB_SCAN)
        self.assertNotIn(RAW_MARKER, report)
        self.assertNotIn("raw_json", report)
        for text in RAW_ONLY:
            self.assertNotIn(text, report)

    def test_not_checked_line(self):
        scan = {k: v for k, v in SMB_SCAN.items() if k != "smb"}
        section = smb_part(read_report(scan))
        self.assertIn("**Not checked:** SMB port(s) 139/tcp, 445/tcp are open but SMB was "
                      "not enumerated with enum4linux-ng.", section)
        self.assertNotIn("Null session allowed", section)

    def test_failed_run_says_not_checked(self):
        scan = dict(SMB_SCAN, smb=smb_enum._result("timeout", TARGET))
        section = smb_part(read_report(scan))
        self.assertIn("_enum4linux-ng did not complete (status timeout), so SMB was not "
                      "checked._", section)

    def test_empty_sections(self):
        scan = dict(SMB_SCAN, smb=smb_enum._result("ok", TARGET))
        section = smb_part(read_report(scan))
        self.assertIn("**Null session allowed:** not reported", section)
        self.assertIn("**Domain or workgroup:** not reported", section)
        self.assertIn("**OS:** not reported", section)
        self.assertIn("**Users (0):** none", section)
        self.assertIn("_No shares reported._", section)
        self.assertIn("_No password policy reported._", section)

    def test_null_session_no(self):
        result = ok_result()
        result["null_session"] = False
        section = smb_part(read_report(dict(SMB_SCAN, smb=result)))
        self.assertIn("**Null session allowed:** no\n", section)

    def test_no_section_without_smb_ports(self):
        scan = {"target": TARGET, "status": "ok", "ports": copy.deepcopy(NO_SMB_PORTS),
                "smb": ok_result()}
        self.assertNotIn(SMB_HEAD, read_report(scan))
        self.assertNotIn(SMB_HEAD, read_report({"target": TARGET, "status": "ok",
                                                "ports": []}))

    def test_smb_text_has_no_em_dashes_or_dash_separators(self):
        text = smb_part(read_report(SMB_SCAN))
        text += smb_part(read_report({k: v for k, v in SMB_SCAN.items() if k != "smb"}))
        text += smb_part(read_report(dict(SMB_SCAN, smb=smb_enum._result("timeout"))))
        text += smb_part(read_report(dict(SMB_SCAN, smb=smb_enum._result("ok"))))
        # enum4linux-ng data, not our text
        result = ok_result()
        tool_values = [result["domain"], smb_enum.os_summary(result["os"])]
        tool_values += [u["username"] for u in result["users"]]
        for s in result["shares"]:
            tool_values += [s["name"], s["type"], s["comment"], s["mapping"], s["listing"]]
        for field, value in smb_enum.policy_fields(result["policy"]):
            tool_values += [field, smb_enum.format_value(value)]
        for value in sorted((v for v in tool_values if v), key=len, reverse=True):
            text = text.replace(value, "")
        self.assertTrue(text.strip())
        self.assertNotIn("—", text)
        self.assertNotIn(" - ", text)
        for constant in (reportmod.SMB_HEAD, reportmod.SMB_NOT_CHECKED, reportmod.SMB_FAILED,
                         reportmod.SMB_NULL_SESSION, reportmod.SMB_DOMAIN, reportmod.SMB_OS,
                         reportmod.SMB_USERS, reportmod.SMB_NO_SHARES, reportmod.SMB_NO_POLICY,
                         reportmod.SMB_UNKNOWN, reportmod.SMB_ANONYMOUS_NOTE):
            self.assertNotIn("—", constant)
            self.assertNotIn(" - ", constant)


if __name__ == "__main__":
    unittest.main()
