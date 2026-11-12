"""
Offline tests for the enum4linux-ng wrapper: the authorization gate running
before enum4linux-ng, a missing binary, the command (anonymous only, no
credential options), JSON parsing of every section, missing or oddly shaped
sections, the raw JSON kept as evidence, temp cleanup and clean error
statuses. subprocess.run is replaced by a fake that writes a canned JSON
file, so enum4linux-ng never runs.
"""

import json
import os
import shlex
import subprocess
import unittest
from unittest import mock

from reconmind.tools import smb_enum

TARGET = "10.10.1.100"
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "fixtures", "enum4linux_ng.json")
with open(FIXTURE) as _fh:
    JSON_TEXT = _fh.read()

# Every option enum4linux-ng has for credentials or guessing. None may appear.
CREDENTIAL_OPTIONS = ("-u", "-p", "-w", "-K", "-H", "--user", "--password",
                      "--keybased", "--nthash", "--hash")


def out_base_of(cmd):
    return cmd[cmd.index("-oJ") + 1]


def fake_enum(json_text, returncode=0, stdout="", stderr=""):
    """Stand in for subprocess.run: writes json_text to <-oJ path>.json, like
    enum4linux-ng does. json_text None writes nothing."""
    seen = []

    def run(cmd, **kwargs):
        path = out_base_of(cmd) + ".json"
        seen.append(path)
        assert not os.path.exists(path), "JSON path already exists"
        if json_text is not None:
            with open(path, "w") as fh:
                fh.write(json_text)
        return mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)

    fake = mock.Mock(side_effect=run)
    fake.json_paths = seen
    return fake


def which_enum(binary):
    return "/usr/bin/enum4linux-ng" if binary == "enum4linux-ng" else None


class Base(unittest.TestCase):

    def _run(self, run, target=TARGET):
        with mock.patch.object(smb_enum, "is_authorized", return_value=True), \
             mock.patch.object(smb_enum.shutil, "which", side_effect=which_enum), \
             mock.patch.object(smb_enum.subprocess, "run", run):
            return smb_enum.run_enum4linux(target)


class GateTests(unittest.TestCase):

    def test_refusal_never_reaches_subprocess(self):
        with mock.patch.object(smb_enum, "is_authorized", return_value=False) as gate, \
             mock.patch.object(smb_enum.shutil, "which") as which, \
             mock.patch.object(smb_enum.tempfile, "mkdtemp") as mkdtemp, \
             mock.patch.object(smb_enum.subprocess, "run") as run:
            result = smb_enum.run_enum4linux("8.8.8.8")
        gate.assert_called_once_with("8.8.8.8")
        run.assert_not_called()
        which.assert_not_called()
        mkdtemp.assert_not_called()
        self.assertEqual(result["status"], "refused")
        self.assertEqual(result["command"], "")
        self.assertEqual(result["users"], [])
        self.assertEqual(result["raw_json"], "")


class MissingBinaryTests(unittest.TestCase):

    def test_missing_enum4linux_ng_does_not_crash(self):
        with mock.patch.object(smb_enum, "is_authorized", return_value=True), \
             mock.patch.object(smb_enum.shutil, "which", return_value=None) as which, \
             mock.patch.object(smb_enum.tempfile, "mkdtemp") as mkdtemp, \
             mock.patch.object(smb_enum.subprocess, "run") as run:
            result = smb_enum.run_enum4linux(TARGET)
        run.assert_not_called()
        mkdtemp.assert_not_called()
        which.assert_called_once_with("enum4linux-ng")
        self.assertEqual(result["status"], "enum4linux-ng-not-found")
        self.assertEqual(result["target"], TARGET)
        self.assertTrue(result["error"])
        self.assertEqual(result["shares"], [])


class CommandTests(Base):

    def test_command_and_timeout(self):
        run = fake_enum(JSON_TEXT)
        result = self._run(run)
        self.assertEqual(run.call_count, 1)
        cmd = run.call_args.args[0]
        base = out_base_of(cmd)
        self.assertEqual(cmd, ["enum4linux-ng", "-A", "-oJ", base, TARGET])
        self.assertEqual(os.path.basename(base), "enum4linux_ng")
        self.assertEqual(run.call_args.kwargs["timeout"], 600)
        self.assertEqual(result["command"], shlex.join(cmd))
        self.assertEqual(result["target"], TARGET)

    def test_no_credential_options(self):
        run = fake_enum(JSON_TEXT)
        self._run(run)
        cmd = run.call_args.args[0]
        options = [a for a in cmd if a.startswith("-")]
        self.assertEqual(options, ["-A", "-oJ"])
        for option in CREDENTIAL_OPTIONS:
            self.assertNotIn(option, cmd)

    def test_temp_dir_is_deleted(self):
        run = fake_enum(JSON_TEXT)
        self._run(run)
        self.assertEqual(len(run.json_paths), 1)
        self.assertFalse(os.path.exists(run.json_paths[0]))
        self.assertFalse(os.path.exists(os.path.dirname(run.json_paths[0])))

    def test_temp_dir_deleted_on_timeout(self):
        seen = []

        def run(cmd, **kwargs):
            seen.append(out_base_of(cmd))
            raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

        result = self._run(mock.Mock(side_effect=run))
        self.assertEqual(result["status"], "timeout")
        self.assertTrue(result["command"].startswith("enum4linux-ng -A -oJ "))
        self.assertFalse(os.path.exists(os.path.dirname(seen[0])))


class ParseTests(Base):

    def test_result_keys(self):
        result = self._run(fake_enum(JSON_TEXT))
        self.assertEqual(set(result), {"status", "target", "command", "null_session",
                                       "domain", "os", "users", "groups", "shares",
                                       "policy", "raw_json"})
        self.assertEqual(result["status"], "ok")

    def test_session_domain_and_os(self):
        result = self._run(fake_enum(JSON_TEXT))
        self.assertIs(result["null_session"], True)
        self.assertEqual(result["domain"], "WORKGROUP")
        self.assertEqual(result["os"]["OS"], "Linux/Unix (Samba 3.0.20-Debian)")
        self.assertEqual(result["os"]["Native LAN manager"], "Samba 3.0.20-Debian")
        self.assertNotIn("OS release", result["os"])  # empty values are left out
        self.assertEqual(smb_enum.os_summary(result["os"]),
                         "OS: Linux/Unix (Samba 3.0.20-Debian); OS version: 4.9; "
                         "Native OS: Unix; Native LAN manager: Samba 3.0.20-Debian")

    def test_users(self):
        users = self._run(fake_enum(JSON_TEXT))["users"]
        self.assertEqual(len(users), 25)
        self.assertEqual(users[0], {"username": "msfadmin", "rid": "1000",
                                    "description": "msfadmin,,,"})
        # Empty or missing description: no description key.
        self.assertEqual(users[1], {"username": "games", "rid": "1001"})
        self.assertEqual(users[2], {"username": "nobody", "rid": "1002"})
        self.assertEqual(users[-1]["username"], "tomcat55")

    def test_groups(self):
        groups = self._run(fake_enum(JSON_TEXT))["groups"]
        self.assertEqual(groups, [
            {"name": "Administrators", "rid": "544", "type": "builtin"},
            {"name": "Users", "rid": "545", "type": "builtin"},
            {"name": "sambashare", "rid": "3000", "type": "local"}])

    def test_shares(self):
        shares = self._run(fake_enum(JSON_TEXT))["shares"]
        self.assertEqual([s["name"] for s in shares], ["print$", "tmp", "opt", "IPC$", "ADMIN$"])
        self.assertEqual(shares[1], {"name": "tmp", "type": "Disk", "comment": "oh noes!",
                                     "mapping": "ok", "listing": "ok"})
        self.assertEqual(shares[3]["listing"], "not supported")

    def test_policy(self):
        policy = self._run(fake_enum(JSON_TEXT))["policy"]
        fields = dict(smb_enum.policy_fields(policy))
        self.assertEqual(fields["Minimum password length"], 5)
        self.assertIsNone(fields["Lockout threshold"])
        self.assertEqual(fields["Force logoff time"], "not set")
        self.assertEqual(smb_enum.format_value(fields["Password properties"][:2]),
                         "DOMAIN_PASSWORD_COMPLEX: false, DOMAIN_PASSWORD_NO_ANON_CHANGE: false")

    def test_null_session_false(self):
        data = json.loads(JSON_TEXT)
        data["sessions"]["null"] = False
        self.assertIs(self._run(fake_enum(json.dumps(data)))["null_session"], False)

    def test_list_shaped_sections(self):
        data = {"users": [{"username": "alice", "rid": "1100", "description": "test"}],
                "groups": [{"groupname": "staff", "rid": "1200"}],
                "shares": [{"name": "public", "type": "Disk", "comment": "",
                            "access": {"mapping": "ok", "listing": "ok"}}],
                "domain": "LAB"}
        result = self._run(fake_enum(json.dumps(data)))
        self.assertEqual(result["users"], [{"username": "alice", "rid": "1100",
                                            "description": "test"}])
        self.assertEqual(result["groups"], [{"name": "staff", "rid": "1200", "type": ""}])
        self.assertEqual(result["shares"][0]["name"], "public")
        self.assertEqual(result["domain"], "LAB")


class MissingSectionTests(Base):

    def test_empty_object(self):
        result = self._run(fake_enum("{}"))
        self.assertEqual(result["status"], "ok")
        self.assertIsNone(result["null_session"])
        self.assertEqual(result["domain"], "")
        self.assertEqual(result["os"], {})
        self.assertEqual(result["users"], [])
        self.assertEqual(result["groups"], [])
        self.assertEqual(result["shares"], [])
        self.assertEqual(result["policy"], {})
        self.assertEqual(result["raw_json"], "{}")

    def test_null_and_wrong_type_sections(self):
        data = {"sessions": None, "os_info": None, "users": "error", "groups": 5,
                "shares": {"tmp": "not a dict", "pub": {"access": None}},
                "policy": ["x"], "rpc_domain_info": "oops"}
        result = self._run(fake_enum(json.dumps(data)))
        self.assertEqual(result["status"], "ok")
        self.assertIsNone(result["null_session"])
        self.assertEqual(result["users"], [])
        self.assertEqual(result["groups"], [])
        self.assertEqual(result["shares"], [{"name": "pub", "type": "", "comment": "",
                                             "mapping": "", "listing": ""}])
        self.assertEqual(result["policy"], {})

    def test_each_section_removed(self):
        for key in ("sessions", "rpc_domain_info", "os_info", "users", "groups", "shares",
                    "policy", "workgroup", "smb_domain_info"):
            data = json.loads(JSON_TEXT)
            del data[key]
            result = self._run(fake_enum(json.dumps(data)))
            self.assertEqual(result["status"], "ok", key)

    def test_domain_fallbacks(self):
        data = json.loads(JSON_TEXT)
        del data["rpc_domain_info"]
        del data["workgroup"]
        self.assertEqual(self._run(fake_enum(json.dumps(data)))["domain"], "WORKGROUP")
        del data["smb_domain_info"]
        self.assertEqual(self._run(fake_enum(json.dumps(data)))["domain"], "")


class RawJsonTests(Base):

    def test_raw_json_is_the_whole_file(self):
        self.assertEqual(self._run(fake_enum(JSON_TEXT))["raw_json"], JSON_TEXT)

    def test_raw_json_kept_when_json_is_broken(self):
        text = '{"users": {"1000": '
        result = self._run(fake_enum(text))
        self.assertEqual(result["status"], "bad-json")
        self.assertEqual(result["raw_json"], text)


class BadJsonTests(Base):

    def assert_clean_error(self, result, status):
        self.assertEqual(result["status"], status)
        self.assertEqual(result["users"], [])
        self.assertTrue(result["error"])
        self.assertNotIn("—", result["error"])
        self.assertNotIn(" - ", result["error"])

    def test_no_json_file(self):
        result = self._run(fake_enum(None, returncode=1, stderr="Connection refused\n"))
        self.assert_clean_error(result, "empty-json")
        self.assertIn("exited with code 1: Connection refused", result["error"])

    def test_empty_json(self):
        self.assert_clean_error(self._run(fake_enum("")), "empty-json")

    def test_broken_json(self):
        self.assert_clean_error(self._run(fake_enum("{not json")), "bad-json")

    def test_wrong_shape(self):
        self.assert_clean_error(self._run(fake_enum("[1, 2]")), "bad-json")

    def test_cannot_start(self):
        result = self._run(mock.Mock(side_effect=OSError("exec format error")))
        self.assert_clean_error(result, "failed")


class HelperTests(unittest.TestCase):

    def test_smb_ports(self):
        ports = [{"port": 22}, {"port": 139}, {"port": "445"}, {"port": 4450}, {"port": None}]
        self.assertEqual([p["port"] for p in smb_enum.smb_ports(ports)], [139, "445"])
        self.assertEqual(smb_enum.smb_ports(None), [])

    def test_format_value(self):
        self.assertEqual(smb_enum.format_value(None), "None")
        self.assertEqual(smb_enum.format_value(True), "true")
        self.assertEqual(smb_enum.format_value("30 minutes"), "30 minutes")
        self.assertEqual(smb_enum.format_value({"a": 1}), "a: 1")


if __name__ == "__main__":
    unittest.main()
