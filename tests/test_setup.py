"""Setup wizard tests. Offline: every download, package manager and git call is faked."""
import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from unittest import mock

from reconmind import toolpath
from reconmind.setup import __main__ as cli
from reconmind.setup import detect, install, manifest, preflight

UBUNTU = {"ID": "ubuntu", "PRETTY_NAME": "Ubuntu 22.04.5 LTS"}
GOOD = dict(machine="x86_64", version=(3, 11, 9), free=10 * 1024 ** 3, online=True,
            root=False, which=lambda name: "/usr/bin/" + name, wsl=False)


class Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


class FakeRun:
    """Records commands. dpkg-query answers from the installed set."""
    def __init__(self, installed=()):
        self.calls = []
        self.installed = set(installed)

    def __call__(self, cmd, **kw):
        self.calls.append(list(cmd))
        if cmd[0] == "dpkg-query":
            ok = cmd[-1] in self.installed
            return Proc(0 if ok else 1, "install ok installed" if ok else "")
        if "apt-get" in cmd and "install" in cmd:
            self.installed.update(c for c in cmd if not c.startswith("-") and c not in (
                "sudo", "apt-get", "install", "DPkg::Lock::Timeout=120"))
        return Proc(0)


class PreflightTests(unittest.TestCase):
    def test_supported_distros_only(self):
        self.assertEqual(preflight.distro(UBUNTU), "ubuntu")
        self.assertEqual(preflight.distro({"ID": "kali", "ID_LIKE": "debian"}), "kali")
        self.assertIsNone(preflight.distro({"ID": "linuxmint", "ID_LIKE": "ubuntu debian"}))
        self.assertIsNone(preflight.distro({}))

    def test_arch(self):
        self.assertEqual(preflight.arch("x86_64"), "amd64")
        self.assertEqual(preflight.arch("aarch64"), "arm64")
        self.assertIsNone(preflight.arch("armv7l"))

    def test_good_machine_passes(self):
        checks = preflight.run_checks(info=UBUNTU, **GOOD)
        self.assertEqual(preflight.blocking_failures(checks), [])

    def test_blocking_problems(self):
        for change, name in (({"version": (3, 9, 1)}, "Python"),
                             ({"free": 1024 ** 3}, "Disk space"),
                             ({"online": False}, "Network"),
                             ({"machine": "armv7l"}, "CPU")):
            with self.subTest(name=name):
                args = dict(GOOD, **change)
                failed = preflight.blocking_failures(preflight.run_checks(info=UBUNTU, **args))
                self.assertEqual([c.name for c in failed], [name])
        failed = preflight.blocking_failures(preflight.run_checks(
            info={"ID": "fedora", "PRETTY_NAME": "Fedora"}, **GOOD))
        self.assertIn("not supported yet", failed[0].detail)

    def test_os_release_parsing(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write('ID=kali\nPRETTY_NAME="Kali GNU/Linux Rolling"\n')
        try:
            self.assertEqual(preflight.read_os_release(f.name)["PRETTY_NAME"],
                             "Kali GNU/Linux Rolling")
        finally:
            os.unlink(f.name)


class ToolPathTests(unittest.TestCase):
    def test_prepends_once_and_ignores_missing_folder(self):
        with tempfile.TemporaryDirectory() as d:
            env = {"PATH": "/usr/bin:" + d}
            self.assertTrue(toolpath.activate(env, bin_dir=d))
            self.assertEqual(env["PATH"], d + ":/usr/bin")
            self.assertFalse(toolpath.activate(env, bin_dir=d))
            env2 = {"PATH": "/usr/bin"}
            self.assertFalse(toolpath.activate(env2, bin_dir=os.path.join(d, "nope")))
            self.assertEqual(env2["PATH"], "/usr/bin")


class DetectTests(unittest.TestCase):
    def test_version_skips_banner_and_color(self):
        out = "  __  _\n /_/ /\n\x1b[34m[INF]\x1b[0m Current Version: v1.12.0\n"
        with mock.patch.object(detect.subprocess, "run", return_value=Proc(0, "", out)):
            self.assertEqual(detect.tool_version("/x", ("-version",)),
                             "[INF] Current Version: v1.12.0")

    def test_no_flags_means_no_version_call(self):
        with mock.patch.object(detect.subprocess, "run") as run:
            self.assertEqual(detect.tool_version("/x", ()), "")
            run.assert_not_called()


def _zip(path, files):
    with zipfile.ZipFile(path, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)


class ExtractTests(unittest.TestCase):
    def test_only_the_named_member_is_written(self):
        with tempfile.TemporaryDirectory() as d:
            archive = os.path.join(d, "a.zip")
            _zip(archive, {"../../evil": b"x", "nuclei": b"BIN", "README.md": b"r"})
            dest = os.path.join(d, "out", "nuclei")
            os.makedirs(os.path.dirname(dest))
            install.extract_member(archive, "nuclei", dest)
            with open(dest, "rb") as f:
                self.assertEqual(f.read(), b"BIN")
            self.assertTrue(os.access(dest, os.X_OK))
            self.assertEqual(sorted(os.listdir(os.path.join(d, "out"))), ["nuclei"])
            self.assertFalse(os.path.exists(os.path.join(os.path.dirname(d), "evil")))

    def test_missing_member_and_symlink_member_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            archive = os.path.join(d, "a.tar.gz")
            with tarfile.open(archive, "w:gz") as t:
                info = tarfile.TarInfo("ffuf")
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                t.addfile(info)
            with self.assertRaises(install.StepError):
                install.extract_member(archive, "ffuf", os.path.join(d, "ffuf"))
            with self.assertRaises(install.StepError):
                install.extract_member(archive, "other", os.path.join(d, "other"))
            self.assertFalse(os.path.exists(os.path.join(d, "ffuf")))


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data = os.path.join(self.tmp.name, "data")
        self.path = mock.patch.dict(os.environ, {"PATH": "/usr/bin"})
        self.path.start()

    def tearDown(self):
        self.path.stop()
        self.tmp.cleanup()

    def make(self, distro="ubuntu", root=True, run=None, fetch=None):
        return install.Installer(distro, "amd64", data_dir=self.data, root=root,
                                 run=run or FakeRun(), fetch=fetch or self.fail_fetch,
                                 log=lambda *a: None,
                                 rules_dir=os.path.join(self.tmp.name, "rules"))

    @staticmethod
    def fail_fetch(url, dest):
        raise AssertionError("no download expected")

    def test_kali_uses_apt_for_scanners(self):
        kali = self.make("kali").plan()
        titles = " ".join(t for t, _ in kali)
        self.assertNotIn("ffuf 2.3.0", titles)
        self.assertNotIn("searchsploit", titles)
        self.assertIn("exploitdb", kali[0][1])
        self.assertIn("httpx-toolkit", kali[0][1])
        ubuntu = " ".join(t for t, _ in self.make("ubuntu").plan())
        for name in ("ffuf 2.3.0", "nuclei 3.11.1", "httpx 1.12.0", "searchsploit",
                     "enum4linux-ng"):
            self.assertIn(name, ubuntu)

    def test_apt_only_missing_packages_and_sudo_when_not_root(self):
        run = FakeRun(installed=["nmap", "git"])
        worker = self.make(root=False, run=run)
        with mock.patch.object(install.shutil, "which", return_value="/usr/bin/sudo"):
            status, message = worker.step_apt()
        self.assertEqual(status, install.DONE)
        apt = [c for c in run.calls if "install" in c and "apt-get" in c][0]
        self.assertEqual(apt[0], "sudo")
        self.assertNotIn("nmap", apt)
        self.assertIn("testssl.sh", apt)
        self.assertEqual(worker.step_apt()[0], install.SKIPPED)

    def test_apt_without_sudo_fails_clearly(self):
        worker = self.make(root=False)
        with mock.patch.object(install.shutil, "which", return_value=None):
            with self.assertRaises(install.StepError) as err:
                worker.step_apt()
        self.assertIn("sudo is missing", str(err.exception))

    def _fake_release(self, payload):
        def fetch(url, dest):
            self.assertTrue(url.startswith("https://github.com/projectdiscovery/nuclei/"))
            _zip(dest, {"nuclei": payload})
        return fetch

    def test_release_sha_mismatch_installs_nothing(self):
        worker = self.make(fetch=self._fake_release(b"tampered"))
        with self.assertRaises(install.StepError) as err:
            worker.step_release("nuclei")
        self.assertIn("did not match", str(err.exception))
        self.assertFalse(os.path.exists(os.path.join(self.data, "bin", "nuclei")))
        self.assertEqual(worker.markers(), {})

    def test_release_with_matching_sha_installs_then_skips(self):
        payload = b"#!/bin/sh\necho nuclei\n"
        archive_bytes = io.BytesIO()
        with zipfile.ZipFile(archive_bytes, "w") as z:
            z.writestr("nuclei", payload)
        digest = hashlib.sha256(archive_bytes.getvalue()).hexdigest()

        def fetch(url, dest):
            with open(dest, "wb") as f:
                f.write(archive_bytes.getvalue())
        pinned = dict(manifest.RELEASES["nuclei"], sha256={"amd64": digest})
        with mock.patch.dict(manifest.RELEASES, {"nuclei": pinned}):
            worker = self.make(fetch=fetch)
            self.assertEqual(worker.step_release("nuclei")[0], install.DONE)
            launcher = os.path.join(self.data, "bin", "nuclei")
            with open(launcher) as f:
                self.assertIn("exec ", f.read())
            self.assertEqual(worker.markers()["nuclei"], pinned["version"])
            worker.fetch = self.fail_fetch
            self.assertEqual(worker.step_release("nuclei")[0], install.SKIPPED)

    def test_failed_step_does_not_stop_the_rest(self):
        worker = self.make()
        calls = []

        def boom():
            raise install.StepError("network down")
        worker.steps = lambda: [("a", boom), ("b", lambda: calls.append("b") or (install.DONE, "ok"))]
        with mock.patch.object(install.detect, "tools", return_value=[]):
            results, _ = worker.install()
        self.assertEqual([r[1] for r in results], [install.FAILED, install.DONE])
        self.assertEqual(calls, ["b"])
        with open(os.path.join(self.data, "setup.log")) as f:
            self.assertIn("network down", f.read())

    def test_clone_checks_pinned_commit(self):
        class GitRun(FakeRun):
            def __call__(self, cmd, **kw):
                self.calls.append(list(cmd))
                if cmd[:1] == ["git"] and "rev-parse" in cmd:
                    return Proc(0, "0" * 40 + "\n")
                return Proc(0)
        worker = self.make(run=GitRun())
        dest = os.path.join(self.tmp.name, "checkout")
        with self.assertRaises(install.StepError) as err:
            worker._clone("https://example.invalid/x.git", "v1", "a" * 40, dest)
        self.assertIn("not the pinned", str(err.exception))
        self.assertFalse(os.path.exists(dest))
        self.assertEqual([n for n in os.listdir(self.tmp.name) if n.startswith(".clone-")], [])

    def test_searchsploit_rc_points_only_exploits_and_shellcodes(self):
        rc = os.path.join(self.tmp.name, ".searchsploit_rc")
        with open(rc, "w") as f:
            f.write('files_array+=("files_exploits.csv")\npath_array+=("/opt/exploitdb")\n'
                    'files_array+=("files_shellcodes.csv")\npath_array+=("/opt/exploitdb")\n'
                    'files_array+=("files_papers.csv")\npath_array+=("/opt/exploitdb-papers")\n')
        install.point_searchsploit_rc(rc, "/data/exploitdb")
        with open(rc) as f:
            text = f.read()
        self.assertEqual(text.count('path_array+=("/data/exploitdb")'), 2)
        self.assertIn('path_array+=("/opt/exploitdb-papers")', text)

    def test_templates_version_keeps_other_nuclei_settings(self):
        config = os.path.join(self.tmp.name, "nuclei", ".templates-config.json")
        os.makedirs(os.path.dirname(config))
        with open(config, "w") as f:
            json.dump({"custom-s3-templates-directory": "/x"}, f)
        install.record_templates_version(config, "/t", "v10.5.2")
        with open(config) as f:
            data = json.load(f)
        self.assertEqual(data["nuclei-templates-version"], "v10.5.2")
        self.assertEqual(data["custom-s3-templates-directory"], "/x")
        self.assertEqual(install.templates_dir(config), "/t")

    def test_semgrep_launcher_turns_off_online_version_check(self):
        path = install.write_launcher("semgrep", "/v/bin/semgrep", self.data)
        with open(path) as f:
            text = f.read()
        self.assertIn("export SEMGREP_ENABLE_VERSION_CHECK=0", text)
        self.assertTrue(text.rstrip().endswith('exec /v/bin/semgrep "$@"'))

    def test_installer_never_touches_scope(self):
        for module in (install, manifest, preflight, cli):
            with open(module.__file__) as f:
                text = f.read()
            self.assertNotIn("ALLOWLIST", text)
            self.assertNotIn("DENYLIST", text)
            self.assertNotIn("core import config", text)


class ReviewFixTests(unittest.TestCase):
    def test_semgrep_rule_id_drops_rules_folder(self):
        from reconmind.code import semgrep_scan
        with tempfile.TemporaryDirectory() as d:
            rules = os.path.join(d, ".local", "semgrep-rules")
            os.makedirs(rules)
            prefix = os.path.realpath(rules).strip(os.sep).replace(os.sep, ".")
            self.assertEqual(semgrep_scan.short_rule_id(
                prefix + ".python.lang.security.audit.x", rules), "python.lang.security.audit.x")
            self.assertEqual(semgrep_scan.short_rule_id("python.lang.y", rules), "python.lang.y")

    def test_job_page_has_one_open_report_button(self):
        root = os.path.join(os.path.dirname(__file__), "..", "reconmind", "web", "static")
        with open(os.path.join(root, "index.html")) as f:
            self.assertEqual(f.read().count(">Open report<"), 1)
        with open(os.path.join(root, "js", "views", "job.js")) as f:
            self.assertNotIn("reportLink", f.read())


class CliTests(unittest.TestCase):
    def setUp(self):
        checks = [preflight.Check("Operating system", True, "Ubuntu", True)]
        self.patches = [
            mock.patch.object(cli.preflight, "run_checks", return_value=checks),
            mock.patch.object(cli.preflight, "read_os_release", return_value=UBUNTU),
            mock.patch.object(cli.detect, "tools", return_value=[]),
            mock.patch.object(cli.install.Installer, "plan", return_value=[("x", "y")]),
            mock.patch.object(cli.install.Installer, "install",
                              side_effect=AssertionError("must not install")),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def quiet(self, *args, **kw):
        with mock.patch("sys.stdout", new=io.StringIO()) as out:
            code = cli.main(*args, **kw)
        return code, out.getvalue()

    def test_check_installs_nothing(self):
        code, out = self.quiet(["--check"])
        self.assertEqual(code, 0)
        self.assertIn("check only", out)

    def test_declined_prompt_installs_nothing(self):
        code, out = self.quiet(["--install"], inp=lambda prompt: "n")
        self.assertEqual(code, 3)
        self.assertIn("Nothing was installed", out)

    def test_blocked_preflight_stops(self):
        blocked = [preflight.Check("Network", False, "offline", True)]
        with mock.patch.object(cli.preflight, "run_checks", return_value=blocked):
            code, out = self.quiet(["--install", "--yes"])
        self.assertEqual(code, 2)

    def test_accepted_install_reports_missing_tools(self):
        tools = [{"name": "nmap", "action": "Surface Map", "status": "missing", "version": ""}]
        with mock.patch.object(cli.install.Installer, "install", side_effect=None,
                               return_value=([("nmap", install.FAILED, "apt broke")], tools)):
            code, out = self.quiet(["--install"], inp=lambda prompt: "y")
        self.assertEqual(code, 1)
        self.assertIn("apt broke", out)


if __name__ == "__main__":
    unittest.main()
