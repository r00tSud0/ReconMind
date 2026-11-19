"""
Install or repair the scanning tools. Every step is idempotent: a piece that
is already in place at the pinned version is skipped, so running --install
again is also the repair.

Where things go (nothing outside these, apart from the apt packages):
    ~/.local/share/reconmind/bin/        one launcher per installed program
    ~/.local/share/reconmind/tools/      release binaries and git checkouts
    ~/.local/share/reconmind/venvs/      one Python environment per Python tool
    ~/.local/share/reconmind/setup.log   what ran and what it printed
    semgrep rules at reconmind.code.semgrep_scan.rules_dir()

The installer never scans a target and never touches the allow or deny lists.
"""

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile

from reconmind import toolpath
from reconmind.code import semgrep_scan
from reconmind.ai import attack_mapper
from reconmind.setup import detect, manifest, model
from reconmind.tools import nuclei_scan

MAX_DOWNLOAD = 300 * 1024 * 1024
DONE, SKIPPED, FAILED = "done", "skipped", "failed"


NEEDS_TERMINAL = ("System packages need your password. Open a terminal in the ReconMind "
                  "folder and run: python3 -m reconmind.setup --install")


class StepError(Exception):
    pass


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def download(url, dest, attempts=3, timeout=60, opener=urllib.request.urlopen, sleep=time.sleep):
    """Stream url to dest, at most MAX_DOWNLOAD bytes, retrying on errors."""
    last = None
    for attempt in range(attempts):
        try:
            with opener(url, timeout=timeout) as response, open(dest, "wb") as out:
                total = 0
                while True:
                    block = response.read(1 << 20)
                    if not block:
                        break
                    total += len(block)
                    if total > MAX_DOWNLOAD:
                        raise StepError("The download is larger than expected.")
                    out.write(block)
            return
        except StepError:
            raise
        except Exception as exc:  # network errors of every kind get a retry
            last = exc
            if attempt + 1 < attempts:
                sleep(2 * (attempt + 1))
    raise StepError("Download failed after {n} tries: {e}".format(n=attempts, e=last))


def extract_member(archive, member, dest):
    """Copy the one regular file called member out of a .zip or .tar.gz.
    Nothing else is extracted, so archive paths can never escape dest."""
    tmp = dest + ".part"
    try:
        if archive.endswith(".zip"):
            with zipfile.ZipFile(archive) as z:
                names = [i for i in z.infolist() if i.filename == member and not i.is_dir()]
                if len(names) != 1:
                    raise StepError("The archive does not hold " + member + ".")
                with z.open(names[0]) as src, open(tmp, "wb") as out:
                    shutil.copyfileobj(src, out)
        else:
            with tarfile.open(archive, "r:gz") as t:
                names = [i for i in t.getmembers() if i.name in (member, "./" + member)]
                if len(names) != 1 or not names[0].isfile():
                    raise StepError("The archive does not hold " + member + ".")
                src = t.extractfile(names[0])
                with src, open(tmp, "wb") as out:
                    shutil.copyfileobj(src, out)
        os.chmod(tmp, 0o755)
        os.replace(tmp, dest)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


# Settings each launcher fixes for its program. Semgrep otherwise checks for a
# newer version online on every start, which can stall it for over a minute.
LAUNCHER_ENV = {"semgrep": {"SEMGREP_ENABLE_VERSION_CHECK": "0"}}


def write_launcher(name, target, bin_dir):
    """bin/<name>: a small shell script that runs target."""
    os.makedirs(bin_dir, exist_ok=True)
    path = os.path.join(bin_dir, name)
    tmp = path + ".part"
    lines = ["#!/bin/sh"]
    lines += ["export {k}={v}".format(k=k, v=shlex.quote(v))
              for k, v in sorted(LAUNCHER_ENV.get(name, {}).items())]
    lines.append("exec {t} \"$@\"".format(t=shlex.quote(target)))
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(tmp, 0o755)
    os.replace(tmp, path)
    return path


def point_searchsploit_rc(rc_path, checkout):
    """Point the Exploit and Shellcode entries of searchsploit's own config at
    checkout. Other entries (Papers) are left alone."""
    with open(rc_path, encoding="utf-8") as f:
        lines = f.readlines()
    out, current = [], ""
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("files_array+="):
            current = stripped
        if stripped.startswith("path_array+=") and (
                "files_exploits.csv" in current or "files_shellcodes.csv" in current):
            line = 'path_array+=("{p}")\n'.format(p=checkout)
        out.append(line)
    with open(rc_path, "w", encoding="utf-8") as f:
        f.writelines(out)


def nuclei_config_path():
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "nuclei", ".templates-config.json")


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def templates_dir(config_path):
    """The templates folder nuclei uses: its config's choice, else ~/nuclei-templates."""
    folder = _read_json(config_path).get("nuclei-templates-directory")
    if isinstance(folder, str) and os.path.isabs(folder):
        return folder
    return os.path.join(os.path.expanduser("~"), "nuclei-templates")


def record_templates_version(config_path, folder, version):
    """Write the templates folder and version into nuclei's own config, as
    nuclei's updater does after an update. Other keys are kept."""
    data = _read_json(config_path)
    data["nuclei-templates-directory"] = folder
    data["nuclei-templates-version"] = version
    os.makedirs(os.path.dirname(config_path), mode=0o700, exist_ok=True)
    tmp = config_path + ".part"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, config_path)


class Installer:
    def __init__(self, distro, arch, data_dir=None, python=None, root=None,
                 run=None, fetch=download, log=print, rules_dir=None,
                 interactive=True, on_event=None, env=None):
        self.distro = distro
        self.arch = arch
        self.data = data_dir or toolpath.DATA_DIR
        self.bin = os.path.join(self.data, "bin")
        self.tools_dir = os.path.join(self.data, "tools")
        self.venvs = os.path.join(self.data, "venvs")
        self.python = python or sys.executable
        self.root = (os.geteuid() == 0) if root is None else root
        self._run = run or subprocess.run
        self.fetch = fetch
        self.say = log
        self.rules_dir = rules_dir or semgrep_scan.rules_dir()
        self.marker_path = os.path.join(self.data, "installed.json")
        # interactive: a terminal is attached, so sudo can ask for the password.
        # Without one (the app's Setup screen) pkexec shows a password window
        # on a desktop, or the step explains how to run setup in a terminal.
        self.interactive = interactive
        self.on_event = on_event or (lambda event: None)
        self.env = os.environ if env is None else env

    # ---- helpers ----------------------------------------------------------

    def kali(self):
        return self.distro == "kali"

    def log_line(self, text):
        os.makedirs(self.data, exist_ok=True)
        with open(os.path.join(self.data, "setup.log"), "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + text.rstrip() + "\n")

    def run(self, cmd, interactive=False, timeout=1800, cwd=None):
        """Run cmd. interactive keeps the terminal (sudo password, apt)."""
        self.log_line("$ " + " ".join(shlex.quote(c) for c in cmd))
        try:
            if interactive:
                proc = self._run(cmd, cwd=cwd, timeout=timeout, check=False)
            else:
                proc = self._run(cmd, cwd=cwd, timeout=timeout, check=False,
                                 capture_output=True, text=True, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.log_line("  could not run: " + str(exc))
            raise StepError("{c} could not run: {e}".format(c=cmd[0], e=exc)) from None
        out = "\n".join(x for x in (getattr(proc, "stdout", ""), getattr(proc, "stderr", "")) if x)
        if out:
            self.log_line(out[-4000:])
        if proc.returncode != 0:
            tail = out.strip().splitlines()[-3:] if out else []
            raise StepError("{c} failed (exit {r}). {t}".format(
                c=os.path.basename(cmd[0]), r=proc.returncode, t=" ".join(tail)).strip())
        return out

    def markers(self):
        try:
            with open(self.marker_path, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def mark(self, name, version):
        data = self.markers()
        data[name] = version
        os.makedirs(self.data, exist_ok=True)
        tmp = self.marker_path + ".part"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1, sort_keys=True)
        os.replace(tmp, self.marker_path)

    def installed(self, name, version, path):
        return self.markers().get(name) == version and os.path.exists(path)

    # ---- what is needed ---------------------------------------------------

    def apt_packages(self):
        return list(manifest.APT_COMMON) + (list(manifest.APT_KALI) if self.kali() else [])

    def dpkg_installed(self, package):
        try:
            proc = self._run(["dpkg-query", "-W", "-f=${Status}", package], check=False,
                             capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            return False
        return proc.returncode == 0 and "install ok installed" in (proc.stdout or "")

    def apt_missing(self):
        return [p for p in self.apt_packages() if not self.dpkg_installed(p)]

    def plan(self):
        """[(title, detail)] in the order they run."""
        steps = []
        missing = self.apt_missing()
        if missing:
            steps.append(("System packages" + ("" if self.root else " (asks for your password)"),
                          ("" if self.root else "sudo ") + "apt-get install " + " ".join(missing)))
        if not self.kali():
            for name, item in manifest.RELEASES.items():
                steps.append((name + " " + item["version"],
                              "download " + item["url"].format(v=item["version"], a=self.arch)
                              + " and check its SHA-256"))
            steps.append(("searchsploit (Exploit-DB)", "git clone " + manifest.EXPLOITDB["url"]
                          + " (large, can take several minutes)"))
            steps.append(("enum4linux-ng " + manifest.ENUM4LINUX_NG["ref"],
                          "git clone " + manifest.ENUM4LINUX_NG["url"] + " into its own Python environment"))
        for name, spec in manifest.PIP_TOOLS.items():
            steps.append((spec, "pip install into its own Python environment"))
        steps.append(("Semgrep rules", "git checkout " + manifest.SEMGREP_RULES["commit"][:12]
                      + " into " + self.rules_dir))
        steps.append(("nuclei templates", "nuclei -update-templates, or the pinned "
                      + manifest.NUCLEI_TEMPLATES["ref"] + " release if that does not work"))
        steps.append(("ATT&CK mapper packages", "torch (CPU), transformers, safetensors "
                      "into this Python environment, if missing"))
        src = manifest.MODEL
        steps.append(("SciBERT Run 3 model", ("download " + src["url"] + ", check size and "
                      "SHA-256, test load and one prediction") if src["url"]
                      else "download source not set yet"))
        return steps

    # ---- steps ------------------------------------------------------------

    def privilege(self):
        """How to run apt-get as root: ("root"|"sudo"|"sudo-n"|"pkexec", prefix).
        Raises StepError with what to do when there is no way without a terminal."""
        if self.root:
            return "root", []
        if self.interactive:
            if not shutil.which("sudo"):
                raise StepError("sudo is missing, so system packages cannot be installed.")
            return "sudo", ["sudo"]
        if shutil.which("sudo"):
            try:
                ok = self._run(["sudo", "-n", "true"], check=False, capture_output=True,
                               text=True, stdin=subprocess.DEVNULL, timeout=15).returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                ok = False
            if ok:
                return "sudo-n", ["sudo", "-n"]
        if shutil.which("pkexec") and (self.env.get("DISPLAY") or self.env.get("WAYLAND_DISPLAY")):
            return "pkexec", ["pkexec"]
        raise StepError(NEEDS_TERMINAL)

    def step_apt(self):
        missing = self.apt_missing()
        if not missing:
            return SKIPPED, "already installed"
        how, prefix = self.privilege()
        install_cmd = ["apt-get", "-o", "DPkg::Lock::Timeout=120", "install", "-y",
                       "--no-install-recommends"] + missing
        self.say("   Installing system packages: " + " ".join(missing))
        if how == "pkexec":
            # One password window for both commands. The package names are
            # fixed in the manifest, never user input.
            script = "apt-get update && " + " ".join(shlex.quote(c) for c in install_cmd)
            self.say("   A password window opens. Enter your password to continue.")
            try:
                self.run(["pkexec", "/bin/sh", "-c", script], timeout=3600)
            except StepError as exc:
                if "exit 126" in str(exc) or "exit 127" in str(exc):
                    raise StepError("The password window was closed or is not available. "
                                    + NEEDS_TERMINAL) from None
                raise
        else:
            self.run(prefix + ["apt-get", "update"], interactive=self.interactive)
            self.run(prefix + install_cmd, interactive=self.interactive)
        still = self.apt_missing()
        if still:
            raise StepError("These packages are still missing: " + " ".join(still))
        return DONE, "installed " + " ".join(missing)

    def step_release(self, name):
        item = manifest.RELEASES[name]
        version = item["version"]
        folder = os.path.join(self.tools_dir, name, version)
        binary = os.path.join(folder, item["member"])
        if self.installed(name, version, binary) and os.path.exists(os.path.join(self.bin, name)):
            return SKIPPED, "version " + version + " already installed"
        expected = item["sha256"].get(self.arch)
        if not expected:
            raise StepError("No pinned build of {n} for {a}.".format(n=name, a=self.arch))
        url = item["url"].format(v=version, a=self.arch)
        os.makedirs(folder, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=self.data) as tmp:
            archive = os.path.join(tmp, url.rsplit("/", 1)[-1])
            self.log_line("download " + url)
            self.fetch(url, archive)
            actual = sha256_file(archive)
            if actual != expected:
                self.log_line("SHA-256 mismatch for {n}: {a}".format(n=name, a=actual))
                raise StepError("The {n} download did not match its pinned SHA-256, "
                                "so it was thrown away.".format(n=name))
            extract_member(archive, item["member"], binary)
        write_launcher(name, binary, self.bin)
        self.mark(name, version)
        return DONE, "version " + version + " installed, SHA-256 checked"

    def _clone(self, url, ref, commit, dest):
        """Clone into a temporary folder next to dest, check the commit, then
        move it into place, so a failed clone never leaves half a folder."""
        parent = os.path.dirname(dest)
        os.makedirs(parent, exist_ok=True)
        tmp = tempfile.mkdtemp(prefix=".clone-", dir=parent)
        try:
            if ref:
                self.run(["git", "clone", "-q", "--depth", "1", "--branch", ref, url, tmp])
            else:
                self.run(["git", "init", "-q", tmp])
                self.run(["git", "-C", tmp, "fetch", "-q", "--depth", "1", url, commit])
                self.run(["git", "-C", tmp, "checkout", "-q", "FETCH_HEAD"])
            head = self.run(["git", "-C", tmp, "rev-parse", "HEAD"]).strip().splitlines()[0]
            if commit and head != commit:
                raise StepError("{u} gave commit {h}, not the pinned {c}.".format(
                    u=url, h=head[:12], c=commit[:12]))
            if os.path.exists(dest):
                shutil.rmtree(dest)
            os.replace(tmp, dest)
            tmp = None
            self.log_line("{u} at commit {h}".format(u=url, h=head))
            return head
        finally:
            if tmp and os.path.exists(tmp):
                shutil.rmtree(tmp, ignore_errors=True)

    def step_exploitdb(self):
        dest = os.path.join(self.tools_dir, "exploitdb")
        script = os.path.join(dest, "searchsploit")
        if os.path.isfile(script) and os.path.exists(os.path.join(self.bin, "searchsploit")):
            return SKIPPED, "already installed"
        src = manifest.EXPLOITDB
        self.say("   Cloning Exploit-DB. This is large and can take several minutes.")
        head = self._clone(src["url"], src["ref"], src["commit"], dest)
        rc = os.path.join(dest, ".searchsploit_rc")
        if os.path.isfile(rc):
            point_searchsploit_rc(rc, dest)
        if not os.path.isfile(script):
            raise StepError("The Exploit-DB checkout has no searchsploit script.")
        write_launcher("searchsploit", script, self.bin)
        return DONE, "installed at commit " + head[:12]

    def _venv(self, name):
        folder = os.path.join(self.venvs, name)
        if not os.path.isfile(os.path.join(folder, "bin", "python")):
            self.run([self.python, "-m", "venv", folder])
        return folder

    def _pip(self, venv, *args):
        self.run([os.path.join(venv, "bin", "python"), "-m", "pip", "install", "-q",
                  "--disable-pip-version-check", *args])

    def step_enum4linux(self):
        src = manifest.ENUM4LINUX_NG
        venv_bin = os.path.join(self.venvs, "enum4linux-ng", "bin", "enum4linux-ng")
        if self.installed("enum4linux-ng", src["commit"], venv_bin):
            return SKIPPED, src["ref"] + " already installed"
        checkout = os.path.join(self.tools_dir, "enum4linux-ng")
        self._clone(src["url"], src["ref"], src["commit"], checkout)
        venv = self._venv("enum4linux-ng")
        self._pip(venv, checkout)
        if not os.path.isfile(venv_bin):
            raise StepError("enum4linux-ng did not install its program.")
        write_launcher("enum4linux-ng", venv_bin, self.bin)
        self.mark("enum4linux-ng", src["commit"])
        return DONE, src["ref"] + " installed"

    def step_pip_tool(self, name):
        spec = manifest.PIP_TOOLS[name]
        program = os.path.join(self.venvs, name, "bin", name)
        if self.installed(name, spec, program) and os.path.exists(os.path.join(self.bin, name)):
            write_launcher(name, program, self.bin)  # cheap; keeps launcher settings current
            return SKIPPED, spec + " already installed"
        venv = self._venv(name)
        self._pip(venv, spec)
        if not os.path.isfile(program):
            raise StepError(name + " did not install its program.")
        write_launcher(name, program, self.bin)
        self.mark(name, spec)
        return DONE, spec + " installed"

    def step_semgrep_rules(self):
        commit = manifest.SEMGREP_RULES["commit"]
        dest = self.rules_dir
        if os.path.isdir(os.path.join(dest, ".git")):
            try:
                head = self.run(["git", "-C", dest, "rev-parse", "HEAD"]).strip()
            except StepError:
                head = ""
            if head == commit:
                return SKIPPED, "pinned commit already checked out"
        elif os.path.exists(dest) and os.listdir(dest):
            raise StepError(dest + " exists but is not a git checkout. Move it away and retry.")
        self._clone(manifest.SEMGREP_RULES["url"], None, commit, dest)
        return DONE, "commit " + commit[:12] + " checked out"

    def step_templates(self):
        toolpath.activate(bin_dir=self.bin)
        nuclei = shutil.which("nuclei")
        if not nuclei:
            raise StepError("nuclei is not installed, so templates cannot be fetched.")
        version, _ = nuclei_scan.templates_version()
        if version:
            return SKIPPED, "templates " + version + " already installed"
        try:
            self.run([nuclei, "-update-templates", "-disable-update-check", "-silent"], timeout=900)
        except StepError as exc:
            self.log_line("nuclei -update-templates failed, using the pinned checkout: " + str(exc))
        version, _ = nuclei_scan.templates_version()
        if version:
            return DONE, "templates " + version + " installed"
        # Fallback: the pinned templates release, recorded where nuclei reads it.
        src = manifest.NUCLEI_TEMPLATES
        config = nuclei_config_path()
        folder = templates_dir(config)
        self._clone(src["url"], src["ref"], src["commit"], folder)
        record_templates_version(config, folder, src["ref"])
        version, _ = nuclei_scan.templates_version()
        if not version:
            raise StepError("The templates were downloaded but nuclei does not report them.")
        return DONE, "templates " + version + " installed from the pinned release"

    def _python_has(self, code):
        try:
            proc = self._run([self.python, "-c", code], check=False, capture_output=True,
                             text=True, stdin=subprocess.DEVNULL, timeout=120)
        except (OSError, subprocess.TimeoutExpired):
            return False, ""
        return proc.returncode == 0, (proc.stdout or "").strip()

    def step_mapper_packages(self):
        ok, _ = self._python_has("import torch, transformers, safetensors")
        if ok:
            return SKIPPED, "torch and transformers already installed"
        in_venv, out = self._python_has("import sys; print(sys.prefix != sys.base_prefix)")
        if not in_venv or out != "True":
            raise StepError("Run setup from ReconMind's own Python environment, so the model "
                            "packages are installed there and not into the system Python.")
        self.say("   Installing torch for the CPU. This is a large download.")
        try:
            self.run([self.python, "-m", "pip", "install", "-q", "--disable-pip-version-check",
                      "torch", "--index-url", manifest.MAPPER_TORCH_INDEX], timeout=3600)
            self.run([self.python, "-m", "pip", "install", "-q", "--disable-pip-version-check",
                      *manifest.MAPPER_PACKAGES[1:]], timeout=1800)
        except StepError:
            # pip's own output is in setup.log; the screen gets one plain sentence.
            raise StepError("torch or transformers could not be downloaded. Check the internet "
                            "connection and run setup again. Details are in setup.log.") from None
        ok, _ = self._python_has("import torch, transformers, safetensors")
        if not ok:
            raise StepError("torch or transformers still cannot be imported.")
        return DONE, "torch, transformers and safetensors installed"

    def step_model(self, verify=None, model_dir=None):
        real = verify is None
        verify = verify or (lambda d: model.verify(d, manifest.MODEL["labels"], python=self.python))
        if real:
            ready, _ = self._python_has("import torch, transformers, safetensors")
            if not ready:
                raise StepError("The model needs the ATT&CK mapper packages, which are not "
                                "installed yet. Fix that step, then run setup again.")
        src = manifest.MODEL
        dest = model_dir or attack_mapper.model_dir()
        present = all(os.path.isfile(os.path.join(dest, n)) for n in attack_mapper.REQUIRED_FILES)
        problem = ""
        if present:
            try:
                verify(dest)
                return SKIPPED, "already installed, loads with {n} labels".format(n=src["labels"])
            except model.ModelError as exc:
                problem = str(exc)
                self.log_line("installed model failed its check: " + problem)
        if not (src["url"] and src["sha256"] and src["size"]):
            raise StepError((problem + " " if problem else "") + "The model download source "
                            "is not set yet, so the model cannot be installed.")
        downloads = os.path.join(self.data, "downloads")
        os.makedirs(downloads, exist_ok=True)
        archive = os.path.join(downloads, src["url"].rsplit("/", 1)[-1])
        self.say("   Downloading the model ({m} MB). An interrupted download resumes.".format(
            m=src["size"] // (1024 * 1024)))
        self.log_line("download " + src["url"])
        model.download_resume(src["url"], archive, src["size"])
        if os.path.getsize(archive) != src["size"] or sha256_file(archive) != src["sha256"]:
            os.unlink(archive)
            raise StepError("The model download did not match its published size and "
                            "SHA-256, so it was thrown away.")
        parent = os.path.dirname(dest)
        os.makedirs(parent, exist_ok=True)
        holder, extracted = model.safe_extract(archive, parent, src["folder"])
        try:
            self.say("   Checking the model loads and predicts. This takes a minute.")
            verify(extracted)
            model.swap_in(extracted, dest)
        except model.ModelError as exc:
            raise StepError(str(exc)) from None
        finally:
            shutil.rmtree(holder, ignore_errors=True)
        os.unlink(archive)
        attack_mapper.clear_cache()
        return DONE, "installed and checked: {n} labels, one test prediction".format(
            n=src["labels"])

    def steps(self):
        """[(title, callable)] in the order they run."""
        out = [("System packages", self.step_apt)]
        if not self.kali():
            for name in manifest.RELEASES:
                out.append((name, lambda n=name: self.step_release(n)))
            out.append(("searchsploit", self.step_exploitdb))
            out.append(("enum4linux-ng", self.step_enum4linux))
        for name in manifest.PIP_TOOLS:
            out.append((name.capitalize() if name != "semgrep" else "Semgrep",
                        lambda n=name: self.step_pip_tool(n)))
        out.append(("Semgrep rules", self.step_semgrep_rules))
        out.append(("nuclei templates", self.step_templates))
        out.append(("ATT&CK mapper packages", self.step_mapper_packages))
        out.append(("SciBERT Run 3 model", self.step_model))
        return out

    def install(self):
        """Run every step, keep going after a failure, then verify.
        Returns (results, tools) where results is [(title, status, message)]."""
        os.makedirs(self.data, exist_ok=True)
        self.log_line("setup started for {d} {a}".format(d=self.distro, a=self.arch))
        toolpath.activate(bin_dir=self.bin)
        results = []
        steps = self.steps()
        for index, (title, step) in enumerate(steps, 1):
            self.say("{i}/{n} {t}".format(i=index, n=len(steps), t=title))
            self.on_event({"type": "step", "index": index, "total": len(steps),
                           "title": title, "state": "running"})
            try:
                status, message = step()
            except (StepError, model.ModelError) as exc:
                status, message = FAILED, str(exc)
            except Exception as exc:  # never crash halfway without a summary
                status, message = FAILED, "unexpected error: {e}".format(e=exc)
            self.log_line("{t}: {s}: {m}".format(t=title, s=status, m=message))
            self.say("   {s}: {m}".format(s={DONE: "Done", SKIPPED: "Already fine",
                                             FAILED: "FAILED"}[status], m=message))
            results.append((title, status, message))
            self.on_event({"type": "step", "index": index, "total": len(steps),
                           "title": title, "state": status, "message": message})
        toolpath.activate(bin_dir=self.bin)
        return results, detect.tools()
