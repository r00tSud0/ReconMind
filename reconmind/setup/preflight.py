"""
Read-only checks before anything is installed: operating system, CPU,
Python, disk space, network, admin rights and the package manager.
"""

import collections
import os
import platform
import shutil
import sys
import urllib.error
import urllib.request

from reconmind import toolpath
from reconmind.setup import manifest

Check = collections.namedtuple("Check", "name ok detail blocking")


def read_os_release(path="/etc/os-release"):
    """/etc/os-release as a dict, {} if it cannot be read."""
    info = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                key, sep, value = line.strip().partition("=")
                if sep and key:
                    info[key] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return info


def distro(info):
    """"ubuntu", "debian" or "kali" when supported, else None. Derivatives
    such as Linux Mint are not supported yet, so only ID counts."""
    value = info.get("ID", "").lower()
    return value if value in manifest.SUPPORTED_DISTROS else None


def arch(machine=None):
    """"amd64" or "arm64", else None."""
    return manifest.ARCHES.get((machine or platform.machine()).lower())


def is_wsl(path="/proc/version"):
    try:
        with open(path, encoding="utf-8") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _free_bytes(folder):
    probe = os.path.abspath(folder)
    while not os.path.exists(probe):
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent
    try:
        return shutil.disk_usage(probe).free
    except OSError:
        return None


def network_ok(url="https://github.com", timeout=8):
    """True when an HTTPS answer of any status comes back."""
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="HEAD"),
                                    timeout=timeout):
            return True
    except urllib.error.HTTPError:
        return True
    except (urllib.error.URLError, OSError, ValueError):
        return False


def run_checks(info=None, machine=None, version=None, free=None, online=None,
               root=None, which=shutil.which, wsl=None):
    """A list of Check. A blocking Check that is not ok stops --install."""
    info = read_os_release() if info is None else info
    version = sys.version_info[:3] if version is None else version
    free = _free_bytes(toolpath.DATA_DIR) if free is None else free
    online = network_ok() if online is None else online
    root = is_root() if root is None else root
    wsl = is_wsl() if wsl is None else wsl

    name = info.get("PRETTY_NAME") or info.get("ID") or "Unknown Linux"
    found = distro(info)
    checks = [
        Check("Operating system", bool(found),
              name + (" under WSL" if wsl else "") + ("" if found else
                  ". Supported: Ubuntu, Debian and Kali. This system is not supported yet."),
              True),
    ]
    cpu = arch(machine)
    checks.append(Check("CPU", bool(cpu), (machine or platform.machine()) + (
        "" if cpu else ". Only 64 bit Intel/AMD and ARM are supported."), True))
    py_ok = tuple(version[:2]) >= manifest.MIN_PYTHON
    checks.append(Check("Python", py_ok, "Python " + ".".join(str(x) for x in version) + (
        "" if py_ok else ". Python 3.10 or newer is needed."), True))
    if free is None:
        checks.append(Check("Disk space", False, "Free space could not be read.", False))
    else:
        disk_ok = free >= manifest.MIN_FREE_BYTES
        checks.append(Check("Disk space", disk_ok, "{g:.1f} GiB free{n}".format(
            g=free / 1024 ** 3, n="" if disk_ok else ". About 3 GiB is needed."), True))
    checks.append(Check("Network", bool(online), "GitHub reachable" if online
                        else "GitHub could not be reached. Check the internet connection.", True))
    apt = bool(which("apt-get"))
    checks.append(Check("Package manager", apt, "apt-get found" if apt
                        else "apt-get was not found.", True))
    sudo = root or bool(which("sudo"))
    checks.append(Check("Admin rights", sudo, "running as root" if root else (
        "sudo found. You will be asked for your password once." if sudo
        else "sudo was not found, so system packages cannot be installed."), False))
    checks.append(Check("Git", bool(which("git")), "git found" if which("git")
                        else "git will be installed in the system packages step.", False))
    return checks


def blocking_failures(checks):
    return [c for c in checks if c.blocking and not c.ok]
