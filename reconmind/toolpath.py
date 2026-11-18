"""
Where ReconMind's own installed tools live, and putting them on PATH.

The setup wizard (python3 -m reconmind.setup) installs programs that the
system package manager does not provide into DATA_DIR, with one small
launcher per program in BIN_DIR. Every engine module finds its tools with
shutil.which, so prepending BIN_DIR to PATH once, when the reconmind package
is imported, is enough for the CLI, the web app and every scan child process
(they inherit the environment). Nothing is added when BIN_DIR does not exist.
"""

import os

DATA_DIR = os.path.join(
    os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share"),
    "reconmind")
BIN_DIR = os.path.join(DATA_DIR, "bin")


def activate(path_env=None, bin_dir=None):
    """Prepend bin_dir (default BIN_DIR) to PATH if it exists and is not already first."""
    env = os.environ if path_env is None else path_env
    bin_dir = bin_dir or BIN_DIR
    if not os.path.isdir(bin_dir):
        return False
    parts = [p for p in env.get("PATH", "").split(os.pathsep) if p]
    if parts and parts[0] == bin_dir:
        return False
    parts = [bin_dir] + [p for p in parts if p != bin_dir]
    env["PATH"] = os.pathsep.join(parts)
    return True
