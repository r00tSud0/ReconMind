"""
Read-only System check for ReconMind's localhost frontend.

Nothing here starts a scan, installs tools, changes configuration, calls an
LLM, or loads model weights. It checks the same executable names as the engine
and never returns API key values.
"""
import importlib.util
import os
import shutil
import subprocess

from reconmind.agent import llm
from reconmind.agent.__main__ import _load_dotenv
from reconmind.ai import attack_mapper
from reconmind.core import config
from reconmind.tools import httpx_scan

# (label, engine check, version command, check category). Installing or
# repairing tools belongs to the setup wizard, so no install guidance is kept here.
TOOLS = (
    ("nmap", "nmap", ("--version",), "Surface Map"),
    ("searchsploit", "searchsploit", ("-h",), "Exploit Hunt"),
    ("httpx", "httpx", ("-version",), "Web Fingerprint"),
    ("ffuf", "ffuf", ("-V",), "Hidden Paths"),
    ("nuclei", "nuclei", ("-version",), "Vuln Probe"),
    ("testssl.sh", "testssl", ("--version",), "Crypto Check"),
    ("enum4linux-ng", "enum4linux-ng", ("-h",), "SMB Recon"),
    ("Semgrep", "semgrep", ("--version",), "Code scan"),
    ("Bandit", "bandit", ("--version",), "Code scan"),
)


def _path(name):
    """Exact engine selection for ProjectDiscovery httpx and testssl variants."""
    if name == "httpx":
        return shutil.which(httpx_scan.find_binary() or "")
    if name == "testssl":
        return shutil.which("testssl") or shutil.which("testssl.sh")
    return shutil.which(name)


def _version(binary, flags):
    """Best-effort version, never fail System if a tool hangs or prints junk."""
    try:
        result = subprocess.run([binary, *flags], capture_output=True, text=True,
                                stdin=subprocess.DEVNULL, timeout=2, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    lines = (result.stdout or result.stderr or "").splitlines()
    return next((line.strip()[:120] for line in lines if line.strip()), "")


def _tools():
    result = []
    for label, executable, flags, action in TOOLS:
        binary = _path(executable)
        result.append({
            "name": label,
            "action": action,
            "status": "ready" if binary else "missing",
            "version": _version(binary, flags) if binary else "",
        })
    return result


def _ai():
    # The CLI loads .env when launching a scan. Reuse its semantics here.
    _load_dotenv()
    name = os.environ.get("RECONMIND_PROVIDER", llm.DEFAULT_PROVIDER).lower().strip()
    provider = llm.PROVIDERS.get(name)
    key_env = provider.get("api_key_env") if provider else None
    model = os.environ.get("RECONMIND_MODEL") or (provider or {}).get("default_model")
    key_set = not key_env or bool(os.environ.get(key_env))
    return {
        "provider": name,
        "model": model or "",
        "key_set": key_set,
        "configured": bool(provider and model and key_set),
        "custom_endpoint": bool(os.environ.get("RECONMIND_BASE_URL", "").strip()),
        "providers": list(llm.PROVIDERS),
    }


def _mapper():
    direc = attack_mapper.model_dir()
    files = all(os.path.isfile(os.path.join(direc, name))
                for name in attack_mapper.REQUIRED_FILES)
    packages = importlib.util.find_spec("torch") is not None and (
        importlib.util.find_spec("transformers") is not None)
    return {
        "status": "files present" if files and packages else (
            "dependencies missing" if files else "model missing"),
        "folder": os.path.basename(direc),
        "files_present": files,
        "dependencies_present": packages,
        # A full model load is deliberately not performed by System check.
        "loaded": False,
    }


def snapshot(report_dir):
    """Collect statuses and public configuration, with no side effects."""
    _load_dotenv()
    folder = os.path.abspath(report_dir)
    probe = folder
    while not os.path.exists(probe):
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent
    try:
        disk = shutil.disk_usage(probe)
        free_bytes = disk.free
    except OSError:
        free_bytes = None
    return {
        "tools": _tools(),
        "ai": _ai(),
        "mapper": _mapper(),
        "nvd": {"key_set": bool(os.environ.get("NVD_API_KEY"))},
        "safety": {"allowlist": list(config.ALLOWLIST),
                   "denylist": list(config.DENYLIST), "locked": True},
        "storage": {"reports_folder": os.path.basename(folder),
                    "free_bytes": free_bytes},
    }
