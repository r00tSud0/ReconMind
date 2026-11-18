"""
Read-only System check for ReconMind's localhost frontend.

Nothing here starts a scan, installs tools, changes configuration, calls an
LLM, or loads model weights. It checks the same executable names as the engine
and never returns API key values.
"""
import importlib.util
import os
import shutil

from reconmind.agent import llm
from reconmind.agent.__main__ import _load_dotenv
from reconmind.ai import attack_mapper
from reconmind.core import config
from reconmind.setup import detect
from reconmind.tools import httpx_scan  # noqa: F401  (tests patch it here)

# Tool detection is shared with the setup wizard, so both use the engine's
# own lookup rules. Installing or repairing tools belongs to the wizard only.
TOOLS = detect.TOOLS
_path = detect.tool_path
_version = detect.tool_version


def _tools():
    return detect.tools()


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
