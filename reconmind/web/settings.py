"""Local System settings: atomic 0600 .env updates; a bounded provider probe.
No scan execution, scope changes, credential reflection, or live agent actions.
"""
import json
import os
import re
import tempfile
import threading
import urllib.error
import urllib.request
from reconmind.agent import llm
from reconmind.agent.__main__ import _load_dotenv

_LOCK = threading.Lock()
MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,179}\Z")
TIMEOUT = 8


class SettingsError(ValueError):
    pass


def _text(value, name, limit):
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise SettingsError(name + " contains invalid characters.")
    return value.strip()


def validate(body):
    if not isinstance(body, dict):
        raise SettingsError("Settings must be an object.")
    provider = body.get("provider")
    if not isinstance(provider, str) or provider not in llm.PROVIDERS:
        raise SettingsError("Choose a supported AI provider.")
    model = _text(body.get("model", ""), "Model", 180)
    model = model or (llm.PROVIDERS[provider]["default_model"] or "")
    if not MODEL.fullmatch(model):
        raise SettingsError("Enter a valid model name for this provider.")
    key = _text(body.get("api_key", ""), "API key", 8192)
    nvd = _text(body.get("nvd_key", ""), "NVD key", 8192)
    for value in (key, nvd):
        if value and (value.startswith(('"', "'")) or value.endswith(('"', "'"))
                      or any(c.isspace() for c in value)):
            raise SettingsError("Keys must have no spaces or boundary quotes.")
    for name in ("clear_api_key", "clear_nvd_key"):
        if not isinstance(body.get(name, False), bool):
            raise SettingsError("Remove-key options must be true or false.")
    if (key and body.get("clear_api_key")) or (nvd and body.get("clear_nvd_key")):
        raise SettingsError("Choose a new key or remove the old key, not both.")
    if key and llm.PROVIDERS[provider]["api_key_env"] is None:
        raise SettingsError("This provider does not use an API key.")
    return provider, model, key, nvd


def save(body, root):
    provider, model, key, nvd = validate(body)
    updates = {"RECONMIND_PROVIDER": provider, "RECONMIND_MODEL": model}
    keyvar = llm.PROVIDERS[provider]["api_key_env"]
    if keyvar and (key or body.get("clear_api_key")):
        updates[keyvar] = key or None
    if nvd or body.get("clear_nvd_key"):
        updates["NVD_API_KEY"] = nvd or None
    envpath = os.path.join(os.path.abspath(root), ".env")
    with _LOCK:
        if os.path.islink(envpath):
            raise SettingsError("The configuration file cannot be a symlink.")
        try:
            with open(envpath, encoding="utf-8", newline="") as src:
                lines = src.readlines()
        except FileNotFoundError:
            lines = []
        except (OSError, UnicodeError):
            raise SettingsError("Could not read the configuration file.") from None
        out = []
        seen = set()
        for line in lines:
            name = line.split("=", 1)[0].strip() if "=" in line else ""
            if name in updates:
                if name not in seen and updates[name] is not None:
                    out.append(name + "=" + updates[name] + "\n")
                seen.add(name)
            else:
                out.append(line)
        for name, value in updates.items():
            if name not in seen and value is not None:
                if out and not out[-1].endswith("\n"):
                    out.append("\n")
                out.append(name + "=" + value + "\n")
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(envpath), prefix=".reconmind-env-")
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as dst:
                os.fchmod(dst.fileno(), 0o600)
                dst.write("".join(out))
                dst.flush()
                os.fsync(dst.fileno())
            os.replace(tmp, envpath)
            tmp = None
            os.chmod(envpath, 0o600)
        except OSError:
            raise SettingsError("Could not save settings. Check directory permissions.") from None
        finally:
            if tmp and os.path.exists(tmp):
                os.unlink(tmp)
        # Refresh in-process values: _load_dotenv uses setdefault.
        # Scan child processes then inherit the updated values.
        for name, value in updates.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    return {"saved": True}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def test_connection(body, root):
    """One explicit request only; never return a response body or credentials."""
    provider, model, key, _ = validate(body)
    _load_dotenv(os.path.join(root, ".env"))
    if os.environ.get("RECONMIND_BASE_URL", "").strip():
        raise SettingsError("Custom AI endpoints must be tested through the CLI.")
    preset = llm.PROVIDERS[provider]
    if preset["api_key_env"]:
        secret = key or os.environ.get(preset["api_key_env"], "")
        if not secret:
            raise SettingsError("Enter an API key or save one first.")
    else:
        secret = None
    if provider == "anthropic":
        url = "https://api.anthropic.com/v1/messages"
        payload = {"model": model, "max_tokens": 8,
                   "messages": [{"role": "user", "content": "Reply OK."}]}
        headers = {"x-api-key": secret, "anthropic-version": "2023-06-01"}
    else:
        url = preset["base_url"].rstrip("/") + "/chat/completions"
        payload = {"model": model, "max_tokens": 8,
                   "messages": [{"role": "user", "content": "Reply OK."}]}
        headers = {"Authorization": "Bearer " + (secret or llm.NO_KEY_PLACEHOLDER)}
    headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                     headers=headers, method="POST")
    try:
        with urllib.request.build_opener(_NoRedirect).open(request, timeout=TIMEOUT) as response:
            response.read(512)
        return {"reachable": True, "message": "Reachable. The provider accepted the test request."}
    except urllib.error.HTTPError as exc:
        return {"reachable": False,
                "message": "The provider returned HTTP " + str(exc.code) + ". Check the model or key."}
    except (urllib.error.URLError, TimeoutError, OSError):
        return {"reachable": False, "message": "Connection failed or timed out."}
