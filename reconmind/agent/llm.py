"""
ReconMind LLM providers.

The brain speaks the Anthropic Messages format: it calls
client.messages.create(...) and reads back content blocks and a stop_reason.
This module hands it a client for whichever provider is configured:

  anthropic     the native Anthropic SDK, used as-is (no translation)
  openrouter,   any OpenAI-compatible Chat Completions endpoint, wrapped in
  huggingface,  OpenAICompatClient, which translates each request to the
  ollama        OpenAI format and each response back to Anthropic blocks

Switching provider is a setting (.env or a CLI flag), not a code change.
Adding a provider is one entry in PROVIDERS. Only openrouter has a default
model, and it is the zero-cost "openrouter/free". Every other provider needs
RECONMIND_MODEL, so a paid model is never picked silently.
"""

import json
import os
from dataclasses import dataclass, field

PROVIDERS = {
    "openrouter": {
        "kind": "openai",
        "base_url": "https://openrouter.ai/api/v1",
        "api_key_env": "OPENROUTER_API_KEY",
        "default_model": "openrouter/free",
    },
    "anthropic": {
        "kind": "anthropic",
        "base_url": None,
        "api_key_env": "ANTHROPIC_API_KEY",
        "default_model": None,
    },
    "huggingface": {
        "kind": "openai",
        "base_url": "https://router.huggingface.co/v1",
        "api_key_env": "HF_TOKEN",
        "default_model": None,
    },
    "ollama": {
        "kind": "openai",
        "base_url": "http://localhost:11434/v1",
        "api_key_env": None,
        "default_model": None,
    },
}
DEFAULT_PROVIDER = "openrouter"
NO_KEY_PLACEHOLDER = "no-key"  # the openai SDK refuses an empty key


class ConfigError(ValueError):
    """Provider settings are missing or wrong. The message says what to set."""


@dataclass
class ProviderConfig:
    name: str
    kind: str
    base_url: str
    api_key_env: str
    api_key: str
    model: str


def load_config(provider=None, model=None):
    """
    Resolve provider settings. Precedence: argument (CLI flag), then
    environment (.env), then the preset. Raises ConfigError with a message
    naming the setting to fix.
    """
    name = (provider or os.environ.get("RECONMIND_PROVIDER") or DEFAULT_PROVIDER).strip().lower()
    preset = PROVIDERS.get(name)
    if preset is None:
        raise ConfigError("Unknown provider '{n}'. Choose one of: {p}.".format(
            n=name, p=", ".join(sorted(PROVIDERS))))

    # A custom endpoint never inherits the preset's default model, so
    # "openrouter/free" is never sent to some other server.
    custom_url = os.environ.get("RECONMIND_BASE_URL", "").strip()
    base_url = custom_url or preset["base_url"]
    default_model = None if custom_url else preset["default_model"]

    model = model or os.environ.get("RECONMIND_MODEL") or default_model
    if not model:
        raise ConfigError(
            "Provider '{n}' has no default model. Set RECONMIND_MODEL in .env "
            "or pass --model.".format(n=name))

    key_env = preset["api_key_env"]
    api_key = os.environ.get(key_env, "").strip() if key_env else NO_KEY_PLACEHOLDER
    if not api_key:
        raise ConfigError(
            "{k} is not set. Put it in .env in the repo root:\n    {k}=...".format(k=key_env))

    return ProviderConfig(name, preset["kind"], base_url, key_env, api_key, model)


def make_client(config):
    """Build the client run_agent expects. SDKs are imported only when used."""
    if config.kind == "anthropic":
        import anthropic
        kwargs = {"api_key": config.api_key}
        if config.base_url:
            kwargs["base_url"] = config.base_url
        return anthropic.Anthropic(**kwargs)

    import openai
    return OpenAICompatClient(openai.OpenAI(base_url=config.base_url, api_key=config.api_key))


# ---- Anthropic-shaped response blocks -----------------------------------

@dataclass
class TextBlock:
    text: str
    type: str = "text"


@dataclass
class ToolUseBlock:
    id: str
    name: str
    input: dict = field(default_factory=dict)
    type: str = "tool_use"


@dataclass
class Response:
    content: list
    stop_reason: str


# ---- translator ----------------------------------------------------------

class OpenAICompatClient:
    """
    Looks like anthropic.Anthropic to the brain (client.messages.create) but
    talks to an OpenAI-compatible client (client.chat.completions.create).
    """

    def __init__(self, openai_client):
        self._client = openai_client
        self.messages = self  # so brain's client.messages.create(...) lands here

    def create(self, model, messages, max_tokens=None, system=None, tools=None, **_ignored):
        request = {"model": model, "messages": to_openai_messages(system, messages)}
        if tools:
            request["tools"] = to_openai_tools(tools)
        if max_tokens:
            request["max_tokens"] = max_tokens
        return from_openai_response(self._client.chat.completions.create(**request))


def _get(block, key, default=None):
    """Read a field from a block that may be a dict or an object."""
    if isinstance(block, dict):
        return block.get(key, default)
    return getattr(block, key, default)


def to_openai_tools(tools):
    return [{
        "type": "function",
        "function": {
            "name": t["name"],
            "description": t.get("description", ""),
            "parameters": t.get("input_schema", {"type": "object", "properties": {}}),
        },
    } for t in tools]


def to_openai_messages(system, messages):
    out = [{"role": "system", "content": system}] if system else []
    for msg in messages:
        role, content = msg["role"], msg["content"]
        if isinstance(content, str):
            out.append({"role": role, "content": content})
        elif role == "assistant":
            out.append(_assistant_message(content))
        else:
            out.extend(_user_messages(content))
    return out


def _assistant_message(blocks):
    text = "\n".join(_get(b, "text", "") for b in blocks if _get(b, "type") == "text").strip()
    calls = [{
        "id": _get(b, "id"),
        "type": "function",
        "function": {"name": _get(b, "name"), "arguments": json.dumps(_get(b, "input") or {})},
    } for b in blocks if _get(b, "type") == "tool_use"]
    message = {"role": "assistant", "content": text or None}
    if calls:
        message["tool_calls"] = calls
    return message


def _user_messages(blocks):
    # Tool results become one "tool" message each, right after the assistant
    # turn that asked for them, which is the order OpenAI requires.
    out, texts = [], []
    for b in blocks:
        kind = _get(b, "type")
        if kind == "tool_result":
            content = _get(b, "content", "")
            if not isinstance(content, str):
                content = json.dumps(content)
            out.append({"role": "tool", "tool_call_id": _get(b, "tool_use_id"), "content": content})
        elif kind == "text":
            texts.append(_get(b, "text", ""))
    if texts:
        out.append({"role": "user", "content": "\n".join(texts)})
    return out


def _parse_arguments(raw):
    """
    Tool arguments arrive as a JSON string the model wrote, and free models
    get it wrong. Never raise: a bad value becomes an argument ToolBox rejects,
    so the model sees an error observation and can retry.
    """
    if isinstance(raw, dict):
        return raw
    try:
        args = json.loads(raw) if raw else {}
    except (TypeError, ValueError):
        args = None
    if isinstance(args, dict):
        return args
    return {"_invalid_arguments": str(raw)[:200]}


def from_openai_response(response):
    choices = _get(response, "choices") or []
    if not choices:
        return Response([TextBlock("The model provider returned no answer.")], "end_turn")

    choice = choices[0]
    message = _get(choice, "message")
    content = []

    text = _get(message, "content")
    if isinstance(text, str) and text.strip():
        content.append(TextBlock(text))

    for n, call in enumerate(_get(message, "tool_calls") or [], 1):
        fn = _get(call, "function")
        content.append(ToolUseBlock(
            id=_get(call, "id") or "call_{n}".format(n=n),
            name=_get(fn, "name") or "",
            input=_parse_arguments(_get(fn, "arguments")),
        ))

    # Some providers send finish_reason "stop" alongside tool calls, so the
    # presence of calls decides.
    if any(b.type == "tool_use" for b in content):
        stop = "tool_use"
    elif _get(choice, "finish_reason") == "length":
        stop = "max_tokens"
    else:
        stop = "end_turn"
    return Response(content, stop)
