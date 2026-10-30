"""
Offline tests for the ReconMind provider layer (reconmind/agent/llm.py).

A scripted fake OpenAI client drives the real ReAct loop through the
translator, so these run with no API key, no network and no SDK installed:

    python3 -m unittest discover -s tests -v
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace as NS
from unittest import mock

from reconmind.agent import brain, llm, tools as toolmod
from reconmind.agent.__main__ import main

TARGET = "10.10.1.100"

FAKE_SCAN = {
    "target": TARGET, "status": "ok",
    "ports": [
        {"port": 21, "protocol": "tcp", "service": "ftp", "product": "vsftpd", "version": "2.3.4"},
    ],
}
FAKE_EXPLOITS = [{"title": "vsftpd 2.3.4 - Backdoor Command Execution", "edb_id": "49757"}]


def call(name, arguments, call_id):
    if not isinstance(arguments, str):
        arguments = json.dumps(arguments)
    return NS(id=call_id, type="function", function=NS(name=name, arguments=arguments))


def turn(content=None, calls=None, finish=None):
    finish = finish or ("tool_calls" if calls else "stop")
    return NS(choices=[NS(message=NS(content=content, tool_calls=calls), finish_reason=finish)])


class FakeOpenAI:
    """Plays back fixed Chat Completions responses and records each request."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []
        self.chat = NS(completions=NS(create=self._create))

    def _create(self, **kwargs):
        self.requests.append(json.loads(json.dumps(kwargs)))  # deep copy, and proves it is JSON
        return self.responses.pop(0)


def fake_scan():
    return dict(FAKE_SCAN, ports=[dict(p) for p in FAKE_SCAN["ports"]])


class TmpDirTest(unittest.TestCase):
    """Runs each test in an empty directory with an empty environment."""

    def setUp(self):
        self._cwd = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        os.chdir(self._tmp.name)  # logs/, reports/ land here, and no .env is read
        self._env = mock.patch.dict(os.environ, {}, clear=True)
        self._env.start()

    def tearDown(self):
        self._env.stop()
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def run_loop(self, responses):
        fake = FakeOpenAI(responses)
        with mock.patch.object(toolmod, "run_nmap", return_value=fake_scan()), \
             mock.patch.object(toolmod, "search_exploits", return_value=FAKE_EXPLOITS):
            tb, summary = brain.run_agent(
                TARGET, client=llm.OpenAICompatClient(fake), model="fake", trace=False)
        return fake, tb, summary


class TranslatorTests(TmpDirTest):

    def test_full_react_loop_through_translator(self):
        fake, tb, summary = self.run_loop([
            turn("Start with a service scan.", [call("nmap_scan", {"target": TARGET}, "t1")]),
            turn(None, [call("exploit_lookup", {"port": 21, "product": "vsftpd", "version": "2.3.4"}, "t2")]),
            turn("### Key findings\n1. vsftpd 2.3.4 backdoor on 21/tcp"),
        ])

        self.assertEqual([c[0] for c in tb.calls], ["nmap_scan", "exploit_lookup"])
        self.assertIn("vsftpd 2.3.4 backdoor", summary)
        self.assertEqual(tb.scan["ports"][0]["exploits"], FAKE_EXPLOITS)

        first = fake.requests[0]
        self.assertEqual(first["model"], "fake")
        self.assertEqual(first["messages"][0]["role"], "system")
        self.assertEqual(first["messages"][1]["role"], "user")
        by_name = {t["function"]["name"]: t for t in first["tools"]}
        for spec in toolmod.TOOL_SPECS:
            self.assertEqual(by_name[spec["name"]]["type"], "function")
            self.assertEqual(by_name[spec["name"]]["function"]["parameters"], spec["input_schema"])

        last = fake.requests[2]["messages"]
        assistant, tool = last[-2], last[-1]
        self.assertEqual(assistant["role"], "assistant")
        self.assertEqual(assistant["tool_calls"][0]["id"], "t2")
        self.assertEqual(json.loads(assistant["tool_calls"][0]["function"]["arguments"]),
                         {"port": 21, "product": "vsftpd", "version": "2.3.4"})
        self.assertEqual(tool["role"], "tool")
        self.assertEqual(tool["tool_call_id"], "t2")
        self.assertNotIn("error", json.loads(tool["content"]))

    def test_malformed_arguments_do_not_crash_the_loop(self):
        fake, tb, summary = self.run_loop([
            turn(None, [call("nmap_scan", "{not json", "t1")]),
            turn(None, [call("nmap_scan", "[1, 2]", "t2")]),
            turn("Could not form a valid request, stopping."),
        ])
        self.assertIn("stopping", summary)
        self.assertEqual(len(tb.calls), 2)

        for request, call_id in ((fake.requests[1], "t1"), (fake.requests[2], "t2")):
            tool = request["messages"][-1]
            self.assertEqual(tool["tool_call_id"], call_id)
            self.assertIn("_invalid_arguments", json.loads(tool["content"])["error"])
        # the history sent back never carries the broken JSON
        for msg in fake.requests[2]["messages"]:
            for c in msg.get("tool_calls", []):
                json.loads(c["function"]["arguments"])

    def test_tool_calls_with_finish_reason_stop_still_act(self):
        _, tb, _ = self.run_loop([
            turn(None, [call("nmap_scan", {"target": TARGET}, "t1")], finish="stop"),
            turn("done"),
        ])
        self.assertEqual([c[0] for c in tb.calls], ["nmap_scan"])

    def test_empty_choices_end_the_run(self):
        _, tb, summary = self.run_loop([NS(choices=[])])
        self.assertEqual(tb.calls, [])
        self.assertIn("no answer", summary)

    def test_brain_refuses_to_pick_a_model(self):
        with self.assertRaises(ValueError):
            brain.run_agent(TARGET, client=llm.OpenAICompatClient(FakeOpenAI([])), trace=False)


class ConfigTests(TmpDirTest):

    def test_default_is_openrouter_free(self):
        os.environ["OPENROUTER_API_KEY"] = "k"
        cfg = llm.load_config()
        self.assertEqual(cfg.name, "openrouter")
        self.assertEqual(cfg.model, "openrouter/free")
        self.assertEqual(cfg.base_url, "https://openrouter.ai/api/v1")
        self.assertEqual(cfg.api_key, "k")

    def test_model_env_overrides_default(self):
        os.environ.update(OPENROUTER_API_KEY="k", RECONMIND_MODEL="some/model")
        self.assertEqual(llm.load_config().model, "some/model")

    def test_huggingface_preset(self):
        os.environ.update(RECONMIND_PROVIDER="huggingface", HF_TOKEN="hf", RECONMIND_MODEL="m")
        cfg = llm.load_config()
        self.assertEqual(cfg.base_url, "https://router.huggingface.co/v1")
        self.assertEqual(cfg.api_key, "hf")

    def test_ollama_needs_no_key(self):
        cfg = llm.load_config(provider="ollama", model="llama3.1")
        self.assertEqual(cfg.base_url, "http://localhost:11434/v1")
        self.assertTrue(cfg.api_key)

    def test_anthropic_uses_native_sdk_untranslated(self):
        os.environ["ANTHROPIC_API_KEY"] = "a"
        cfg = llm.load_config(provider="anthropic", model="m")
        self.assertEqual(cfg.kind, "anthropic")
        fake_sdk = NS(Anthropic=mock.Mock(return_value="native-client"))
        with mock.patch.dict(sys.modules, {"anthropic": fake_sdk}):
            self.assertEqual(llm.make_client(cfg), "native-client")
        fake_sdk.Anthropic.assert_called_once_with(api_key="a")

    def test_openai_kind_is_wrapped_in_translator(self):
        fake_sdk = NS(OpenAI=mock.Mock(return_value=FakeOpenAI([])))
        cfg = llm.load_config(provider="ollama", model="m")
        with mock.patch.dict(sys.modules, {"openai": fake_sdk}):
            client = llm.make_client(cfg)
        self.assertIsInstance(client, llm.OpenAICompatClient)
        fake_sdk.OpenAI.assert_called_once_with(base_url=cfg.base_url, api_key=cfg.api_key)

    def test_custom_base_url(self):
        os.environ.update(RECONMIND_BASE_URL="http://lab:8000/v1", RECONMIND_MODEL="m")
        cfg = llm.load_config(provider="ollama")
        self.assertEqual(cfg.base_url, "http://lab:8000/v1")

    def test_unknown_provider(self):
        with self.assertRaises(llm.ConfigError) as ctx:
            llm.load_config(provider="nope", model="m")
        self.assertIn("openrouter", str(ctx.exception))

    def test_presets_without_default_model_require_one(self):
        os.environ.update(ANTHROPIC_API_KEY="a", HF_TOKEN="h")
        for name in ("anthropic", "huggingface", "ollama"):
            with self.assertRaises(llm.ConfigError) as ctx:
                llm.load_config(provider=name)
            self.assertIn("RECONMIND_MODEL", str(ctx.exception))

    def test_custom_url_never_inherits_free_default(self):
        os.environ.update(OPENROUTER_API_KEY="k", RECONMIND_BASE_URL="http://lab:8000/v1")
        with self.assertRaises(llm.ConfigError):
            llm.load_config()

    def test_missing_key_names_the_setting(self):
        with self.assertRaises(llm.ConfigError) as ctx:
            llm.load_config(provider="huggingface", model="m")
        self.assertIn("HF_TOKEN", str(ctx.exception))


class RunnerFlagTests(TmpDirTest):

    def run_main(self, *args):
        out = io.StringIO()
        fake_sdk = NS(OpenAI=mock.Mock(return_value=FakeOpenAI([])))
        with mock.patch.object(brain, "run_agent",
                               return_value=(toolmod.ToolBox(TARGET), "summary")) as agent, \
             mock.patch.dict(sys.modules, {"openai": fake_sdk}), \
             contextlib.redirect_stdout(out):
            code = main(["reconmind.agent"] + list(args))
        return code, agent, out.getvalue()

    def test_flags_pick_provider_and_model(self):
        code, agent, out = self.run_main("--provider", "ollama", "--model", "llama3.1", TARGET)
        self.assertEqual(code, 0)
        kwargs = agent.call_args.kwargs
        self.assertEqual(kwargs["model"], "llama3.1")
        self.assertIsInstance(kwargs["client"], llm.OpenAICompatClient)
        self.assertIn("provider=ollama", out)
        self.assertIn("model=llama3.1", out)

    def test_model_flag_overrides_env(self):
        os.environ.update(OPENROUTER_API_KEY="k", RECONMIND_MODEL="from-env")
        code, agent, out = self.run_main("--model", "from-flag", TARGET)
        self.assertEqual(code, 0)
        self.assertEqual(agent.call_args.kwargs["model"], "from-flag")
        self.assertNotIn("RECONMIND_PROVIDER", os.environ)  # flags never leak into env

    def test_provider_without_model_stops(self):
        os.environ["HF_TOKEN"] = "h"
        code, agent, out = self.run_main("--provider", "huggingface", TARGET)
        self.assertEqual(code, 1)
        agent.assert_not_called()
        self.assertIn("RECONMIND_MODEL", out)

    def test_missing_key_stops(self):
        code, agent, out = self.run_main(TARGET)
        self.assertEqual(code, 1)
        agent.assert_not_called()
        self.assertIn("OPENROUTER_API_KEY", out)

    def test_gate_still_runs_first(self):
        code, agent, out = self.run_main("--provider", "nope", "10.0.3.15")
        self.assertEqual(code, 2)
        agent.assert_not_called()


if __name__ == "__main__":
    unittest.main()
