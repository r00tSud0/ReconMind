"""Settings and key privacy tests: offline; no real provider call or scan."""
import os
import stat
import tempfile
import unittest
from unittest import mock

try:
    from fastapi.testclient import TestClient
except ImportError:
    raise unittest.SkipTest("FastAPI test dependencies missing")

from reconmind.agent import llm
from reconmind.web import settings
from reconmind.web.server import create_app


def body(**kw):
    d = {"provider": "openrouter", "model": "openrouter/free",
         "api_key": "", "nvd_key": ""}
    d.update(kw)
    return d


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.prev = os.getcwd()
        os.chdir(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {}, clear=True)
        self.env.start()
        self.path = os.path.join(self.tmp.name, ".env")

    def tearDown(self):
        self.env.stop()
        os.chdir(self.prev)
        self.tmp.cleanup()

    def test_save_permissions_preserves_nonowned_and_loads_for_next_scan(self):
        with open(self.path, "w") as f:
            f.write("# comment\nCUSTOM=kept\nRECONMIND_PROVIDER=anthropic\n"
                    "RECONMIND_PROVIDER=duplicate\nTAIL=last")
        os.chmod(self.path, 0o644)
        settings.save(body(api_key="private1", nvd_key="private2"), self.tmp.name)
        with open(self.path) as f:
            text = f.read()
        self.assertIn("# comment\nCUSTOM=kept\n", text)
        self.assertIn("TAIL=last\n", text)
        self.assertEqual(text.count("RECONMIND_PROVIDER="), 1)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        self.assertEqual(llm.load_config().api_key, "private1")
        self.assertEqual(os.environ["NVD_API_KEY"], "private2")

    def test_blank_keys_keep_and_clear_is_explicit(self):
        settings.save(body(api_key="first", nvd_key="second"), self.tmp.name)
        settings.save(body(model="openrouter/model"), self.tmp.name)
        self.assertEqual(os.environ["OPENROUTER_API_KEY"], "first")
        self.assertEqual(os.environ["NVD_API_KEY"], "second")
        settings.save(body(clear_api_key=True, clear_nvd_key=True), self.tmp.name)
        self.assertNotIn("OPENROUTER_API_KEY", os.environ)
        self.assertNotIn("NVD_API_KEY", os.environ)

    def test_invalid_key_injection_not_saved(self):
        for value in ("one\nEXTRA=bad", "two words", '"quoted"'):
            with self.subTest(value=value):
                with self.assertRaises(settings.SettingsError):
                    settings.save(body(api_key=value), self.tmp.name)
        self.assertFalse(os.path.exists(self.path))

    def test_provider_switch_keeps_other_provider_key(self):
        settings.save(body(api_key="old"), self.tmp.name)
        settings.save(body(provider="anthropic", model="model-x", api_key="new"),
                      self.tmp.name)
        with open(self.path) as f:
            data = f.read()
        self.assertIn("OPENROUTER_API_KEY=old", data)
        self.assertIn("ANTHROPIC_API_KEY=new", data)

    def test_symlink_rejected(self):
        target = os.path.join(self.tmp.name, "outside")
        with open(target, "w") as f: f.write("keep")
        os.symlink(target, self.path)
        with self.assertRaises(settings.SettingsError):
            settings.save(body(), self.tmp.name)
        with open(target) as f: self.assertEqual(f.read(), "keep")

    def test_test_connection_one_bounded_request(self):
        class Reply:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, n): return b"{}"
        class Opener:
            def __init__(self): self.calls = []
            def open(self, req, timeout):
                self.calls.append((req, timeout))
                return Reply()
        opener = Opener()
        with mock.patch.object(settings.urllib.request, "build_opener", return_value=opener):
            result = settings.test_connection(body(api_key="secret"), self.tmp.name)
        self.assertTrue(result["reachable"])
        self.assertEqual(len(opener.calls), 1)
        self.assertEqual(opener.calls[0][1], 8)
        self.assertNotIn("secret", str(result))
        self.assertFalse(os.path.exists(self.path))

    def test_custom_endpoint_cannot_receive_credentials_via_web(self):
        with mock.patch.dict(os.environ, {"RECONMIND_BASE_URL": "http://example.test"}):
            with mock.patch.object(settings.urllib.request, "build_opener") as call:
                with self.assertRaises(settings.SettingsError):
                    settings.test_connection(body(api_key="secret"), self.tmp.name)
                call.assert_not_called()

    def test_web_routes_guard_and_secret_redaction(self):
        app = create_app(report_dir=os.path.join(self.tmp.name, "reports"), port=8777)
        client = TestClient(app, base_url="http://127.0.0.1:8777")
        self.assertEqual(client.post("/api/system/save", json=body()).status_code, 403)
        response = client.post("/api/system/save", json=body(api_key="private"))
        self.assertEqual(response.status_code, 403)
        response = client.post("/api/system/save", json=body(api_key="private"),
                               headers={"X-ReconMind": "1"})
        self.assertEqual(response.status_code, 200)
        with mock.patch("reconmind.web.system._tools", return_value=[]):
            data = client.get("/api/system").json()
        self.assertTrue(data["ai"]["key_set"])
        self.assertNotIn("private", str(data))
        self.assertNotIn("private", str(response.json()))
        self.assertEqual(client.post("/api/system/save", json=body(model="bad model"),
                                     headers={"X-ReconMind": "1"}).status_code, 400)


if __name__ == "__main__":
    unittest.main()
