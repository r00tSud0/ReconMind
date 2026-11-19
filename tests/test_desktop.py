"""Desktop launcher tests: which window opens, and the first page. No real windows."""
import unittest
from unittest import mock

from reconmind import desktop

URL = "http://127.0.0.1:8000/#/new"


class Proc:
    def wait(self):
        return 0


class WindowTests(unittest.TestCase):
    def test_native_window_when_available(self):
        webview = mock.Mock()
        kind, wait = desktop.open_window(URL, webview_module=webview, native=True)
        self.assertEqual(kind, "window")
        webview.create_window.assert_called_once()
        self.assertEqual(webview.create_window.call_args[0][:2], ("ReconMind", URL))
        wait()
        webview.start.assert_called_once()

    def test_native_failure_at_start_falls_back_to_app_window(self):
        webview = mock.Mock()
        webview.start.side_effect = RuntimeError("no GTK")
        calls = []
        kind, wait = desktop.open_window(
            URL, webview_module=webview, native=True,
            which=lambda name: "/usr/bin/chromium" if name == "chromium" else None,
            popen=lambda argv, **kw: calls.append(argv) or Proc())
        wait()
        self.assertEqual(calls[0][0], "/usr/bin/chromium")
        self.assertIn("--app=" + URL, calls[0])

    def test_app_window_uses_its_own_profile(self):
        calls = []
        kind, wait = desktop.open_window(
            URL, native=False, which=lambda name: "/usr/bin/" + name,
            popen=lambda argv, **kw: calls.append(argv) or Proc())
        self.assertEqual(kind, "app")
        self.assertTrue(any(a.startswith("--user-data-dir=") and "reconmind" in a for a in calls[0]))

    def test_default_browser_last(self):
        opened = []
        kind, wait = desktop.open_window(URL, native=False, which=lambda name: None,
                                         browser_open=opened.append)
        self.assertEqual((kind, wait, opened), ("browser", None, [URL]))

    def test_no_display_means_no_native_window(self):
        self.assertFalse(desktop.native_window_available(env={}))


class PageTests(unittest.TestCase):
    def test_setup_first_when_something_is_missing(self):
        missing = {"tools": [{"status": "ready"}, {"status": "missing"}],
                   "mapper": {"files_present": True}}
        ready = {"tools": [{"status": "ready"}], "mapper": {"files_present": True}}
        no_model = {"tools": [{"status": "ready"}], "mapper": {"files_present": False}}
        for data, page in ((missing, "#/setup"), (ready, "#/new"), (no_model, "#/setup")):
            with mock.patch.object(desktop, "_get", return_value=data):
                self.assertEqual(desktop.first_page(8000), page)
        with mock.patch.object(desktop, "_get", side_effect=OSError):
            self.assertEqual(desktop.first_page(8000), "#/new")

    def test_reuses_a_running_reconmind_only(self):
        answers = {8000: {"something": "else"}, 8001: {"presets": [], "allowlist": []}}

        def fake(port, path, timeout=1.5):
            if port not in answers:
                raise OSError("closed")
            return answers[port]
        with mock.patch.object(desktop, "_get", side_effect=fake):
            self.assertEqual(desktop.running_reconmind(range(8000, 8003)), 8001)
            self.assertIsNone(desktop.running_reconmind(range(8000, 8001)))


if __name__ == "__main__":
    unittest.main()
