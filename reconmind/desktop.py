"""
ReconMind desktop launcher.

    python3 -m reconmind.desktop        (the menu entry and the `reconmind` command run this)

Starts the local server on 127.0.0.1 and opens ReconMind in its own window:

1. pywebview (a native window) when it and its GTK WebKit libraries are installed,
2. else a Chromium style browser in app mode (its own window, no tabs or address bar),
3. else the default browser.

If ReconMind is already running, the window opens on that server instead of a
second one. The first page is Setup when a tool or the model is missing, so a
fresh install lands where it can be finished. Closing the window ends the app,
unless a scan is still running: then the server keeps going until the scan
ends, so no scan is ever cut off, and the window can be opened again.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser

HOST = "127.0.0.1"
PORTS = range(8000, 8011)
TITLE = "ReconMind"
SIZE = (1360, 900)
MIN_SIZE = (900, 640)
BROWSERS = ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
            "brave-browser", "microsoft-edge")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROFILE = os.path.join(os.path.expanduser("~"), ".local", "share", "reconmind", "window-profile")


def _get(port, path, timeout=1.5):
    request = urllib.request.Request("http://{h}:{p}{path}".format(h=HOST, p=port, path=path),
                                     headers={"Host": "{h}:{p}".format(h=HOST, p=port)})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=timeout) as response:
        return json.loads(response.read(1_000_000).decode("utf-8"))


def running_reconmind(ports=PORTS):
    """The port of a ReconMind server already running here, or None."""
    for port in ports:
        try:
            data = _get(port, "/api/options")
        except Exception:
            continue
        if isinstance(data, dict) and "presets" in data and "allowlist" in data:
            return port
    return None


def free_port(ports=PORTS):
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((HOST, port))
            except OSError:
                continue
            return port
    raise RuntimeError("No free port between {a} and {b} on {h}.".format(
        a=ports[0], b=ports[-1], h=HOST))


def first_page(port):
    """Setup when anything is missing, otherwise New scan."""
    try:
        data = _get(port, "/api/system", timeout=20)
        tools = data.get("tools") or []
        mapper = data.get("mapper") or {}
        ready = all(t.get("status") == "ready" for t in tools) and mapper.get("files_present")
        return "#/new" if ready else "#/setup"
    except Exception:
        return "#/new"


class Server:
    """The app's server in this process, on its own thread."""

    def __init__(self, port):
        import uvicorn
        from reconmind.web.server import create_app
        self.port = port
        self.app = create_app(port=port)
        config = uvicorn.Config(self.app, host=HOST, port=port, log_level="warning",
                                server_header=False)
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True, name="reconmind-web")

    def start(self, wait=15.0):
        self.thread.start()
        deadline = time.time() + wait
        while time.time() < deadline:
            if self.server.started:
                return
            time.sleep(0.05)
        raise RuntimeError("The ReconMind server did not start.")

    def busy(self):
        jobs = self.app.state.jobs
        setup = self.app.state.setup
        return bool(jobs.running_id) or setup.running()

    def stop(self):
        self.server.should_exit = True
        self.thread.join(10)


def native_window_available(env=os.environ):
    """True when pywebview can open a GTK WebKit window here: a display, the
    GTK bindings and WebKit2. Checked up front, because pywebview only fails
    when its window starts."""
    if not (env.get("DISPLAY") or env.get("WAYLAND_DISPLAY")):
        return False
    try:
        import gi
        gi.require_version("Gtk", "3.0")
        for version in ("4.1", "4.0"):
            try:
                gi.require_version("WebKit2", version)
                break
            except ValueError:
                continue
        else:
            return False
        from gi.repository import Gtk, WebKit2  # noqa: F401
        import webview  # noqa: F401  (pywebview)
        return True
    except Exception:
        return False


def open_browser_window(url, which=shutil.which, popen=subprocess.Popen,
                        browser_open=webbrowser.open):
    """A Chromium style app window, else the default browser."""
    for name in BROWSERS:
        binary = which(name)
        if binary:
            os.makedirs(PROFILE, mode=0o700, exist_ok=True)
            proc = popen([binary, "--app=" + url, "--user-data-dir=" + PROFILE,
                          "--window-size={w},{h}".format(w=SIZE[0], h=SIZE[1]),
                          "--no-first-run", "--no-default-browser-check"],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
            return "app", proc.wait
    browser_open(url)
    return "browser", None


def open_window(url, webview_module=None, which=shutil.which, popen=subprocess.Popen,
                browser_open=webbrowser.open, native=None):
    """Open url in the best available window. Returns (kind, waiter): waiter()
    blocks until the window closes, or is None when that cannot be known."""
    native = native_window_available() if native is None else native
    if native:
        if webview_module is None:
            import webview as webview_module  # pywebview
        try:
            webview_module.create_window(TITLE, url, width=SIZE[0], height=SIZE[1],
                                         min_size=MIN_SIZE, background_color="#070708")
        except Exception as exc:
            print("Native window unavailable ({e}). Using a browser window.".format(e=exc))
        else:
            def wait():
                try:
                    webview_module.start()
                except Exception as exc:  # the backend failed while starting
                    print("Native window failed ({e}). Using a browser window.".format(e=exc))
                    _, waiter = open_browser_window(url, which, popen, browser_open)
                    if waiter is not None:
                        waiter()
                    else:
                        _wait_forever()
            return "window", wait
    return open_browser_window(url, which, popen, browser_open)


def _wait_forever():
    print("Press Ctrl+C here to quit ReconMind.")
    while True:
        time.sleep(1)


def main(argv=None):
    os.chdir(REPO_ROOT)  # reports/, logs/ and .env live in the repo root, as for the CLI
    port = running_reconmind()
    server = None
    if port is None:
        try:
            server = Server(free_port())
        except ImportError:
            print("Missing web packages. Run ./install.sh in the ReconMind folder first.")
            return 1
        server.start()
        port = server.port
    url = "http://{h}:{p}/{page}".format(h=HOST, p=port, page=first_page(port))
    kind, wait = open_window(url)
    print("ReconMind is open at " + url)
    if server is None:
        return 0  # the window belongs to the ReconMind that was already running
    try:
        if wait is not None:
            wait()
        else:
            _wait_forever()
        if server.busy():
            print("A scan or setup is still running, so ReconMind keeps working until it "
                  "ends. Open {u} to follow it.".format(u=url))
            while server.busy():
                time.sleep(2)
    except KeyboardInterrupt:
        pass
    server.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
