"""
ReconMind web app.

    python3 -m reconmind.web [--port 8000]

Serves the localhost frontend on 127.0.0.1 only. There is no option to listen
on another address: the app starts scans, so it must never be reachable from
the network.

Start it from the repo root, like the CLI, so reports/, logs/ and .env are the
same folders and file the CLI uses. Scans run as python3 -m reconmind child
processes in that folder.
"""

import argparse
import os
import sys

HOST = "127.0.0.1"
DEFAULT_PORT = 8000

NOT_REPO_ROOT = ("Start the web app from the ReconMind repo root (the folder that holds "
                 "reconmind/), so reports/, logs/ and .env match the CLI:\n"
                 "    cd /path/to/ReconMind && python3 -m reconmind.web")
MISSING_PACKAGES = ("Missing web packages. Activate your venv and run:\n"
                    "    pip install -r requirements-web.txt")


def _port(text):
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("{t!r} is not a port number".format(t=text)) from None
    if not 1 <= value <= 65535:
        raise argparse.ArgumentTypeError("the port must be 1 to 65535")
    return value


def _parse_args(args):
    parser = argparse.ArgumentParser(
        prog="python3 -m reconmind.web",
        description="The ReconMind web app, on {h} only.".format(h=HOST))
    parser.add_argument("--port", type=_port, default=DEFAULT_PORT,
                        help="port on {h} (default {p})".format(h=HOST, p=DEFAULT_PORT))
    return parser.parse_args(args)


def main(argv):
    try:
        args = _parse_args(argv[1:])
    except SystemExit as exc:  # argparse already printed the usage or the help
        return exc.code or 0
    if not os.path.isdir("reconmind"):
        print(NOT_REPO_ROOT)
        return 1
    try:
        import uvicorn
        from reconmind.web.server import create_app
    except ImportError:
        print(MISSING_PACKAGES)
        return 1

    app = create_app(port=args.port)
    print("ReconMind web app: open http://{h}:{p}/ in your browser.".format(
        h=HOST, p=args.port))
    print("Scans keep running if you close the page. Press Ctrl+C here to stop the app.")
    uvicorn.run(app, host=HOST, port=args.port, log_level="warning", server_header=False)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
