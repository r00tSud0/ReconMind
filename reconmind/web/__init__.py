"""
ReconMind localhost web frontend.

    python3 -m reconmind.web [--port 8000]

server.py builds the FastAPI app, jobs.py runs the existing CLI
(python3 -m reconmind) as a child process for every scan, and static/ holds
the page, its stylesheet and its JavaScript modules. The web app never runs
the agent inside the server and never changes the configuration.
"""
