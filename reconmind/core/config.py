"""
ReconMind configuration.

The ALLOWLIST is the single source of truth for what ReconMind is permitted
to touch. Only networks you own or have written permission to test go here.

NEVER add 10.0.3.0/24. That is the real home network. ReconMind must never
scan it. Anything not listed below is refused in code before any tool runs.
"""

# Lab networks ReconMind is authorized to scan.
ALLOWLIST = [
    "10.10.1.0/24",      # Lab A, target network (Metasploitable, Win11)
    "10.10.2.0/24",      # Lab B, attacker network (Kali)
    "192.168.100.0/24",  # pfSense transit / lab services
    "192.168.56.0/24",   # VirtualBox host-only, lab only
]

# Where the authorization log is written.
LOG_DIR = "logs"
