"""
ReconMind risky service flags.

Some services are a finding just by being reachable, whatever their version:
an open root shell, a cleartext login, a desktop or file share exposed to the
network. This is a fixed rules table, matched on nmap's service name or a
phrase in its product name. No AI and no CVE claims.

The table is ordered from most to least severe and the first matching rule
wins, so one port gets at most one flag.
"""

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

RULES = [
    {
        "severity": "critical",
        "services": {"bindshell"},
        "products": ("root shell", "bindshell"),
        "reason": "Unauthenticated root shell. Anyone who connects gets a "
                  "root command prompt without logging in.",
    },
    {
        "severity": "critical",
        "services": {"distccd"},
        "products": ("distccd",),
        "reason": "distcc compile daemon exposed. Without host restrictions it "
                  "runs commands sent by anyone who connects, as its service user.",
    },
    {
        "severity": "critical",
        "services": {"drb"},
        "products": ("ruby drb",),
        "reason": "Ruby DRb (distributed Ruby) service exposed. Without access "
                  "control, anyone who connects can make it run code.",
    },
    {
        "severity": "high",
        "services": {"telnet"},
        "products": ("telnetd",),
        "reason": "Telnet login. Usernames, passwords and the whole session "
                  "cross the network in cleartext.",
    },
    {
        "severity": "high",
        "services": {"exec", "login", "shell", "rsh", "rexec", "rlogin"},
        "products": ("rexecd", "rlogind", "rshd"),
        "reason": "Remote shell service (rsh, rexec or rlogin). Login is "
                  "cleartext or based on host trust.",
    },
    {
        "severity": "medium",
        "services": {"vnc"},
        "products": ("vnc",),
        "reason": "VNC remote desktop exposed to the network.",
    },
    {
        "severity": "medium",
        "services": {"x11"},
        "products": (),
        "reason": "X11 display server exposed to the network.",
    },
    {
        "severity": "medium",
        "services": {"nfs", "nfs_acl"},
        "products": (),
        "reason": "NFS file sharing exposed to the network.",
    },
    {
        "severity": "medium",
        "services": {"java-rmi", "rmiregistry"},
        "products": ("rmiregistry",),
        "reason": "Java RMI registry exposed to the network.",
    },
]


def flag_port(port):
    """{severity, reason} for the first rule that matches the port, or None."""
    service = (port.get("service") or "").strip().lower()
    product = (port.get("product") or "").strip().lower()
    for rule in RULES:
        if service in rule["services"] or any(p in product for p in rule["products"]):
            return {"severity": rule["severity"], "reason": rule["reason"]}
    return None


def flag_ports(ports):
    """[(port, flag)] for every flagged port, most severe first."""
    flagged = [(p, flag_port(p)) for p in ports]
    flagged = [(p, f) for p, f in flagged if f]
    flagged.sort(key=lambda pf: (SEVERITY_ORDER[pf[1]["severity"]], pf[0].get("port", 0)))
    return flagged
