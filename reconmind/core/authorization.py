"""
ReconMind authorization gate.

Every target must pass through is_authorized() before any tool is allowed to
run against it. A target is authorized only if its IP falls inside one of the
CIDR ranges in ALLOWLIST. Everything else is refused, and every decision,
allow or deny, is written to the authorization log.

This is the project's safety interlock. No scanning code may run a tool on a
target that this function has not returned True for.
"""

import ipaddress
import os
from datetime import datetime

from reconmind.core.config import ALLOWLIST, DENYLIST, LOG_DIR


def _log(target, decision):
    """Append one timestamped line to logs/authorization.log."""
    os.makedirs(LOG_DIR, exist_ok=True)
    line = "{ts}  {target:<18}  {decision}\n".format(
        ts=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        target=str(target),
        decision=decision,
    )
    with open(os.path.join(LOG_DIR, "authorization.log"), "a") as fh:
        fh.write(line)


def is_authorized(target_ip):
    """
    Return True only if target_ip is a valid IP address inside an ALLOWLIST
    range. Invalid input and out-of-scope addresses return False. Every call
    is logged.
    """
    # Reject anything that is not a well-formed IP address.
    try:
        ip = ipaddress.ip_address(str(target_ip).strip())
    except ValueError:
        _log(target_ip, "DENIED (invalid IP)")
        return False

    # The denylist always wins, even over the allowlist.
    for cidr in DENYLIST:
        if ip in ipaddress.ip_network(cidr, strict=False):
            _log(ip, "DENIED (denylist)")
            return False

    # Only private RFC1918 addresses are ever in scope.
    if not ip.is_private:
        _log(ip, "DENIED (not private)")
        return False

    # Check the IP against every allowed network.
    for cidr in ALLOWLIST:
        if ip in ipaddress.ip_network(cidr, strict=False):
            _log(ip, "ALLOWED ({cidr})".format(cidr=cidr))
            return True

    _log(ip, "DENIED (out of scope)")
    return False


if __name__ == "__main__":
    # Quick self test. The first should allow, the rest should deny.
    checks = [
        ("10.10.1.100", True),   # a lab target, must be allowed
        ("10.0.3.15", False),    # the real home network, must be denied
        ("8.8.8.8", False),      # public internet, must be denied
        ("not-an-ip", False),    # garbage input, must be denied
    ]
    for target, expected in checks:
        result = is_authorized(target)
        mark = "ok" if result == expected else "FAIL"
        print("{mark:<4} {target:<14} -> {result}".format(
            mark=mark, target=target, result=result))
