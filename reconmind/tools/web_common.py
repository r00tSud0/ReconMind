"""
ReconMind shared web helpers.

Small helpers every web tool uses: deciding whether an nmap port is a web
service, whether it wants HTTPS, and building the URL for it. They know
nothing about any particular scanner.
"""


def is_web_service(port):
    """True if nmap named the port's service as some kind of HTTP or HTTPS
    (http, https, ssl/http, http-proxy, http-alt and similar)."""
    return "http" in (port.get("service") or "").lower()


def wants_https(port):
    """True if the service name or nmap's tunnel field says SSL/TLS or HTTPS."""
    service = (port.get("service") or "").lower()
    tunnel = (port.get("tunnel") or "").lower()
    return tunnel in ("ssl", "tls") or "ssl" in service or "https" in service


def build_url(target_ip, port, use_https=False):
    """http:// or https:// plus target and port, e.g. http://10.10.1.100:80."""
    host = str(target_ip).strip()
    if ":" in host:  # IPv6 literal
        host = "[{h}]".format(h=host)
    return "{s}://{h}:{p}".format(s="https" if use_https else "http", h=host, p=int(port))
