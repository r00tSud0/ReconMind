"""
Offline tests for the risky service rules table, using Metasploitable's
nmap service and product names.
"""

import unittest

from reconmind.tools.risky_services import flag_port, flag_ports


def port(num, service, product="", version=""):
    return {"port": num, "protocol": "tcp", "service": service, "product": product,
            "version": version}


class RiskyServiceTests(unittest.TestCase):

    def test_root_shell_is_critical(self):
        flag = flag_port(port(1524, "bindshell", "Metasploitable root shell"))
        self.assertEqual(flag["severity"], "critical")
        self.assertIn("Unauthenticated root shell", flag["reason"])
        # Matched on product alone, whatever nmap calls the service.
        self.assertEqual(flag_port(port(1524, "ingreslock", "Metasploitable root shell"))["severity"],
                         "critical")

    def test_distccd_and_ruby_drb_are_critical(self):
        # nmap's real service, product and version values.
        distcc = flag_port(port(3632, "distccd", "distccd", "v1"))
        self.assertEqual(distcc["severity"], "critical")
        self.assertIn("distcc compile daemon", distcc["reason"])
        drb = flag_port(port(8787, "drb", "Ruby DRb RMI"))
        self.assertEqual(drb["severity"], "critical")
        self.assertIn("Ruby DRb", drb["reason"])

    def test_cleartext_logins_are_high(self):
        self.assertEqual(flag_port(port(23, "telnet", "Linux telnetd"))["severity"], "high")
        for num, service, product in ((512, "exec", "netkit-rsh rexecd"),
                                      (513, "login", "OpenBSD or Solaris rlogind"),
                                      (514, "shell", "Netkit rshd")):
            with self.subTest(service=service):
                flag = flag_port(port(num, service, product))
                self.assertEqual(flag["severity"], "high")
                self.assertIn("cleartext", flag["reason"])

    def test_exposed_services_are_medium(self):
        for num, service, product in ((5900, "vnc", "VNC"), (6000, "X11", ""),
                                      (2049, "nfs", ""), (1099, "java-rmi", "GNU Classpath grmiregistry")):
            with self.subTest(service=service):
                self.assertEqual(flag_port(port(num, service, product))["severity"], "medium")

    def test_ordinary_services_are_not_flagged(self):
        for p in (port(21, "ftp", "vsftpd"), port(22, "ssh", "OpenSSH"),
                  port(80, "http", "Apache httpd"), port(514, "tcpwrapped")):
            self.assertIsNone(flag_port(p))

    def test_flag_ports_sorts_most_severe_first(self):
        flagged = flag_ports([port(5900, "vnc"), port(23, "telnet"), port(22, "ssh"),
                              port(1524, "bindshell")])
        self.assertEqual([p["port"] for p, _ in flagged], [1524, 23, 5900])

    def test_no_dash_separators_in_reasons(self):
        for p in (port(1524, "bindshell"), port(3632, "distccd"), port(8787, "drb"),
                  port(23, "telnet"), port(512, "exec"),
                  port(5900, "vnc"), port(6000, "x11"), port(2049, "nfs"), port(1099, "java-rmi")):
            reason = flag_port(p)["reason"]
            self.assertNotIn(" - ", reason)
            self.assertNotIn("—", reason)


if __name__ == "__main__":
    unittest.main()
