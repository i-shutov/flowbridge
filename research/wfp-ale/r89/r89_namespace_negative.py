"""R89: deterministic source-logic negative oracle; no Windows, sockets or WFP use."""
import hashlib
import ipaddress
import unittest

CASES = (
    ("v4_loopback", "127.0.0.1", True, "local"),
    ("v4_loopback_other", "127.0.0.2", True, "local"),
    ("v4_linklocal", "169.254.4.5", True, "local"),
    ("v4_private_10", "10.2.3.4", True, "private"),
    ("v4_private_172", "172.16.10.5", True, "private"),
    ("v4_private_192", "192.168.1.2", True, "private"),
    ("v4_shared", "100.64.10.20", True, "non_global"),
    ("v4_documentation", "192.0.2.3", True, "non_global"),
    ("v4_global", "8.8.8.8", True, "global"),
    ("v4_unspecified", "0.0.0.0", False, "invalid"),
    ("v4_multicast", "239.1.1.1", False, "invalid"),
    ("v4_class_e", "240.1.2.3", False, "invalid"),
    ("v6_loopback", "::1", True, "local"),
    ("v6_ula", "fd12::2", True, "private"),
    ("v6_documentation", "2001:db8::2", True, "non_global"),
    ("v6_global", "2606:4700:4700::1111", True, "global"),
    ("v6_linklocal", "fe80::4", False, "invalid"),
    ("v6_unspecified", "::", False, "invalid"),
    ("v6_multicast", "ff02::1", False, "invalid"),
    ("v6_mapped", "::ffff:127.0.0.1", False, "invalid"),
)


def destination_valid(address):
    """Independent Python reproduction of the pinned handoff.rs Destination::valid predicate."""
    ip = ipaddress.ip_address(address)
    b = ip.packed
    if ip.version == 4:
        return b != bytes(4) and b[0] < 224
    return (b != bytes(16) and b[0] != 255
            and not (b[0] == 254 and (b[1] & 192) == 128)
            and not (b[:10] == bytes(10) and b[10:12] == b'\xff\xff'))


def source_decision(ip, target_port, broker_port=4040):
    """Issue candidate only: live ledger, AUTH and WFP effectiveness are NOT asserted."""
    if not destination_valid(ip):
        return "DEST_REJECTED"
    p = ipaddress.ip_address(ip)
    exact_broker_loopback = (p == ipaddress.ip_address("127.0.0.1") if p.version == 4
                             else p == ipaddress.ip_address("::1"))
    if exact_broker_loopback and target_port == broker_port:
        return "BROKER_PORT_EXCLUDED"
    return "SSH_REMOTE_NAMESPACE_CANDIDATE"


def rows():
    for case, ip, expected, scope in CASES:
        for port in (4040, 8080):
            yield (case, ip, scope, port, source_decision(ip, port))


def rendered():
    return "".join(f"{case}|{ip}|{scope}|{port}|{result}\n"
                   for case, ip, scope, port, result in rows())


class R89Tests(unittest.TestCase):
    def test_exact_reproduction_of_expected_validity(self):
        for case, ip, expected, scope in CASES:
            with self.subTest(case=case):
                self.assertEqual(destination_valid(ip), expected)

    def test_local_loopback_diverted_except_exact_broker_port(self):
        self.assertEqual(source_decision("127.0.0.1",8080),"SSH_REMOTE_NAMESPACE_CANDIDATE")
        self.assertEqual(source_decision("127.0.0.1",4040),"BROKER_PORT_EXCLUDED")
        self.assertEqual(source_decision("127.0.0.2",4040),"SSH_REMOTE_NAMESPACE_CANDIDATE")
        self.assertEqual(source_decision("::1",8080),"SSH_REMOTE_NAMESPACE_CANDIDATE")

    def test_ipv4_ipv6_linklocal_asymmetry(self):
        self.assertEqual(source_decision("169.254.4.5",8080),"SSH_REMOTE_NAMESPACE_CANDIDATE")
        self.assertEqual(source_decision("fe80::4",8080),"DEST_REJECTED")

    def test_private_address_space(self):
        for address in ("10.2.3.4","172.16.10.5","192.168.1.2","fd12::2"):
            self.assertEqual(source_decision(address,8080),"SSH_REMOTE_NAMESPACE_CANDIDATE")

    def test_no_actual_end_to_end_claim(self):
        self.assertEqual(len(list(rows())),len(CASES)*2)
        self.assertEqual(rendered().count("SSH_REMOTE_NAMESPACE_CANDIDATE"),24)

if __name__ == "__main__":
    unittest.main(exit=False)
    print("R89_SHA256="+hashlib.sha256(rendered().encode()).hexdigest())
    print("R89_ROWS="+str(len(list(rows()))))
