#!/usr/bin/env python3
"""R216: executable, dependency-free model of the R19 Destination.valid scope.

No WFP, sockets, drivers, services, filters, packets or network access.
Does NOT assert a native classify occurred; dual-stack V6 input is conditional.
"""
from __future__ import annotations

import hashlib
import ipaddress
import unittest


def r19_destination_valid(family: int, ip: bytes, port: int = 443) -> bool:
    if port == 0 or len(ip) != 16:
        return False
    if family == 4:
        return (ip[4:] == bytes(12) and ip[:4] != bytes(4) and ip[0] < 224)
    if family == 6:
        return (ip != bytes(16) and ip[0] != 0xff
                and not (ip[0] == 0xfe and ip[1] & 0xc0 == 0x80)
                and not (ip[:10] == bytes(10) and ip[10:12] == b'\xff\xff'))
    return False


def cases():
    v4 = lambda s: ipaddress.IPv4Address(s).packed + bytes(12)
    v6 = lambda s: ipaddress.IPv6Address(s).packed
    return [
        ('v4_unicast', 4, v4('198.51.100.7'), True),
        ('v4_loopback', 4, v4('127.0.0.1'), True),
        ('v4_unspecified', 4, v4('0.0.0.0'), False),
        ('v4_multicast', 4, v4('224.0.0.1'), False),
        ('v6_global', 6, v6('2001:db8::7'), True),
        ('v6_loopback', 6, v6('::1'), True),
        ('v6_unspecified', 6, v6('::'), False),
        ('v6_linklocal', 6, v6('fe80::1'), False),
        ('v6_multicast', 6, v6('ff02::1'), False),
        ('v6_mapped_public', 6, v6('::ffff:198.51.100.7'), False),
        ('v6_mapped_loopback', 6, v6('::ffff:127.0.0.1'), False),
        ('v6_mapped_private', 6, v6('::ffff:10.0.0.2'), False),
    ]


def transcript():
    rows = []
    for name, family, ip, expected in cases():
        actual = r19_destination_valid(family, ip)
        if actual is not expected:
            raise AssertionError(f'{name}: expected={expected} actual={actual}')
        rows.append(f'{name}\t{family}\t{ip.hex()}\t{int(actual)}\n')
    return ''.join(rows)


class R216Tests(unittest.TestCase):
    def test_all_12_source_policy_cases(self):
        self.assertEqual(len(cases()), 12)
        self.assertEqual(len(transcript().splitlines()), 12)

    def test_mapped_public_v6_rejected_despite_v4_unicast(self):
        s = '198.51.100.7'
        self.assertTrue(r19_destination_valid(4, ipaddress.IPv4Address(s).packed + bytes(12)))
        self.assertFalse(r19_destination_valid(6, ipaddress.IPv6Address('::ffff:' + s).packed))

    def test_three_ipv4_mapped_are_rejected(self):
        for _, family, ip, expected in cases():
            if ip[:12] == bytes(10) + b'\xff\xff':
                self.assertEqual((family, expected, r19_destination_valid(family, ip)), (6, False, False))

    def test_mutant_without_mapped_guard_must_fail(self):
        # Mutation sensitivity: removing the final exclusion changes verdict.
        ip = ipaddress.IPv6Address('::ffff:198.51.100.7').packed
        actual = r19_destination_valid(6, ip)
        mutant = ip != bytes(16) and ip[0] != 0xff and not (ip[0] == 0xfe and ip[1] & 0xc0 == 0x80)
        self.assertNotEqual(actual, mutant)
        self.assertFalse(actual)
        self.assertTrue(mutant)


if __name__ == '__main__':
    unittest.main(exit=False, verbosity=2)
    data = transcript().encode('ascii')
    print('R216 rows=12 sha256=' + hashlib.sha256(data).hexdigest())
