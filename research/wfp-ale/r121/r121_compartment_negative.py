#!/usr/bin/env python3
"""R121: deterministic compartment-to-SSH projection negatives; NO OS/socket access."""
from hashlib import sha256
from itertools import product, combinations
from collections import defaultdict
import json
import unittest

TARGETS = ((4, '10.55.0.7'), (4, '198.51.100.17'),
           (6, 'fd00:dead::7'), (6, '2001:db8::17'))
PORTS = (443, 8443)
COMPARTMENTS = (1, 7, 42, 99)
EPOCHS = (100, 101)  # same numeric PID, different process creation epoch
ENDPOINTS = (11, 12)  # distinct endpoint handles / synthetic issuance tickets


def payload(family, addr, port, compartment, epoch, endpoint, ssh, protocol):
    # Source-model R19: Destination has ONLY family+IP+port; SSH direct-tcpip
    # receives address string and port, not the Windows compartment/epoch/ticket.
    if not ssh or protocol != 6:
        return None
    return (family, addr, port)


def guarded(family, addr, port, compartment, epoch, endpoint, ssh, protocol):
    # Explicitly hypothetical FIX: reject every non-approved compartment.
    # This does NOT grant native authentication or prove remote routing.
    return payload(family, addr, port, compartment, epoch, endpoint, ssh, protocol) \
        if compartment == 7 else None


def measure():
    lines, by_payload = [], defaultdict(list)
    candidates = restricted = 0
    for (family, addr), port, compartment, epoch, endpoint, ssh, protocol in product(
        TARGETS, PORTS, COMPARTMENTS, EPOCHS, ENDPOINTS, (0, 1), (6, 17)):
        args = family, addr, port, compartment, epoch, endpoint, ssh, protocol
        forwarded = payload(*args) is not None
        strict = guarded(*args) is not None
        candidates += forwarded
        restricted += strict
        lines.append(f'{family}|{addr}|{port}|{compartment}|{epoch}|{endpoint}|{ssh}|{protocol}|{int(forwarded)}|{int(strict)}')
        if forwarded:
            by_payload[(family, addr, port)].append((compartment, epoch, endpoint))
    collisions = sum(1 for group in by_payload.values()
                     for a, b in combinations(group, 2) if a[0] != b[0])
    same_owner_collisions = sum(1 for group in by_payload.values()
                                for a, b in combinations(group, 2)
                                if a[0] != b[0] and a[1:] == b[1:])
    return dict(cases=len(lines), tcp_ssh_candidates=candidates,
                explicit_compartment_7_candidates=restricted,
                compartment_unqualified_candidates=candidates-restricted,
                cross_compartment_same_remote_selector_pairs=collisions,
                same_epoch_endpoint_cross_compartment_pairs=same_owner_collisions,
                matrix_sha256=sha256(('\n'.join(lines)+'\n').encode()).hexdigest(),
                native_wfp_observed=False, kernel_origin_proven=False,
                no_direct_proven=False)


class SourceProjectionTests(unittest.TestCase):
    def test_both_ip_families_lose_compartment_in_forward_selector(self):
        for f, ip in TARGETS:
            self.assertEqual(payload(f, ip, 443, 1, 100, 11, 1, 6),
                             payload(f, ip, 443, 99, 100, 11, 1, 6))

    def test_epoch_endpoint_and_ticket_cannot_restore_removed_compartment(self):
        a = payload(4, '10.55.0.7', 443, 1, 100, 11, 1, 6)
        b = payload(4, '10.55.0.7', 443, 99, 101, 12, 1, 6)
        self.assertEqual(a, b)

    def test_explicit_one_compartment_rejection_is_a_narrow_policy_not_proof(self):
        self.assertIsNone(guarded(6, 'fd00:dead::7', 443, 99, 100, 11, 1, 6))
        self.assertIsNotNone(guarded(6, 'fd00:dead::7', 443, 7, 100, 11, 1, 6))

    def test_udp_or_ssh_failure_are_outside_projection_candidates(self):
        for ssh, protocol in ((0, 6), (1, 17), (0, 17)):
            self.assertIsNone(payload(4, '10.55.0.7', 443, 7, 100, 11, ssh, protocol))

    def test_matrix(self):
        m = measure()
        self.assertEqual((m['cases'], m['tcp_ssh_candidates'],
                          m['explicit_compartment_7_candidates']), (512, 128, 32))
        self.assertEqual(m['cross_compartment_same_remote_selector_pairs'], 768)
        self.assertEqual(m['same_epoch_endpoint_cross_compartment_pairs'], 192)


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(SourceProjectionTests))
    if not result.wasSuccessful():
        raise SystemExit(1)
    print('R121_MATRIX ' + json.dumps(measure(), sort_keys=True))
