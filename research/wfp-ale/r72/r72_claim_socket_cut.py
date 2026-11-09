#!/usr/bin/env python3
"""Offline 16-bit negative model of the R19 IOCTL CLAIM trust boundary.
Not a kernel emulator, network test, WFP dispatch trace or physical leak proof.
"""
import hashlib
import json
import unittest

DIMS = (
    'caller_is_pinned_broker', 'slot_is_live', 'auth_seen', 'context_matches',
    'ttl_and_clock_valid', 'owner_is_live', 'epoch_matches', 'start_key_matches',
    'image_matches', 'generation_matches', 'pid_not_reused',
    'context_from_this_accepted_socket', 'wfp_context_query_success',
    'tuple_not_reused', 'sibling_direct_suppressed', 'ssh_transport_healthy',
)


def current_claim(bits):
    # Exact logical conditions read from redirect::ioctl (CLAIM), Book::take
    # and state lookup, abstracting prior release-time issue/attest.
    # No socket argument exists at DeviceIoControl / Book::take.
    return all(bits[i] for i in range(11))


def strengthened_evidence(bits):
    # Hypothetical proof obligations, NOT implemented kernel validation.
    return current_claim(bits) and all(bits[i] for i in range(11, 16))


def count_matrix():
    c = dict(states=0, claim=0, full_evidence=0, claim_without_socket_pair=0,
             claim_without_wfp_query=0, claim_with_reused_tuple=0,
             claim_with_sibling_direct=0, claim_with_ssh_loss=0)
    stream = hashlib.sha256()
    for family in (4, 6):
        for mask in range(1 << len(DIMS)):
            bits = tuple(bool((mask >> i) & 1) for i in range(len(DIMS)))
            a = current_claim(bits)
            b = strengthened_evidence(bits)
            c['states'] += 1
            c['claim'] += a
            c['full_evidence'] += b
            c['claim_without_socket_pair'] += a and not bits[11]
            c['claim_without_wfp_query'] += a and not bits[12]
            c['claim_with_reused_tuple'] += a and not bits[13]
            c['claim_with_sibling_direct'] += a and not bits[14]
            c['claim_with_ssh_loss'] += a and not bits[15]
            stream.update(f'{family}:{mask:05d}:{int(a)}:{int(b)}\n'.encode())
    c['decision_sha256'] = stream.hexdigest()
    return c


class Tests(unittest.TestCase):
    def good(self):
        return [True] * len(DIMS)

    def test_baseline_claim(self):
        self.assertTrue(current_claim(self.good()))
        self.assertTrue(strengthened_evidence(self.good()))

    def test_current_kernel_fields_all_required(self):
        for i in range(11):
            with self.subTest(field=DIMS[i]):
                b = self.good(); b[i] = False
                self.assertFalse(current_claim(b))

    def test_socket_not_part_of_kernel_claim(self):
        b = self.good(); b[11] = False
        self.assertTrue(current_claim(b))
        self.assertFalse(strengthened_evidence(b))

    def test_wfp_query_not_part_of_kernel_claim(self):
        b = self.good(); b[12] = False
        self.assertTrue(current_claim(b))
        self.assertFalse(strengthened_evidence(b))

    def test_tuple_not_authority(self):
        b = self.good(); b[13] = False
        self.assertTrue(current_claim(b))
        self.assertFalse(strengthened_evidence(b))

    def test_sibling_direct_not_authority(self):
        b = self.good(); b[14] = False
        self.assertTrue(current_claim(b))
        self.assertFalse(strengthened_evidence(b))

    def test_ssh_not_authority(self):
        b = self.good(); b[15] = False
        self.assertTrue(current_claim(b))
        self.assertFalse(strengthened_evidence(b))

    def test_swapped_accepted_sockets_counterexample(self):
        # Both ticket A and B may be live, same broker identity and owner path.
        # An explicitly misbehaving in-process broker sends A's context while
        # intending to claim accepted socket B. No socket handle is in IOCTL.
        a, b = {'ticket': 'A', 'socket': 'socket-A'}, {'ticket': 'B', 'socket': 'socket-B'}
        assert a['ticket'] != b['ticket']
        c = self.good(); c[11] = (a['socket'] == b['socket'])
        self.assertTrue(current_claim(c))
        self.assertFalse(strengthened_evidence(c))

    def test_duplicate_claim_terminality(self):
        # Book::take consumes a valid slot; second attempt has slot_live false.
        c = self.good(); self.assertTrue(current_claim(c))
        c[1] = False; self.assertFalse(current_claim(c))

    def test_pid_reuse_fails(self):
        c = self.good(); c[10] = False
        self.assertFalse(current_claim(c))

    def test_epoch_mismatch_fails(self):
        c = self.good(); c[6] = False
        self.assertFalse(current_claim(c))

    def test_start_key_mismatch_fails(self):
        c = self.good(); c[7] = False
        self.assertFalse(current_claim(c))

    def test_image_mismatch_fails(self):
        c = self.good(); c[8] = False
        self.assertFalse(current_claim(c))

    def test_generation_mismatch_fails(self):
        c = self.good(); c[9] = False
        self.assertFalse(current_claim(c))

    def test_auth_required(self):
        c = self.good(); c[2] = False
        self.assertFalse(current_claim(c))

    def test_no_selected_socket_or_network_gate(self):
        for i in range(11,16):
            c = self.good(); c[i] = False
            self.assertTrue(current_claim(c))
            self.assertFalse(strengthened_evidence(c))

    def test_exhaustive_counts(self):
        c = count_matrix()
        self.assertEqual(c['states'], 131072)
        self.assertEqual(c['claim'], 64)
        self.assertEqual(c['full_evidence'], 2)
        for field in ('claim_without_socket_pair', 'claim_without_wfp_query',
                      'claim_with_reused_tuple', 'claim_with_sibling_direct', 'claim_with_ssh_loss'):
            self.assertEqual(c[field], 32)


if __name__ == '__main__':
    print(json.dumps(count_matrix(), sort_keys=True))
    unittest.main(exit=False, verbosity=2)
