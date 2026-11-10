#!/usr/bin/env python3
"""R92: policy-loss negative oracle. Pure state model; never asserts traffic behavior."""
import hashlib
import itertools
import unittest


def rows():
    for mask, notified, lease, broker, ticket, barrier in itertools.product(
        range(16), (0, 1), (0, 1), (0, 1), (0, 1), (0, 1)
    ):
        # Source: R19 ready() uses broker process, lease and Book, not FWPM objects.
        ready = lease & broker & ticket
        missing_v4 = int((mask & 3) != 3)
        missing_v6 = int((mask & 12) != 12)
        unsupported = int(bool(ready and (missing_v4 or missing_v6)))
        # A barrier is a HYPOTHETICAL requirement, not an existing WFP rule.
        no_separate_barrier = int(bool(unsupported and not barrier))
        yield (mask, notified, lease, broker, ticket, barrier, ready,
               missing_v4, missing_v6, unsupported, no_separate_barrier)


def manifest():
    return '\n'.join(','.join(map(str, r)) for r in rows()) + '\n'


class Negative(unittest.TestCase):
    def test_512_deterministic_worlds(self):
        self.assertEqual(len(list(rows())), 512)
        self.assertEqual(len(set(rows())), 512)

    def test_noop_notify_cannot_revoke_liveness(self):
        # R19 notify callback ignores both ADD and DELETE notifications.
        cases = list(rows())
        for mask in range(15):
            for barrier in (0, 1):
                old = next(r for r in cases if r[:6] == (mask, 0, 1, 1, 1, barrier))
                new = next(r for r in cases if r[:6] == (mask, 1, 1, 1, 1, barrier))
                self.assertEqual(old[6:], new[6:])
                self.assertEqual(new[6], 1)
                self.assertEqual(new[9], 1)

    def test_per_family_partial_policy_is_not_full_attestation(self):
        rs = list(rows())
        for mask in range(15):
            r = next(r for r in rs if r[:6] == (mask, 1, 1, 1, 1, 0))
            self.assertEqual(r[9], 1)
        full = next(r for r in rs if r[:6] == (15, 1, 1, 1, 1, 0))
        self.assertEqual(full[9], 0)

    def test_unobserved_deletion_remains_even_if_notify_is_fixed(self):
        # A notification-only repair cannot handle missing/late delivery.
        r = next(r for r in rows() if r[:6] == (7, 0, 1, 1, 1, 0))
        self.assertEqual((r[6], r[8], r[9], r[10]), (1, 1, 1, 1))

    def test_no_direct_not_proved_from_manifest(self):
        # The matrix has no packet observation, only configuration predicates.
        assert 'packet' not in manifest().lower()
        self.assertTrue(any(r[10] == 1 for r in rows()))


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Negative)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    print('ROWS', len(list(rows())))
    print('SHA256', hashlib.sha256(manifest().encode()).hexdigest())
    print('UNVERIFIED_POLICY', sum(r[9] for r in rows()))
    print('NO_INDEPENDENT_BARRIER', sum(r[10] for r in rows()))
