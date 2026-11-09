#!/usr/bin/env python3
"""R63 independent offline model: a socket's ALE endpoint is not historical AUTH identity."""
import hashlib
import json
import unittest

FIELD_NAMES = (
    "dispatched", "wsaioc_success", "exact_8_bytes", "bfe_open",
    "endpoint_lookup", "endpoint_id_equal", "family_valid", "appid_present",
    "tcp", "owner_notified_live", "ssh_live", "wfp_live",
    "original_owner", "creation_epoch_equal", "redirect_record_join", "physically_alive",
)
OBSERVED = (1 << 12) - 1
TRUTH = 0b1111 << 12
N = 1 << len(FIELD_NAMES)


def assess(mask):
    if (mask & 1) == 0:
        return 'U'  # UNOBSERVED is not BLOCK
    if mask & OBSERVED != OBSERVED:
        return 'R'  # model rejects as insufficient diagnostic, not OS drop
    return 'D'  # socket endpoint diagnostic ONLY, no original-owner proof


def strict_hypothesis(mask):
    return assess(mask) == 'D' and mask & TRUTH == TRUTH


def summarize():
    digest = hashlib.sha256()
    stats = dict(states=0, unobserved=0, invalid=0, diagnostic_only=0,
                 hypothetical_strict=0, weak_without_original=0,
                 weak_after_physical_death=0, weak_without_record_join=0)
    for mask in range(N):
        d = assess(mask)
        digest.update(d.encode('ascii'))
        stats['states'] += 1
        if d == 'U': stats['unobserved'] += 1
        elif d == 'R': stats['invalid'] += 1
        else:
            stats['diagnostic_only'] += 1
            stats['hypothetical_strict'] += int(strict_hypothesis(mask))
            stats['weak_without_original'] += int(not mask & (1 << 12))
            stats['weak_after_physical_death'] += int(not mask & (1 << 15))
            stats['weak_without_record_join'] += int(not mask & (1 << 14))
    stats['ordered_decision_sha256'] = digest.hexdigest()
    # Same observed I/O, different hidden owner/epoch/provenance/liveness.
    stats['indistinguishable_witnesses'] = [OBSERVED, OBSERVED | TRUTH]
    assert assess(OBSERVED) == assess(OBSERVED | TRUTH) == 'D'
    return stats


class NegativeTests(unittest.TestCase):
    def test_dispatch_absent_not_block(self): self.assertEqual(assess(0), 'U')
    def test_full_diagnostic_never_proof(self): self.assertEqual(assess(OBSERVED|TRUTH),'D')
    def test_sibling_looks_identical(self): self.assertEqual(assess(OBSERVED), assess(OBSERVED | TRUTH))
    def test_pid_reuse_unobservable(self): self.assertEqual(assess(OBSERVED),assess(OBSERVED | (1<<13)))
    def test_record_not_kernel_claim(self): self.assertEqual(assess(OBSERVED),assess(OBSERVED | (1<<14)))
    def test_real_death_notification_lag(self): self.assertEqual(assess(OBSERVED),assess(OBSERVED | (1<<15)))
    def test_each_observed_missing(self):
        for bit in range(1,12):
            self.assertEqual(assess(OBSERVED & ~(1 << bit)),'R',msg=FIELD_NAMES[bit])
    def test_endpoint_id_is_not_creation_epoch(self): self.assertFalse(strict_hypothesis(OBSERVED | (1<<12)))
    def test_trust_requires_hidden_fields(self): self.assertTrue(strict_hypothesis(OBSERVED | TRUTH))
    def test_full_space(self):
        r=summarize()
        self.assertEqual(r['states'],65536)
        self.assertEqual(r['unobserved'],32768)
        self.assertEqual(r['diagnostic_only'],16)
        self.assertEqual(r['hypothetical_strict'],1)


if __name__ == '__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NegativeTests))
    if not result.wasSuccessful(): raise SystemExit(1)
    print(json.dumps(summarize(),sort_keys=True))
