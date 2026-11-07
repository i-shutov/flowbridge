#!/usr/bin/env python3
"""Independent offline temporal oracle for R16. No Windows or Rust runtime.

A result from this script is NOT a kernel identity, WFP/SSH-loss detection,
Rust compilation, system no-DIRECT guarantee, or release acceptance.
"""
from __future__ import annotations

import itertools
import unittest
from pathlib import Path

HEALTHY = (True, True, True)  # filter, callout, SSH
UNPROTECTED = "UNPROTECTED_BY_WFP"
REJECT = "REJECT_OWNED_INGRESS"
MODEL = "MODEL_ROUTE_ONLY"


class ReferenceLatch:
    """Separate tiny temporal specification, not an import of Rust model."""

    def __init__(self):
        self.wfp_was_lost = False
        self.ssh_was_lost = False

    def observe(self, health):
        filter_present, callout_present, ssh_up = health
        self.wfp_was_lost |= not (filter_present and callout_present)
        self.ssh_was_lost |= not ssh_up
        if self.wfp_was_lost:
            return UNPROTECTED
        if self.ssh_was_lost:
            return REJECT
        return MODEL


def old_rust_decision(health):
    """Original R15 decision on a valid unconsumed ticket; stateless health."""
    f, c, s = health
    if not (f and c):
        return UNPROTECTED
    if not s:
        return REJECT
    return MODEL


class HealthLatchTests(unittest.TestCase):
    def test_ssh_recovery_cannot_reanimate_old_ticket(self):
        m = ReferenceLatch()
        self.assertEqual(m.observe((True, True, False)), REJECT)
        self.assertEqual(m.observe(HEALTHY), REJECT)
        self.assertEqual(old_rust_decision(HEALTHY), MODEL)

    def test_wfp_recovery_cannot_reanimate_old_ticket(self):
        for state in [(False, True, True), (True, False, True), (False, False, True)]:
            with self.subTest(state=state):
                m = ReferenceLatch()
                self.assertEqual(m.observe(state), UNPROTECTED)
                self.assertEqual(m.observe(HEALTHY), UNPROTECTED)
                self.assertEqual(old_rust_decision(HEALTHY), MODEL)

    def test_wfp_loss_dominates_earlier_ssh_loss(self):
        m = ReferenceLatch()
        self.assertEqual(m.observe((True, True, False)), REJECT)
        self.assertEqual(m.observe((False, True, True)), UNPROTECTED)
        self.assertEqual(m.observe(HEALTHY), UNPROTECTED)

    def test_all_three_component_health_combinations(self):
        for bits in itertools.product((False, True), repeat=3):
            m = ReferenceLatch()
            outcome = m.observe(bits)
            expected = UNPROTECTED if not (bits[0] and bits[1]) else (REJECT if not bits[2] else MODEL)
            self.assertEqual(outcome, expected)

    def test_exhaustive_recovery_histories_never_restore_admission(self):
        # 8^4 possible health histories; append a healthy observation to each.
        states = list(itertools.product((False, True), repeat=3))
        checked = 0
        for sequence in itertools.product(states, repeat=4):
            m = ReferenceLatch()
            for state in sequence:
                m.observe(state)
            final = m.observe(HEALTHY)
            expected = (UNPROTECTED if any(not (x[0] and x[1]) for x in sequence)
                        else REJECT if any(not x[2] for x in sequence) else MODEL)
            self.assertEqual(final, expected)
            checked += 1
        self.assertEqual(checked, 4096)

    def test_unlatched_mutant_fails_two_recovery_witnesses(self):
        for loss in [(True, True, False), (False, True, True), (True, False, True)]:
            m = ReferenceLatch()
            m.observe(loss)
            expected = m.observe(HEALTHY)
            self.assertNotEqual(expected, old_rust_decision(HEALTHY))

    def test_source_contract_if_rust_source_available(self):
        path = Path(__file__).resolve().with_name('trust_contract.rs')
        if not path.is_file():
            self.skipTest('Rust source not present in offline standalone audit; model-only result')
        source = path.read_text(encoding='utf-8')
        self.assertIn('#![forbid(unsafe_code)]', source)
        self.assertIn('observed_wfp_loss: bool', source)
        self.assertIn('observed_ssh_loss: bool', source)
        self.assertIn('self.observed_wfp_loss |=', source)
        self.assertIn('self.observed_ssh_loss |=', source)
        prefix = source.split('pub fn decide(', 1)[1].split('if classify.transport', 1)[0]
        self.assertIn('self.observed_wfp_loss', prefix)
        self.assertIn('self.observed_ssh_loss', prefix)
        self.assertNotIn('FwpmFilterAdd', source)
        self.assertNotIn('FwpsCalloutRegister', source)


if __name__ == '__main__':
    unittest.main(verbosity=2)
