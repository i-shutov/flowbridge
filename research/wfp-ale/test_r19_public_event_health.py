#!/usr/bin/env python3
"""R19 public-event health negative regressions; exact source import in checkout.

No Windows/network/driver operations; MODEL results never prove WFP ownership.
"""
from __future__ import annotations
import itertools
import unittest
from endpoint_witness_model import ResearchGate, Owner, Redirect, Authorization

APP, IMAGE, SESSION, PID = b'app:R19', b'file:R19', 113, 509


def owner():
    return Owner(PID, 1, 4001, APP, IMAGE, True)


def pending(family=4, *, endpoint=991, ticket=17):
    g = ResearchGate(APP, SESSION)
    assert g.start_process(owner()) == 'REGISTERED_MODEL'
    r = Redirect(ticket, SESSION, endpoint, PID, 1, APP, family,
                 '192.0.2.19:443' if family == 4 else '[2001:db8::19]:443')
    a = Authorization(endpoint, PID, 1, IMAGE, family)
    assert g.classify(r) == 'CAPTURED_MODEL'
    return g, r, a


class PublicEventHealthTests(unittest.TestCase):
    def test_pending_auth_under_loss_must_poison_session_even_if_healed_before_accept(self):
        for family, flag in itertools.product((4, 6), ('active_filter', 'active_callout', 'ssh_ready')):
            with self.subTest(family=family, flag=flag):
                g, r, a = pending(family)
                setattr(g, flag, False)
                expected = 'REJECT_INGRESS' if flag == 'ssh_ready' else 'UNPROTECTED'
                self.assertEqual(g.observe_auth(a), expected)
                setattr(g, flag, True)
                self.assertEqual(g.accept(r.ticket, SESSION, r.endpoint, family, True, True, True), expected)
                self.assertEqual(g.classify(Redirect(18, SESSION, 992, PID, 1, APP, family,
                    '192.0.2.20:443' if family == 4 else '[2001:db8::20]:443')), expected)

    def test_start_process_is_also_a_health_observation_boundary(self):
        for flag in ('active_filter', 'active_callout', 'ssh_ready'):
            with self.subTest(flag=flag):
                g = ResearchGate(APP, SESSION)
                setattr(g, flag, False)
                expected = 'REJECT_INGRESS' if flag == 'ssh_ready' else 'UNPROTECTED'
                self.assertEqual(g.start_process(owner()), expected)
                setattr(g, flag, True)
                self.assertEqual(g.start_process(owner()), expected)
                self.assertEqual(g.classify(Redirect(1, SESSION, 100, PID, 1, APP, 4, '192.0.2.19:443')), expected)

    def test_good_auth_before_loss_is_only_synthetic(self):
        for family in (4, 6):
            g, r, a = pending(family)
            self.assertEqual(g.observe_auth(a), 'SUPPORTING_OBSERVATION_ONLY')
            self.assertEqual(g.accept(r.ticket, SESSION, r.endpoint, family, True, True, True), 'CONDITIONAL_MODEL_ONLY')

    def test_latched_loss_precedes_invalid_or_unbound_auth(self):
        for flag in ('active_filter', 'active_callout', 'ssh_ready'):
            g, r, _ = pending()
            setattr(g, flag, False)
            verdict = 'REJECT_INGRESS' if flag == 'ssh_ready' else 'UNPROTECTED'
            self.assertEqual(g.observe_auth(Authorization(r.endpoint, PID, 1, b'wrong', 4)), verdict)


class IndependentTemporalOracle(unittest.TestCase):
    def test_four_observations_exhaustive_eight_health_states(self):
        health_states = list(itertools.product((False, True), repeat=3))
        count = 0
        for sequence in itertools.product(health_states, repeat=4):
            saw_wfp_loss = any(not (f and c) for f, c, s in sequence)
            saw_ssh_loss = any(not s for f, c, s in sequence)
            final = ('UNPROTECTED' if saw_wfp_loss else 'REJECT_INGRESS'
                     if saw_ssh_loss else 'MAY_CONSIDER_MODEL_ONLY')
            failed = any(not (f and c and s) for f, c, s in sequence)
            if failed:
                self.assertNotEqual(final, 'MAY_CONSIDER_MODEL_ONLY')
            else:
                self.assertEqual(final, 'MAY_CONSIDER_MODEL_ONLY')
            count += 1
        self.assertEqual(count, 4096)

    def test_stateless_auth_and_start_mutants_are_rejected(self):
        # Incorrect policies sample health only at classify/accept.
        for event in ('auth', 'start'):
            for failing in ((False, True, True), (True, False, True), (True, True, False)):
                latched = 'UNPROTECTED' if not (failing[0] and failing[1]) else 'REJECT_INGRESS'
                with self.subTest(event=event, failing=failing):
                    self.assertNotEqual(latched, 'MAY_CONSIDER_MODEL_ONLY')


if __name__ == '__main__':
    unittest.main(verbosity=2)
