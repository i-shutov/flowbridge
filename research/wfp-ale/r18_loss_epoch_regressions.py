#!/usr/bin/env python3
"""R18 negative regression of ResearchGate observed-loss epoch, stdlib only.

Import the real source from the same directory. No sockets, Win32, driver,
filter or WFP calls. Never interpret conditional model as G2 authority.
"""
import unittest
import itertools
try:
    from endpoint_witness_model import ResearchGate, Owner, Redirect, Authorization
    AVAILABLE = True
except ImportError:
    AVAILABLE = False

class IndependentOracle(unittest.TestCase):
    def test_4096_health_histories(self):
        states=list(itertools.product((False, True),repeat=3))
        for path in itertools.product(states,repeat=4):
            wfp_lost=ssh_lost=False
            for f,c,s in path:
                wfp_lost |= not(f and c)
                ssh_lost |= not s
            verdict='UNPROTECTED' if wfp_lost else 'REJECT_INGRESS' if ssh_lost else 'CAPTURED_MODEL'
            self.assertEqual(verdict,'UNPROTECTED' if any(not(f and c) for f,c,s in path)
                else 'REJECT_INGRESS' if any(not s for f,c,s in path) else 'CAPTURED_MODEL')

    def test_old_health_mutant_reanimates(self):
        # Original ResearchGate classify used only current active_filter/callout.
        old_decision=lambda f,c: 'UNPROTECTED' if not(f and c) else 'CAPTURED_MODEL'
        self.assertEqual(old_decision(True,True),'CAPTURED_MODEL')
        self.assertNotEqual('REJECT_INGRESS',old_decision(True,True))
        self.assertNotEqual('UNPROTECTED',old_decision(True,True))

@unittest.skipUnless(AVAILABLE,'actual GitHub model not mounted; independent oracle only')
class HealthEpochRegression(unittest.TestCase):
    def gate(self):
        g = ResearchGate(b'A', 19)
        assert g.start_process(Owner(701, 1, 9876, b'A', b'file:A', True)) == 'REGISTERED_MODEL'
        return g

    @staticmethod
    def request(ticket, family=4):
        return Redirect(ticket,19,100+ticket,701,1,b'A',family,
                        '192.0.2.10:443' if family==4 else '[2001:db8::1]:443')

    def test_positive_before_loss_both_families(self):
        for fam in (4,6):
            g=self.gate()
            self.assertEqual(g.classify(self.request(1,fam)), 'CAPTURED_MODEL')

    def test_events_latch_and_cannot_revive(self):
        for component in ('ssh','filter','callout'):
            with self.subTest(component=component):
                g=self.gate()
                self.assertEqual(g.loss(component),
                    'OWNED_INGRESS_CLOSED_ONLY' if component=='ssh' else 'UNPROTECTED')
                g.ssh_ready=g.active_filter=g.active_callout=True
                expected='REJECT_INGRESS' if component=='ssh' else 'UNPROTECTED'
                self.assertEqual(g.classify(self.request(2)),expected)
                self.assertEqual(g.classify(self.request(3,6)),expected)

    def test_poll_observed_loss_latches_without_event(self):
        for attr in ('ssh_ready','active_filter','active_callout'):
            with self.subTest(attr=attr):
                g=self.gate();setattr(g,attr,False)
                expected='REJECT_INGRESS' if attr=='ssh_ready' else 'UNPROTECTED'
                self.assertEqual(g.classify(self.request(1)), expected)
                setattr(g,attr,True)
                self.assertEqual(g.classify(self.request(2)), expected)

    def test_accept_observed_loss_latches(self):
        for attr in ('ssh_ready','active_filter','active_callout'):
            with self.subTest(attr=attr):
                g=self.gate();r=self.request(1)
                self.assertEqual(g.classify(r), 'CAPTURED_MODEL')
                self.assertEqual(g.observe_auth(Authorization(r.endpoint,701,1,b'file:A',4)),
                                 'SUPPORTING_OBSERVATION_ONLY')
                setattr(g,attr,False)
                expected='REJECT_INGRESS' if attr=='ssh_ready' else 'UNPROTECTED'
                self.assertEqual(g.accept(1,19,r.endpoint,4,True,True,True),expected)
                setattr(g,attr,True)
                self.assertEqual(g.classify(self.request(2)), expected)

    def test_wfp_outage_dominates_previous_ssh_loss(self):
        g=self.gate();g.loss('ssh');g.ssh_ready=True
        self.assertEqual(g.classify(self.request(1)),'REJECT_INGRESS')
        g.loss('filter');g.active_filter=True
        self.assertEqual(g.classify(self.request(2)),'UNPROTECTED')

    def test_unknown_loss_not_a_poison_event(self):
        g=self.gate()
        self.assertEqual(g.loss('bad-type'),'UNKNOWN_COMPONENT')
        self.assertEqual(g.classify(self.request(1)),'CAPTURED_MODEL')

    def test_new_object_is_not_os_restoration(self):
        g=self.gate();g.loss('ssh');g.ssh_ready=True
        self.assertEqual(g.classify(self.request(1)),'REJECT_INGRESS')
        self.assertEqual(self.gate().classify(self.request(2)),'CAPTURED_MODEL')

if __name__=='__main__':
    unittest.main(verbosity=2)
