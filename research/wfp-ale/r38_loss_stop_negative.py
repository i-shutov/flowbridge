#!/usr/bin/env python3
"""R38: deterministic control-flow counterexample. Offline, no WFP/network/driver."""
import itertools
import unittest
from dataclasses import dataclass

@dataclass
class Trace:
    family: int
    selected: bool = True
    claimed: bool = True
    ssh_authenticated: bool = True
    ssh_channel_open: bool = True
    stop: bool = False
    kernel_live: bool = True
    elapsed_ms: int = 0
    ssh_live: bool = True

    def accepted(self):
        # Admission in the user-mode negative model is assumed complete;
        # this is NOT a model of the kernel implementation.
        return self.selected and self.claimed and self.ssh_authenticated and self.ssh_channel_open

    def current_r37_can_copy(self):
        # Actual trusted relay receives no `stop`, and copy_bidirectional is
        # controlled by its socket state and the independent 60 s timeout.
        return self.accepted() and self.ssh_live and self.elapsed_ms < 60_000

    def required_revocation_contract(self):
        return self.current_r37_can_copy() and self.kernel_live and not self.stop


class R38Negative(unittest.TestCase):
    def test_initially_healthy_both_families(self):
        for family in (4, 6):
            t = Trace(family)
            self.assertTrue(t.current_r37_can_copy())
            self.assertTrue(t.required_revocation_contract())

    def test_kernel_lease_loss_after_auth_both_families(self):
        for family in (4, 6):
            t = Trace(family, kernel_live=False, stop=True, elapsed_ms=1000)
            self.assertTrue(t.current_r37_can_copy(), 'model preserves copy until timeout/SSH close')
            self.assertFalse(t.required_revocation_contract())

    def test_normal_broker_stop_does_not_revoke_existing_trusted_worker(self):
        t = Trace(4, stop=True)
        self.assertTrue(t.current_r37_can_copy())
        self.assertFalse(t.required_revocation_contract())

    def test_trusted_ssh_failure_already_prevents_copy(self):
        for kw in ({'ssh_live':False},{'ssh_authenticated':False},{'ssh_channel_open':False}):
            self.assertFalse(Trace(4, **kw).current_r37_can_copy())

    def test_does_not_claim_unsupported_network_scope(self):
        # Sibling DIRECT, UDP and DNS aren't forced through the selected TCP
        # trusted relay. An absence of this counterexample proves nothing there.
        for selected in (False,):
            self.assertFalse(Trace(4, selected=selected).current_r37_can_copy())

    def test_deadline_is_not_health_revocation(self):
        self.assertTrue(Trace(6, stop=True, elapsed_ms=59_999).current_r37_can_copy())
        self.assertFalse(Trace(6, stop=True, elapsed_ms=60_000).current_r37_can_copy())

    def test_cross_product_loss_continuity(self):
        cases=0
        for family,elapsed_ms,reason in itertools.product((4,6),(1,500,30_000,59_999),('kernel_ping_failed','normal_stop')):
            t=Trace(family, stop=True, kernel_live=reason!='kernel_ping_failed', elapsed_ms=elapsed_ms)
            self.assertTrue(t.current_r37_can_copy())
            self.assertFalse(t.required_revocation_contract())
            cases+=1
        self.assertEqual(cases,16)

    def test_reused_tuple_and_pid_cannot_repair_loss_contract(self):
        # No PID, timestamp, 5-tuple or AppId join appears in the trusted relay's
        # post-admission loop; such a join cannot fix a missing revocation check.
        for family in (4,6):
            t=Trace(family, stop=True)
            self.assertTrue(t.current_r37_can_copy())

if __name__=='__main__': unittest.main(verbosity=2)
