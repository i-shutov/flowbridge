"""R42 deterministic negative tests: epistemic limits of broker-only post-CLAIM observations.
No Windows calls, no network access. Observational equivalence is conditional
on pending data and no EOF/close event arriving in the observation window.
"""
from dataclasses import dataclass
from itertools import product
import unittest

@dataclass(frozen=True)
class BrokerView:
    family: int
    session: int
    ticket: int
    process_pid: int
    five_tuple: int
    kernel_ping: bool
    ssh_alive: bool
    pending_data: bool
    socket_closed_observed: bool

@dataclass(frozen=True)
class World:
    view: BrokerView
    owner_epoch: int
    original_owner_alive: bool
    pid_reused: bool
    process_exit_notice_delivered: bool
    def strict_allow(self):
        return (self.original_owner_alive and self.view.kernel_ping and
                self.view.ssh_alive and self.view.pending_data)


def indistinguishable_pair(family, reused, same_tuple, observer_closed):
    # No verified per-owner exit notification is delivered to the broker.
    # Same app socket/buffer status during finite observation window.
    # Late PID lookup may see a live unrelated process with the same PID.
    v = BrokerView(family, 23, 1, 1800, 777 if same_tuple else 888,
                   True, True, True, observer_closed)
    alive = World(v, 111, True, False, False)
    dead = World(v, 111, False, reused, False)
    return alive, dead

class NegativeProof(unittest.TestCase):
    def test_indistinguishable_owner_liveness(self):
        for family, reuse, five in product([4,6],[False,True],[False,True]):
            living, exited=indistinguishable_pair(family,reuse,five,False)
            self.assertEqual(living.view, exited.view)
            self.assertNotEqual(living.strict_allow(), exited.strict_allow())

    def test_broker_only_boolean_cannot_satisfy_both_worlds(self):
        for f in [4,6]:
            living, exited=indistinguishable_pair(f,True,True,False)
            for decision in [False, True]:
                self.assertNotEqual((decision == living.strict_allow()) and
                                    (decision == exited.strict_allow()), True)

    def test_late_pid_lookup_not_process_identity(self):
        living, exited=indistinguishable_pair(4,True,True,False)
        self.assertEqual(exited.view.process_pid, living.view.process_pid)
        self.assertNotEqual(exited.original_owner_alive, living.original_owner_alive)

    def test_original_appid_cannot_disambiguate_post_claim(self):
        # A snapshot at AUTH is identical even when one owner later dies.
        alive,dead=indistinguishable_pair(6,False,True,False)
        self.assertEqual(alive.view.ticket, dead.view.ticket)
        self.assertEqual(alive.view.session,dead.view.session)
        self.assertNotEqual(alive.strict_allow(), dead.strict_allow())

    def test_health_failure_stops_both_as_expected(self):
        for f in [4,6]:
            alive, dead=indistinguishable_pair(f,False,False,False)
            from dataclasses import replace
            broken=replace(alive,view=replace(alive.view,kernel_ping=False))
            broken2=replace(dead,view=replace(dead.view,ssh_alive=False))
            self.assertFalse(broken.strict_allow())
            self.assertFalse(broken2.strict_allow())

    def test_actual_eof_is_distinguishing_evidence_not_assumed(self):
        alive, dead=indistinguishable_pair(4,False,True,False)
        from dataclasses import replace
        observed=replace(dead,view=replace(dead.view,socket_closed_observed=True))
        self.assertNotEqual(alive.view,observed.view)
        # Whether Windows delivers EOF immediately is NOT asserted.

    def test_cross_family_and_tuple_are_not_owner_epoch(self):
        for family in [4,6]:
            alive, dead=indistinguishable_pair(family,True,True,False)
            self.assertEqual(alive.view.five_tuple,dead.view.five_tuple)
            self.assertNotEqual(alive.original_owner_alive,dead.original_owner_alive)

    def test_sibling_has_distinct_process_identity(self):
        alive,_=indistinguishable_pair(4,False,True,False)
        from dataclasses import replace
        sibling=replace(alive,view=replace(alive.view,process_pid=1801))
        self.assertNotEqual(alive.view,sibling.view)

    def test_no_revocation_signal_is_different_from_true_healthy_liveness(self):
        alive, dead=indistinguishable_pair(6,False,True,False)
        self.assertFalse(dead.process_exit_notice_delivered)
        self.assertTrue(dead.view.kernel_ping and dead.view.ssh_alive)
        self.assertFalse(dead.strict_allow())

if __name__=='__main__':unittest.main(verbosity=2)
