#!/usr/bin/env python3
"""R41: source-derived post-CLAIM process-liveness negative model; NO native API."""
from dataclasses import dataclass
import unittest

@dataclass
class State:
    selected_pid: int = 1001
    broker_pid: int = 2002
    selected_alive: bool = True
    broker_alive: bool = True
    ledger_lost: bool = False
    kernel_lease_lost: bool = False
    auth_seen: bool = True
    ticket_claimed: bool = True
    worker_active: bool = True
    ssh_healthy: bool = True
    revocation: bool = False
    family: int = 4
    five_tuple: tuple = ("192.0.2.10", 40001, "198.51.100.5", 443, 6)

    def process_exit(self, pid: int):
        # Kernel source: ledger.died(pid); redirect.process_exit(pid).
        # redirect.process_exit calls lose() only for BROKER PID.
        if pid == self.selected_pid:
            self.selected_alive = False
        if pid == self.broker_pid:
            self.broker_alive = False
            self.kernel_lease_lost = True

    def pid_reuse(self):
        # The kernel ledger poisons the session on observed reused PID.
        self.ledger_lost = True

    def heartbeat(self):
        # redirect.ready() tests broker identity, not a claimed flow's owner.
        if not self.broker_alive or self.ledger_lost or self.kernel_lease_lost:
            self.revocation = True

    def source_copy_admissible(self, queued_data=True):
        # Existing worker has a watch signal; no selected-process exit event.
        return bool(self.ticket_claimed and self.worker_active and
                    self.ssh_healthy and not self.revocation and queued_data)

    def strict_liveness_oracle(self, queued_data=True):
        return self.source_copy_admissible(queued_data) and self.selected_alive

class PostClaimExitTests(unittest.TestCase):
    def test_healthy_claimed_flow_is_possible_in_model(self):
        for family in (4, 6):
            s = State(family=family)
            s.heartbeat()
            self.assertTrue(s.source_copy_admissible())
            self.assertTrue(s.strict_liveness_oracle())

    def test_selected_death_after_claim_is_not_relay_revocation(self):
        for family in (4, 6):
            s = State(family=family)
            s.process_exit(s.selected_pid)
            s.heartbeat()
            self.assertFalse(s.selected_alive)
            self.assertFalse(s.revocation)
            self.assertTrue(s.source_copy_admissible())
            self.assertFalse(s.strict_liveness_oracle())

    def test_broker_death_revokes(self):
        for family in (4, 6):
            s = State(family=family)
            s.process_exit(s.broker_pid)
            s.heartbeat()
            self.assertTrue(s.revocation)
            self.assertFalse(s.source_copy_admissible())

    def test_pid_reuse_poisons_kernel_ledger_in_model(self):
        s = State()
        s.process_exit(s.selected_pid)
        s.pid_reuse()
        s.heartbeat()
        self.assertFalse(s.source_copy_admissible())

    def test_before_claim_no_ssh_worker_admission(self):
        self.assertFalse(State(ticket_claimed=False).source_copy_admissible())

    def test_loss_of_ssh_or_kernel_lease_stops_model_copy(self):
        for which in ('ssh_healthy', 'kernel_lease_lost'):
            s = State()
            setattr(s, which, which != 'ssh_healthy')
            s.heartbeat()
            self.assertFalse(s.source_copy_admissible())

    def test_same_tuple_and_epoch_not_a_postclaim_liveness_signal(self):
        s = State()
        before = s.five_tuple
        s.process_exit(s.selected_pid)
        s.heartbeat()
        self.assertEqual(before, s.five_tuple)
        self.assertTrue(s.source_copy_admissible())

    def test_no_buffered_bytes_is_not_an_exfiltration_claim(self):
        s = State()
        s.process_exit(s.selected_pid)
        s.heartbeat()
        self.assertFalse(s.source_copy_admissible(queued_data=False))

    def test_udp_and_sibling_are_outside_this_tcp_owner_model(self):
        s = State()
        self.assertEqual(s.five_tuple[-1], 6)
        self.assertNotEqual(s.selected_pid, s.broker_pid)

if __name__ == '__main__':
    unittest.main(verbosity=2)
