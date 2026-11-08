#!/usr/bin/env python3
"""R45 source-contract emulator. Pure stdlib; NO Windows, WFP, SSH or network calls.

This models only boolean lifecycle guards observed at pinned research blob
9a07e026134d46ef646d39862bd982cc48bbc5f6 (redirect.rs) and the
Book terminal kill at e1d17217db50362ba9c4efc83af820b6beb094cf.
It does not execute, compile or validate the production driver.
"""
from dataclasses import dataclass
import unittest

@dataclass(frozen=True)
class Broker:
    pid: int
    process_object: int

class Route:
    def __init__(self):
        self.configured = False
        self.armed = False
        self.book_lost = False
        self.broker = None
        self.claims = 0

    def arm(self, caller: Broker):
        # Model valid ARM input and existing ledger owner only. The source
        # rejects any subsequent ARM on r.configured, even after lose().
        if self.configured or self.book_lost:
            return False
        self.configured = self.armed = True
        self.broker = caller
        return True

    def ready(self, caller: Broker):
        if not self.armed or self.book_lost or caller != self.broker:
            self.lose()
            return False
        return True

    def claim(self, caller: Broker, authorized_auth: bool, family: int):
        assert family in (4, 6)
        if not self.configured or not authorized_auth or not self.ready(caller):
            return False
        self.claims += 1
        return True

    def lose(self):
        self.armed = False
        self.book_lost = True
        # r.configured intentionally remains true (verified in source)

    def broker_exit(self, pid: int):
        if self.broker and self.broker.pid == pid:
            self.lose()

    def stop(self, caller: Broker):
        if caller != self.broker or not self.configured:
            return False
        self.lose()
        return True

class RestartBoundary(unittest.TestCase):
    def test_initial_arm_both_families(self):
        for family in (4, 6):
            with self.subTest(family=family):
                r=Route(); b=Broker(44,111)
                self.assertTrue(r.arm(b));self.assertTrue(r.claim(b,True,family))

    def test_second_arm_disallowed_while_running(self):
        r=Route();b=Broker(44,111);self.assertTrue(r.arm(b))
        self.assertFalse(r.arm(b));self.assertEqual(r.claims,0)

    def test_exit_blocks_rearm_and_old_claim_for_both_families(self):
        for family in (4,6):
            r=Route(); b=Broker(44,111); n=Broker(55,222)
            self.assertTrue(r.arm(b));r.broker_exit(44)
            self.assertTrue(r.configured);self.assertFalse(r.armed);self.assertTrue(r.book_lost)
            self.assertFalse(r.arm(n));self.assertFalse(r.arm(b))
            self.assertFalse(r.claim(b,True,family))

    def test_same_pid_new_process_does_not_rearm(self):
        r=Route();old=Broker(44,111);new=Broker(44,999)
        r.arm(old);r.broker_exit(44);self.assertFalse(r.arm(new))
        self.assertFalse(r.claim(new,True,4))

    def test_health_loss_is_terminal(self):
        r=Route();b=Broker(44,111);r.arm(b);r.lose()
        self.assertFalse(r.arm(Broker(55,222)))
        self.assertFalse(r.claim(b,True,6))

    def test_stop_terminal_and_not_a_rearm(self):
        r=Route();b=Broker(44,111);r.arm(b)
        self.assertTrue(r.stop(b));self.assertFalse(r.arm(b))
        self.assertFalse(r.claim(b,True,4))

    def test_foreign_exit_does_not_kill_broker(self):
        r=Route();b=Broker(44,111);r.arm(b);r.broker_exit(55)
        self.assertTrue(r.ready(b));self.assertTrue(r.configured)

    def test_no_auth_cannot_claim(self):
        r=Route();b=Broker(44,111);r.arm(b)
        self.assertFalse(r.claim(b,False,4))

    def test_unarmed_never_claims(self):
        r=Route();b=Broker(44,111)
        self.assertFalse(r.claim(b,True,4))
        self.assertFalse(r.claim(b,True,6))

    def test_new_driver_instance_is_not_rearm_transition(self):
        old=Route();b=Broker(44,111);old.arm(b);old.broker_exit(44)
        distinct=Route() # hypothetical driver replacement, NOT an action performed
        self.assertTrue(distinct.arm(Broker(55,222)))
        self.assertFalse(old.arm(Broker(55,222)))

    def test_mutant_clear_configured_reveals_contract_break(self):
        r=Route();b=Broker(44,111);r.arm(b);r.broker_exit(44)
        # A hypothetical unsafe change to lose() would allow a new ARM.
        r.configured=False;r.book_lost=False # explicit mutant, NOT current code
        self.assertTrue(r.arm(Broker(55,222)))

if __name__ == '__main__':
    unittest.main(verbosity=2)
