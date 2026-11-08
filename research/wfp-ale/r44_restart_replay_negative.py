#!/usr/bin/env python3
"""R44 executable negative tests, pure Python standard library. No sockets/OS actions.
The Gate is a *specification emulator* of the R43 in-memory ACK/session behavior;
this is not a native Rust execution, WFP attestation, or physical egress test.
"""
import unittest
from dataclasses import dataclass

@dataclass(frozen=True)
class Owner:
    pid: int
    epoch: int
    process_key: int
    exe: int

@dataclass(frozen=True)
class Ticket:
    session: int
    ident: int
    owner: Owner
    family: int
    endpoint: int
    tuple_hint: int

class VolatileGate:
    def __init__(self, session):
        self.session = session
        self.seq = 1
        self.issued = {}
        self.claimed = set()
        self.dead = set()
        self.stopped = not bool(session)

    def accept(self, session, seq, kind, payload):
        if self.stopped or session != self.session or seq != self.seq:
            self.stopped = True
            return None
        ok = False
        if kind == 'issue':
            t = payload
            ok = t.session == session and t.ident not in self.issued and t.owner not in self.dead
            if ok:
                self.issued[t.ident] = t
        elif kind == 'claim':
            t = payload
            ok = self.issued.get(t.ident) == t and t.ident not in self.claimed and t.owner not in self.dead
            if ok:
                self.claimed.add(t.ident)
        elif kind == 'exit':
            self.dead.add(payload)
            ok = True
        elif kind == 'stop':
            self.stopped = True
            ok = True
        if not ok:
            self.stopped = True
            return None
        self.seq += 1
        return seq  # volatile watermark, NOT a durable ACK

    def permits(self, ticket):
        return not self.stopped and self.issued.get(ticket.ident) == ticket \
            and ticket.ident in self.claimed and ticket.owner not in self.dead


def sample(family=4, epoch=17, session=42):
    return Ticket(session, 99, Owner(1200, epoch, epoch + 7000, 341), family, 314159, 255)


def admit(g, t):
    assert g.accept(t.session, 1, 'issue', t) == 1
    assert g.accept(t.session, 2, 'claim', t) == 2

class RestartReplayTests(unittest.TestCase):
    def test_initial_claim_and_exit_for_ipv4_ipv6(self):
        for family in (4, 6):
            t = sample(family)
            g = VolatileGate(t.session)
            admit(g, t)
            self.assertTrue(g.permits(t))
            self.assertEqual(g.accept(t.session, 3, 'exit', t.owner), 3)
            self.assertFalse(g.permits(t))

    def test_ack_3_not_persistent_across_same_session_restart(self):
        for family in (4, 6):
            t = sample(family)
            before = VolatileGate(t.session)
            admit(before, t)
            self.assertEqual(before.accept(t.session, 3, 'exit', t.owner), 3)
            self.assertFalse(before.permits(t))
            after = VolatileGate(t.session)  # a deliberately UNSAFE session-reuse assumption
            admit(after, t)  # replay old previously valid Issue/Claim frames
            self.assertTrue(after.permits(t))  # counterexample, NOT claimed native exploit

    def test_fresh_session_rejects_old_frames(self):
        t = sample()
        after = VolatileGate(t.session + 1)
        self.assertIsNone(after.accept(t.session, 1, 'issue', t))
        self.assertTrue(after.stopped)
        self.assertFalse(after.permits(t))

    def test_restart_without_replay_is_closed(self):
        t = sample()
        after = VolatileGate(t.session)
        self.assertFalse(after.permits(t))

    def test_replayed_claim_alone_is_closed(self):
        t = sample()
        after = VolatileGate(t.session)
        self.assertIsNone(after.accept(t.session, 1, 'claim', t))
        self.assertFalse(after.permits(t))

    def test_exit_replayed_before_issue_blocks(self):
        t = sample()
        after = VolatileGate(t.session)
        self.assertEqual(after.accept(t.session, 1, 'exit', t.owner), 1)
        self.assertIsNone(after.accept(t.session, 2, 'issue', t))
        self.assertFalse(after.permits(t))

    def test_pid_and_tuple_reuse_do_not_restore_old_owner(self):
        t = sample()
        g = VolatileGate(t.session)
        admit(g, t)
        g.accept(t.session, 3, 'exit', t.owner)
        successor = sample(epoch=t.owner.epoch + 1)
        self.assertEqual(successor.owner.pid, t.owner.pid)
        self.assertEqual(successor.tuple_hint, t.tuple_hint)
        self.assertNotEqual(successor.owner, t.owner)
        self.assertFalse(g.permits(t))

    def test_duplicate_sequence_rejected(self):
        t = sample()
        g = VolatileGate(t.session)
        admit(g, t)
        self.assertIsNone(g.accept(t.session, 2, 'claim', t))
        self.assertFalse(g.permits(t))

    def test_no_claim_for_sibling_exe(self):
        t = sample()
        g = VolatileGate(t.session)
        g.accept(t.session, 1, 'issue', t)
        sibling = Ticket(t.session, t.ident, Owner(t.owner.pid + 1, t.owner.epoch, t.owner.process_key + 1, 999), t.family, t.endpoint, t.tuple_hint)
        self.assertIsNone(g.accept(t.session, 2, 'claim', sibling))
        self.assertFalse(g.permits(t))

if __name__ == '__main__':
    unittest.main(verbosity=2)
