#!/usr/bin/env python3
"""R211: executable differential negatives for R201 temporal abstraction.
No WFP, sockets, drivers, network, system services, or privileged calls.
PASS shows missing model coverage, NOT a Windows/kernel bug.
"""
from dataclasses import dataclass
from pathlib import Path
from hashlib import sha1
import sys
import unittest

TTL = 100_000_000  # R19 Book: 10 seconds, 100 ns ticks
LEASE = 30_000_000  # R19 ready(): 3 seconds, 100 ns ticks

@dataclass(frozen=True)
class Origin:
    pid: int
    epoch: int
    start_key: int
    endpoint: int
    family: int

class R201ValueModel:
    """Only R201's timing-relevant issue/attest/claim predicates. No clock."""
    def __init__(self):
        self.selected_live = True
        self.broker_live = True
        self.healthy = True
        self.seen = set()
        self.tickets = {}

    def issue(self, o):
        if (not self.healthy or not self.selected_live or not self.broker_live
                or o.endpoint in self.seen or o.family not in (4, 6)):
            return False
        self.seen.add(o.endpoint)
        self.tickets[o.endpoint] = [o, False]
        return True

    def attest(self, o):
        t = self.tickets.get(o.endpoint)
        if t is None or t[0] != o or t[1]:
            return False
        t[1] = True
        return True

    def claim(self, o):
        t = self.tickets.pop(o.endpoint, None)
        return bool(self.healthy and self.selected_live and self.broker_live
                    and t and t[0] == o and t[1])

    def health_lost(self):
        self.healthy = False
        self.tickets.clear()

class R19TemporalGate:
    """R19 Book.take timestamp and redirect::ready lease; separate model."""
    def __init__(self, issued, heartbeat):
        self.issued = issued
        self.heartbeat = heartbeat

    def approve(self, claim_at):
        return (claim_at >= self.issued and claim_at - self.issued <= TTL
                and claim_at >= self.heartbeat and claim_at - self.heartbeat <= LEASE)

class Negative(unittest.TestCase):
    def test_expired_ticket_accepted_only_by_timeless_model(self):
        for family in (4, 6):
            o = Origin(101,1001,2001,31+family,family)
            m = R201ValueModel()
            self.assertTrue(m.issue(o))
            self.assertTrue(m.attest(o))
            at = 1_000_000 + TTL + 1
            self.assertFalse(R19TemporalGate(1_000_000,1_000_000+TTL).approve(at))
            self.assertTrue(m.claim(o))  # NEGATIVE: no clock parameter in R201

    def test_stale_broker_lease_accepted_only_by_timeless_model(self):
        o = Origin(102,1002,2002,42,4)
        m = R201ValueModel()
        self.assertTrue(m.issue(o))
        self.assertTrue(m.attest(o))
        self.assertFalse(R19TemporalGate(1,1).approve(1+LEASE+1))
        self.assertTrue(m.claim(o))  # NEGATIVE: no automatic heartbeat check

    def test_rollback_clock_not_detectable_in_r201(self):
        o = Origin(103,1003,2003,43,6)
        m = R201ValueModel()
        self.assertTrue(m.issue(o))
        self.assertTrue(m.attest(o))
        self.assertFalse(R19TemporalGate(100,100).approve(99))
        self.assertTrue(m.claim(o))

    def test_exact_ttl_boundary_with_live_lease_positive_control(self):
        for family in (4, 6):
            o = Origin(105,1005,2005,45+family,family)
            m = R201ValueModel()
            self.assertTrue(m.issue(o))
            self.assertTrue(m.attest(o))
            self.assertTrue(R19TemporalGate(100,100+TTL).approve(100+TTL))
            self.assertTrue(m.claim(o))
            self.assertFalse(m.claim(o))

    def test_health_signal_and_process_death_separate_gates(self):
        o = Origin(106,1006,2006,47,4)
        m = R201ValueModel()
        self.assertTrue(m.issue(o))
        self.assertTrue(m.attest(o))
        m.health_lost()
        self.assertFalse(m.claim(o))
        m = R201ValueModel()
        self.assertTrue(m.issue(o))
        self.assertTrue(m.attest(o))
        m.selected_live = False
        self.assertFalse(m.claim(o))

    def test_pid_epoch_udp_and_endpoint_aba_controls(self):
        o = Origin(107,1007,2007,48,4)
        m = R201ValueModel()
        self.assertTrue(m.issue(o))
        self.assertTrue(m.attest(o))
        wrong = Origin(o.pid,o.epoch+1,o.start_key,o.endpoint,o.family)
        self.assertFalse(m.claim(wrong))
        self.assertFalse(m.issue(o))  # tombstone after terminal failed CLAIM
        self.assertFalse(m.issue(Origin(107,1007,2007,49,17)))

def source_gate():
    root = Path(__file__).resolve().parents[1]
    pinned = {
        'r201': ('r201/selective_ledger.rs','bc4c02daf2f09609cfa11b595d842e5ad2608625'),
        'r19_book': ('kernel-r19/kernel/src/handoff.rs','e1d17217db50362ba9c4efc83af820b6beb094cf'),
        'r19_redirect': ('kernel-r19/kernel/src/redirect.rs','a093f049d162987981a957aac90db1014bc6ff09'),
    }
    source = {}
    for name,(file,expected) in pinned.items():
        raw = (root/file).read_bytes()
        observed = sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        if observed != expected:
            raise AssertionError((name, observed, expected))
        source[name] = raw.decode()
    a,b,c = source['r201'],source['r19_book'],source['r19_redirect']
    guards = [
        'pub fn claim(&mut self, id: &Identity, endpoint: u64) -> Decision {' in a,
        'pub fn attest(&mut self, id: &Identity, endpoint: u64, family: u8,' in a,
        'pub fn issue(&mut self, id: &Identity, endpoint: u64, family: u8,' in a,
        'pub const TTL: u64 = 100_000_000;' in b,
        'pub const LEASE: u64 = 30_000_000;' in b,
        'pub fn take(&mut self, context:Context, now:u64)->Option<Context> {' in b,
        'now<context.number(96) || now-context.number(96)>TTL' in b,
        'time<r.last||time-r.last>h::LEASE' in c,
        'if input.len()!=h::LEN||!ready(time)' in c,
        'let Some(c)=(*ROUTE.0.get()).book.take(c,time)' in c,
    ]
    if not all(guards): raise AssertionError(guards)
    print('Source pins: 3 Git blobs; 10/10 structural guards PASS (not native Rust/WFP)')

if __name__=='__main__':
    if '--source' in sys.argv:
        source_gate()
        sys.argv.remove('--source')
    unittest.main(verbosity=2)
