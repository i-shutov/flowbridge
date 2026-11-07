#!/usr/bin/env python3
"""R28: source-pinned, offline negative tests for endpoint-handle ABA.

No driver, socket, filters, WFP activity, or Windows tests. Independent of R27's
BookProjection. A labelled AUTH is an *oracle-only* field, NOT a WFP input.
"""
from __future__ import annotations

import argparse
import hashlib
import unittest
from dataclasses import dataclass

SOURCE_COMMIT = "e8eac1ea1cb342b79fefdbb8bf21b57dec57397d"
SOURCE_BLOB = "f6200cac997f3c7e2fbd6a60443286727a8c2297"
TTL = 100_000_000
CAP = 32


@dataclass
class Ticket:
    issuance: int
    endpoint: int
    owner: tuple[int, int, int, int]
    destination: tuple[int, int, int]
    stamp: int
    live: bool = True
    auth: bool = False


class Book:
    """R26 Book's relevant issue/retire/attest/take decisions, not real Rust."""

    def __init__(self, tombstone: bool = False):
        self.slots: list[Ticket] = []
        self.issued: set[int] = set()
        self.sequence = 0
        self.lost = False
        self.tombstone = tombstone

    def issue(self, ep: int, owner: tuple, dst: tuple, at: int):
        if self.lost or at <= 0:
            return None
        for t in self.slots:
            if t.live and at >= t.stamp and at - t.stamp > TTL:
                t.live = False
        if self.tombstone and ep in self.issued:
            self.lost = True  # fail-closed, never release for this session
            return None
        if any(t.live and t.endpoint == ep for t in self.slots):
            self.lost = True
            return None
        # CAP represents physical slots, not unbounded allocations.
        if self.tombstone and len(self.issued) == CAP:
            self.lost = True
            return None
        if sum(x.live for x in self.slots) == CAP:
            return None
        self.sequence += 1
        t = Ticket(self.sequence, ep, owner, dst, at)
        self.slots.append(t)
        self.issued.add(ep)
        return t

    def retire(self, t: Ticket):
        t.live = False

    def attest(self, ep: int, owner: tuple, dst: tuple, at: int) -> bool:
        if self.lost:
            return False
        candidates = [s for s in self.slots if s.live and
                      (s.endpoint, s.owner, s.destination) == (ep, owner, dst)]
        if len(candidates) != 1:
            return False
        slot = candidates[0]
        if slot.auth or at < slot.stamp or at - slot.stamp > TTL:
            return False
        slot.auth = True
        return True

    def take(self, t: Ticket, at: int) -> bool:
        if self.lost or not t.live:
            return False
        t.live = False
        return t.auth and at >= t.stamp and at - t.stamp <= TTL


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\x00" + data).hexdigest()


def source_pin(path: str):
    data = open(path, "rb").read()
    actual = git_blob_sha(data)
    if actual != SOURCE_BLOB:
        raise AssertionError(f"STOP: handoff.rs blob changed: {actual} != {SOURCE_BLOB}")
    src = data.decode()
    for needle in (
        "if self.slots.iter().any(|s| s.live && s.context.number(56)==origin.endpoint)",
        "for s in &mut self.slots {if s.live && now.saturating_sub(s.context.number(96))>TTL{s.live=false;}}",
        "pub fn retire(&mut self, context:Context)",
        "let Some(idx)=found else{return false;};",
        "slot.auth_seen=true;",
        "s.live=false; // terminal even on failed, unauthenticated or replayed claim",
    ):
        if needle not in src:
            raise AssertionError(f"STOP: source decision changed: {needle}")


def scenario(lifecycle: str, family: int, variant: int, hardened: bool):
    b = Book(tombstone=hardened)
    origin = (100 + variant, 9001, 9002, 1)  # same PID+epoch+startKey+generation
    dst = (family, 443, 1000 + variant)
    endpoint = 4000 + variant
    a = b.issue(endpoint, origin, dst, 1)
    assert a
    if lifecycle == "retire":
        b.retire(a)  # e.g. another path retires context before AUTH observed
        b_at = 2
    elif lifecycle == "expire":
        b_at = TTL + 3
    elif lifecycle == "claim":
        assert b.attest(endpoint, origin, dst, 2)
        assert b.take(a, 3)
        b_at = 4
    else:
        raise ValueError(lifecycle)
    replacement = b.issue(endpoint, origin, dst, b_at)
    if hardened:
        assert replacement is None and b.lost
        return False
    assert replacement and replacement.issuance != a.issuance
    # Oracle labels the AUTH with A, but actual R26 AUTH input has no issuance id.
    assert b.attest(endpoint, origin, dst, b_at + 1)
    assert b.take(replacement, b_at + 2)
    return True


class NegativeTests(unittest.TestCase):
    def test_three_lifecycle_windows_v4_v6(self):
        for family in (4, 6):
            for lifecycle in ("retire", "expire", "claim"):
                for variant in range(8):
                    with self.subTest(family=family, lifecycle=lifecycle, variant=variant):
                        self.assertTrue(scenario(lifecycle, family, variant, False))
                        self.assertFalse(scenario(lifecycle, family, variant, True))

    def test_hardened_positive_one_time(self):
        b = Book(tombstone=True)
        owner = (9, 10, 11, 12)
        for family in (4, 6):
            ep = 100 + family
            dst = (family, 443, 0)
            c = b.issue(ep, owner, dst, 1)
            self.assertIsNotNone(c)
            self.assertTrue(b.attest(ep, owner, dst, 2))
            self.assertTrue(b.take(c, 3))
            self.assertFalse(b.take(c, 4))

    def test_exhaustion_is_safe_not_live(self):
        b = Book(tombstone=True)
        for n in range(CAP):
            t = b.issue(10_000 + n, (1, 2, 3, 4), (4, 443, n), 1)
            self.assertIsNotNone(t)
            b.retire(t)
        self.assertIsNone(b.issue(100_000, (1, 2, 3, 4), (6, 443, 1), 2))
        self.assertTrue(b.lost)

    def test_original_active_duplicate_also_latches(self):
        for tombstone in (False, True):
            b = Book(tombstone=tombstone)
            self.assertIsNotNone(b.issue(17, (1, 2, 3, 4), (4, 443, 1), 1))
            self.assertIsNone(b.issue(17, (1, 2, 3, 4), (4, 443, 1), 2))
            self.assertTrue(b.lost)

    def test_cross_session_reset_is_not_proven_safe(self):
        # Separate kernel Book sessions carry distinct wire-context nonces,
        # but those bytes are NOT presented to Book::attest at AUTH_CONNECT.
        origin, dst, endpoint = (7, 8, 9, 1), (4, 443, 10), 75
        prior = Book(tombstone=True)
        a = prior.issue(endpoint, origin, dst, 1)
        assert a
        current = Book(tombstone=True)  # fresh Book/session
        b = current.issue(endpoint, origin, dst, 2)
        assert b and b.issuance == a.issuance  # sequence resets too
        # A hypothetically delayed AUTH from the prior session has identical
        # observable fields to AUTH for the new session.
        self.assertTrue(current.attest(endpoint, origin, dst, 3))
        self.assertTrue(current.take(b, 4))
        # Oracle distinguishes sessions; real kernel delivery ordering unknown.
        self.assertNotEqual(id(prior), id(current))

    def test_lookalike_without_same_endpoint_is_rejected(self):
        b = Book()
        a = b.issue(101, (1, 2, 3, 4), (4, 443, 9), 1)
        self.assertFalse(b.attest(102, a.owner, a.destination, 2))
        self.assertFalse(b.attest(101, (1, 2, 3, 5), a.destination, 2))
        self.assertFalse(b.attest(101, a.owner, (4, 443, 10), 2))
        self.assertFalse(b.take(a, 3))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", help="exact handoff.rs in the pinned research HEAD")
    opts = ap.parse_args()
    if opts.source:
        source_pin(opts.source)
    print(f"R28 SOURCE_COMMIT={SOURCE_COMMIT} EXPECTED_BLOB={SOURCE_BLOB} "
          f"PIN={'CHECKED' if opts.source else 'NOT_RUN'}; driver=no; network=no")
    unittest.main(argv=[__file__], verbosity=2)
