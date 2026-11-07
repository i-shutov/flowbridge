#!/usr/bin/env python3
"""R27: deterministic negative test of R26 Book::attest issuance boundary.
Offline model, NOT a native WFP/driver proof. Python 3.13, standard library.
"""
import argparse
import hashlib
from dataclasses import dataclass

COMMIT = "472cbc739f9ba9f8108c5e352312769e8d7ddce5"
BLOB = "f6200cac997f3c7e2fbd6a60443286727a8c2297"
TTL = 100_000_000

@dataclass
class Ticket:
    seq: int
    endpoint: int
    origin: tuple
    dest: tuple
    issued: int
    live: bool = True
    auth_seen: bool = False

class BookProjection:
    def __init__(self):
        self.slots = []
        self.seq = 0
        self.lost = False

    def issue(self, endpoint, origin, dest, now):
        for t in self.slots:
            if t.live and max(now - t.issued, 0) > TTL:
                t.live = False
        if any(t.live and t.endpoint == endpoint for t in self.slots):
            self.lost = True
            return None
        self.seq += 1
        t = Ticket(self.seq, endpoint, origin, dest, now)
        self.slots.append(t)
        return t

    def attest(self, endpoint, origin, dest, now):
        candidates = [t for t in self.slots if t.live and
                      (t.endpoint, t.origin, t.dest) == (endpoint, origin, dest)]
        if len(candidates) != 1:
            return False
        t = candidates[0]
        if t.auth_seen or now < t.issued or now - t.issued > TTL:
            return False
        t.auth_seen = True
        return True

    def take(self, ticket, now):
        if not ticket.live:
            return False
        ticket.live = False
        return ticket.auth_seen and ticket.issued <= now <= ticket.issued + TTL

def pin_source(path):
    data = open(path, "rb").read()
    h = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    assert h == BLOB, f"STOP: source changed: {h} != {BLOB}"
    s = data.decode()
    for part in ("s.context.number(56)==origin.endpoint",
                 "slot.context.matches_origin(origin) && slot.context.destination()==destination",
                 "slot.auth_seen=true;", "now.saturating_sub(s.context.number(96))>TTL"):
        assert part in s, f"STOP: source structure changed: {part}"

def run():
    cases = 0
    for family in (4, 6):
        for variant in range(8):
            book = BookProjection()
            endpoint = 2000 + variant
            origin = (42, 100, 200, 1)  # pid, epoch, start key, generation
            dest = (family, variant, 443)
            old = book.issue(endpoint, origin, dest, 1)
            assert old is not None
            replacement_time = TTL + 2
            new = book.issue(endpoint, origin, dest, replacement_time)
            assert new is not None and new.seq != old.seq and not old.live
            # Labelled AUTH comes from old. R26 takes only endpoint+origin+dest,
            # so it cannot distinguish this event from a new-ticket AUTH.
            assert book.attest(endpoint, origin, dest, replacement_time + 1)
            assert book.take(new, replacement_time + 2)
            assert old.seq != new.seq  # independent issuance-aware oracle rejects
            cases += 1
        book = BookProjection()
        o, d, e = (42, 100, 200, 1), (family, 0, 443), 3000
        t = book.issue(e, o, d, 1)
        assert not book.take(t, 2), "negative control: unauthenticated claim"
        book = BookProjection()
        t = book.issue(e, o, d, 1)
        assert book.attest(e, o, d, 2) and book.take(t, 3)
        assert not book.take(t, 4), "positive control: terminal claim"
        book = BookProjection()
        t = book.issue(e, o, d, 1)
        assert not book.attest(e+1, o, d, 2)
        assert not book.attest(e, o, (family, 9, 443), 2)
        assert not book.take(t, 3), "mismatch controls"
    print(f"R27 COUNTEREXAMPLE={cases}/16; CONTROLS=6/6; SOURCE_PIN={BLOB}")
    print("NO-GO for issuance provenance under assumed late AUTH + endpoint reuse; NOT observed on Windows")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", help="exact handoff.rs; requires pinned Git blob")
    args = ap.parse_args()
    if args.source:
        pin_source(args.source)
    run()
