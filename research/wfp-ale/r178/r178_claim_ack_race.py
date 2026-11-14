#!/usr/bin/env python3
"""R178: deterministic, driver-free negative test for Witness/CLAIM ordering.

NOT a Windows WFP or SSH proof.  Models an imagined future producer/reader
while preserving the source-visible fact that the R19 Book::take path is
independent from Ledger::pop and any durable journal ACK.
"""
from __future__ import annotations
import argparse
import json
import unittest

# PUBLISH precedes AUTH: the redirected WFP request must exist before AUTH.
# QUEUE and PUBLISH are unordered in the *hypothetical* non-atomic fan-out.
# Both paths begin after issuing a kernel-owned transaction R.
PREREQS = {
    'R': '', 'P': 'R', 'A': 'P', 'C': 'A', 'S': 'C',
    'Q': 'R', 'L': 'Q', 'J': 'L', 'K': 'J',
}
EVENTS = ''.join(PREREQS)


def all_schedules(prefix: str = '', left: str = EVENTS):
    if not left:
        yield prefix
        return
    for event in left:
        if all(dependency in prefix for dependency in PREREQS[event]):
            yield from all_schedules(prefix + event, left.replace(event, ''))


def row(family: int, schedule: str):
    at = {e: schedule.index(e) for e in EVENTS}
    return [
        family, schedule,
        at['S'] < at['Q'],             # physical SSH byte before any Witness queue record
        at['S'] < at['J'],             # byte before user-mode persistence
        at['S'] < at['K'],             # byte before authenticated ACK
        at['C'] < at['K'],             # Book::take could succeed without ACK
        at['Q'] < at['P'],             # proposed enqueue-before-context-publication rule
        at['K'] < at['C'],             # proposed trusted ACK-gated claim rule
        at['Q'] < at['P'] and at['K'] < at['C'],
    ]


def matrix():
    schedules = sorted(all_schedules())
    return [row(family, schedule) for family in (4, 6) for schedule in schedules]


class ProposedGate:
    """Counterexample model, NOT implementation of an existing Windows API."""
    def __init__(self, *, ack_required: bool):
        self.issued = self.published = self.auth = self.queued = False
        self.persisted = self.acked = self.claimed = self.sent = False
        self.ack_required = ack_required
        self.terminal = False

    def advance(self, event: str, *, queue_failure=False, journal_failure=False,
                bfe_loss_before_send=False):
        if event == 'R':
            self.issued = True
        elif event == 'P':
            self.published = self.issued
        elif event == 'A':
            self.auth = self.published
        elif event == 'Q':
            self.queued = self.issued and not queue_failure
            self.terminal |= queue_failure
        elif event == 'L':
            self.leased = self.queued
        elif event == 'J':
            self.persisted = self.leased and not journal_failure
        elif event == 'K':
            self.acked = self.persisted
        elif event == 'C':
            self.claimed = (self.published and self.auth and
                            (not self.ack_required or self.acked) and
                            (not self.ack_required or not self.terminal))
        elif event == 'S':
            # The live SSH/BFE guard is separately necessary, even after ACK.
            if bfe_loss_before_send:
                self.terminal = True
            self.sent = self.claimed and (not self.ack_required or not self.terminal)
        else:
            raise ValueError(event)


def run_trace(schedule: str, *, ack_required: bool, **failure):
    model = ProposedGate(ack_required=ack_required)
    for event in schedule:
        model.advance(event, **failure)
    return model


class ProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = matrix()

    def test_complete_70_schedules_per_family(self):
        self.assertEqual(len(self.rows), 140)
        self.assertEqual(len({r[1] for r in self.rows}), 70)
        for r in self.rows:
            at = {e: r[1].index(e) for e in EVENTS}
            self.assertTrue(all(at[d] < at[e] for e, dependencies in PREREQS.items()
                                for d in dependencies))

    def test_counts_and_minimal_counterexamples(self):
        each = self.rows[:70]
        self.assertEqual(tuple(sum(r[i] for r in each) for i in range(2, 9)),
                         (1, 15, 35, 55, 35, 15, 10))
        self.assertEqual([r[1] for r in each if r[2]], ['RPACSQLJK'])
        self.assertEqual([r[1] for r in each if r[7]][0], 'RPAQLJKCS')

    def test_weak_book_claim_before_witness_queue(self):
        weak = run_trace('RPACSQLJK', ack_required=False)
        self.assertTrue(weak.sent)
        self.assertTrue(weak.acked)  # eventually processed, TOO LATE for first byte

    def test_ack_gated_claim_blocks_every_early_claim(self):
        for r in self.rows:
            hardened = run_trace(r[1], ack_required=True)
            self.assertEqual(hardened.sent, r[7], r)
            self.assertFalse(hardened.sent and r[3], r)

    def test_witness_capacity_failure_unblocks_weak_only(self):
        # The 33rd enqueue fails after ticket publication; no durable ACK.
        trace = 'RPACSQLJK'
        weak = run_trace(trace, ack_required=False, queue_failure=True)
        strong = run_trace(trace, ack_required=True, queue_failure=True)
        self.assertTrue(weak.sent)
        self.assertFalse(weak.acked)
        self.assertTrue(weak.terminal)
        self.assertFalse(strong.sent)
        self.assertFalse(strong.acked)

    def test_journal_failure_is_not_successful_ack(self):
        trace = 'RQ LJKPACS'.replace(' ', '')
        weak = run_trace(trace, ack_required=False, journal_failure=True)
        strong = run_trace(trace, ack_required=True, journal_failure=True)
        self.assertTrue(weak.sent)
        self.assertFalse(weak.acked)
        self.assertFalse(strong.sent)

    def test_ack_is_not_permanent_bfe_or_ssh_lease(self):
        trace = 'RQLJKPACS'
        ok = run_trace(trace, ack_required=True)
        revoked = run_trace(trace, ack_required=True, bfe_loss_before_send=True)
        self.assertTrue(ok.sent)
        self.assertFalse(revoked.sent)
        self.assertTrue(revoked.acked)

    def test_both_critical_order_constraints(self):
        for r in self.rows:
            if r[8]:
                self.assertTrue(r[6] and r[7])
                self.assertFalse(r[2] or r[3] or r[4])
        self.assertEqual(sum(r[8] for r in self.rows), 20)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--matrix', action='store_true')
    args = parser.parse_args()
    if args.matrix:
        for entry in matrix():
            print(json.dumps(entry, separators=(',', ':')))
    else:
        unittest.main(argv=['r178_claim_ack_race.py'])
