#!/usr/bin/env python3
"""Independent final-admission ticket oracle; no Windows APIs, driver or network.

An in-scope final admission attempt consumes its ticket even when the accepted
socket evidence is incomplete. Preliminary WSAIoctl buffer-size probing must
happen BEFORE admission and is not represented by a call to decide().
"""
from dataclasses import dataclass, replace
from pathlib import Path
import unittest


@dataclass(frozen=True)
class Attempt:
    family: int = 4
    ticket: int = 1
    session: int = 7
    app: bytes = b"opaque:selected"
    transport: str = "TCP"
    kernel_origin: bool = True
    epoch_matches: bool = True
    app_matches: bool = True
    endpoint_matches: bool = True
    records_on_accept: bool = True
    context_on_accept: bool = True
    proxy_record_set_before_connect: bool = True


class IndependentGate:
    def __init__(self, terminal=True):
        self.terminal = terminal
        self.used = set()

    def decide(self, a):
        if a.transport != "TCP":
            return "UNCOVERED"
        if a.app != b"opaque:selected":
            return "OUTSIDE"
        if a.session != 7 or a.ticket <= 0:
            return "REJECT"
        if a.ticket in self.used or len(self.used) >= 4096:
            return "REJECT"
        if self.terminal:
            self.used.add(a.ticket)
        valid = (a.family in (4, 6) and a.kernel_origin and a.epoch_matches
                 and a.app_matches and a.endpoint_matches
                 and a.records_on_accept and a.context_on_accept
                 and a.proxy_record_set_before_connect)
        if not valid:
            return "REJECT"
        if not self.terminal:
            self.used.add(a.ticket)
        return "MODEL_ROUTE"


FLAGS = ("kernel_origin", "epoch_matches", "app_matches", "endpoint_matches",
         "records_on_accept", "context_on_accept",
         "proxy_record_set_before_connect")


class TerminalTicketAudit(unittest.TestCase):
    def test_independent_old_contract_counterexamples(self):
        # 2 IP families x 7 failed-evidence dimensions = 14 distinct traces.
        for family in (4, 6):
            for index, flag in enumerate(FLAGS):
                with self.subTest(family=family, failed=flag):
                    good = Attempt(family=family, ticket=family * 100 + index)
                    bad = replace(good, **{flag: False})
                    old = IndependentGate(terminal=False)
                    self.assertEqual(old.decide(bad), "REJECT")
                    self.assertEqual(old.decide(good), "MODEL_ROUTE")

    def test_fixed_contract_retires_failed_admission(self):
        for family in (4, 6):
            for index, flag in enumerate(FLAGS):
                with self.subTest(family=family, failed=flag):
                    good = Attempt(family=family, ticket=family * 100 + index)
                    bad = replace(good, **{flag: False})
                    fixed = IndependentGate(terminal=True)
                    self.assertEqual(fixed.decide(bad), "REJECT")
                    self.assertEqual(fixed.decide(good), "REJECT")
                    fresh = replace(good, ticket=good.ticket + 10_000)
                    self.assertEqual(fixed.decide(fresh), "MODEL_ROUTE")

    def test_unselected_and_foreign_session_do_not_poison_selected_ticket(self):
        for family in (4, 6):
            good = Attempt(family=family, ticket=family * 10000)
            fixed = IndependentGate()
            self.assertEqual(fixed.decide(replace(good, session=8)), "REJECT")
            self.assertEqual(fixed.decide(replace(good, app=b"opaque:sibling")), "OUTSIDE")
            self.assertEqual(fixed.decide(good), "MODEL_ROUTE")
            self.assertEqual(fixed.decide(good), "REJECT")

    def test_published_rust_source_has_prevalidation_ticket_burn(self):
        source_path = Path(__file__).with_name("trust_contract.rs")
        if not source_path.exists():
            self.skipTest("No full checkout; independent oracle only")
        source = source_path.read_text(encoding="utf-8")
        start = source.index("pub fn decide(")
        end = source.index("\n}\n", start)
        body = source[start:end]
        positions = [
            body.index("if classify.transport != Transport::Tcp"),
            body.index("if classify.identity.app_id != self.selected_app_id"),
            body.index("if classify.session == 0"),
            body.index("if !self.consumed.insert(classify.ticket)"),
            body.index("accepted.captured != *classify"),
        ]
        self.assertEqual(positions, sorted(positions),
                         "retire ticket before checking a possibly missing/foreign receipt")
        self.assertEqual(body.count("self.consumed.insert(classify.ticket)"), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
