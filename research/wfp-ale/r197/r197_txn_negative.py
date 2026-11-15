#!/usr/bin/env python3
"""R197 user-mode source order and API-contract negative tests; no native WFP calls."""
from pathlib import Path
import unittest
import sys

SESSION = "session_count(engine.0)"
BEGIN = "FwpmTransactionBegin0(engine.0"
INSPECT = "inspect(engine.0, &selected, sessions)"

def guard(src):
    a, b = src.find("    fn run(selected_exe:"), src.find("    pub fn main()")
    c = src.find("    unsafe fn inspect(")
    if min(a, b, c) < 0 or c >= a: return False
    run, inspect = src[a:b], src[c:a]
    i, j, k = (run.find(x) for x in (SESSION, BEGIN, INSPECT))
    return (min(i, j, k) >= 0 and i < j < k
            and run.count(SESSION) == 1 and run.count(BEGIN) == 1
            and "session_count(engine)?" not in inspect
            and "FwpmFilterCreateEnumHandle0(" in src
            and "FwpmSessionCreateEnumHandle0(" in src
            and "FwpmTransactionAbort0(engine.0)" in run
            and not any(x in src for x in ("FwpmFilterAdd0(", "FwpmCalloutAdd0(", "FwpmSubLayerAdd0(", "FwpsCalloutRegister")))

def contract(events):
    transaction = False
    for event in events:
        if event == "begin":
            if transaction: return "FWP_E_TXN_IN_PROGRESS"
            transaction = True
        elif event == "session_create" and transaction:
            return "FWP_E_TXN_IN_PROGRESS"
        elif event in ("commit", "abort"):
            transaction = False
    return "SUCCESS_BY_TRANSACTION_RULE_ONLY"

class Test(unittest.TestCase):
    def test_old_order_fails(self):
        self.assertEqual(contract(["begin","session_create","filter_create","commit"]), "FWP_E_TXN_IN_PROGRESS")
    def test_new_order_passes_contract_only(self):
        self.assertEqual(contract(["session_create","begin","filter_create","commit"]), "SUCCESS_BY_TRANSACTION_RULE_ONLY")
    def test_mutated_order_negative(self):
        fixture = ("    unsafe fn inspect() {}\n"
                   "    fn run(selected_exe: &OsStr) {\n"
                   "      session_count(engine.0); FwpmTransactionBegin0(engine.0, FWPM_TXN_READ_ONLY);\n"
                   "      inspect(engine.0, &selected, sessions); FwpmTransactionAbort0(engine.0);\n"
                   "    }\n    pub fn main() {}\n"
                   "FwpmSessionCreateEnumHandle0( ; FwpmFilterCreateEnumHandle0( ;")
        self.assertTrue(guard(fixture))
        self.assertFalse(guard(fixture.replace("session_count(engine.0); FwpmTransactionBegin0(engine.0", "FwpmTransactionBegin0(engine.0; session_count(engine.0)")))
        self.assertFalse(guard(fixture + "\nFwpmFilterAdd0("))
        self.assertFalse(guard(fixture.replace("FwpmSessionCreateEnumHandle0(", "Unavailable(")))

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Test)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if len(sys.argv) == 2:
        src = Path(sys.argv[1]).read_text(encoding="utf-8")
        ok = guard(src)
        print("FULL_SOURCE_ORDER:", "PASS" if ok else "FAIL")
        if not ok: sys.exit(1)
    if not result.wasSuccessful(): sys.exit(1)
