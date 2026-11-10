"""R88 conditional original-AppId SSH self-block negative model; zero OS/network calls."""
from itertools import product
from pathlib import Path
from collections import Counter
import hashlib
import unittest

ROOT = Path(__file__).resolve().parents[3]
P = ROOT / "research/wfp-ale/kernel-r19/policy_windows.rs"
K = ROOT / "research/wfp-ale/kernel-r19/kernel/src/redirect.rs"
B = ROOT / "research/wfp-ale/kernel-r19/broker_windows.rs"

def decide(origin, remote, redirect, metadata, write, ticket):
    if origin == "UNKNOWN":
        return "UNKNOWN_FILTER_MATCH"
    if origin == "BROKER":
        return "FILTER_NOT_SELECTED"
    if not write:
        return "RIGHTS_UNPROVEN"
    if remote != "LOOPBACK" or not (redirect and metadata and ticket):
        return "SOURCE_BLOCK"
    return "AUTH_CANDIDATE"

def matrix():
    for family, origin, remote, redirect, metadata, write, ticket in product(
        ("4","6"), ("SELECTED","BROKER","UNKNOWN"), ("LOOPBACK","REMOTE"),
        (False,True), (False,True), (False,True), (False,True)
    ):
        yield family, origin, remote, redirect, metadata, write, ticket, decide(
            origin, remote, redirect, metadata, write, ticket
        )

def serialization():
    return "".join("|".join((f,o,r,str(int(d)),str(int(m)),str(int(w)),str(int(t)),s))+"\n"
        for f,o,r,d,m,w,t,s in matrix())

class Tests(unittest.TestCase):
    def test_size(self):
        self.assertEqual(len(list(matrix())),192)
    def test_remote_selected_conditional_block(self):
        for family in ("4","6"):
            for redirect,metadata,ticket in product((False,True),repeat=3):
                self.assertEqual(decide("SELECTED","REMOTE",redirect,metadata,True,ticket),"SOURCE_BLOCK")
    def test_broker_not_selected(self):
        self.assertEqual(decide("BROKER","REMOTE",True,True,True,True),"FILTER_NOT_SELECTED")
    def test_unknown_not_inferred(self):
        self.assertEqual(decide("UNKNOWN","REMOTE",True,True,True,True),"UNKNOWN_FILTER_MATCH")
    def test_loopback_requires_all(self):
        self.assertEqual(decide("SELECTED","LOOPBACK",True,True,True,True),"AUTH_CANDIDATE")
        self.assertEqual(decide("SELECTED","LOOPBACK",True,False,True,True),"SOURCE_BLOCK")
    def test_no_right_no_enforcement_claim(self):
        self.assertEqual(decide("SELECTED","REMOTE",True,True,False,True),"RIGHTS_UNPROVEN")
    def test_actual_checkout_source(self):
        if not all(p.exists() for p in (P,K,B)):
            self.skipTest("full checkout unavailable; Git blob source checked separately")
        p,k,b = (path.read_text(encoding="utf-8") for path in (P,K,B))
        for needle in ("FWPM_CONDITION_ALE_ORIGINAL_APP_ID","FWP_ACTION_CALLOUT_TERMINATING",
                       "r.kind==Kind::AttestOriginal","FWPM_LAYER_ALE_AUTH_CONNECT_V4",
                       "FWPM_LAYER_ALE_AUTH_CONNECT_V6"):
            self.assertIn(needle,p)
        for needle in ("if !loopback{return false;}","if !auth_check(values,meta){block(out);return;}",
                       "FWPS_RIGHT_ACTION_WRITE"):
            self.assertIn(needle,k)
        for needle in ("claim_and_connect_trusted_ssh","SET_RECORDS,self.records.as_ptr()",
                       "ip:remote.ip().octets()"):
            self.assertIn(needle,b)

if __name__=="__main__":
    test = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    rows = list(matrix())
    print("MATRIX",len(rows),dict(sorted(Counter(row[-1] for row in rows).items())),
          hashlib.sha256(serialization().encode()).hexdigest())
    raise SystemExit(0 if test.wasSuccessful() else 1)
