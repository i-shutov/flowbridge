#!/usr/bin/env python3
"""R193, independent synthetic AUTH attribution negative tests; never invokes WFP.

Models only the subset of R19 auth_check that gates book.attest(), not Windows
redirect scheduling or complete filter arbitration. A 'foreign' history is a
COUNTERMODEL ASSUMPTION, not observed or proven reachable on Windows.
"""
import csv
import itertools
import io
import sys
import unittest

KEYS = (
    "family", "tcp", "redirected", "not_reauth", "identity_matches",
    "endpoint_matches", "destination_matches", "target_pid_matches",
    "route_ready", "history",
)
HISTORIES = ("flowbridge", "foreign_same_metadata")

def source_gate(case):
    """Conservative model of prerequisites visible in R19 auth_check.

    Assumes other R19 gates (original/current UTF16 AppId validity and selected
    AppId equality, metadata presence, loopback remote port/IP and unique
    live book slot) hold, and that the foreign history exposes identical WFP
    metadata. Both assumptions must be made explicit in any interpretation.
    """
    return all((case["tcp"], case["redirected"], case["not_reauth"],
                case["identity_matches"], case["endpoint_matches"],
                case["destination_matches"], case["target_pid_matches"],
                case["route_ready"]))

def rows():
    # Fixed product order mirrors independent Node oracle. 2 * 2^8 * 2=1024.
    for family in (4,6):
        for bits in itertools.product((0,1), repeat=8):
            for history in HISTORIES:
                case = dict(zip(KEYS, (family, *bits, history)))
                decision = "PERMIT_CANDIDATE_NO_PROVIDER_PROOF" if source_gate(case) else "DENY_OR_NOT_ATTESTED"
                yield (*[case[k] for k in KEYS], decision)

def matrix():
    out=io.StringIO(newline="")
    writer=csv.writer(out,lineterminator="\n")
    writer.writerow((*KEYS,"source_model_decision"))
    writer.writerows(rows())
    return out.getvalue()

class NegativeTests(unittest.TestCase):
    def example(self, **kw):
        c=dict(family=4,tcp=1,redirected=1,not_reauth=1,
            identity_matches=1,endpoint_matches=1,destination_matches=1,
            target_pid_matches=1,route_ready=1,history="flowbridge")
        c.update(kw)
        return c

    def test_positive_is_only_a_candidate(self):
        self.assertTrue(source_gate(self.example()))
        self.assertNotIn("VERIFIED", "PERMIT_CANDIDATE_NO_PROVIDER_PROOF")

    def test_foreign_redirect_same_metadata_is_indistinguishable(self):
        first=self.example(history="flowbridge")
        second=self.example(history="foreign_same_metadata")
        self.assertEqual(source_gate(first),source_gate(second))
        self.assertTrue(source_gate(second))

    def test_missing_redirect_bit_rejected(self):
        self.assertFalse(source_gate(self.example(redirected=0)))

    def test_reauthorization_rejected(self):
        self.assertFalse(source_gate(self.example(not_reauth=0)))

    def test_wrong_identity_endpoint_destination_or_target_rejected(self):
        for k in ("identity_matches","endpoint_matches","destination_matches","target_pid_matches"):
            self.assertFalse(source_gate(self.example(**{k:0})), k)

    def test_udp_and_route_failure_rejected(self):
        for k in ("tcp","route_ready"):
            self.assertFalse(source_gate(self.example(**{k:0})), k)

    def test_both_families_symmetric(self):
        self.assertEqual(source_gate(self.example(family=4)),source_gate(self.example(family=6)))

    def test_matrix_pairing_and_exact_count(self):
        rs=list(rows())
        self.assertEqual(len(rs),1024)
        self.assertEqual(sum(x[-1].startswith("PERMIT") for x in rs),4)
        for a,b in zip(rs[::2],rs[1::2]):
            self.assertEqual(a[:-2],b[:-2])
            self.assertNotEqual(a[-2],b[-2])
            self.assertEqual(a[-1],b[-1])

if __name__=="__main__":
    if len(sys.argv)==2 and sys.argv[1]=="--matrix":
        sys.stdout.write(matrix())
    elif len(sys.argv)==1:
        unittest.main()
    else:
        sys.exit("usage: python auth_provenance_negative.py [--matrix]")
