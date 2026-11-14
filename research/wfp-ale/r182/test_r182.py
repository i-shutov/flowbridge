"""Tests are offline logical safety checks; no WFP probes or system modifications."""
import collections
import hashlib
import unittest
from dataclasses import replace
from r182_authorized_flow_negative import (
    Certificate, world_pair, strict_authorize, unsafe_tuple_authorize, matrix, canonical,
    FAMILIES, CAUSES, DIRECTIONS, METADATA
)

class AuthorizedFlowTest(unittest.TestCase):
    def test_best_case_independent_of_packet_direction(self):
        for f in FAMILIES:
            for d in DIRECTIONS:
                for m in METADATA:
                    for cause in CAUSES:
                        c, o = world_pair(f, "selected", "reauth", cause, d, "trusted", m)
                        self.assertTrue(strict_authorize(c, o))

    def test_all_unsafe_worlds_are_denied(self):
        worlds=("sibling_direct", "proxy_ssh", "pid_reused", "endpoint_reused",
                "tuple_reused", "foreign_compartment", "owner_dead", "bfe_lost", "ssh_lost",
                "revoked", "witness_unacked", "claim_absent", "not_established", "udp_dns")
        for w in worlds:
            for f in FAMILIES:
                c,o=world_pair(f, w, "reauth", "policy", "in", "trusted", "fwp_empty")
                self.assertFalse(strict_authorize(c,o), w)

    def test_untrusted_join_never_permits(self):
        for token in ("missing", "forged", "stale"):
            for f in FAMILIES:
                c,o=world_pair(f, "selected", "reauth", "policy", "out", token, "full")
                self.assertFalse(strict_authorize(c,o))

    def test_reauth_not_an_initial_or_honor_permit(self):
        for phase in ("initial", "honor"):
            c,o=world_pair(4, "selected", phase, "policy", "out", "trusted", "full")
            self.assertFalse(strict_authorize(c,o))

    def test_tuple_only_unsafe_false_admits(self):
        for w in ("pid_reused", "endpoint_reused", "tuple_reused", "foreign_compartment",
                  "owner_dead", "bfe_lost", "ssh_lost", "revoked", "claim_absent"):
            c,o=world_pair(6, w, "reauth", "policy", "in", "missing", "fwp_empty")
            self.assertTrue(unsafe_tuple_authorize(c,o), w)
            self.assertFalse(strict_authorize(c,o), w)

    def test_missing_any_critical_credential_denies(self):
        c,o=world_pair(4,"selected","reauth","interface","out","trusted","full")
        for field, val in (("original_appid","sibling"),("creation_epoch",234),
            ("exe_id","exe-other"),("owner_pid",100),("endpoint",999),
            ("generation",22),("compartment",8),("family",6),("protocol","udp"),
            ("session_epoch",15),("bfe_epoch",15),("ssh_epoch",15),
            ("tuple_id","tuple-other"),("kernel_join_attested",False),
            ("presented_flow","foreign")):
            self.assertFalse(strict_authorize(c,replace(o,**{field:val})),field)
        for field in ("witness_ack","claimed","established","owner_alive"):
            self.assertFalse(strict_authorize(replace(c,**{field:False}),o),field)
        self.assertFalse(strict_authorize(replace(c,revoked=True),o))

    def test_full_matrix_counts_are_fixed(self):
        counts=collections.Counter()
        hasher=hashlib.sha256()
        for r in matrix():
            counts["total"]+=1
            for field in ("strict","unsafe","false_allow"):
                counts[field]+=r[field]
            hasher.update((canonical(r)+'\n').encode())
        self.assertEqual(counts['total'],2*3*4*2*4*2*15)
        self.assertEqual(counts['strict'],2*1*4*2*1*2*1)
        self.assertGreater(counts['false_allow'],0)
        print('R182 COUNTS',dict(counts),'SHA256',hasher.hexdigest())

if __name__ == '__main__': unittest.main()
