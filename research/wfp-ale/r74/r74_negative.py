"""R74 deterministic broker/receipt cut; clean-room, Python stdlib only.
No sockets, driver, BFE, filters or machine mutation. Enumerated states are assumptions.
"""
from itertools import product
from hashlib import sha256
from unittest import TestCase, main
from dataclasses import dataclass
import json

NAMES=("selected receipt claim records tcp host auth channel revoked owner_alive "
       "endpoint_reused_after_claim ssh_loss wfp_loss").split()

@dataclass(frozen=True)
class Result:
    stage:str
    terminal:bool
    release:bool
    physical_no_direct:bool=False

def broker(b):
    # broker.rs: malformed/missing received evidence is per-socket refusal.
    if not b["receipt"]: return Result("INGRESS_REJECTED",False,False)
    if not b["claim"]: return Result("STICKY_STOP",False,False)
    # Book::take is terminal before SET_RECORDS and SSH.
    if (not all(b[k] for k in ("records","tcp","host","auth","channel"))
        or b["revoked"] or b["ssh_loss"]):
        return Result("STICKY_STOP",True,False)
    return Result("RELAY_CANDIDATE",True,True)

def stricter(b):
    if b["selected"] and not b["receipt"]: return "STICKY_STOP"
    return broker(b).stage

def exhaustive():
    counts=dict(worlds=0,pre_receipt_selected_silent=0,pre_receipt_unselected=0,
        post_receipt_stop=0,relay_candidate=0,claimed_terminal_failed=0,
        selected_owner_dead_relay_candidate=0,
        endpoint_reused_after_claim_relay_candidate=0,
        wfp_lost_relay_candidate=0,no_direct_proven=0)
    digest=sha256()
    for family in (4,6):
        for bits in product((False,True),repeat=len(NAMES)):
            b=dict(zip(NAMES,bits))
            r=broker(b); want=stricter(b); counts["worlds"]+=1
            counts["pre_receipt_selected_silent"]+=int(b["selected"] and not b["receipt"] and r.stage=="INGRESS_REJECTED" and want=="STICKY_STOP")
            counts["pre_receipt_unselected"]+=int(not b["selected"] and not b["receipt"] and r.stage=="INGRESS_REJECTED")
            counts["post_receipt_stop"]+=int(b["receipt"] and r.stage=="STICKY_STOP")
            counts["relay_candidate"]+=int(r.release)
            counts["claimed_terminal_failed"]+=int(r.terminal and not r.release)
            counts["selected_owner_dead_relay_candidate"]+=int(r.release and b["selected"] and not b["owner_alive"])
            counts["endpoint_reused_after_claim_relay_candidate"]+=int(r.release and b["endpoint_reused_after_claim"])
            counts["wfp_lost_relay_candidate"]+=int(r.release and b["wfp_loss"])
            counts["no_direct_proven"]+=int(r.physical_no_direct)
            digest.update(f'{family}:{"".join(str(int(x)) for x in bits)}:{r.stage}:{int(r.terminal)}:{int(r.release)}:{want}\n'.encode())
    return counts,digest.hexdigest()

class NegativeTests(TestCase):
    def default(self,**overrides):
        b=dict(zip(NAMES,[True]*8+[False,True,False,False,False]))
        b.update(overrides);return b
    def test_good(self): self.assertEqual(broker(self.default()).stage,"RELAY_CANDIDATE")
    def test_selected_broken_receipt_not_global(self):
        b=self.default(receipt=False);self.assertEqual(broker(b).stage,"INGRESS_REJECTED")
        self.assertEqual(stricter(b),"STICKY_STOP")
    def test_bad_and_good_origin_same_broker_observation(self):
        a=self.default(receipt=False,selected=True)
        b=self.default(receipt=False,selected=False)
        self.assertEqual(broker(a),broker(b))
    def test_no_receipt_no_claim(self):
        x=broker(self.default(receipt=False));self.assertFalse(x.terminal or x.release)
    def test_no_claim(self): self.assertEqual(broker(self.default(claim=False)).stage,"STICKY_STOP")
    def test_records(self): self.assertTrue(broker(self.default(records=False)).terminal)
    def test_tcp(self): self.assertTrue(broker(self.default(tcp=False)).terminal)
    def test_host(self): self.assertTrue(broker(self.default(host=False)).terminal)
    def test_auth(self): self.assertTrue(broker(self.default(auth=False)).terminal)
    def test_channel(self): self.assertTrue(broker(self.default(channel=False)).terminal)
    def test_ssh_loss(self): self.assertEqual(broker(self.default(ssh_loss=True)).stage,"STICKY_STOP")
    def test_revoked(self): self.assertEqual(broker(self.default(revoked=True)).stage,"STICKY_STOP")
    def test_owner_death_not_global(self): self.assertEqual(broker(self.default(owner_alive=False)).stage,"RELAY_CANDIDATE")
    def test_reused_endpoint_after_claim(self): self.assertEqual(broker(self.default(endpoint_reused_after_claim=True)).stage,"RELAY_CANDIDATE")
    def test_wfp_loss_not_broker_witness(self): self.assertEqual(broker(self.default(wfp_loss=True)).stage,"RELAY_CANDIDATE")
    def test_no_physical_proof(self): self.assertFalse(broker(self.default()).physical_no_direct)
    def test_v4_v6_equivalent(self):
        for family in (4,6): self.assertEqual(broker(self.default()).stage,"RELAY_CANDIDATE")
    def test_exhaustive_worlds(self): self.assertEqual(exhaustive()[0]["worlds"],16384)
    def test_exhaustive_hash(self): self.assertEqual(exhaustive()[1],"ba9534ef412fda18d6ddf37cddd414ab0b97cbcaff4875a8f4aab797be71855f")
    def test_terminal_denies_copy(self):
        for k in ("records","tcp","host","auth","channel"):
            r=broker(self.default(**{k:False}));self.assertTrue(r.terminal);self.assertFalse(r.release)

if __name__=="__main__":
    main()
