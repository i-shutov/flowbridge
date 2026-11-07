"""Independent R25 evidence: R24 static AUTH filters cannot attest redirect provenance.
Pure Python stdlib; no WFP calls, network, driver or services.
"""
from dataclasses import dataclass, replace
from itertools import product
from pathlib import Path
import hashlib
import re
import unittest

PINS = {
    'policy_plan.rs': '2aa7468f8d63b8a74f8837d0de98becd8e4f22b6',
    'policy_windows.rs': 'b487ce24840e2295a8d12cc380fcfae946b0b4e5',
    'kernel/src/lib.rs': 'aff4be74f156ce3864d6848aafe265fa2a12b2c3',
    'kernel/src/redirect.rs': '5b09b668bb331e64c11a1094e52d2714562c25e0',
    'broker_windows.rs': 'f315d2cfab16ed7474446a9bb819980c8c737163',
}
PORTS={4:1091,6:1092}; LOOP={4:'127.0.0.1',6:'::1'}; APP=b'selected'

@dataclass(frozen=True)
class Case:
    family:int; selected:bool; tcp:bool; local:bool; right_port:bool
    redirected:bool; target_pid_matches:bool; epoch_matches:bool; original_matches:bool; ticket_matches:bool

def own_block(c):
    # Two independent FWP_MATCH_NOT_EQUAL BLOCK predicates, not global arbitration.
    if not(c.selected and c.tcp):return 'OUTSIDE_OWN_RULES'
    return 'OWN_BLOCK' if not c.local or not c.right_port else 'NO_OWN_BLOCK_MATCH'

def reference(c):
    # Independent truth table oracle, explicitly different implementation.
    applicable=c.selected and c.tcp
    a=applicable and c.local is False
    b=applicable and c.right_port is False
    return 'OWN_BLOCK' if a or b else ('NO_OWN_BLOCK_MATCH' if applicable else 'OUTSIDE_OWN_RULES')

def source_shape(root):
    blobs={}
    for rel,sha in PINS.items():
        raw=(root/rel).read_bytes()
        blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        if blob!=sha:raise ValueError('HEAD changed: re-audit '+rel)
        blobs[rel]=raw.decode('utf-8')
    plan=blobs['policy_plan.rs']; win=blobs['policy_windows.rs']
    kernel=blobs['kernel/src/lib.rs']; redir=blobs['kernel/src/redirect.rs']
    rules=re.findall(r'Rule\{family:Family::V[46],kind:Kind::(?:BlockNonLoopback|BlockWrongPort|Redirect)\}',plan)
    if len(rules)!=6 or sum('kind:Kind::Redirect' in r for r in rules)!=2:
        raise AssertionError('rule shape changed')
    for token in ['FWPM_CONDITION_ALE_APP_ID','FWPM_CONDITION_IP_PROTOCOL',
                  'FWPM_CONDITION_IP_REMOTE_ADDRESS','FWPM_CONDITION_IP_REMOTE_PORT',
                  'FWP_MATCH_NOT_EQUAL','FWP_ACTION_BLOCK']:
        if token not in win:raise AssertionError('AUTH policy changed: '+token)
    for source in [kernel,redir]:
        for token in ['FWPS_LAYER_ALE_AUTH_CONNECT_V4','FWPS_LAYER_ALE_AUTH_CONNECT_V6']:
            if token in source:raise AssertionError('AUTH kernel path changed: '+token)
    if 'call.calloutKey=if i==0{V4_GUID}else{V6_GUID}' not in kernel:
        raise AssertionError('callout registration changed')
    return {'pinned_blobs':len(blobs),'static_rules':len(rules),'auth_classify_registered':False}

class NegativeProof(unittest.TestCase):
    def test_all_1024_predicate_worlds(self):
        different=0
        for bits in product((False,True),repeat=9):
            for family in (4,6):
                c=Case(family,*bits[:4],*bits[4:])
                self.assertEqual(own_block(c),reference(c))
                if c.selected and c.tcp and c.local and c.right_port:
                    # Different kernel histories remain identical to the static filters.
                    canonical=replace(c,redirected=True,target_pid_matches=True,
                        epoch_matches=True,original_matches=True,ticket_matches=True)
                    if c!=canonical:
                        self.assertEqual(own_block(c),own_block(canonical));different+=1
        self.assertEqual(different,62)
    def test_bad_destination_and_port_block(self):
        for family in (4,6):
            c=Case(family,True,True,False,True,True,True,True,True,True)
            self.assertEqual(own_block(c),'OWN_BLOCK')
            self.assertEqual(own_block(replace(c,local=True,right_port=False)),'OWN_BLOCK')
    def test_sibling_direct_dns_udp_not_promoted(self):
        c=Case(4,False,True,True,True,False,False,False,False,False)
        self.assertEqual(own_block(c),'OUTSIDE_OWN_RULES')
        self.assertEqual(own_block(replace(c,selected=True,tcp=False)),'OUTSIDE_OWN_RULES')
    def test_malicious_and_mutated_oracle_caught(self):
        for family in (4,6):
            c=Case(family,True,True,False,True,False,False,False,False,False)
            faulty_and='OWN_BLOCK' if (not c.local and not c.right_port) else 'NO_OWN_BLOCK_MATCH'
            self.assertNotEqual(faulty_and,own_block(c))
    def test_no_own_block_is_not_an_os_permit(self):
        self.assertNotEqual(own_block(Case(4,*([True]*9))),'PERMIT')

if __name__=='__main__':
    root=Path(__file__).resolve().parent/'kernel-r19'
    if root.is_dir():print('Source-pin audit:',source_shape(root))
    else:print('Source-pin audit: NOT RUN (no exact checkout); offline predicate tests only')
    unittest.main(verbosity=2)
