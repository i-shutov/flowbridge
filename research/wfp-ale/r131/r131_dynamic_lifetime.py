#!/usr/bin/env python3
"""Deterministic negative model for the documented WFP dynamic-session lifetime.

No imports of Windows APIs, no BFE calls, sockets, processes, drivers or network.
A model verdict UNGUARDED means no *FlowBridge-owned* WFP policy, NOT packet success.
"""
from dataclasses import dataclass
from itertools import product
import hashlib, json, unittest

@dataclass(frozen=True)
class Input:
    family: int
    session: str
    install: str
    broker: str
    ssh: str
    other_policy: str
    client: str


def classify(c: Input):
    # FWPM_SESSION_FLAG_DYNAMIC: on end of the owning BFE session,
    # WFP objects installed during that session are removed.
    own_rules = c.install == 'COMMITTED' and c.session == 'ALIVE'
    if not own_rules:
        status = 'NOT_GUARDED_BY_FLOWBRIDGE'
    elif c.broker == 'DEAD' or c.ssh == 'DOWN':
        status = 'RULES_PRESENT_BUT_DELIVERY_UNPROVEN'
    else:
        status = 'RULES_PRESENT_NOT_KERNEL_PROOF'
    return dict(family=c.family, own_rules=own_rules,
                flowbridge_status=status,
                other_policy=c.other_policy, client=c.client,
                direct_packet_observed=False, leak_proven=False, packetbound_g2_pass=False)


def matrix():
    for combo in product((4,6), ('ALIVE','CLOSED','RPC_RUNDOWN','PROCESS_EXIT'),
                         ('NONE','COMMITTED'),('LIVE','DEAD'),('UP','DOWN'),
                         ('ALLOW_UNKNOWN','BLOCK_UNKNOWN'), ('RUNNING','TERMINATED')):
        v = Input(*combo)
        yield v, classify(v)


def digest():
    rows=[dict(inputs=vars(v),output=o) for v,o in matrix()]
    raw=''.join(json.dumps(r,sort_keys=True,separators=(',',':'))+'\n' for r in rows).encode()
    return len(rows), hashlib.sha256(raw).hexdigest(), rows

class NegativeTests(unittest.TestCase):
    def test_caseless_dynamic_session_closure_eliminates_own_rules(self):
        for v,o in matrix():
            if v.session != 'ALIVE':
                self.assertFalse(o['own_rules'])
    def test_controller_loss_independent_of_broker_and_ssh(self):
        for family,broker,ssh in product((4,6),('LIVE','DEAD'),('UP','DOWN')):
            for reason in ('CLOSED','RPC_RUNDOWN','PROCESS_EXIT'):
                v=Input(family,reason,'COMMITTED',broker,ssh,'ALLOW_UNKNOWN','RUNNING')
                self.assertEqual(classify(v)['flowbridge_status'],'NOT_GUARDED_BY_FLOWBRIDGE')
    def test_reopening_without_commit_is_not_equivalent_to_reinstalled_policy(self):
        v=Input(4,'ALIVE','NONE','LIVE','UP','ALLOW_UNKNOWN','RUNNING')
        self.assertFalse(classify(v)['own_rules'])
    def test_other_filter_is_never_mistaken_for_own_proof(self):
        for v,o in matrix():
            self.assertEqual(o['other_policy'],v.other_policy)
            self.assertFalse(o['direct_packet_observed'])
            self.assertFalse(o['leak_proven'])
            self.assertFalse(o['packetbound_g2_pass'])
    def test_active_session_only_proves_rule_lifetime_in_model(self):
        v=Input(6,'ALIVE','COMMITTED','LIVE','UP','BLOCK_UNKNOWN','RUNNING')
        self.assertTrue(classify(v)['own_rules'])
        self.assertEqual(classify(v)['flowbridge_status'],'RULES_PRESENT_NOT_KERNEL_PROOF')
    def test_matrix_coverage(self):
        n, sha, rows=digest();self.assertEqual(n, 2*4*2*2*2*2*2)
        self.assertEqual(len({(v.family,v.session,v.install,v.broker,v.ssh,v.other_policy,v.client) for v,o in matrix()}),n)

if __name__=='__main__':
    import sys
    if '--matrix' in sys.argv:
        n,sha,_=digest();print(json.dumps({'cases':n,'sha256':sha,'scope':'synthetic_policy_lifetime_only','rust_native':'NOT_RUN'},sort_keys=True))
    else:unittest.main(verbosity=2)
