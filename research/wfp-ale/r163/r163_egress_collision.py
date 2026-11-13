#!/usr/bin/env python3
"""R163 conditional SSH egress collision: driverless, source-pinned decision test.

The observed ORIGINAL_APP_ID on a records-tagged physical SSH socket is an
INPUT, never guessed from a synthetic tuple.  This is not a kernel proof.
"""
from __future__ import annotations
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PINS = {
    'research/wfp-ale/kernel-r19/kernel/src/redirect.rs': 'a093f049d162987981a957aac90db1014bc6ff09',
    'research/wfp-ale/kernel-r19/policy_windows.rs': 'acf60334320d970f58af3349ee75fbaa59826602',
}
BROKER_SOURCES = {
    'research/wfp-ale/kernel-r19/broker.rs': '6163e84aea08ddde7e51a7fb94ccb6d68ae951fb',
    'research/wfp-ale/kernel-r19/broker_windows.rs': '329ef14b63e70226bfad7372b0014559213abd04',
}

def git_blob_hash(contents: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(contents)).encode() + b'\0' + contents).hexdigest()

def source_gate() -> dict[str,str]:
    values = {}
    sources = {}
    for path, expected in PINS.items():
        f = ROOT / path
        if not f.is_file():
            f = ROOT / 'snapshot' / path  # self-contained checkpoint
        b = f.read_bytes()
        sources[path] = b.decode('utf-8')
        actual = git_blob_hash(b)
        if actual != expected:
            raise RuntimeError(f'source pin mismatch: {path}: {actual} != {expected}')
        values[path] = actual
    policy = sources['research/wfp-ale/kernel-r19/policy_windows.rs']
    redirect = sources['research/wfp-ale/kernel-r19/kernel/src/redirect.rs']
    for s in ('FWPM_CONDITION_ALE_ORIGINAL_APP_ID', 'FWPM_CONDITION_IP_PROTOCOL',
              'FWP_ACTION_CALLOUT_TERMINATING'):
        if s not in policy: raise RuntimeError('missing policy condition: '+s)
    for s in ('if !loopback{return false;}', 'if !auth_check(values,meta){block(out);return;}',
              'k::FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS',
              'k::FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS'):
        if s not in redirect: raise RuntimeError('missing auth branch: '+s)
    return values

# Only caller-supplied synthetic WFP values.  records_attached is intentionally
# not used as a predictor of original_appid or REDIRECTED flags.
def classify(c: dict) -> str:
    if not c['policy'] or c['orig_app'] != 'selected':
        return 'NOT_INVOKED'
    if not c['write_right']:
        return 'PRESERVE_CONTINUE'  # synthetic prior action is CONTINUE
    if not c['redirect_flag'] or c['reauth'] or c['remote'] != 'loopback' or not c['ticket']:
        return 'BLOCK'
    return 'PERMIT'

def cases():
    for i, tup in enumerate(itertools.product(
        (4, 6), ('selected', 'broker', 'sibling'), ('loopback', 'ssh_peer', 'other'),
        (False, True), (False, True), (False, True), (False, True), (False, True)
    )):
        family, app, remote, policy, records, redirected, reauth, write = tup
        # Ticket valid iff manually indicated as such; tested with both values.
        # This keeps the AUTH stage explicit, separate from user-mode CLAIM.
        for ticket in (False, True):
            c = dict(id=i*2+int(ticket),family=family,orig_app=app,remote=remote,
                     policy=policy,records_attached=records,redirect_flag=redirected,
                     reauth=reauth,write_right=write,ticket=ticket)
            c['decision'] = classify(c)
            yield c

def matrix():
    rows = list(cases())
    counts = {k: sum(c['decision']==k for c in rows)
              for k in ('NOT_INVOKED','PRESERVE_CONTINUE','BLOCK','PERMIT')}
    return dict(kind='R163_CONDITIONAL_AUTH_EGRESS_COLLISION',count=len(rows),counts=counts,
                source_pins=PINS,broker_source_pins_unbundled=BROKER_SOURCES,
                rows=rows)

class Tests(unittest.TestCase):
    def test_exact_pinned_sources(self): self.assertEqual(source_gate(),PINS)
    def test_expected_count(self): self.assertEqual(len(list(cases())),1152)
    def test_original_selected_v4_redirected_can_pass(self):
        r = dict(policy=True,orig_app='selected',remote='loopback',write_right=True,
                 redirect_flag=True,reauth=False,ticket=True)
        self.assertEqual(classify(r),'PERMIT')
    def test_conditional_ssh_collision_v4(self):
        r = dict(policy=True,orig_app='selected',remote='ssh_peer',write_right=True,
                 redirect_flag=True,reauth=False,ticket=True,records_attached=True)
        self.assertEqual(classify(r),'BLOCK')
    def test_records_do_not_automatically_set_orig_app(self):
        r = dict(policy=True,orig_app='broker',remote='ssh_peer',write_right=True,
                 redirect_flag=True,reauth=False,ticket=True,records_attached=True)
        self.assertEqual(classify(r),'NOT_INVOKED')
    def test_ssh_peer_always_rejected_if_auth_invoked_writable(self):
        for family, flags, reauth, ticket in itertools.product((4,6),(False,True),(False,True),(False,True)):
            r=dict(policy=True,orig_app='selected',remote='ssh_peer',write_right=True,
                   redirect_flag=flags,reauth=reauth,ticket=ticket,family=family)
            self.assertEqual(classify(r),'BLOCK')
    def test_disabled_policy_has_no_callout(self):
        r=dict(policy=False,orig_app='selected',remote='ssh_peer',write_right=True,
               redirect_flag=True,reauth=False,ticket=True)
        self.assertEqual(classify(r),'NOT_INVOKED')
    def test_sibling_direct_not_covered(self):
        r=dict(policy=True,orig_app='sibling',remote='other',write_right=True,
               redirect_flag=False,reauth=False,ticket=False)
        self.assertEqual(classify(r),'NOT_INVOKED')
    def test_missing_right_is_not_fake_block(self):
        r=dict(policy=True,orig_app='selected',remote='ssh_peer',write_right=False,
               redirect_flag=True,reauth=False,ticket=True)
        self.assertEqual(classify(r),'PRESERVE_CONTINUE')
    def test_reauth_cannot_reuse_one_shot(self):
        r=dict(policy=True,orig_app='selected',remote='loopback',write_right=True,
               redirect_flag=True,reauth=True,ticket=True)
        self.assertEqual(classify(r),'BLOCK')

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--matrix',action='store_true');args=ap.parse_args()
    if args.matrix:
        source_gate()
        print(json.dumps(matrix(),sort_keys=True,separators=(',',':')))
    else:
        unittest.main(argv=[__file__],verbosity=2)
