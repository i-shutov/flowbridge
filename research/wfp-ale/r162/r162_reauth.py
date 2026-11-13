#!/usr/bin/env python3
"""R162: driverless, deterministic WFP AUTH_CONNECT reauthorization negative test.

Narrow gate only: assumes all other R19 checks pass when matches=True.
Neither a Windows callout nor a proof of WFP policy arbitration.
"""
from __future__ import annotations
import argparse
import hashlib
import itertools
import json
import pathlib
import subprocess
import unittest

PINNED = {
    'research/wfp-ale/kernel-r19/kernel/src/redirect.rs': 'a093f049d162987981a957aac90db1014bc6ff09',
    'research/wfp-ale/kernel-r19/kernel/src/lib.rs': '53f5ce6faa0f9f591974287f38ea890cafeb0dd2',
    'research/wfp-ale/kernel-r19/kernel/src/handoff.rs': 'e1d17217db50362ba9c4efc83af820b6beb094cf',
    'research/wfp-ale/kernel-r19/policy_windows.rs': 'acf60334320d970f58af3349ee75fbaa59826602',
}
PRIOR = ('PERMIT', 'CONTINUE', 'BLOCK')


def classify(family: int, reauth: bool, honoring: bool, redirected: bool,
             write: bool, prior: str, match: bool, attested: bool,
             filter_live: bool) -> str:
    assert family in (4, 6) and prior in PRIOR
    # Missing policy cannot be treated as PERMIT or BLOCK; no invocation.
    if not filter_live:
        return 'NOT_INVOKED'
    # lib.rs::guarded_block: absent ACTION_WRITE only a preceding PERMIT
    # may be vetoed. CONTINUE cannot be silently promoted to BLOCK.
    if not write:
        return 'BLOCK_VETO' if prior == 'PERMIT' else 'PRESERVE_' + prior
    # redirect.rs::auth_check rejects reauthorization before accessing Book.
    if reauth or honoring or not redirected or not match or attested:
        return 'BLOCK'
    return 'PERMIT_ONCE'


def enumerate_cases():
    for a in itertools.product((4, 6), (False, True), (False, True),
                               (False, True), (False, True), PRIOR,
                               (False, True), (False, True), (False, True)):
        family, reauth, honoring, redirected, write, prior, match, attested, live = a
        yield {'family': family, 'reauth': reauth, 'honoring': honoring,
               'redirected': redirected, 'write': write, 'prior': prior,
               'matches': match, 'attested': attested, 'filter_live': live,
               'outcome': classify(family, reauth, honoring, redirected,
                                   write, prior, match, attested, live)}


def matrix():
    cases = list(enumerate_cases())
    from collections import Counter
    return {'schema': 'FlowBridge-R162-reAuth-negative-v1',
            'case_count': len(cases),
            'outcomes': dict(sorted(Counter(x['outcome'] for x in cases).items())),
            'cases': cases}


def source_gate(root: pathlib.Path):
    for name, expected in PINNED.items():
        p = root / name
        data = p.read_bytes()
        # Git blob = SHA1(b'blob ' + decimal length + NUL + bytes).
        actual = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if actual != expected:
            raise RuntimeError(f'REJECT source drift {name}: {actual} != {expected}')
    redirect = (root / 'research/wfp-ale/kernel-r19/kernel/src/redirect.rs').read_text()
    lib = (root / 'research/wfp-ale/kernel-r19/kernel/src/lib.rs').read_text()
    required = [
        'bits & 0x0010_0000==0 || bits & (0x0000_0004|0x0200_0000)!=0',
        'if !auth_check(values,meta){block(out);return;}',
        '(*out).actionType=k::FWP_ACTION_PERMIT;',
        'if slot.auth_seen || now<when || now-when>TTL{return false;}',
    ]
    handoff = (root / 'research/wfp-ale/kernel-r19/kernel/src/handoff.rs').read_text()
    for token, body in zip(required, [redirect, redirect, redirect, handoff]):
        if token not in body:
            raise RuntimeError(f'REJECT pinned semantic token absent: {token}')
    if 'BlockDecision::MustPreserve' not in lib or '(*out).actionType=k::FWP_ACTION_BLOCK;' not in lib:
        raise RuntimeError('REJECT guarded_block contract drift')
    return True


class Tests(unittest.TestCase):
    def test_reauth_same_flow_never_permitted(self):
        for c in enumerate_cases():
            if c['reauth'] and c['filter_live']:
                self.assertNotEqual(c['outcome'], 'PERMIT_ONCE')

    def test_initial_good_receipt_admitted(self):
        for family in (4, 6):
            self.assertEqual(classify(family, False, False, True, True,
                                      'CONTINUE', True, False, True), 'PERMIT_ONCE')

    def test_subsequent_reauth_denied_even_if_initial_was_good(self):
        for family in (4, 6):
            self.assertEqual(classify(family, True, False, True, True,
                                      'CONTINUE', True, True, True), 'BLOCK')

    def test_no_write_cannot_turn_continue_into_block(self):
        for family in (4, 6):
            self.assertEqual(classify(family, True, False, True, False,
                                      'CONTINUE', True, True, True), 'PRESERVE_CONTINUE')

    def test_no_write_prior_permit_veto(self):
        for family in (4, 6):
            self.assertEqual(classify(family, True, False, True, False,
                                      'PERMIT', True, True, True), 'BLOCK_VETO')

    def test_filter_absent_means_not_involved(self):
        for c in enumerate_cases():
            if not c['filter_live']:
                self.assertEqual(c['outcome'], 'NOT_INVOKED')

    def test_one_shot_even_without_reauth(self):
        for family in (4, 6):
            self.assertEqual(classify(family, False, False, True, True,
                                      'PERMIT', True, True, True), 'BLOCK')

    def test_honoring_policy_authorize_rejected(self):
        for family in (4, 6):
            self.assertEqual(classify(family, False, True, True, True,
                                      'CONTINUE', True, False, True), 'BLOCK')

    def test_denied_when_no_redirected_bit(self):
        for family in (4, 6):
            self.assertEqual(classify(family, False, False, False, True,
                                      'CONTINUE', True, False, True), 'BLOCK')

    def test_different_process_or_endpoint_denied(self):
        for family in (4, 6):
            self.assertEqual(classify(family, False, False, True, True,
                                      'CONTINUE', False, False, True), 'BLOCK')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--source-gate', type=pathlib.Path, help='exact checkout root, FAIL on drift')
    ap.add_argument('--test', action='store_true')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()
    if args.source_gate:
        source_gate(args.source_gate)
        print('SOURCE_GATE_PASS: four exact original Git blobs + semantic checks')
    if args.test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
        result = unittest.TextTestRunner(verbosity=1).run(suite)
        if not result.wasSuccessful():
            raise SystemExit(1)
    if args.json:
        print(json.dumps(matrix(), sort_keys=True, separators=(',', ':')))
    if not args.test and not args.json and not args.source_gate:
        ap.error('Select --json, --test or --source-gate')


if __name__ == '__main__':
    main()
