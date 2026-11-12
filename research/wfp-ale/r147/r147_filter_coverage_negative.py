#!/usr/bin/env python3
"""R147: Pure offline WFP filter-match/callout-reachability counterexample.

No Windows APIs, drivers, sockets or WFP policy mutation. SOURCE_CHECK is required
for repo-backed execution; --model-only is expressly insufficient for native proof.
"""
import hashlib
import itertools
import json
from pathlib import Path
import sys

PINS = {
    'policy_windows.rs': ('acf60334320d970f58af3349ee75fbaa59826602',
        ('FWPM_CONDITION_ALE_ORIGINAL_APP_ID', 'FWPM_CONDITION_IP_PROTOCOL',
         'FWP_MATCH_EQUAL', 'FWP_BYTE_BLOB_TYPE', 'FWP_ACTION_CALLOUT_TERMINATING')),
    'kernel/src/redirect.rs': ('a093f049d162987981a957aac90db1014bc6ff09',
        ('pub unsafe fn auth_classify(', 'bits & (0x0000_0004|0x0200_0000)!=0')),
}

def source_gate():
    root = Path(__file__).resolve().parent.parent / 'kernel-r19'
    for name, (pin, markers) in PINS.items():
        raw = (root / name).read_bytes()
        got = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\x00' + raw).hexdigest()
        if got != pin: raise ValueError('SOURCE_PIN_MISMATCH ' + name + ' ' + got)
        for marker in markers:
            if marker.encode() not in raw:
                raise ValueError('SOURCE_MARKER_MISSING ' + name + ' ' + marker)

def evaluate(app_field, tcp, active, higher_same_sublayer_terminal):
    if not active:
        return 'FILTER_ABSENT_NO_CLAIM'
    # The R19 filter has an exact BLOB AppId match AND TCP protocol == 6.
    if app_field != 'selected' or not tcp:
        return 'FILTER_NONMATCH_NO_CALLBACK'
    # WFP same-sublayer arbitration may stop on a higher weighted action.
    if higher_same_sublayer_terminal:
        return 'FILTER_MATCH_MAY_BE_SKIPPED'
    return 'FILTER_ELIGIBLE_NOT_KERNEL_PROOF'

def matrix():
    rows = []
    counts = {}
    empty_reauth_live = 0
    for family, app, tcp, phase, active, alive, earlier in itertools.product(
        ('v4', 'v6'), ('selected', 'empty', 'foreign', 'absent'), (0, 1),
        ('initial', 'reauth'), (0, 1), (0, 1), (0, 1)):
        decision = evaluate(app, tcp, active, earlier)
        if app == 'empty' and phase == 'reauth' and active and alive and tcp:
            if decision != 'FILTER_NONMATCH_NO_CALLBACK':
                raise RuntimeError('EMPTY_REAUTH_MUST_NOT_HIT_SELECTED_BLOB_FILTER')
            empty_reauth_live += 1
        if app == 'selected' and tcp and active and not earlier:
            if decision != 'FILTER_ELIGIBLE_NOT_KERNEL_PROOF':
                raise RuntimeError('EXPECTED_MATCH_ELIGIBILITY')
        if 'PROOF' in decision and decision != 'FILTER_ELIGIBLE_NOT_KERNEL_PROOF':
            raise RuntimeError('INVALID_PROOF_LABEL')
        counts[decision] = counts.get(decision, 0) + 1
        rows.append('|'.join((family, app, str(tcp), phase, str(active), str(alive), str(earlier), decision))+'\n')
    if len(rows) != 256 or empty_reauth_live != 4:
        raise RuntimeError('MATRIX_SHAPE_INCORRECT')
    return dict(rows=len(rows), empty_reauth_live_hypothetical=empty_reauth_live,
        counts=dict(sorted(counts.items())), matrix_sha256=hashlib.sha256(''.join(rows).encode()).hexdigest(),
        appid_empty_at_reauth_observed=False, callback_invocation_observed=False,
        direct_egress_observed=False, native_filter_execution=False,
        packetbound_g2_pass=False, release_go=False)

if __name__ == '__main__':
    if sys.argv[1:] == ['--model-only']:
        pass
    elif not sys.argv[1:]:
        source_gate()
    else:
        raise SystemExit('usage: r147_filter_coverage_negative.py [--model-only]')
    print(json.dumps(matrix(), sort_keys=True, separators=(',', ':')))
