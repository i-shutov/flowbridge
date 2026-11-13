#!/usr/bin/env python3
"""R156: offline model of R19 outer classify wrapper AND redirect::classify.

No Windows API calls; no WFP activation; no driver; no packets.
The model deliberately records the returned FWPS_CLASSIFY_OUT0 fields, NOT a
final WFP arbitration or leak/no-DIRECT outcome.
"""
from __future__ import annotations
import argparse
import hashlib
import itertools
import json
from pathlib import Path

PINS = {
    'kernel/src/lib.rs': '53f5ce6faa0f9f591974287f38ea890cafeb0dd2',
    'kernel/src/redirect.rs': 'a093f049d162987981a957aac90db1014bc6ff09',
    'policy_windows.rs': 'acf60334320d970f58af3349ee75fbaa59826602',
    'kernel/src/action_rights.rs': 'c6a4a107255cc5ecca82266481935c93467a01ed',
}
FAMILIES = (4, 6)
REDIRECT_STATES = ('SELF', 'PREVIOUS_SELF')
ACTIONS = ('PERMIT', 'BLOCK', 'CONTINUE', 'NONE')
PATHS = ('SELF_RETURN', 'APPID_MISMATCH', 'NOT_CONFIGURED',
         'RUNDOWN_DENIED', 'STOPPED', 'BAD_METADATA', 'OTHER_INSPECTOR')


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(data)).encode('ascii') + b'\x00' + data).hexdigest()


def source_gate(root: Path) -> dict:
    verified = {}
    src = {}
    for rel, expected in PINS.items():
        raw = (root / rel).read_bytes()
        got = blob_sha(raw)
        if got != expected:
            raise ValueError('SOURCE_DRIFT:' + rel + ':' + got)
        verified[rel] = got
        src[rel] = raw.decode('utf-8')
    wrapper = src['kernel/src/lib.rs']
    redirect = src['kernel/src/redirect.rs']
    policy = src['policy_windows.rs']
    # Structural/control-flow markers, not a Rust parser. Exact blob pins are
    # the main source integrity gate; marker checks explain assumptions.
    markers = {
        'outer_preset': 'if !out.is_null() && (*out).rights & k::FWPS_RIGHT_ACTION_WRITE!=0{(*out).actionType=k::FWP_ACTION_CONTINUE;}',
        'outer_dispatch': 'redirect::classify(values,meta,_context,_filter,out);',
        'guarded_block': 'let gate=action_rights::decision((*out).rights,(*out).actionType as u32,',
        'veto_if_no_write': 'if matches!(gate,action_rights::BlockDecision::MustPreserve){return false;}',
        'no_rundown': 'let Some(_active)=Active::enter() else{let _=guarded_block(out);return};',
        'stop': 'if STOP.load(Ordering::Acquire){let _=guarded_block(out);return;}',
    }
    for label, marker in markers.items():
        if marker not in wrapper:
            raise ValueError('WRAPPER_MARKER_DRIFT:' + label)
    tests = {
        'self_early_return': 'if state==k::FWPS_CONNECTION_REDIRECTED_BY_SELF||state==k::FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF{return;}',
        'appid_mismatch': 'if appid!=&r.name[..r.len]{return;}',
        'bad_metadata': 'if values.is_null()||meta.is_null(){block(out);return;}',
        'other_inspector': 'if state!=k::FWPS_CONNECTION_NOT_REDIRECTED{block(out);return;}',
        'unconfigured': 'if !(*ROUTE.0.get()).configured{block(out);return;}',
    }
    for label, marker in tests.items():
        if marker not in redirect:
            raise ValueError('REDIRECT_MARKER_DRIFT:' + label)
    if 'if r.kind==Kind::Redirect{FWP_ACTION_CALLOUT_UNKNOWN}' not in policy:
        raise ValueError('FILTER_ACTION_CHANGED')
    return verified


def callback_return(family: int, state: str, incoming_action: str, write: int, path: str) -> tuple[str, int, str]:
    if (family not in FAMILIES or state not in REDIRECT_STATES or
        incoming_action not in ACTIONS or type(write) is not int or write not in (0, 1) or path not in PATHS):
        raise ValueError('INVALID_INPUT')
    # lib.rs::classify pre-sets CONTINUE whenever ACTION_WRITE exists.
    action = 'CONTINUE' if write else incoming_action
    rights = write
    if path in ('SELF_RETURN', 'APPID_MISMATCH'):
        # redirect.rs returns without modifying action, but the outer classify
        # callback has ALREADY replaced the action on writable paths.
        return action, rights, 'OUTER_CONTINUE' if write else 'PRESERVED_NO_WRITE'
    # redirect.rs calls block(out), or outer callback does on missing rundown
    # and STOP. guarded_block is a veto only when no write and prior PERMIT.
    if write:
        return 'BLOCK', 0, 'BLOCK_WITH_WRITE'
    if action == 'PERMIT':
        return 'BLOCK', 0, 'VETO_PERMIT_NO_WRITE'
    return action, 0, 'PRESERVED_NO_WRITE'


def matrix() -> dict:
    rows = []
    counts = {}
    for family, state, incoming, write, path in itertools.product(
        FAMILIES, REDIRECT_STATES, ACTIONS, (0, 1), PATHS
    ):
        action, rights, reason = callback_return(family, state, incoming, write, path)
        counts[reason] = counts.get(reason, 0) + 1
        rows.append(f'{family}|{state}|{incoming}|{write}|{path}|{action}|{rights}|{reason}\n')
    expected = {'OUTER_CONTINUE': 32, 'PRESERVED_NO_WRITE': 92,
                'BLOCK_WITH_WRITE': 80, 'VETO_PERMIT_NO_WRITE': 20}
    # The sum of reasons is 224. These expectations are intentionally audited
    # by a separate Node model and unit tests, rather than changed on drift.
    if len(rows) != 224:
        raise RuntimeError('INCOMPLETE_MATRIX:'+str(len(rows)))
    if counts != expected:
        raise RuntimeError('CHANGED_BRANCH_COUNTS:'+str(counts))
    # R155 considered the incoming action as the return even when the outer
    # callback had rewritten it. Exactly 12 of R155's 32 self-return rows differ.
    changed_r155 = sum(
        int(callback_return(f, s, a, w, 'SELF_RETURN')[0] != a)
        for f, s, a, w in itertools.product(FAMILIES, REDIRECT_STATES, ACTIONS, (0, 1))
    )
    if changed_r155 != 12:
        raise RuntimeError('INCORRECT_R155_DELTA:'+str(changed_r155))
    return {'cases': len(rows), 'counts': dict(sorted(counts.items())),
            'changed_r155_action_rows': changed_r155,
            'sha256': hashlib.sha256(''.join(rows).encode('ascii')).hexdigest(),
            'model_only': True, 'kernel_executed': False, 'release_accepted': False,
            'no_direct_proved': False}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument('--model-only', action='store_true')
    group.add_argument('--source-root', type=Path)
    opts = p.parse_args()
    if opts.source_root is not None:
        source_gate(opts.source_root)
    print(json.dumps(matrix(), sort_keys=True, separators=(',', ':')))

if __name__ == '__main__':
    main()
