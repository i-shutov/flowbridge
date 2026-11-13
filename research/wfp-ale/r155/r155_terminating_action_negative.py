#!/usr/bin/env python3
"""R155: deterministic negative coverage for unchanged action at self redirect.

No kernel, Windows API, driver, network or filter operations. This is not an
observed initial classifyOut state. Exact R19 source pin optional but required
for any 'source-backed' label.
"""
import argparse
import hashlib
import itertools
import json
from pathlib import Path

PINS = {
    'kernel/src/redirect.rs': 'a093f049d162987981a957aac90db1014bc6ff09',
    'policy_windows.rs': 'acf60334320d970f58af3349ee75fbaa59826602',
}
STATES = ('SELF', 'PREVIOUS_SELF')
ACTIONS = ('BLOCK', 'PERMIT', 'CONTINUE', 'NONE')


def git_blob(raw):
    return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()


def source_gate(root):
    for relative, pin in PINS.items():
        raw = (root / relative).read_bytes()
        if git_blob(raw) != pin:
            raise ValueError('R19_BLOB_DRIFT:'+relative)
    source = (root / 'kernel/src/redirect.rs').read_text(encoding='utf-8')
    marker = 'if state==k::FWPS_CONNECTION_REDIRECTED_BY_SELF||state==k::FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF{return;}'
    if marker not in source: raise ValueError('REDIRECT_STATE_BRANCH_CHANGED')
    state_offset = source.index(marker)
    action_offset = source.index('(*out).actionType=k::FWP_ACTION_PERMIT;', state_offset)
    if action_offset <= state_offset: raise ValueError('EXPECTED_LATE_PERMIT_MISSING')
    policy = (root / 'policy_windows.rs').read_text(encoding='utf-8')
    for marker in ('if r.kind==Kind::Redirect{FWP_ACTION_CALLOUT_UNKNOWN}',
                   'else{FWP_ACTION_CALLOUT_TERMINATING}',
                   'FWPM_LAYER_ALE_CONNECT_REDIRECT_V4'):
        if marker not in policy: raise ValueError('FILTER_ACTION_PIN_CHANGED:'+marker)


def verdict(state, previous_action, action_write, family):
    if state not in STATES or previous_action not in ACTIONS or action_write not in (0,1) or family not in (4,6):
        raise ValueError('invalid model input')
    # R19 does not modify actionType or rights on the SELF/PREVIOUS_SELF return.
    # IMPORTANT: redirect filter is CALLOUT_UNKNOWN, not TERMINATING.
    # BLOCK/PERMIT/CONTINUE are documented allowed values at this filter.
    # NONE is outside that documented return set: no final outcome inferred.
    effective = previous_action if previous_action in ('PERMIT', 'BLOCK', 'CONTINUE') else 'UNSPECIFIED'
    return 'SELF_RETURN_UNSET' if state == 'SELF' else 'PREVIOUS_SELF_UNSET', effective


def matrix():
    rows, counts = [], {'SELF_RETURN_UNSET':0, 'PREVIOUS_SELF_UNSET':0,
                         'INHERITED_PERMIT':0, 'INHERITED_BLOCK':0, 'INHERITED_CONTINUE':0, 'UNSPECIFIED':0}
    for family, state, action, write in itertools.product((4,6),STATES,ACTIONS,(0,1)):
        category, effective = verdict(state,action,write,family)
        counts[category]+=1
        counts['INHERITED_'+effective if effective!='UNSPECIFIED' else 'UNSPECIFIED']+=1
        rows.append(f'{family}|{state}|{action}|{write}|{category}|{effective}\n')
    expected = {'SELF_RETURN_UNSET':16,'PREVIOUS_SELF_UNSET':16,'INHERITED_PERMIT':8,'INHERITED_BLOCK':8,'INHERITED_CONTINUE':8,'UNSPECIFIED':8}
    if len(rows)!=32 or counts!=expected:
        raise RuntimeError('INCOMPLETE_OR_CHANGED_MODEL:'+str(counts))
    return dict(states=32,categories=counts,sha256=hashlib.sha256(''.join(rows).encode('ascii')).hexdigest(),
                source_is_runtime_proof=False,native_wfp_executed=False,release_accepted=False)


def main():
    p=argparse.ArgumentParser()
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--model-only',action='store_true')
    mode.add_argument('--source-root',type=Path)
    a=p.parse_args()
    if a.source_root is not None:source_gate(a.source_root)
    print(json.dumps(matrix(),sort_keys=True,separators=(',',':')))

if __name__=='__main__':main()
