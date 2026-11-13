#!/usr/bin/env python3
"""Source-pinned composition of the R19 wrapper and pre-redirection control flow.

No OS or Windows calls. Stages describe the first applicable source boundary;
NONE is a hypothetical input, not a witnessed WFP value. Passing means only
MODEL_CONTRACT_PASS. The unmodelled modifying path gets no final packet verdict.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import itertools
import json
from pathlib import Path

PINS = {
    'kernel/src/lib.rs': '53f5ce6faa0f9f591974287f38ea890cafeb0dd2',
    'kernel/src/redirect.rs': 'a093f049d162987981a957aac90db1014bc6ff09',
    'kernel/src/action_rights.rs': 'c6a4a107255cc5ecca82266481935c93467a01ed',
    'policy_windows.rs': 'acf60334320d970f58af3349ee75fbaa59826602',
}
ACTIONS = ('BLOCK', 'PERMIT', 'CONTINUE', 'NONE')
RIGHTS = (0, 1, 256, 257, 0xfffffffe, 0xffffffff)
STAGES = ('NO_OUTPUT', 'RUNDOWN_DENIED', 'STOPPING', 'UNCONFIGURED',
          'NULL_INPUT', 'WRONG_LAYER', 'INVALID_APPID', 'FOREIGN_APPID',
          'MISSING_IDENTITY', 'NON_TCP', 'SELF', 'PREVIOUS_SELF', 'OTHER',
          'NOT_REDIRECTED', 'RECORDS_ABSENT')

class ContractError(ValueError):
    pass

def need(condition, reason):
    if type(condition) is not bool or not condition:
        raise ContractError(reason)

def blob(raw: bytes) -> str:
    return hashlib.sha1(b'blob '+str(len(raw)).encode('ascii')+b'\0'+raw).hexdigest()

def source_shape(texts: dict[str, str]) -> None:
    """Narrow source-contract checks, not a general Rust parser or native proof."""
    lib, red, guard, policy = (texts[k] for k in PINS)
    start = lib.index('unsafe extern "C" fn classify(')
    end = lib.index('unsafe extern "C" fn auth_callback(', start)
    wrapper = lib[start:end]
    fragments = (
        'if !out.is_null() && (*out).rights & k::FWPS_RIGHT_ACTION_WRITE!=0{(*out).actionType=k::FWP_ACTION_CONTINUE;}',
        'let Some(_active)=Active::enter() else{let _=guarded_block(out);return};',
        'if STOP.load(Ordering::Acquire){let _=guarded_block(out);return;}',
        'redirect::classify(values,meta,_context,_filter,out);',
    )
    positions = [wrapper.find(x) for x in fragments]
    need(all(p >= 0 for p in positions) and positions == sorted(positions), 'WRAPPER_ORDER')
    need('call.classifyFn=Some(if i<2{classify}else{auth_callback})' in lib, 'CALLBACK_REGISTRATION')
    need('let gate=action_rights::decision((*out).rights,(*out).actionType as u32,' in lib
         and 'if matches!(gate,action_rights::BlockDecision::MustPreserve){return false;}' in lib,
         'GUARDED_BLOCK_BINDING')
    need('if action_write!=0 && rights & action_write != 0' in guard
         and 'else if prior_action == permit' in guard
         and 'BlockDecision::MustPreserve' in guard, 'VETO_GUARD')
    begin = red.index('pub unsafe fn classify(')
    end = red.index('pub unsafe fn auth_classify(', begin)
    inner = red[begin:end]
    markers = (
        'let incoming_write=(*out).rights&k::FWPS_RIGHT_ACTION_WRITE;',
        'if incoming_write==0||m.currentMetadataValues&needed!=needed||read_at::<i32>(p,k::FB_VALUE_TYPE)!=k::FWP_UINT8||read_at::<u8>(p,k::FB_VALUE_U8)!=6{block(out);return;}',
        'let state=k::FwpsQueryConnectionRedirectState0(m.redirectRecords,HANDLE,ptr::null_mut());',
        'if state==k::FWPS_CONNECTION_REDIRECTED_BY_SELF||state==k::FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF{return;}',
        'let Some(w)=writable(classify_context,filter,out)else{block(out);return;};',
    )
    positions = [inner.find(x) for x in markers]
    need(all(p >= 0 for p in positions) and positions == sorted(positions), 'INNER_REACHABILITY_ORDER')
    prefix = inner[:inner.index(markers[3])]
    need('(*out).actionType=' not in prefix and '(*out).rights=' not in prefix,
         'UNMODELLED_PRE_SELF_WRITE')
    need('if r.kind==Kind::Redirect{FWP_ACTION_CALLOUT_UNKNOWN}' in policy
         and 'else{FWP_ACTION_CALLOUT_TERMINATING}' in policy, 'ACTION_KIND')

def source_gate(root: Path) -> list[dict]:
    texts, records = {}, []
    for name, expected in PINS.items():
        raw = (root/name).read_bytes()
        canonical = raw if blob(raw) == expected else raw.replace(b'\r\n', b'\n')
        need(blob(canonical) == expected, 'SOURCE_PIN:'+name)
        texts[name] = canonical.decode('utf-8')
        records.append({'path': name, 'git_blob': expected,
                        'raw_sha256': hashlib.sha256(raw).hexdigest(),
                        'canonical_sha256': hashlib.sha256(canonical).hexdigest(),
                        'crlf_normalized': canonical != raw})
    source_shape(texts)
    return records

def evaluate(family: int, prior: str, rights: int, stage: str) -> dict:
    need(type(family) is int and family in (4, 6), 'FAMILY')
    need(type(prior) is str and prior in ACTIONS, 'ACTION')
    need(type(rights) is int and 0 <= rights <= 0xffffffff, 'RIGHTS')
    need(type(stage) is str and stage in STAGES, 'STAGE')
    current, remaining = prior, rights
    query = False
    def result(path, final=True):
        return {'path': path, 'action': current, 'rights': remaining,
                'query_reached': query, 'action_is_final_for_modelled_path': final,
                'native_wfp_executed': False, 'release_accepted': False}
    def deny(reason):
        nonlocal current, remaining
        if remaining & 1 or current == 'PERMIT':
            current, remaining = 'BLOCK', remaining & ~1
            return result(reason+':BLOCK')
        return result(reason+':PRESERVE')
    if stage == 'NO_OUTPUT':
        return result('NO_OUTPUT', False)
    # This is in the registered outer callback, before Active/STOP and delegation.
    if rights & 1:
        current = 'CONTINUE'
    for failure in ('RUNDOWN_DENIED', 'STOPPING', 'UNCONFIGURED', 'NULL_INPUT'):
        if stage == failure:
            return deny(failure)
    if stage == 'WRONG_LAYER':
        return result('WRONG_LAYER_RETURN')
    if stage == 'INVALID_APPID':
        return deny(stage)
    if stage == 'FOREIGN_APPID':
        return result('FOREIGN_APPID_RETURN')
    # The inner no-write check dominates every redirect-state query.
    if not remaining & 1:
        return deny('NO_WRITE_BEFORE_QUERY')
    if stage in ('MISSING_IDENTITY', 'NON_TCP'):
        return deny(stage)
    if stage != 'RECORDS_ABSENT':
        query = True
    if stage in ('SELF', 'PREVIOUS_SELF'):
        return result(stage+':RETURN_CONTINUE')
    if stage == 'OTHER':
        return deny('OTHER_REDIRECT')
    return result('MODIFYING_PATH_NOT_MODELLED', False)

def matrix_rows():
    for family, prior, rights, stage in itertools.product((4, 6), ACTIONS, RIGHTS, STAGES):
        out = evaluate(family, prior, rights, stage)
        yield f"{family}|{prior}|{rights}|{stage}|{out['path']}|{out['action']}|{out['rights']}|{int(out['query_reached'])}|{int(out['action_is_final_for_modelled_path'])}\n", out, stage

def matrix():
    counts, digest, states, self_returns = Counter(), hashlib.sha256(), 0, 0
    for row, out, stage in matrix_rows():
        digest.update(row.encode('ascii')); states += 1; counts[out['path']] += 1
        if stage in ('SELF', 'PREVIOUS_SELF') and out['query_reached']:
            need(out['action'] == 'CONTINUE' and out['rights'] & 1 == 1, 'SELF_POSTCONDITION')
            self_returns += 1
        need(not out['query_reached'] or out['rights'] & 1 == 1 or out['path']=='OTHER_REDIRECT:BLOCK', 'QUERY_REACHABILITY')
        need(out['native_wfp_executed'] is False and out['release_accepted'] is False, 'NO_NATIVE_PROMOTION')
    need(states == 720 and self_returns == 48, 'CARDINALITY')
    return {'states': states, 'reachable_self_returns': self_returns,
            'categories': dict(sorted(counts.items())), 'sha256': digest.hexdigest(),
            'native_wfp_executed': False, 'release_accepted': False}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    modes = p.add_mutually_exclusive_group(required=True)
    modes.add_argument('--source-root', type=Path)
    modes.add_argument('--model-only', action='store_true')
    p.add_argument('--rows', action='store_true')
    args = p.parse_args()
    if args.source_root is not None:
        source_gate(args.source_root)
    if args.rows:
        print(''.join(row for row, _, _ in matrix_rows()), end='')
    else:
        print(json.dumps({**matrix(), 'source_pins_checked': args.source_root is not None}, sort_keys=True))

if __name__ == '__main__':
    main()
