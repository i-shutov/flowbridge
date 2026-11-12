#!/usr/bin/env python3
"""R145: no-driver/no-WFP deterministic source-contract counterexample.

NOT native evidence. Run from an exact FlowBridge research checkout for Git blob pin checks.
"""
import hashlib
import itertools
import json
from pathlib import Path
import sys

PINS = {
    'kernel-r19/policy_windows.rs': 'acf60334320d970f58af3349ee75fbaa59826602',
    'kernel-r19/broker_windows.rs': '16ec8853d322b40f0e00e14d49ae3410741b9395',
    'kernel-r19/kernel/src/redirect.rs': 'a093f049d162987981a957aac90db1014bc6ff09',
}
CHECKS = {
    'kernel-r19/policy_windows.rs': ('FWPM_CONDITION_ALE_ORIGINAL_APP_ID', 'FWPM_LAYER_ALE_AUTH_CONNECT_V4', 'FWPM_LAYER_ALE_AUTH_CONNECT_V6'),
    'kernel-r19/broker_windows.rs': ('claim_and_connect_trusted_ssh', 'WSAIoctl(s.0,SET_RECORDS', 'connect(s.0', 'remote.ip().octets()'),
    'kernel-r19/kernel/src/redirect.rs': ('if !loopback{return false;}', 'if !auth_check(values,meta){block(out);return;}', '0x0000_0004|0x0200_0000'),
}

def source_pins():
    base = Path(__file__).resolve().parent.parent
    for path, sha in PINS.items():
        raw = (base / path).read_bytes()
        observed = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\x00' + raw).hexdigest()
        if observed != sha:
            raise RuntimeError(f'SOURCE_PIN_MISMATCH {path} {observed}')
        for token in CHECKS[path]:
            if token.encode() not in raw:
                raise RuntimeError(f'SOURCE_CONTRACT_MISSING {path} {token}')

# Model conditions assume (without proving) that selected-original AppId is
# retained by WFP on the outbound record-tagged SSH socket and filter matches.
# R19 AUTH requires current remote=loopback; physical SSH remote is external.
def decision(kind, selected, redirected, complete, reauth, live, write, prior_permit):
    if not selected:
        return 'UNMATCHED'
    valid = (kind == 'LOCAL' and redirected and complete and not reauth and live)
    if valid and write:
        return 'PERMIT_CANDIDATE'
    if write or prior_permit:
        return 'BLOCK_CANDIDATE'
    return 'PRESERVE_UNPROVEN'

def run():
    output = []
    count = {}
    for family, kind, selected, records, redirected, complete, reauth, live, write, prior_permit in itertools.product(
            (4, 6), ('LOCAL', 'SSH', 'DIRECT'), (0, 1), (0, 1), (0, 1), (0, 1), (0, 1), (0, 1), (0, 1), (0, 1)):
        d = decision(kind, selected, redirected, complete, reauth, live, write, prior_permit)
        if selected and kind in ('SSH', 'DIRECT') and d == 'PERMIT_CANDIDATE':
            raise RuntimeError('UNEXPECTED_EXTERNAL_PERMIT')
        if selected and reauth and d == 'PERMIT_CANDIDATE':
            raise RuntimeError('UNEXPECTED_REAUTH_PERMIT')
        key = f'{kind}:{d}'
        count[key] = count.get(key, 0) + 1
        output.append(f'{family}|{kind}|{selected}{records}{redirected}{complete}{reauth}{live}{write}{prior_permit}|{d}\n')
    encoded = ''.join(output).encode()
    result = dict(rows=len(output), sha256=hashlib.sha256(encoded).hexdigest(), distribution=dict(sorted(count.items())),
                  source_contract='PINNED_R19', original_appid_propagation='CONDITIONAL_UNPROVEN',
                  native_wfp_executed=False, physical_ssh_proved=False, release_accepted=False)
    assert len(output) == 1536
    assert count['LOCAL:PERMIT_CANDIDATE'] == 8
    assert count.get('SSH:PERMIT_CANDIDATE', 0) == 0
    assert count.get('DIRECT:PERMIT_CANDIDATE', 0) == 0
    return result

if __name__ == '__main__':
    if sys.argv[1:] != ['--model-only']:
        if sys.argv[1:]:
            raise SystemExit('usage: r145_auth_egress_negative.py [--model-only]')
        source_pins()
    print(json.dumps(run(), sort_keys=True, separators=(',', ':')))
