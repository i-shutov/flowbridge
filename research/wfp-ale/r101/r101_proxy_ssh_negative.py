#!/usr/bin/env python3
"""R101: conditional model only; no WFP calls, socket creation, or driver execution."""
import hashlib
import itertools
from collections import Counter

FIELDS = ('records_set', 'original_selected', 'auth_rule', 'auth_invoked', 'claim_consumed', 'remote_loopback', 'ssh_ready')

def classify(v):
    records_set, original_selected, auth_rule, auth_invoked, claimed, loopback, ssh_ready = v
    if not records_set:
        return 'NO_WFP_RECORD'
    if not ssh_ready:
        return 'SSH_UNAVAILABLE'
    if not original_selected:
        return 'ORIGINAL_APPID_NOT_SELECTED_UNPROVED'
    if not auth_rule or not auth_invoked:
        return 'AUTH_ENFORCEMENT_UNPROVED'
    # Most favorable other checks: flag, PID, epoch, original target, metadata, write-right all valid.
    # R19 rejects a non-loopback endpoint and an already-consumed one-shot ticket.
    if not loopback or claimed:
        return 'R19_AUTH_CALLBACK_BLOCK'
    return 'SYNTHETIC_AUTH_ALLOW_NOT_WINDOWS_PASS'

def main():
    rows=[]
    for family in (4, 6):
        for bits in itertools.product((0, 1), repeat=len(FIELDS)):
            rows.append(';'.join(map(str, (family, *bits)))+';'+classify(bits))
    matrix='\n'.join(rows)+'\n'
    counts=Counter(r.rsplit(';',1)[1] for r in rows)
    assert len(rows)==256 and len(set(rows))==256
    witness=(1,1,1,1,1,0,1)
    assert classify(witness)=='R19_AUTH_CALLBACK_BLOCK'
    assert classify((1,1,1,1,0,1,1))=='SYNTHETIC_AUTH_ALLOW_NOT_WINDOWS_PASS'
    assert classify((1,1,1,0,1,0,1))=='AUTH_ENFORCEMENT_UNPROVED'
    assert classify((1,0,1,1,1,0,1))=='ORIGINAL_APPID_NOT_SELECTED_UNPROVED'
    print('rows',len(rows),'sha256',hashlib.sha256(matrix.encode()).hexdigest())
    print('counts',','.join(f'{k}={counts[k]}' for k in sorted(counts)))
    print('conditional_witness',';'.join(map(str,(4,*witness)))+';'+classify(witness))

if __name__=='__main__': main()
