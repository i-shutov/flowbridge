#!/usr/bin/env python3
"""Read-only offline negative model: R19-owned BFE filters; not a packet proof."""
from hashlib import sha256
from itertools import product
PHASES = ('ARMED_BEFORE_POLICY','POLICY_LIVE','SSH_LOSS_POLICY_LIVE',
          'BROKER_EXIT','GRACEFUL_POLICY_CLOSE','BFE_STATE_UNKNOWN')
def owned(phase):
    if phase in ('ARMED_BEFORE_POLICY','BROKER_EXIT','GRACEFUL_POLICY_CLOSE'):
        return 'ABSENT'
    if phase in ('POLICY_LIVE','SSH_LOSS_POLICY_LIVE'):
        return 'PRESENT'
    return 'UNKNOWN'
rows = []
for phase,alive,attempt,guard in product(PHASES,(0,1),(0,1),(0,1)):
    coverage = owned(phase)
    gap = coverage == 'ABSENT' and bool(alive) and bool(attempt)
    conditional = gap and not guard
    verdict = 'CANDIDATE' if conditional else 'NOT_ESTABLISHED'
    rows.append(f'{phase}|{alive}|{attempt}|{guard}|{coverage}|{int(gap)}|{verdict}')
columns=[r.split('|') for r in rows]
assert len(rows)==48
assert sum(r[4]=='ABSENT' for r in columns)==24
assert sum(r[4]=='PRESENT' for r in columns)==16
assert sum(r[4]=='UNKNOWN' for r in columns)==8
assert sum(r[5]=='1' for r in columns)==6
assert sum(r[6]=='CANDIDATE' for r in columns)==3
assert not any('DIRECT_OBSERVED' in r for r in rows)
assert all(r[4]=='ABSENT' for r in columns if r[0]=='BROKER_EXIT')
digest=sha256(('\n'.join(rows)+'\n').encode()).hexdigest()
assert digest=='5fef8e2d1307ca8d13ec949b4725e163fb0576ce074700b0f7382e78f48d3ef0'
print('R106 PY PASS 48 states, 6 owned-policy gap attempts, 3 candidates; sha256='+digest)
