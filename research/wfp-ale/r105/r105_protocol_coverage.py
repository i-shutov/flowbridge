#!/usr/bin/env python3
"""Synthetic negative WFP filter-condition coverage, not a live WFP test."""
from itertools import product
from hashlib import sha256
from collections import Counter

FAMILIES = (4, 6)
STAGES = ('AUTH', 'REDIRECT')
PROTOCOLS = (1, 6, 17, 58)  # ICMPv4, TCP, UDP/QUIC, ICMPv6
APPIDS = ('SELECTED', 'SIBLING', 'ALIAS', 'MISSING')


def match(stage, protocol, current, original):
    # From exact R19 policy_windows.rs: two ANDed conditions per layer.
    # AUTH: ALE_ORIGINAL_APP_ID == SELECTED and IP_PROTOCOL == 6.
    # REDIRECT: ALE_APP_ID == SELECTED and IP_PROTOCOL == 6.
    if protocol != 6:
        return False
    return (original if stage == 'AUTH' else current) == 'SELECTED'


rows = []
counts = Counter()
for f, st, p, current, original in product(FAMILIES, STAGES, PROTOCOLS, APPIDS, APPIDS):
    result = 'MATCH' if match(st, p, current, original) else 'NO_MATCH'
    rows.append(f'{f}|{st}|{p}|{current}|{original}|{result}')
    counts[result] += 1

assert len(rows) == 256
assert counts == {'MATCH': 16, 'NO_MATCH': 240}, counts
assert all(match(st, 17, 'SELECTED', 'SELECTED') is False for st in STAGES)
assert all(match(st, 6, 'SIBLING', 'SIBLING') is False for st in STAGES)
assert all(match(st, 6, 'ALIAS', 'ALIAS') is False for st in STAGES)
assert all(match(st, 6, 'SELECTED', 'SELECTED') is True for st in STAGES)
assert match('AUTH', 6, 'SIBLING', 'SELECTED')
assert not match('REDIRECT', 6, 'SIBLING', 'SELECTED')
print('states', len(rows), 'matched', counts['MATCH'], 'not_matched', counts['NO_MATCH'])
print('matrix_sha256', sha256(('\n'.join(rows) + '\n').encode()).hexdigest())
