#!/usr/bin/env python3
"""Finite negative evidence, no Windows calls, sockets, or installed filters."""
import hashlib
import itertools

# Microsoft: FWP_EMPTY effective weight is in [0, 2**60). Thus 2**60 strictly
# outranks any unmodified FlowBridge R19 filter using FWP_EMPTY, if both match
# in the same sublayer.  This is a SYNTHETIC additional-filter scenario.
AUTO_MAX_EXCLUSIVE = 1 << 60
COMPETITOR_WEIGHT = 1 << 60

def outcome(present: bool, matches: bool, action: str) -> str:
    if present and matches and COMPETITOR_WEIGHT >= AUTO_MAX_EXCLUSIVE:
        if action == 'PERMIT':
            return 'SHADOWED_BY_PERMIT'
        if action == 'BLOCK':
            return 'SHADOWED_BY_BLOCK'
    return 'FLOWBRIDGE_CALLOUT_REACHED_IN_MODEL'

def matrix():
    rows = []
    for family, layer, present, matches, action in itertools.product(
        ('v4', 'v6'), ('AUTH_CONNECT', 'CONNECT_REDIRECT'),
        (0, 1), (0, 1), ('PERMIT', 'BLOCK', 'CONTINUE')
    ):
        verdict = outcome(bool(present), bool(matches), action)
        rows.append('|'.join(map(str, (family, layer, present, matches, action, verdict))))
    return rows

def main():
    assert COMPETITOR_WEIGHT >= AUTO_MAX_EXCLUSIVE
    rows = matrix()
    assert len(rows) == 48
    assert len(set(rows)) == 48
    assert sum('SHADOWED_BY_PERMIT' in r for r in rows) == 4
    assert sum('SHADOWED_BY_BLOCK' in r for r in rows) == 4
    assert sum('FLOWBRIDGE_CALLOUT_REACHED_IN_MODEL' in r for r in rows) == 40
    assert outcome(True, True, 'PERMIT') == 'SHADOWED_BY_PERMIT'
    assert outcome(True, True, 'BLOCK') == 'SHADOWED_BY_BLOCK'
    assert outcome(True, True, 'CONTINUE') == 'FLOWBRIDGE_CALLOUT_REACHED_IN_MODEL'
    assert outcome(False, True, 'PERMIT') == 'FLOWBRIDGE_CALLOUT_REACHED_IN_MODEL'
    assert outcome(True, False, 'PERMIT') == 'FLOWBRIDGE_CALLOUT_REACHED_IN_MODEL'
    # A purposeful mutant must fail the invariant, avoiding a vacuous test.
    assert outcome(True, True, 'PERMIT') != 'FLOWBRIDGE_CALLOUT_REACHED_IN_MODEL'
    digest = hashlib.sha256(('\n'.join(rows) + '\n').encode()).hexdigest()
    print('R102 NEGATIVE: 48 deterministic cases; shadowed=8, reached=40; PASS')
    print('MATRIX_SHA256=' + digest)
    print('WITNESS=' + next(r for r in rows if 'SHADOWED_BY_PERMIT' in r))
    print('LIMIT=source-and-document-model-only; no BFE state, WFP callback or network observation')

if __name__ == '__main__':
    main()
