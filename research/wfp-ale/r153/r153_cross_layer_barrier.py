#!/usr/bin/env python3
"""FlowBridge R153: logical closure-vs-AUTH barrier countermodel, no WFP calls.

This explores candidate interleavings that documentation does not rule out by an
explicit global AUTH/CLAIM drain guarantee. It does NOT prove Windows executes
any particular interleaving, endpoint handle reuse or a traffic leak.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

R152_BLOB = 'ab703d06ab07ac003b0ea3c4aded0ab02a0e2b68'
R19_HANDOFF_BLOB = 'e1d17217db50362ba9c4efc83af820b6beb094cf'

# Logical event graph. Closure's own queued work is completed before its release,
# but there is NO assumed documented total-order between closure completion and
# an AUTH callback already in flight at another layer.
EVENTS = ('ISSUE_OLD', 'AUTH_OLD_ENTER', 'CLOSE_ENTER', 'CLOSE_PEND',
          'CLOSE_OWN_WORK_DONE', 'CLOSE_COMPLETE', 'ISSUE_NEW',
          'AUTH_OLD_RESUME', 'AUTH_NEW')
BEFORE = {
    'ISSUE_OLD': (),
    'AUTH_OLD_ENTER': ('ISSUE_OLD',),
    'CLOSE_ENTER': ('ISSUE_OLD',),
    'CLOSE_PEND': ('CLOSE_ENTER',),
    'CLOSE_OWN_WORK_DONE': ('CLOSE_PEND',),
    'CLOSE_COMPLETE': ('CLOSE_OWN_WORK_DONE',),
    'ISSUE_NEW': ('CLOSE_COMPLETE',),
    'AUTH_OLD_RESUME': ('AUTH_OLD_ENTER',),
    'AUTH_NEW': ('ISSUE_NEW',),
}

def gitblob(data: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest()

def pin(path: Path, wanted: str) -> None:
    raw = path.read_bytes()
    if gitblob(raw) != wanted:
        raise RuntimeError('SOURCE_PIN_MISMATCH:' + path.name)

def schedules():
    def dfs(seq, seen):
        if len(seq) == len(EVENTS):
            yield tuple(seq)
            return
        for e in EVENTS:
            if e not in seen and all(x in seen for x in BEFORE[e]):
                yield from dfs((*seq, e), seen | {e})
    yield from dfs((), frozenset())

def classify(schedule: tuple[str, ...], same_visible: bool, reuse: bool) -> str:
    # The old AUTH has no authenticated issuance nonce. Its visible tuple is
    # assumed identical to the new tuple only if same_visible and reuse.
    # An endpoint-specific rule promoted on CLOSE_COMPLETE is the design under test.
    ordered = {name: i for i, name in enumerate(schedule)}
    if not reuse:
        return 'REUSE_QUARANTINED'
    if ordered['AUTH_OLD_RESUME'] < ordered['ISSUE_NEW']:
        return 'OLD_AUTH_BEFORE_NEW_ISSUANCE'
    return 'STALE_AUTH_ALIAS' if same_visible else 'OBSERVABLE_DIFFERENCE'

def campaign():
    ss = list(schedules())
    if len(set(ss)) != len(ss) or not ss:
        raise RuntimeError('BAD_SCHEDULE_ENUMERATION')
    rows = []
    stats = Counter()
    for family in (4, 6):
        for same_visible in (False, True):
            for reuse in (False, True):
                for s in ss:
                    result = classify(s, same_visible, reuse)
                    line = f'{family}|{int(same_visible)}|{int(reuse)}|{",".join(s)}|{result}\n'
                    rows.append(line)
                    stats[result] += 1
                    if result == 'STALE_AUTH_ALIAS':
                        # Hypothetical per-issuance authentication separates old
                        # nonce 1 from new nonce 2; R19 exposes no such proof.
                        if 1 == 2:
                            raise RuntimeError('NONCE_NOT_DISTINCT')
    if stats['STALE_AUTH_ALIAS'] == 0 or stats['REUSE_QUARANTINED'] == 0:
        raise RuntimeError('NEGATIVE_CASES_NOT_COVERED')
    if stats['STALE_AUTH_ALIAS'] != stats['OBSERVABLE_DIFFERENCE']:
        raise RuntimeError('SYMMETRY_BROKEN')
    if stats['REUSE_QUARANTINED'] != len(ss) * 4:
        raise RuntimeError('QUARANTINE_INCONSISTENT')
    return {'schedules': len(ss), 'cases': len(rows), 'sha256': hashlib.sha256(''.join(rows).encode()).hexdigest(),
            'categories': dict(sorted(stats.items())), 'native_wfp_executed': False,
            'actual_reuse_observed': False, 'cross_layer_barrier_proved': False,
            'release_accepted': False}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--r152-source', type=Path, required=True)
    parser.add_argument('--r19-handoff', type=Path, default=None)
    args = parser.parse_args()
    pin(args.r152_source, R152_BLOB)
    if args.r19_handoff is not None:
        pin(args.r19_handoff, R19_HANDOFF_BLOB)
    print(json.dumps(campaign(), sort_keys=True, separators=(',', ':')))

if __name__ == '__main__':
    main()
