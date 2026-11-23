#!/usr/bin/env python3
"""R222: deterministic value-only negative; no Windows or network calls."""
from itertools import product
import hashlib

L, T = 30_000_000, 100_000_000
S = 200_000_000

def ready(now, last):
    return now >= last and now - last <= L

def claim(now, last, issued):
    if not ready(now, last):
        return 0  # terminal lease loss
    return 2 if issued <= now and now - issued <= T else 1

def matrix():
    for family, a, b, d, refresh in product((4, 6), (0, L-1, L, L+1), (0, T-1, T, T+1), (0, 1, 2), (0, 1)):
        last, issued, locked = S-a, S-b, S+d
        if refresh:
            # A fresh PING sampled at S+1 acquires the lock before CLAIM.
            if d == 0 or not ready(S+1, last):
                continue
            last = S+1
        old = claim(S, last, issued)
        fresh = claim(locked, last, issued)
        yield (family, a, b, d, refresh, old, fresh)

def main():
    rows = list(matrix())
    counts = [sum(r[-2] == 2 and r[-1] != 2 for r in rows),
              sum(r[-2] == 0 and r[-1] == 2 for r in rows)]
    for f in (4, 6):
        assert (f,L,0,1,0,2,0) in rows  # lease crossed
        assert (f,0,T,1,0,2,1) in rows  # ticket crossed
        assert (f,0,0,1,1,0,2) in rows  # newer PING triggers false terminal loss
        assert (f,L,T,0,0,2,2) in rows  # inclusive boundaries
        assert (f,L+1,0,0,0,0,0) in rows  # already expired
    data = ''.join(','.join(map(str,r))+'\n' for r in rows).encode()
    print(f'rows={len(rows)} late_admission={counts[0]} false_terminal_loss={counts[1]} sha256={hashlib.sha256(data).hexdigest()}')
    assert counts[0] and counts[1]

if __name__ == '__main__':
    main()
