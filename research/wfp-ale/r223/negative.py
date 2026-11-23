#!/usr/bin/env python3
"""R223: stale PING renewal vs fresh CLAIM; absolute-time state machine."""
from itertools import product
from hashlib import sha256
L, T, BASE = 30_000_000, 100_000_000, 200_000_000

def run(s, c, q, issued, fresh_ping, fresh_claim):
    last = BASE
    lost = False
    def ready(t):
        nonlocal lost
        if lost or not last <= t <= last + L:
            lost = True
        return not lost
    p = c if fresh_ping else s
    if not ready(p):
        return 0
    last = p
    # No concurrent PING/CLAIM: CLAIM starts only after PING returns.
    t = q if fresh_claim else c
    if not ready(t):
        return 0
    return 2 if issued <= t <= issued + T else 1

def main():
    rows = []
    for f, a, d, lag, age in product((4,6), (L-10000,L-1,L,L+1), (0,1,2,10000,20000), (0,1,10000,L), (0,L,T-1,T,T+1)):
        s = BASE+a; c=s+d; q=c+lag; issued=s-age
        outcomes = [run(s,c,q,issued,p,k) for p,k in ((False,False),(False,True),(True,False),(True,True))]
        rows.append((f,a,d,lag,age,*outcomes))
    witnesses = [r for r in rows if r[1]<=L<r[1]+r[2] and r[6]==2 and r[8]==0]
    for f in (4,6):
        assert (f,L,10000,10000,L,2,2,0,0) in rows
        assert (f,L-10000,20000,10000,L,2,2,0,0) in rows
        assert (f,L,0,0,0,2,2,2,2) in rows
        assert (f,L+1,0,0,0,0,0,0,0) in rows
        assert (f,L,10000,L,0,2,0,0,0) in rows
    assert witnesses and all(r[7]==0 for r in witnesses)
    assert all(r[8]==0 for r in rows if r[1]+r[2]>L)
    data=''.join(','.join(map(str,r))+'\n' for r in rows).encode()
    print(f'rows={len(rows)} fresh_claim_only_late_renewal={len(witnesses)} sha256={sha256(data).hexdigest()}')

if __name__=='__main__': main()
