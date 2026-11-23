"""R224: value-only AUTH timing, no Windows calls."""
from itertools import product
from hashlib import sha256
L,T,B=30_000_000,100_000_000,200_000_000

def run(h,i,s,a,q,mode):
    # h=last heartbeat; i=issued ticket, s=first locked sample,
    # a=second sample; q=next fresh gate, no intervening renewal.
    lost=False
    def ready(t):
        nonlocal lost
        lost = lost or not h <= t <= h+L
        return not lost
    t=a if mode==2 else s
    auth=ready(t) and i <= (s if mode==1 else a) <= i+T
    lost_at_auth=lost
    claim=ready(q) and auth and i<=q<=i+T
    return int(auth),int(lost_at_auth),int(claim)

def main():
    rows=[]
    for f,age,lag,ticket_age,gap in product((4,6),(0,L-10000,L-1,L,L+1),(0,1,10000,20000),(0,T-10000,T-1,T,T+1),(0,1,10000,L)):
        h=B;s=h+age;a=s+lag;i=s-ticket_age;q=a+gap
        old,first,last=(run(h,i,s,a,q,m) for m in range(3))
        # Two-sample AUTH cannot authorize beyond the first-sample contract.
        assert not old[0] or first[0]
        # Strict second-sample mismatch cannot compose into fresh CLAIM
        # without another renewal. Here that renewal would also be expired.
        assert not (old[0] and not last[0]) or not old[2]
        assert old[2]==first[2]==last[2]
        rows.append((f,age,lag,ticket_age,gap,*old,*first,*last))
    late=sum(r[5] and not r[11] for r in rows)
    early=sum(r[8] and not r[5] for r in rows)
    assert late>0 and early>0
    assert (4,L-10000,20000,0,1,1,0,0,1,0,0,0,1,0) in rows
    assert (6,0,20000,T-10000,1,0,0,0,1,0,0,0,0,0) in rows
    data=''.join(','.join(map(str,r))+'\n' for r in rows).encode()
    print(f'rows={len(rows)} late_auth={late} early_contract_reject={early} claim_disagreements=0 sha256={sha256(data).hexdigest()}')
if __name__=='__main__':main()
