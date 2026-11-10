#!/usr/bin/env python3
"""Independent negative model for four consecutive R98 BFE object-pair reads.
No live BFE, no registry, no sockets, no WFP activity.
"""
from itertools import product
from hashlib import sha256
def main():
    counts={"total":0,"old_pass":0,"old_pass_no_coexistence":0,"old_pass_with_coexistence":0,"txn_pass":0}
    h=sha256()
    for a,b,c,d in product(range(16),repeat=4):
        old=int(bool((a&1) and (b&2) and (c&4) and (d&8)))
        co=int(15 in (a,b,c,d))
        txn=int(a==15)
        counts["total"]+=1;counts["old_pass"]+=old
        counts["old_pass_no_coexistence"]+=old*(1-co)
        counts["old_pass_with_coexistence"]+=old*co
        counts["txn_pass"]+=txn
        h.update(f"{a},{b},{c},{d},{old},{co},{txn}\n".encode())
    assert (counts["total"],counts["old_pass"],counts["old_pass_no_coexistence"],counts["old_pass_with_coexistence"],counts["txn_pass"])==(65536,4096,2401,1695,4096)
    print(counts)
    print(h.hexdigest())
if __name__=="__main__":main()
