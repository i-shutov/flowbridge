#!/usr/bin/env python3
"""Independent logical spec for a TEST composition, not kernel enforcement."""
from __future__ import annotations
import argparse
import hashlib
import itertools
import json
from pathlib import Path

FAMILIES=(4,6)
HAZARDS=('none','death_observed','pid_rebirth_observed','stop_applied','endpoint_reused')
VARIANTS=('valid','payload_changed','foreign_session','unknown_sequence','udp_byte')
ORDERS=tuple(itertools.permutations(range(6)))

def trace(hazard:int,variant:int,order:tuple[int,...],mutant:str='') -> tuple[str,...]:
    alive=True; ledger_lost=False; book_lost=False
    outstanding=True; authorized=False; expired=False
    result=[]; bl=[]; ll=[]; life=[]
    for event in order:
        ok=False
        if event<4:
            if book_lost or ledger_lost:
                book_lost=True;outstanding=False
            elif event<2:
                if alive and outstanding and not authorized and not expired:
                    authorized=True;ok=True
            else:
                v=variant if event==2 else 0
                if v not in (2,3) and outstanding:
                    # R19 consumes a matching sequence before validating auth/payload/liveness.
                    consumes=not (mutant=='nonterminal_failed_claim' and
                                  (not authorized or expired or v!=0))
                    if consumes: outstanding=False
                    if authorized and not expired and v==0:
                        ok=alive or mutant=='omit_claim_liveness'
        elif event==4:
            if hazard==1:
                alive=False;ok=True
            elif hazard==2:
                alive=False;ledger_lost=True
            elif hazard==3:
                book_lost=True;outstanding=False;ok=True
            elif hazard==4:
                if not book_lost:
                    if expired: outstanding=False
                    book_lost=True  # issued endpoint is an immutable tombstone
        elif event==5:
            expired=True;ok=True
        else:
            raise ValueError('unknown event')
        result.append(str(int(ok)));bl.append(str(int(book_lost)))
        ll.append(str(int(ledger_lost)));life.append(str(int(alive and not ledger_lost)))
    return tuple(''.join(x) for x in (result,bl,ll,life))

def campaign(mutant:str=''):
    for family in FAMILIES:
        for hazard in range(5):
            for variant in range(5):
                for order in ORDERS:
                    fields=trace(hazard,variant,order,mutant)
                    yield f"{family}|{hazard}|{variant}|{''.join(map(str,order))}|{'|'.join(fields)}\n"

def summarize(lines):
    digest=hashlib.sha256();cases=claims=auths=0;hazards={str(i):0 for i in range(5)}
    for line in lines:
        digest.update(line.encode('ascii'));parts=line.strip().split('|')
        order=parts[3];bits=parts[4]; accepted=sum(bits[i]=='1' and event in '23' for i,event in enumerate(order))
        assert accepted<=1
        claims+=accepted;auths+=sum(bits[i]=='1' and event in '01' for i,event in enumerate(order))
        hazards[parts[1]]+=accepted;cases+=1
    return {'traces':cases,'events':cases*6,'accepted_claims':claims,'accepted_auths':auths,
            'claims_by_hazard':hazards,'sha256':digest.hexdigest()}

def mutation_counts():
    result={}
    for mutant in ('omit_claim_liveness','nonterminal_failed_claim'):
        changed=extra=0
        for h in range(5):
            for v in range(5):
                for order in ORDERS:
                    a=trace(h,v,order);b=trace(h,v,order,mutant)
                    changed+=int(a!=b)
                    extra+=sum(b[0][i]=='1' and a[0][i]=='0' and e in (2,3) for i,e in enumerate(order))
        result[mutant]={'changed_traces':changed*2,'additional_claims':extra*2}
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path);parser.add_argument('--mutations',action='store_true')
    args=parser.parse_args()
    if args.output:
        with args.output.open('w',encoding='ascii',newline='\n') as f:
            f.writelines(campaign())
    result=summarize(campaign())
    if args.mutations: result['negative_controls']=mutation_counts()
    print(json.dumps(result,sort_keys=True))
