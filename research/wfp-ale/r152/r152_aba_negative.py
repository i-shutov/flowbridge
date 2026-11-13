#!/usr/bin/env python3
"""R152: observational indistinguishability of stale AUTH under hypothetical endpoint ABA.

Offline model; does not assert WFP actually reuses endpoint handles. No API calls,
network, services, WFP filters, drivers, or elevated privileges.
"""
from __future__ import annotations
import argparse
from dataclasses import dataclass
import hashlib
import itertools
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
PINS = {
 'r150/r150_preselection_negative.py':'3e81d27a80e88671775be9015f436bdf5cd100bb',
 'r151/r151_negative.py':'cd8891e999f6e7f350ddbe853cd68ea26dde8d1d',
}
R19_PINS = {
 'kernel/src/handoff.rs':'e1d17217db50362ba9c4efc83af820b6beb094cf',
 'kernel/src/redirect.rs':'a093f049d162987981a957aac90db1014bc6ff09',
}

def need(ok:bool, code:str)->None:
    if type(ok) is not bool or not ok: raise RuntimeError('INVARIANT:'+code)

def pin(path:Path, expected:str)->None:
    raw=path.read_bytes()
    got=hashlib.sha1(b'blob '+str(len(raw)).encode('ascii')+b'\0'+raw).hexdigest()
    if got!=expected: raise RuntimeError(f'SOURCE_PIN_MISMATCH:{path.name}:{got}')

def source_gate(root:Path, r19_root:Path|None):
    for file,sha in PINS.items(): pin(root/file,sha)
    if r19_root is not None:
        for file,sha in R19_PINS.items(): pin(r19_root/file,sha)

@dataclass(frozen=True)
class Visible:
    app:str
    process_epoch:int
    pid:int
    start_key:int
    endpoint:int
    family:int
    compartment:int
    destination:str

@dataclass(frozen=True)
class Ticket:
    issuance:int
    observed:Visible
    authenticated:bool=False

# Literal R19-equivalent decision predicate, *not* native AUTH visibility proof.
def auth_matches_ticket(ticket:Ticket, auth:Visible)->bool:
    return ticket.observed == auth and not ticket.authenticated

# Closure-only recycling is a proposed mutant, NOT R19's current implementation.
def closure_only_attest(new_ticket:Ticket, auth:Visible)->bool:
    return auth_matches_ticket(new_ticket,auth)

# This is conservative and can harm availability. A closure indication by itself
# is not treated as a proof that every delayed AUTH and async consumer has drained.
def session_quarantine_allows_new_issue(same_numeric_handle:bool)->bool:
    return not same_numeric_handle

# Trusted native issuance ID is hypothetical: no such field is claimed in WFP.
def hypothetical_native_nonce_attest(new_ticket:Ticket, auth:Visible,
                                    auth_native_nonce:int)->bool:
    return auth_matches_ticket(new_ticket,auth) and new_ticket.issuance==auth_native_nonce

def r19_book_shape_attest(ticket:Ticket, auth:Visible)->bool:
    # Modeled only after Book::attest/Origin::matches_origin and source AppId guard.
    # The R19 handoff Context has no compartment field and no issuance sequence
    # supplied by the AUTH classify; this predicate is deliberately weaker.
    new=ticket.observed
    return (new.app=='selected' and auth.app=='selected' and new.pid==auth.pid
            and new.process_epoch==auth.process_epoch and new.start_key==auth.start_key
            and new.endpoint==auth.endpoint and new.family==auth.family
            and new.destination==auth.destination and not ticket.authenticated)

def campaign():
    rows=[]; aliases=[]; twins=0; stale_accepted=0; fresh_accepted=0; weaker_alias=0
    for family,epoch_same,app_same,comp_same,dest_same,handle_same,auth_old in itertools.product(
      (4,6), (0,1),(0,1),(0,1),(0,1),(0,1),(0,1)):
        old=Visible('selected',100,501,300,71,family,9,'198.51.100.10:443')
        new=Visible('selected' if app_same else 'sibling',
                    100 if epoch_same else 101, 501,
                    300 if epoch_same else 301,
                    71 if handle_same else 72,
                    family,9 if comp_same else 10,
                    old.destination if dest_same else '198.51.100.11:443')
        ticket=Ticket(2,new)
        auth=old if auth_old else new
        accepted=closure_only_attest(ticket,auth)
        quarantine=session_quarantine_allows_new_issue(bool(handle_same))
        # The *external* classification generation would distinguish old vs new,
        # but is currently NOT an available authenticated WFP field.
        hypothetical=hypothetical_native_nonce_attest(ticket,auth,1 if auth_old else 2)
        alias=bool(auth_old and accepted)
        weaker=bool(r19_book_shape_attest(ticket,auth))
        if auth_old and weaker: weaker_alias+=1
        if alias: aliases.append((family,epoch_same,app_same,comp_same,dest_same,handle_same))
        if auth_old and accepted: stale_accepted+=1
        if not auth_old and accepted: fresh_accepted+=1
        if (old==new):
            twins+=1
            need(closure_only_attest(ticket,old)==closure_only_attest(ticket,new),'twins_same_visible')
            need(hypothetical_native_nonce_attest(ticket,old,1) is False,'old_native_nonce')
            need(hypothetical_native_nonce_attest(ticket,new,2) is True,'new_native_nonce')
        need(accepted == (not auth_old or old==new),'strong_visible_match')
        need(hypothetical == (not auth_old),'native_nonce_model')
        need(quarantine == (not handle_same),'quarantine')
        rows.append(f'{family}|{epoch_same}{app_same}{comp_same}{dest_same}{handle_same}{auth_old}|{int(accepted)}|{int(quarantine)}|{int(hypothetical)}|{int(alias)}|{int(weaker)}\n')
    need(len(rows)==128,'matrix_cardinality')
    need(len(aliases)==2 and twins==4 and stale_accepted==2 and fresh_accepted==64 and weaker_alias==4,'matrix_distribution')
    sha=hashlib.sha256(''.join(rows).encode()).hexdigest()
    return {'states':len(rows),'stale_auth_alias':len(aliases),'indistinguishable_rows':twins,
            'fresh_auth_accepted_by_naive':fresh_accepted,'stale_auth_accepted_by_naive':stale_accepted,'stale_auth_matches_r19_book_shape':weaker_alias,
            'sha256':sha,'native_windows_proof':False,'no_direct_proved':False,'release_accepted':False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--root',type=Path,default=BASE)
    p.add_argument('--r19-root',type=Path,default=None)
    a=p.parse_args()
    source_gate(a.root,a.r19_root)
    print(json.dumps({**campaign(),'r150_r151_pins_checked':True,'r19_local_pins_checked':a.r19_root is not None},sort_keys=True))

if __name__=='__main__': main()
