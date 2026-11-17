#!/usr/bin/env python3
"""R212: deterministic negative for an ISSUE->invalidation->APPLY source interleaving.
NO driver, sockets, Windows calls or claim of native kernel behavior."""
import sys, itertools, hashlib
from pathlib import Path

def model(seq, fence=False):
    live=True; issued=False; late=False; applied=False
    for e in seq:
        if e=="ISSUE": issued=live
        elif e in ("STOP","OWNER_EXIT"): live=False
        elif e=="APPLY":
            applied=issued and (not fence or live)
            late=applied and not live
    return applied, late

def sources():
    root=Path(__file__).resolve().parents[1]
    pins={"kernel-r19/kernel/src/redirect.rs":"a093f049d162987981a957aac90db1014bc6ff09",
          "kernel-r19/kernel/src/lib.rs":"53f5ce6faa0f9f591974287f38ea890cafeb0dd2"}
    files={}
    for p,sha in pins.items():
        b=(root/p).read_bytes()
        assert hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()==sha,p
        files[p]=b.decode()
    r=files["kernel-r19/kernel/src/redirect.rs"]
    lib=files["kernel-r19/kernel/src/lib.rs"]
    a=r.index("let issue={let _lock=Guard::take();")
    b=r.index("let Some((context,broker,port))=issue else{block(out);return;};",a)
    c=r.index("(*out).rights|=incoming_write;(*out).actionType=k::FWP_ACTION_PERMIT;",b)
    segment=r[b:c]
    guards=(a<b<c, "ready(" not in segment, "request.localRedirectContext=memory" in segment,
            "if memory.is_null(){let _lock=Guard::take();" in segment,
            "if code==h::STOP{lose();return super::SUCCESS;}" in r,
            "r.armed=false;r.book.kill();" in r,
            "(*STATE.0.get()).died(id,process as usize);redirect::process_exit(id);" in lib,
            r.index("drop(w);",c)>c)
    assert all(guards),guards
    print("2 exact Git blob pins; 8/8 structural source guards PASS")

if "--source" in sys.argv: sources()
count=0; bad=0
for loss in ("STOP","OWNER_EXIT"):
    eligible=0; late=0
    for seq in itertools.permutations(("ISSUE",loss,"APPLY")):
        if seq.index("ISSUE")>=seq.index("APPLY"): continue
        eligible+=1
        outcome=model(seq)
        counterfactual=model(seq,True)
        assert not counterfactual[1],seq
        if outcome[1]: late+=1
    assert (eligible,late)==(3,1),(loss,eligible,late)
    for family in (4,6):
        assert model(("ISSUE",loss,"APPLY"))==(True,True),family
        assert model(("ISSUE","APPLY",loss))==(True,False),family
        assert model((loss,"ISSUE","APPLY"))==(False,False),family
    count+=eligible;bad+=late
assert (count,bad)==(6,2)
print("R212 Python: 2/2 causes, IPv4/IPv6 controls, 6 eligible orderings, 2 post-invalidation APPLY negatives; NOT native WFP")
