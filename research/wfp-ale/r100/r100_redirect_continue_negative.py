#!/usr/bin/env python3
"""R100 source-anchored abstract transition negative; NO Windows/driver/network use."""
import hashlib, itertools, pathlib, sys
ROOT=pathlib.Path("research/wfp-ale/kernel-r19/kernel/src")
def guard(root):
    lib=(root/ROOT/"lib.rs").read_text(encoding="utf-8")
    red=(root/ROOT/"redirect.rs").read_text(encoding="utf-8")
    assert "(*out).actionType=k::FWP_ACTION_CONTINUE;" in lib
    assert "redirect::classify(values,meta,_context,_filter,out);" in lib
    assert "if appid!=&r.name[..r.len]{return;}" in red
    assert "if !auth_check(values,meta){block(out);return;}" in red
def step(selected,installed,writable,equal,auth_called,downstream_permit,ready):
    if not selected: return ("OUT_OF_SCOPE","NA",False)
    if not installed: redirect="NO_REDIRECT_CALLOUT"
    elif not writable: redirect="UNDETERMINED_NO_WRITE_RIGHT"
    elif not equal: redirect="CONTINUE"
    elif not ready: redirect="DRIVER_BLOCK"
    else: redirect="REDIRECT_CANDIDATE"
    if redirect=="CONTINUE" and auth_called: auth="AUTH_DRIVER_BLOCK"
    elif redirect=="CONTINUE": auth="AUTH_NOT_INVOKED"
    else: auth="NOT_EVALUATED"
    return (redirect,auth,redirect=="CONTINUE" and not auth_called and downstream_permit)
def main():
    if len(sys.argv)>2: raise SystemExit("usage: script [checkout_root]")
    if len(sys.argv)==2: guard(pathlib.Path(sys.argv[1]))
    rows=[]
    for bits in itertools.product((0,1),repeat=7):
        r,a,p=step(*[bool(v) for v in bits])
        rows.append("".join(map(str,bits))+","+r+","+a+","+str(int(p)))
    assert len(rows)==128
    assert step(True,True,True,False,False,True,True)==("CONTINUE","AUTH_NOT_INVOKED",True)
    assert step(True,True,True,False,True,True,True)==("CONTINUE","AUTH_DRIVER_BLOCK",False)
    assert step(True,True,True,True,True,True,False)[0]=="DRIVER_BLOCK"
    data=("\n".join(rows)+"\n").encode()
    print("rows=128 continue="+str(sum(",CONTINUE," in row for row in rows))+" conditional_potential_direct="+str(sum(row.endswith(",1") for row in rows)))
    print("sha256="+hashlib.sha256(data).hexdigest())
if __name__=="__main__":main()
