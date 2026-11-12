#!/usr/bin/env python3
"""Offline process-instance gate, not an ALE/socket attribution model."""
import hashlib,itertools,json
EXPECTED=((7,11),(7,0),(0,11),(0,0))
OBSERVED=((7,11),(8,11),(7,12),(8,12),(0,0))
WAITS=((258,258),(0,0),(258,0),(0,258),(4294967295,4294967295),(128,128))
def admit(ep,et,cp,ct,w0,w1,exit_code,same_app):
    return ep>0 and et>0 and (ep,et)==(cp,ct) and (w0,w1)==(258,258) and exit_code==259 and same_app

def matrix():
    rows=[]
    for (ep,et),(cp,ct),(w0,w1),code,app in itertools.product(EXPECTED,OBSERVED,WAITS,(259,23),(False,True)):
        result=admit(ep,et,cp,ct,w0,w1,code,app)
        rows.append(f'{ep}:{et}:{cp}:{ct}:{w0}:{w1}:{code}:{int(app)}:{int(result)}\n')
    return ''.join(rows)
def result():
    text=matrix();rows=text.splitlines()
    return dict(states=len(rows),eligible=sum(r.endswith(':1') for r in rows),
        appid_only_eligible=sum(r.split(':')[-2]=='1' for r in rows),
        sha256=hashlib.sha256(text.encode('ascii')).hexdigest())
if __name__=='__main__':print(json.dumps(result(),sort_keys=True))
