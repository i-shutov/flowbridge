#!/usr/bin/env python3
"""Offline specification of wait/exit-code handling. No native execution here."""
import hashlib
import json

WAITS=(0,258,128,0xffffffff,1,999)
CODES=(0,23,259,0xffffffff,1)

def observed(wait,ok,code):
    if not ok: return 'EXIT_QUERY_ERROR'
    table={0:'EXITED',258:'NOT_SIGNALED_AT_READ' if code==259 else 'RACED_OR_INCONSISTENT'}
    return table.get(wait,'UNKNOWN_WAIT')

def matrix():
    return ''.join(f'{w}:{c}:{int(ok)}:{observed(w,ok,c)}\n' for w in WAITS for c in CODES for ok in (False,True))

def result():
    text=matrix()
    return {'states':60,'sha256':hashlib.sha256(text.encode('ascii')).hexdigest(),
            'terminated_259':observed(0,True,259),
            'naive_exit_only_alive_259':True}
if __name__=='__main__': print(json.dumps(result(),sort_keys=True))
