#!/usr/bin/env python3
"""Independent WFP action-rights decision oracle, offline only."""
import hashlib, json
RIGHTS=(0,1,2,3,0x100,0x101,0xffffffff)
ACTIONS=(0,0x11,0x12,0x26,7,0x1234)
def decide(rights,action):
    may=bool(rights&1) or action==0x12
    return int(may), rights&~1 if may else rights, 0x11 if may else action

def matrix():
    return ''.join(f'{r}:{a}:{allowed}:{nr}:{na}\n' for r in RIGHTS for a in ACTIONS for allowed,nr,na in (decide(r,a),))

def summary():
    rows=matrix().splitlines()
    return dict(states=len(rows), blocks=sum(row.split(':')[2]=='1' for row in rows),
                preserved=sum(row.split(':')[2]=='0' for row in rows),
                sha256=hashlib.sha256(matrix().encode()).hexdigest())
if __name__=='__main__':print(json.dumps(summary(),sort_keys=True))
