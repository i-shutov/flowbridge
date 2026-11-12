#!/usr/bin/env python3
"""R151 read-only negative tests of actual R150 Candidate; no WFP/driver/network."""
import argparse, hashlib, importlib.util, json
from pathlib import Path
BASE=Path(__file__).resolve().parent.parent
PINS={'r150/r150_preselection_negative.py':'3e81d27a80e88671775be9015f436bdf5cd100bb',
      'kernel-r19/kernel/src/handoff.rs':'e1d17217db50362ba9c4efc83af820b6beb094cf',
      'kernel-r19/kernel/src/redirect.rs':'a093f049d162987981a957aac90db1014bc6ff09'}
def check(cond):
    if not cond:raise RuntimeError('R151_INVARIANT_FAILED')
def pin(path,sha):
    raw=path.read_bytes();check(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==sha)
def campaign(m):
    rows=[];ends=(0,1,7,77,4096,65535)
    def fresh(pid=101,epoch=1001,key=3001,ptr=9001):
        c=m.Candidate();check(c.configure(m.SELECTED)=='CONFIGURED');check(c.birth(pid,epoch,key,ptr,m.SELECTED)=='TRACK_SELECTED');return c
    for family in ('v4','v6'):
        for ep in ends:
            for swap in (0,1):
                for pid in (101,202):
                    epoch,key,ptr=pid+100,pid+200,pid+300
                    c=fresh(pid,epoch,key,ptr)
                    five=f'{family}|tcp|192.0.2.10:3001|198.51.100.11:443'
                    other=five+('|DIFFERENT_REMOTE' if swap else '')
                    a=c.issue(pid,epoch,key,ptr,ep,five);b=c.issue(pid,epoch,key,ptr,ep,other)
                    one=c.claim(a,pid,epoch,key,ptr,ep,five);two=c.claim(b,pid,epoch,key,ptr,ep,other)
                    again=c.claim(a,pid,epoch,key,ptr,ep,five)
                    check((a,b,one,two,again)==(2,3,'MODEL_ROUTE','MODEL_ROUTE','REJECT'))
                    rows.append(f'alias|{family}|{ep}|{swap}|{pid}|{one}|{two}|{again}\n')
        c=fresh();t=c.issue(101,1001,3001,9001,0,'');v=c.claim(t,101,1001,3001,9001,0,'')
        check(t==2 and v=='MODEL_ROUTE');rows.append(f'zero|{family}|{v}\n')
        for ep in ends:
            c=fresh();a=c.issue(101,1001,3001,9001,ep,family)
            check(c.death(101,9001)=='RELEASE_REF_AFTER_RETIRE')
            before=c.claim(a,101,1001,3001,9001,ep,family)
            check(c.birth(101,1002,3002,9002,m.SELECTED)=='TRACK_SELECTED')
            b=c.issue(101,1002,3002,9002,ep,family)
            after=c.claim(b,101,1002,3002,9002,ep,family)
            check((before,after)==('REJECT','MODEL_ROUTE'))
            rows.append(f'recycle|{family}|{ep}|{before}|{after}\n')
        c=fresh();a=c.issue(101,1001,3001,9001,11,family);b=c.issue(101,1001,3001,9001,12,family)
        one=c.claim(a,101,1001,3001,9001,11,family);two=c.claim(b,101,1001,3001,9001,12,family)
        check((one,two)==('MODEL_ROUTE','MODEL_ROUTE'));rows.append(f'control|{family}|{one}|{two}\n')
    check(len(rows)==64)
    return hashlib.sha256(''.join(rows).encode()).hexdigest()
def main():
    p=argparse.ArgumentParser();p.add_argument('--model-only',action='store_true');p.add_argument('--root',type=Path,default=BASE);a=p.parse_args()
    pin(a.root/'r150/r150_preselection_negative.py',PINS['r150/r150_preselection_negative.py'])
    if not a.model_only:
        for path in ('kernel-r19/kernel/src/handoff.rs','kernel-r19/kernel/src/redirect.rs'):pin(a.root/path,PINS[path])
    f=a.root/'r150/r150_preselection_negative.py';spec=importlib.util.spec_from_file_location('r150',f)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    print(json.dumps({'cases':64,'alias_double_claim':48,'zero_endpoint':2,'recycle':12,'controls':2,
      'sha256':campaign(m),'r150_blob_verified':True,'r19_local_blobs_verified':not a.model_only,
      'native_wfp_executed':False,'native_rust_executed':False,'release_accepted':False},sort_keys=True))
if __name__=='__main__':main()
