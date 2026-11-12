#!/usr/bin/env python3
"""R150 broker-bootstrap contract: offline; not live WFP or driver proof."""
import hashlib
import json
import argparse
from pathlib import Path
BROKER='opaque:FlowBridgeBroker.exe'; TARGET='opaque:Selected.exe'; SIBLING='opaque:another.exe'
PINS={'redirect.rs':('a093f049d162987981a957aac90db1014bc6ff09',('if code==h::ARM{','let Some((broker,_))=(*STATE.0.get()).lookup(pid)else{return super::DENIED};','broker.process!=caller as usize')),
      'lib.rs':('53f5ce6faa0f9f591974287f38ea890cafeb0dd2',('unsafe extern "C" fn process_event(', '(*STATE.0.get()).born(owner).is_ok()'))}

def verify(path):
    for name,(expected,markers) in PINS.items():
        raw=(path/name).read_bytes();digest=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        if digest!=expected or any(x.encode() not in raw for x in markers):raise RuntimeError('PIN_MISMATCH:'+name)

class Observer:
    def __init__(self, mode):self.mode=mode;self.broker={};self.target={};self.configured=False
    def born(self,pid,epoch,ptr,img):
        if img==BROKER and self.mode in ('global','dual'):
            self.broker[pid]=(epoch,ptr);return 'BROKER_TRACKED'
        if self.configured and img==TARGET:self.target[pid]=(epoch,ptr);return 'SELECTED_TRACKED'
        return 'SKIPPED'
    def arm(self,pid,epoch,ptr,image):
        if self.broker.get(pid)!=(epoch,ptr):return 'ARM_DENY_UNPROVEN_BROKER'
        if image==BROKER or self.configured:return 'ARM_DENY_INVALID'
        self.configured=True;return 'ARM_MODEL_ONLY'
    def probe(self,pid,epoch,ptr):return 'SELECTED_BIRTH_PROVED' if self.target.get(pid)==(epoch,ptr) else 'SELECTED_UNPROVEN'


def campaign():
    rows=[]
    def rec(label,result,m):rows.append(f'{label}|{result}|{int(m.configured)}|{len(m.broker)}|{len(m.target)}\n')
    current=Observer('global');scoped=Observer('selected');dual=Observer('dual')
    for model,label in ((current,'current'),(scoped,'selected_only'),(dual,'dual_role')):
        rec(label+'_broker_birth',model.born(101,9,1001,BROKER),model)
        rec(label+'_arm',model.arm(101,9,1001,TARGET),model)
        rec(label+'_selected_birth',model.born(202,10,2002,TARGET),model)
        rec(label+'_selected_probe',model.probe(202,10,2002),model)
    if not(current.configured and not scoped.configured and dual.configured):raise RuntimeError('ARM_BOOTSTRAP_BOUNDARY')
    early=Observer('dual')
    rec('early_selected_ignored',early.born(300,20,3000,TARGET),early)
    rec('early_broker_birth',early.born(301,21,3001,BROKER),early)
    rec('early_arm',early.arm(301,21,3001,TARGET),early)
    rec('early_selected_denied',early.probe(300,20,3000),early)
    rec('later_selected_birth',early.born(302,22,3002,TARGET),early)
    rec('later_selected_proved',early.probe(302,22,3002),early)
    bogus=Observer('dual')
    rec('unknown_broker',bogus.arm(10,2,3,TARGET),bogus)
    bogus.born(10,2,3,BROKER)
    rec('wrong_broker_ptr',bogus.arm(10,2,4,TARGET),bogus)
    rec('wrong_broker_epoch',bogus.arm(10,3,3,TARGET),bogus)
    rec('broker_self_selection',bogus.arm(10,2,3,BROKER),bogus)
    rec('valid_broker',bogus.arm(10,2,3,TARGET),bogus)
    for i in range(1000):
        rec('foreign_churn_'+str(i),bogus.born(1000+i,100+i,5000+i,SIBLING),bogus)
    if len(bogus.broker)!=1 or len(bogus.target)!=0:raise RuntimeError('UNRELATED_PROCESSES_NOT_TRACKED')
    return rows

def main():
    p=argparse.ArgumentParser();p.add_argument('--model-only',action='store_true');p.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parent.parent/'kernel-r19/kernel/src')
    a=p.parse_args()
    if not a.model_only:verify(a.source_root)
    rows=campaign()
    print(json.dumps({'cases':len(rows),'sha256':hashlib.sha256(''.join(rows).encode()).hexdigest(),'source_pinned':not a.model_only,'native_wfp_executed':False,'release_accepted':False},sort_keys=True))
if __name__=='__main__':main()
