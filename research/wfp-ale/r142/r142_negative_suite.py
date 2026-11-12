#!/usr/bin/env python3
"""Pure offline regressions of R141 descriptor validator, including python -O.
No WFP API, no sockets, no driver, no policy writes.
"""
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parent.parent / 'r141' / 'r141_descriptors.py'
PIN = 'af2d14c2d6c7738d3ad80cc776a0dd7479056a1e'
CASES = ('valid','permit_unregistered','protocol_swap','layer_swap',
         'action_swap','missing_filter','native_proof_claim',
         'boot_fake_proof','provider_activated')

def git_blob(data:bytes)->str:
    return hashlib.sha1(b'blob '+str(len(data)).encode('ascii')+b'\0'+data).hexdigest()

def get_module():
    if git_blob(SOURCE.read_bytes())!=PIN:
        raise RuntimeError('descriptor source pin changed')
    spec=importlib.util.spec_from_file_location('r141_descriptors',SOURCE)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def mutated(d,case):
    x=d.build()
    if case=='valid':pass
    elif case=='permit_unregistered':x['filters'][0]['permit_if_callout_unregistered']=True
    elif case=='protocol_swap':
        x['filters'][0]['protocol'],x['filters'][1]['protocol']=x['filters'][1]['protocol'],x['filters'][0]['protocol']
    elif case=='layer_swap':
        x['filters'][0]['layer'],x['filters'][2]['layer']=x['filters'][2]['layer'],x['filters'][0]['layer']
    elif case=='action_swap':
        x['filters'][0]['action'],x['filters'][1]['action']=x['filters'][1]['action'],x['filters'][0]['action']
    elif case=='missing_filter':x['filters'].pop()
    elif case=='native_proof_claim':x['no_direct_proved']=True
    elif case=='boot_fake_proof':x['boot_time_filter']['pair_transition_proved']=True
    elif case=='provider_activated':x['provider']['service_name']='FlowBridgeUnsafe'
    else:raise ValueError('unknown case')
    return x

def probe(case):
    d=get_module()
    try:d.validate(mutated(d,case))
    except AssertionError:return 'REJECT'
    return 'ACCEPT'

def suite():
    lines=[]
    for opt in ('normal','optimized'):
        for case in CASES:
            args=[sys.executable,'-B']+(['-O'] if opt=='optimized' else [])+[__file__,'--probe',case]
            r=subprocess.run(args,capture_output=True,text=True,timeout=15,check=False)
            if r.returncode!=0 or r.stderr or r.stdout.strip() not in ('ACCEPT','REJECT'):
                raise RuntimeError(f'probe_error:{opt}:{case}:{r.returncode}:{r.stderr}')
            expected='ACCEPT' if case=='valid' else 'REJECT'
            if r.stdout.strip()!=expected:
                raise RuntimeError(f'FAIL_OPEN:{opt}:{case}:{r.stdout.strip()}')
            lines.append(f'{opt}|{case}|{r.stdout.strip()}\n')
    raw=''.join(lines).encode('ascii')
    print(json.dumps({'source_git_blob':PIN,'cases':len(CASES),
                      'checks':len(lines),'failed':0,
                      'sha256':hashlib.sha256(raw).hexdigest()},sort_keys=True))

if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--probe' and sys.argv[2] in CASES:
        print(probe(sys.argv[2]))
    elif len(sys.argv)==1:suite()
    else:raise SystemExit(2)
