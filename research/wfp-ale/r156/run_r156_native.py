#!/usr/bin/env python3
"""Compile ONLY standalone pure Rust tests in an isolated user-mode snapshot.

No Cargo, build.rs, Windows APIs, driver, network, installer or WFP activation.
Exit 0 = explicitly labelled pure-test PASS or preflight-only; 2 = failure;
3 = compiler unavailable (NOT_RUN). Every output directory must be new.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
PINS = {
    'kernel-r19/kernel/src/ledger.rs': 'b88c4c9237c4c118517978fc454f5048f522aa7f',
    'kernel-r19/kernel/src/handoff.rs': 'e1d17217db50362ba9c4efc83af820b6beb094cf',
    'kernel-r19/kernel/src/action_rights.rs': 'c6a4a107255cc5ecca82266481935c93467a01ed',
    'r156/r156_pure_regressions.rs': '399931dd90036c0fa889cce3fd4d4e8a843b175d',
}
EXPECTED_TESTS = 52

class NativeGateError(ValueError):
    pass

def git_blob(raw):
    return hashlib.sha1(b'blob '+str(len(raw)).encode('ascii')+b'\0'+raw).hexdigest()

def sources(root):
    captured=[]
    for path, expected in PINS.items():
        with (root/path).open('rb') as f: raw=f.read(262145)
        if len(raw)>262144: raise NativeGateError('SOURCE_TOO_LARGE:'+path)
        normalized=raw if git_blob(raw)==expected else raw.replace(b'\r\n',b'\n')
        if git_blob(normalized)!=expected: raise NativeGateError('SOURCE_PIN:'+path)
        captured.append((path, normalized, {
            'path':path,'git_blob':expected,'raw_sha256':hashlib.sha256(raw).hexdigest(),
            'compiled_sha256':hashlib.sha256(normalized).hexdigest(),
            'crlf_normalized':raw!=normalized}))
    return captured

def run(root, output, compiler=None, preflight=False):
    output.mkdir(parents=True,exist_ok=False)
    evidence={'status':'RUNNING_NOT_ACCEPTED','native_wfp_executed':False,
              'driver_built':False,'release_accepted':False,'commands':[]}
    def save():
        tmp=output/'NATIVE_EVIDENCE.json.tmp'
        tmp.write_text(json.dumps(evidence,indent=2,sort_keys=True)+'\n',encoding='utf-8')
        tmp.replace(output/'NATIVE_EVIDENCE.json')
    def command(label, argv, cwd):
        try:
            p=subprocess.run(argv,cwd=cwd,capture_output=True,timeout=60,shell=False)
        except subprocess.TimeoutExpired as exc:
            for ch in ('stdout','stderr'): (output/(label+'.'+ch)).write_bytes(getattr(exc,ch) or b'')
            evidence['commands'].append({'name':label,'exit':None,'timed_out':True});save()
            raise NativeGateError('TIMEOUT:'+label) from exc
        item={'name':label,'exit':p.returncode}
        for ch in ('stdout','stderr'):
            raw=getattr(p,ch);(output/(label+'.'+ch)).write_bytes(raw)
            item[ch+'_sha256']=hashlib.sha256(raw).hexdigest()
        evidence['commands'].append(item);save()
        if p.returncode!=0:raise NativeGateError('COMMAND_FAILED:'+label)
        return p
    save()
    try:
        captured=sources(root);evidence['sources']=[item[2] for item in captured];save()
        if preflight:
            evidence['status']='PREFLIGHT_ONLY_NOT_COMPILED';return evidence
        rustc=shutil.which(compiler or 'rustc')
        if rustc is None:
            evidence['status']='NOT_RUN_COMPILER_UNAVAILABLE';return evidence
        with tempfile.TemporaryDirectory(prefix='flowbridge-r156-pure-') as d:
            temp=Path(d)
            for path,raw,_ in captured:
                p=temp/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
            version=command('rustc_version',[rustc,'--version','--verbose'],temp)
            evidence['rustc_version']=version.stdout.decode('utf-8',errors='replace')
            binary=output/('pure-tests.exe' if os.name=='nt' else 'pure-tests')
            command('compile',[rustc,'--edition=2021','--test',str(temp/'r156/r156_pure_regressions.rs'),'-o',str(binary)],temp)
            evidence['binary_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest();save()
            listed=command('list',[str(binary),'--list'],temp)
            count=sum(line.endswith(': test') for line in listed.stdout.decode('utf-8').splitlines())
            if count!=EXPECTED_TESTS:raise NativeGateError('TEST_COUNT_MISMATCH')
            tested=command('tests',[str(binary),'--test-threads=1'],temp)
            text=tested.stdout.decode('utf-8')
            if not re.search(r'test result: ok\. 52 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out',text):
                raise NativeGateError('INCOMPLETE_TEST_REPORT')
            evidence['status']='PURE_RUST_TESTS_PASS_NOT_WFP_PROOF';evidence['tests_passed']=count
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        evidence['status']='FAILED';evidence['error']=type(exc).__name__+':'+str(exc)
    finally:
        save()
    return evidence

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,default=HERE.parent,help='research/wfp-ale directory')
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--rustc',help='Existing compiler path; never downloads or installs one')
    p.add_argument('--preflight-only',action='store_true')
    args=p.parse_args()
    try:r=run(args.root.resolve(),args.output.resolve(),args.rustc,args.preflight_only)
    except OSError as exc:
        print(json.dumps({'status':'FAILED','error':type(exc).__name__,'release_accepted':False}));return 2
    print(json.dumps(r,sort_keys=True))
    return 3 if r['status']=='NOT_RUN_COMPILER_UNAVAILABLE' else 0 if r['status'] in (
        'PREFLIGHT_ONLY_NOT_COMPILED','PURE_RUST_TESTS_PASS_NOT_WFP_PROOF') else 2
if __name__=='__main__':raise SystemExit(main())
