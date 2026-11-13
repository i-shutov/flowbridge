#!/usr/bin/env python3
"""Exact-R19-source static reachability gate; safe on a local checkout."""
import hashlib
import re
from pathlib import Path

BASE = Path(__file__).resolve().parents[1] / 'kernel-r19/kernel/src'
PINS = {
 'lib.rs':'53f5ce6faa0f9f591974287f38ea890cafeb0dd2',
 'redirect.rs':'a093f049d162987981a957aac90db1014bc6ff09',
 'ledger.rs':'b88c4c9237c4c118517978fc454f5048f522aa7f',
 'handoff.rs':'e1d17217db50362ba9c4efc83af820b6beb094cf',
 'auth_appid.rs':'f16ab6ad0f618c74ed4e79ce606583169084970d',
 'action_rights.rs':'c6a4a107255cc5ecca82266481935c93467a01ed',
 'msvc_runtime.rs':'c0cb2f171ec841e91fc14b290a3c1d08dde518a0',
}
def check(sources):
    ledger = sources['ledger.rs']
    required = ('count:0','pub fn observe(', 'self.count+=1',
                'pub fn pop(', 'if self.count==0{return Ok(None);}')
    if any(m not in ledger for m in required): raise RuntimeError('LEDGER_CHANGED')
    if len(re.findall(r'self\.count\s*\+=\s*1',ledger)) != 1:
        raise RuntimeError('QUEUE_HAS_ADDITIONAL_WRITER')
    if '(*STATE.0.get()).pop()' not in sources['lib.rs']:
        raise RuntimeError('DISPATCH_CONTRACT_CHANGED')
    for name, code in sources.items():
        if name!='ledger.rs' and re.search(r'(?:\.\s*observe|::\s*observe)\s*\(',code):
            raise RuntimeError('PRODUCER_NEWLY_WIRED:'+name)
    return 'PINNED_SOURCE_NO_RUNTIME_WITNESS_PRODUCER'
def main():
    sources={}
    for name,pin in PINS.items():
        raw=(BASE/name).read_bytes()
        sha=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        if sha!=pin: raise RuntimeError('SOURCE_SHA_CHANGED:'+name+':'+sha)
        sources[name]=raw.decode('utf-8')
    print(check(sources))
if __name__=='__main__': main()
