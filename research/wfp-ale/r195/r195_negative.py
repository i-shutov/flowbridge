#!/usr/bin/env python3
"""R195: exact-source observer producer audit; no native WFP or driver activity."""
import json
import re
import sys
import unittest
from pathlib import Path

MODULES = ('lib', 'ledger', 'handoff', 'auth_appid', 'action_rights', 'redirect')
ROOT = Path(__file__).resolve().parents[3]

def audit(root=ROOT):
    src = root / 'research/wfp-ale/kernel-r19/kernel/src'
    m = {n: (src / f'{n}.rs').read_text().split('#[cfg(test)]', 1)[0] for n in MODULES}
    if set(re.findall(r'(?m)^mod\s+(\w+)\s*;', m['lib'])) != set(MODULES) - {'lib'}:
        raise ValueError('UNKNOWN module graph')
    if len(re.findall(r'include!\s*\(', m['lib'])) != 1:
        raise ValueError('UNKNOWN generated code')
    if 'pub fn observe(' not in m['ledger'] or 'self.queue[(self.read+self.count)%MAX_RECORDS]=w;self.count+=1' not in m['ledger']:
        raise ValueError('UNKNOWN queue producer')
    if 'pub fn pop(' not in m['ledger'] or '(*STATE.0.get()).pop()' not in m['lib'] or 'FB_WITNESS_IOCTL' not in m['lib']:
        raise ValueError('UNKNOWN queue consumer')
    hits = [(n, i) for n, s in m.items() for i, line in enumerate(s.splitlines(), 1)
            if re.search(r'\.\s*observe\s*\(|\bLedger\s*::\s*observe\s*\(', line)]
    return {'calls': hits, 'verdict': 'NO_RUNTIME_WITNESS_PRODUCER' if not hits else 'REVIEW_NEW_PRODUCER'}

class Tests(unittest.TestCase):
    def test_current_source(self):
        self.assertEqual(audit()['verdict'], 'NO_RUNTIME_WITNESS_PRODUCER')
    def test_mutant_and_unknown_module(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); src=root/'research/wfp-ale/kernel-r19/kernel/src';src.mkdir(parents=True)
            old=ROOT/'research/wfp-ale/kernel-r19/kernel/src'
            for n in MODULES: (src/f'{n}.rs').write_bytes((old/f'{n}.rs').read_bytes())
            with (src/'redirect.rs').open('a') as f:f.write('\nfn injected() { ledger.observe(1,2,4,&[]); }\n')
            self.assertEqual(audit(root)['verdict'], 'REVIEW_NEW_PRODUCER')
            with (src/'lib.rs').open('a') as f:f.write('\nmod external_observer;\n')
            with self.assertRaises(ValueError):audit(root)

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--test':
        unittest.main(argv=[sys.argv[0]],verbosity=2)
    else:
        print(json.dumps(audit(),sort_keys=True,separators=(',',':')))
