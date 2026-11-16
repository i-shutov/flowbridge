#!/usr/bin/env python3
"""R205 negative test: per-commit evidence collector head-admission policy.
Pure stdlib policy fixtures, no driver, WFP, PowerShell or native Rust execution.
"""
ANCHOR='7631a5904189ba90949259909d4f317f06e2584d'
PUBLISHED_R204_HEAD='42cd076110815b2c3e7163f4c708e997d7122b2e'
ALLOWED=('research/wfp-ale/r203/','research/wfp-ale/r204/','research/wfp-ale/r205/')
R204_FILES=('research/wfp-ale/r204/bfe_engine_contract.py',
 'research/wfp-ale/r204/bfe_engine_oracle.mjs',
 'research/wfp-ale/r204/R204_BFE_ENGINE_CODE_CONSISTENCY.md')
def node(paths,parents=1):
 return {'files':tuple(paths),'parents':parents}
published=[node(R204_FILES),node(R204_FILES)]
def legacy(history):
 return len(history)==1 and all(p.startswith('research/wfp-ale/r203/') for p in history[0]['files'])
def accepted(history,ancestor=True,pins=True,branch=True):
 if not (ancestor and pins and branch):return False
 for c in history:
  if c['parents']!=1 or not c['files']:return False
  if not all(p.startswith(ALLOWED) for p in c['files']):return False
 return True
tests=[
 ('anchor',[],True,True,True,True),
 ('single R203', [node(['research/wfp-ale/r203/verify_evidence.py'])],True,True,True,True),
 ('published R204 twice',published,True,True,True,True),
 ('R205 addition',published+[node(['research/wfp-ale/r205/check.py'])],True,True,True,True),
 ('changed then reverted kernel source',published+[node(['research/wfp-ale/kernel-r19/kernel/src/lib.rs']),node(['research/wfp-ale/kernel-r19/kernel/src/lib.rs'])],True,True,True,False),
 ('untrusted pinned blob',published,True,False,True,False),
 ('wrong branch',published,True,True,False,False),
 ('diverged from anchor',published,False,True,True,False),
 ('merge',published+[node(['research/wfp-ale/r205/merge'],2)],True,True,True,False),
 ('outside allowed paths',published+[node(['research/wfp-ale/r206/test.rs'])],True,True,True,False),
 ('empty diff',published+[node([])],True,True,True,False),
]
if __name__=='__main__':
 assert not legacy(published),'R203v4 must reject two-commit R204 HEAD'
 for name,h,a,p,b,want in tests:
  got=accepted(h,a,p,b)
  assert got==want,(name,got,want)
  print('PASS',name,'ACCEPT' if got else 'REJECT')
 print(str(len(tests))+'/'+str(len(tests))+' PASS (synthetic graph; no native evidence)')
