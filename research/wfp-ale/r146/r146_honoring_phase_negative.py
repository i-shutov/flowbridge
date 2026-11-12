#!/usr/bin/env python3
"""R146: read-only/no-driver source-contract negative model. No Windows or network calls."""
import hashlib
import itertools
import json
from pathlib import Path
import sys

PINS = {
 'kernel-r19/policy_windows.rs': ('acf60334320d970f58af3349ee75fbaa59826602', ('FWPM_CONDITION_ALE_ORIGINAL_APP_ID', 'FWPM_LAYER_ALE_AUTH_CONNECT_V4','FWPM_LAYER_ALE_AUTH_CONNECT_V6')),
 'kernel-r19/kernel/src/redirect.rs': ('a093f049d162987981a957aac90db1014bc6ff09', ('0x0010_0000==0','0x0000_0004|0x0200_0000','if !loopback{return false;}','if !auth_check(values,meta){block(out);return;}')),
 'kernel-r19/kernel/src/lib.rs': ('53f5ce6faa0f9f591974287f38ea890cafeb0dd2',('redirect::auth_classify(values,meta,out);','unsafe fn guarded_block(')),
}
def source_gate():
 root=Path(__file__).resolve().parent.parent
 for path,(expected,markers) in PINS.items():
  raw=(root/path).read_bytes()
  observed=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\x00'+raw).hexdigest()
  if observed!=expected: raise ValueError(f'SOURCE_PIN_MISMATCH {path} {observed}')
  for token in markers:
   if token.encode() not in raw: raise ValueError(f'SOURCE_MARKER_MISSING {path} {token}')

def decision(bits):
 selected,honoring,redirected,reauth,metadata,loopback,receipt,write,prior=bits
 if not selected:return 'NOT_SELECTED'
 # All other WFP/owner/epoch/port/ticket checks are ASSUMED to succeed.
 candidate=redirected and not honoring and not reauth and metadata and loopback and receipt
 if candidate and write:return 'PERMIT_CANDIDATE'
 return 'BLOCK_CANDIDATE' if (write or prior) else 'PRESERVE_UNPROVEN'

def run():
 rows=[];count={};honoring_write=effective_permit=0
 for family in (4,6):
  for bits in itertools.product((0,1),repeat=9):
   selected,honoring,redirected,reauth,metadata,loopback,receipt,write,prior=bits
   d=decision(bits)
   if selected and honoring and write:
    assert d=='BLOCK_CANDIDATE'
    honoring_write+=1
   if selected and honoring:assert d!='PERMIT_CANDIDATE'
   if selected and not honoring and redirected and not reauth and metadata and loopback and receipt and write:
    assert d=='PERMIT_CANDIDATE'
    effective_permit+=1
   count[d]=count.get(d,0)+1
   rows.append(str(family)+'|'+''.join(map(str,bits))+'|'+d+'\n')
 if len(rows)!=1024 or honoring_write!=128 or effective_permit!=4:raise RuntimeError('INVARIANTS')
 return {
  'counts':dict(sorted(count.items())),
  'favorable_effective_permit_candidates':effective_permit,
  'honoring_stage_seen_in_windows':False,
  'honoring_write_block_candidates':honoring_write,
  'kernel_driver_executed':False,
  'release_go':False,
  'rows':len(rows),'sha256':hashlib.sha256(''.join(rows).encode()).hexdigest(),
  'source_model':'PINNED_R19_ONLY','subsequent_authorization_proved':False,
 }
if __name__=='__main__':
 if sys.argv[1:]==['--model-only']:pass
 elif not sys.argv[1:]:source_gate()
 else:raise SystemExit('usage: r146_honoring_phase_negative.py [--model-only]')
 print(json.dumps(run(),sort_keys=True,separators=(',',':')))
