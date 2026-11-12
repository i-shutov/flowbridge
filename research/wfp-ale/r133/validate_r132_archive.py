#!/usr/bin/env python3
"""Validate owner-supplied evidence bytes, never execute/extract the archive."""
from pathlib import Path
from zipfile import ZipFile
import argparse,hashlib,json,re

EXPECTED_CAMPAIGN='c2af3f996ec4c52620c973f0fb34dc4ead470e94f6805edeb9a8d49fcf278e37'
EXPECTED_BLOBS={
 'auth_appid.rs':'f16ab6ad0f618c74ed4e79ce606583169084970d',
 'handoff.rs':'e1d17217db50362ba9c4efc83af820b6beb094cf',
 'ledger.rs':'b88c4c9237c4c118517978fc454f5048f522aa7f',
 'policy_plan.rs':'c8ab344551f1adfc20fd0019c4606cf3ca3c81c4',
 'r132_event_orders.rs':'82b97b3952cb8006ed389c68030bf136af9bdf47'}

def pairs(items):
 out={}
 for k,v in items:
  if k in out: raise ValueError('duplicate JSON key')
  out[k]=v
 return out

def validate(path:Path):
 raw=path.read_bytes()
 with ZipFile(path) as z:
  entries=z.infolist();names=[x.filename for x in entries]
  if len(entries)!=15 or len(set(names))!=15 or any(Path(n).name!=n or '\\' in n for n in names):
   raise ValueError('unexpected archive names/cardinality')
  if sum(x.file_size for x in entries)>10_000_000 or any(x.flag_bits&1 for x in entries):
   raise ValueError('archive size/encryption')
  if z.testzip() is not None: raise ValueError('CRC failure')
  report=json.loads(z.read('R132_EVIDENCE.json').decode('utf-8-sig'),object_pairs_hook=pairs)
  if report['status']!='EXACT_SOURCE_EVENT_ORDERS_PASS_NOT_KERNEL_PROOF':raise ValueError('not a successful R132 record')
  for k in ('metadata_exit','test_link_exit','tests_exit','campaign_exit'):
   if type(report[k]) is not int or report[k]!=0:raise ValueError('wrong stage code '+k)
  for k in ('listed_tests','passed_tests','expected_tests'):
   if type(report[k]) is not int or report[k]!=64:raise ValueError('wrong count '+k)
  for k in ('bfe_queried','kernel_origin_proof','packet_bound_g2_pass','kernel_adapter_executed','real_process_liveness_proof','no_direct_proof'):
   if report[k] is not False:raise ValueError('proof boundary '+k)
  if len(report['sources'])!=5 or {Path(s['path']).name:s['git_blob'] for s in report['sources']}!=EXPECTED_BLOBS:raise ValueError('source pin mismatch')
  if report['proof_scope']!='EXACT_SOURCE_SYNTHETIC_EVENT_ORDERS':raise ValueError('scope mismatch')
  listed=re.findall(r'(?m)^([^\r\n]+): test\r?$',z.read('test-list.stdout.txt').decode())
  passed=re.findall(r'(?m)^test ([^\r\n ]+) \.\.\. ok\r?$',z.read('unit-tests.stdout.txt').decode())
  if len(listed)!=64 or len(set(listed))!=64 or sorted(listed)!=sorted(passed):raise ValueError('test list/result mismatch')
  for prefix,n in {'auth_appid':7,'handoff':19,'ledger':11,'policy_plan':9,'schedule_tests':18}.items():
   if sum(name.startswith(prefix+'::') for name in listed)!=n:raise ValueError('test group mismatch')
  if not re.search(rb'test result: ok\. 64 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;',z.read('unit-tests.stdout.txt')):raise ValueError('test summary mismatch')
  for n in names:
   if n.endswith('.stderr.txt') and z.read(n).strip():raise ValueError('nonempty stderr '+n)
  campaign=z.read('campaign.stdout.txt').replace(b'\r\n',b'\n')
  digest=hashlib.sha256(campaign).hexdigest()
  if len(campaign.splitlines())!=36000 or digest!=EXPECTED_CAMPAIGN or report['campaign_sha256']!=digest:raise ValueError('campaign mismatch')
  for k in ('test_exe_sha256','campaign_exe_sha256'):
   if not re.fullmatch('[0-9a-f]{64}',report[k]):raise ValueError('reported binary digest format')
  return {'schema':1,'result':'R132_RECEIVED_LOGS_VALIDATED_NOT_KERNEL_PROOF',
   'source':'owner-uploaded evidence-only.zip','archive_sha256':hashlib.sha256(raw).hexdigest(),
   'members':{n:{'bytes':len(z.read(n)),'sha256':hashlib.sha256(z.read(n)).hexdigest()} for n in sorted(names)},
   'source_pins_reported':EXPECTED_BLOBS,'tests':64,'traces':36000,'event_steps':216000,
   'campaign_sha256':digest,'windows_build_reported':report['windows_build'],
   'rustc_version_reported':report['rustc_version'],
   'binary_sha256_reported':{k:report[k] for k in ('test_exe_sha256','campaign_exe_sha256')},
   'binary_files_received':False,'binaries_independently_rehashed':False,
   'host_wall_clock_attested':False,'timestamps_used_as_authority':False,
   'kernel_origin_proof':False,'no_direct_proof':False}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('archive',type=Path);p.add_argument('--output',type=Path);a=p.parse_args()
 result=validate(a.archive);text=json.dumps(result,indent=2,ensure_ascii=False)+'\n'
 if a.output:a.output.write_text(text,encoding='utf-8')
 print(text)
