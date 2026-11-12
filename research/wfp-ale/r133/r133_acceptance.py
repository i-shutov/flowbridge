#!/usr/bin/env python3
"""Offline source/JSON validation. It does not claim Windows execution."""
import copy,hashlib,importlib.util,json,re,subprocess,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('oracle',ROOT/'r133_oracle.py')
o=importlib.util.module_from_spec(spec);spec.loader.exec_module(o)
FLAGS=('kernel_origin_proof','network_owner_proof','no_direct_proof')

def is_uint(v):return type(v) is int and 0<=v<=0xffffffff

def timehex(v):return type(v) is str and re.fullmatch('[0-9A-F]{16}',v) and v!='0'*16

def namehex(v):
 return type(v) is str and 0<len(v)<=131068 and re.fullmatch('(?:[0-9A-F]{4})+',v) and all(v[i:i+4]!='0000' for i in range(0,len(v),4))

def valid(records,exit_code=0):
 if type(exit_code) is not int or exit_code!=0 or len(records)!=5:raise ValueError('runtime/cardinality')
 for r in records:
  if type(r.get('schema')) is not int or r['schema']!=1 or any(r.get(k) is not False for k in FLAGS):raise ValueError('schema/proof')
 for i,wanted in enumerate((23,259)):
  a,d=records[2*i:2*i+2]
  for r in (a,d):
   if type(r.get('case')) is not int or r['case']!=i or not is_uint(r.get('pid')) or r['pid']==0 or not is_uint(r.get('planned_exit')) or r['planned_exit']!=wanted or not is_uint(r.get('get_exit_code')) or not timehex(r.get('creation_filetime_hex')) or r.get('secondary_matches') is not True:raise ValueError('identity/type')
  if a.get('kind')!='alive' or d.get('kind')!='exited':raise ValueError('phase order')
  if not all(is_uint(a.get(k)) and a[k]==258 for k in ('wait_before','wait_after')) or a['get_exit_code']!=259:raise ValueError('live state')
  if not namehex(a.get('win32_name_utf16_hex')) or not namehex(a.get('native_name_utf16_hex')):raise ValueError('name encoding')
  if not is_uint(d.get('wait_result')) or d['wait_result']!=0 or d['get_exit_code']!=wanted or d['pid']!=a['pid'] or d['creation_filetime_hex']!=a['creation_filetime_hex'] or not timehex(d.get('exit_filetime_hex')) or d.get('same_held_handles') is not True:raise ValueError('retained identity/death')
 s=records[-1]
 if s.get('kind')!='summary' or s.get('status')!='OWN_CHILD_HANDLE_LIFETIME_PASS_NOT_NETWORK_PROOF' or type(s.get('cases')) is not int or s['cases']!=2 or not is_uint(s.get('readonly_open_rights')) or s['readonly_open_rights']!=0x101000 or s.get('exit259_is_signaled') is not True:raise ValueError('summary')
 if any(s.get(k) is not False for k in ('pid_reuse_test_performed','canonical_file_identity_proof','atomic_snapshot')):raise ValueError('overclaim')
 return True

def fixture():
 rows=[]
 for i,code in enumerate((23,259)):
  base=dict(schema=1,case=i,planned_exit=code,pid=100+i,creation_filetime_hex=f'{2**56+i:016X}',secondary_matches=True,**{k:False for k in FLAGS})
  rows.append(dict(base,kind='alive',wait_before=258,wait_after=258,get_exit_code=259,win32_name_utf16_hex='0043003A005C0061',native_name_utf16_hex='005C004400650076'))
  rows.append(dict(base,kind='exited',wait_result=0,get_exit_code=code,exit_filetime_hex=f'{2**56+999+i:016X}',same_held_handles=True))
 rows.append(dict(schema=1,kind='summary',status='OWN_CHILD_HANDLE_LIFETIME_PASS_NOT_NETWORK_PROOF',cases=2,readonly_open_rights=0x101000,exit259_is_signaled=True,pid_reuse_test_performed=False,canonical_file_identity_proof=False,atomic_snapshot=False,**{k:False for k in FLAGS}))
 return rows

class Acceptance(unittest.TestCase):
 def bad(self,row,key,value):
  rows=fixture();rows[row][key]=value
  with self.assertRaises(ValueError):valid(rows)
 def test_valid_control(self):self.assertTrue(valid(fixture()))
 def test_259_terminal_counterexample(self):self.assertEqual(o.observed(0,True,259),'EXITED')
 def test_wait_failure_not_alive(self):self.assertEqual(o.observed(0xffffffff,True,259),'UNKNOWN_WAIT')
 def test_query_failure_wins(self):self.assertEqual(o.observed(0,False,259),'EXIT_QUERY_ERROR')
 def test_raced_read_not_alive(self):self.assertEqual(o.observed(258,True,23),'RACED_OR_INCONSISTENT')
 def test_raw_time_is_not_double(self):self.bad(0,'creation_filetime_hex',float(2**56))
 def test_creation_changed_rejected(self):self.bad(1,'creation_filetime_hex','0000000000000001')
 def test_pid_changed_rejected(self):self.bad(3,'pid',999)
 def test_bool_is_not_pid(self):self.bad(0,'pid',True)
 def test_wait_string_rejected(self):self.bad(1,'wait_result','0')
 def test_still_active_does_not_override_signal(self):self.bad(3,'wait_result',258)
 def test_wrong_exit_rejected(self):self.bad(3,'get_exit_code',23)
 def test_embedded_nul_name_rejected(self):self.bad(0,'native_name_utf16_hex','004100000042')
 def test_phase_order_rejected(self):self.bad(0,'kind','exited')
 def test_string_boolean_rejected(self):self.bad(1,'same_held_handles','true')
 def test_kernel_claim_rejected(self):self.bad(4,'kernel_origin_proof',True)
 def test_canonical_file_claim_rejected(self):self.bad(4,'canonical_file_identity_proof',True)
 def test_pid_reuse_claim_rejected(self):self.bad(4,'pid_reuse_test_performed',True)
 def test_no_wallclock_order_assumption(self):
  rows=fixture();rows[1]['exit_filetime_hex']='0000000000000001';self.assertTrue(valid(rows))
 def test_matrix_agrees_independently(self):
  other=json.loads(subprocess.check_output(['node',str(ROOT/'r133_independent.mjs')],text=True));self.assertEqual(other,o.result())
 def test_source_pins(self):
  b=(ROOT/'r133_owned_process_lifetime.rs').read_bytes();s=(ROOT/'FlowBridge-R133-ProcessLifetime.ps1').read_text()
  self.assertIn(hashlib.sha256(b).hexdigest(),s);self.assertIn(hashlib.sha1(f'blob {len(b)}\0'.encode()+b).hexdigest(),s)
 def test_exact_ffi_allowlist(self):
  s=(ROOT/'r133_owned_process_lifetime.rs').read_text();block=s.split('unsafe extern "system" {')[1].split('\n    }')[0]
  self.assertEqual(set(re.findall(r'fn (\w+)\(',block)),{'OpenProcess','CloseHandle','GetProcessId','GetProcessTimes','QueryFullProcessImageNameW','GetExitCodeProcess','WaitForSingleObject','GetLastError'})
 def test_only_own_child_target_and_read_rights(self):
  s=(ROOT/'r133_owned_process_lifetime.rs').read_text();self.assertIn('OpenProcess(READ_RIGHTS,0,pid)',s)
  self.assertIn('let expected_pid=child.0.id()',s);self.assertIn('Command::new(exe)',s);self.assertIn('std::env::current_exe()',s)
  self.assertIn('0x0010_1000',s);self.assertNotIn('PROCESS_ALL_ACCESS',s);self.assertNotIn('std::net',s)
 def test_no_bfe_or_kill_call(self):
  s=(ROOT/'r133_owned_process_lifetime.rs').read_text()
  code='\n'.join(line.split('//',1)[0] for line in s.splitlines())
  self.assertNotRegex(code,r'\b(?:Fwpm\w+|Fwps\w+|TerminateProcess|kill)\s*\(')
  self.assertIn('Duration::from_secs(30)',s);self.assertIn('wait(primary,10000)',s)
 def test_child_is_opt_in_and_tests_pure(self):
  s=(ROOT/'r133_owned_process_lifetime.rs').read_text();ps=(ROOT/'FlowBridge-R133-ProcessLifetime.ps1').read_text()
  self.assertIn('not(test)',s);self.assertEqual(s.count('#[test]'),16);self.assertIn('if ($RunOwnChildProbe)',ps)
  self.assertIn(o.result()['sha256'],ps);self.assertIn('16 passed; 0 failed; 0 ignored;',ps)
 def test_source_crlf_not_accepted_as_exact(self):
  raw=(ROOT/'r133_owned_process_lifetime.rs').read_bytes();self.assertNotEqual(hashlib.sha256(raw).digest(),hashlib.sha256(raw.replace(b'\n',b'\r\n')).digest())
 def test_missing_or_extra_records_fail(self):
  rows=fixture()
  for data in (rows[:4],rows+rows[:1]):
   with self.assertRaises(ValueError):valid(data)
 def test_runtime_nonzero_never_passes(self):
  with self.assertRaises(ValueError):valid(fixture(),2)

if __name__=='__main__':unittest.main(verbosity=2)
