#!/usr/bin/env python3
"""Independent source/JSON gate checks; not a Rust compiler or Windows execution."""
import copy,ctypes,hashlib,importlib.util,json,re,subprocess,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('oracle',ROOT/'r138_oracle.py')
o=importlib.util.module_from_spec(spec);spec.loader.exec_module(o)
FLAGS=('kernel_origin_proof','socket_binding_proof','no_direct_proof')

def uint(x):return type(x) is int and 0<=x<=0xffffffff

def epoch(x):return type(x) is str and re.fullmatch('[0-9A-F]{16}',x) is not None and x!='0'*16

def wide(x):return type(x) is str and len(x)<=131068 and re.fullmatch('(?:[0-9A-F]{4})+',x) and all(x[i:i+4]!='0000' for i in range(0,len(x),4))

def opaque(x):return type(x) is str and len(x)<=131072 and re.fullmatch('(?:[0-9A-F]{2})+',x)

def validate(rows,exit_code=0):
    if type(exit_code) is not int or exit_code!=0 or len(rows)!=7:raise ValueError('cardinality/exit')
    for r in rows:
        if type(r.get('schema')) is not int or r['schema']!=1 or any(r.get(k) is not False for k in FLAGS):raise ValueError('schema/proof')
    subjects=('A','B','A','B','B');phases=('both_alive','both_alive','A_exited','B_survives','both_exited')
    waits=(258,258,0,258,0);codes=(259,259,23,259,29)
    for i,r in enumerate(rows[:5]):
        if r.get('kind')!='process' or r.get('subject')!=subjects[i] or r.get('phase')!=phases[i]:raise ValueError('phase order')
        if not uint(r.get('pid')) or r['pid']==0 or not epoch(r.get('creation_hex')) or r.get('secondary_matches') is not True:raise ValueError('identity')
        for k,want in [('wait_before',waits[i]),('wait_after',waits[i]),('exit_code',codes[i])]:
            if not uint(r.get(k)) or r[k]!=want:raise ValueError('lifetime sample')
    if rows[0]['pid']==rows[1]['pid']:raise ValueError('concurrent PID collision')
    for a,b in ((0,2),(1,3),(1,4)):
        if any(rows[a][k]!=rows[b][k] for k in ('pid','creation_hex')):raise ValueError('retained identity changed')
    apps,s=rows[5:]
    if apps.get('kind')!='appid' or type(apps.get('queries')) is not int or apps['queries']!=4 or apps.get('opaque_bytes') is not True:raise ValueError('AppId header')
    paths=[apps.get(k) for k in ('a_path_hex','b_path_hex','b_path_after_hex')]
    if not all(wide(p) for p in paths) or len(set(paths))!=1:raise ValueError('image names')
    data=[apps.get(k) for k in ('a_before','b_before','a_name_after_exit','b_after')]
    if not all(opaque(d) for d in data) or len(set(data))!=1:raise ValueError('AppId observations')
    expected=rows[0];binding=weak=0
    for i,r in enumerate(rows[:4]):
        equal=data[i]==data[0]
        weak|=int(equal)<<i
        bound=o.admit(expected['pid'],int(expected['creation_hex'],16),r['pid'],int(r['creation_hex'],16),r['wait_before'],r['wait_after'],r['exit_code'],equal)
        binding|=int(bound)<<i
    if binding!=1 or weak!=15 or s.get('kind')!='summary' or s.get('status')!='SAME_APPID_DISTINCT_PROCESSES_NOT_ALE_PROOF':raise ValueError('decision')
    for k,v in [('processes',2),('binding_mask',binding),('appid_only_mask',weak),('query_handle_rights',1052672)]:
        if type(s.get(k)) is not int or s[k]!=v:raise ValueError('summary mismatch')
    if s.get('pid_reuse_test_performed') is not False or s.get('atomic_snapshot') is not False:raise ValueError('overclaim')
    return dict(binding_mask=binding,appid_only_mask=weak)

def fixture():
    f=dict(schema=1,**{k:False for k in FLAGS});rows=[]
    for who,phase,pid,e,w,c in [('A','both_alive',101,11,258,259),('B','both_alive',102,12,258,259),('A','A_exited',101,11,0,23),('B','B_survives',102,12,258,259),('B','both_exited',102,12,0,29)]:
        rows.append(dict(f,kind='process',subject=who,phase=phase,pid=pid,creation_hex=f'{e:016X}',wait_before=w,wait_after=w,exit_code=c,secondary_matches=True))
    rows.append(dict(f,kind='appid',queries=4,a_path_hex='0043003A005C0061',b_path_hex='0043003A005C0061',b_path_after_hex='0043003A005C0061',a_before='FF00D8',b_before='FF00D8',a_name_after_exit='FF00D8',b_after='FF00D8',opaque_bytes=True))
    rows.append(dict(f,kind='summary',status='SAME_APPID_DISTINCT_PROCESSES_NOT_ALE_PROOF',processes=2,binding_mask=1,appid_only_mask=15,query_handle_rights=1052672,pid_reuse_test_performed=False,atomic_snapshot=False))
    return rows

class Tests(unittest.TestCase):
    def bad(self,i,k,v):
        r=fixture();r[i][k]=v
        with self.assertRaises(ValueError):validate(r)
    def test_positive_fixture(self):self.assertEqual(validate(fixture())['binding_mask'],1)
    def test_equal_creation_times_do_not_imply_same_process(self):
        r=fixture()
        for i in (1,3,4):r[i]['creation_hex']=r[0]['creation_hex']
        self.assertEqual(validate(r)['binding_mask'],1)
    def test_distinct_live_pid_required(self):
        r=fixture()
        for i in (1,3,4):r[i]['pid']=r[0]['pid']
        with self.assertRaises(ValueError):validate(r)
    def test_epoch_change_rejected(self):self.bad(2,'creation_hex','000000000000FFFF')
    def test_survivor_epoch_change_rejected(self):self.bad(3,'creation_hex','000000000000FFFF')
    def test_survivor_pid_change_rejected(self):self.bad(3,'pid',105)
    def test_both_exit_only_after_probe(self):self.bad(3,'wait_after',0)
    def test_exit259_is_not_liveness(self):self.bad(2,'exit_code',259)
    def test_signaled_before_release_rejected(self):self.bad(0,'wait_before',0)
    def test_failed_wait_rejected(self):self.bad(1,'wait_after',4294967295)
    def test_claimed_handle_match_not_string(self):self.bad(0,'secondary_matches','true')
    def test_boolean_pid_rejected(self):self.bad(0,'pid',True)
    def test_float_pid_rejected(self):self.bad(0,'pid',101.0)
    def test_64bit_epoch_not_float(self):self.bad(0,'creation_hex',float(2**56))
    def test_zero_epoch_rejected(self):self.bad(0,'creation_hex','0'*16)
    def test_epoch_max_hex_exact(self):
        r=fixture()
        for i in (0,2):r[i]['creation_hex']='F'*16
        self.assertEqual(validate(r)['binding_mask'],1)
    def test_summary_cannot_promote_live_sibling(self):self.bad(6,'binding_mask',9)
    def test_summary_weak_mask_not_trusted(self):self.bad(6,'appid_only_mask',1)
    def test_changed_after_exit_appid_rejected(self):self.bad(5,'a_name_after_exit','BB')
    def test_different_sibling_appid_rejected(self):self.bad(5,'b_before','AB')
    def test_empty_appid_rejected(self):self.bad(5,'a_before','')
    def test_odd_byte_blob_is_opaque(self):self.assertEqual(validate(fixture())['appid_only_mask'],15)
    def test_changed_sibling_name_rejected(self):self.bad(5,'b_path_after_hex','00420042')
    def test_embedded_nul_name_rejected(self):self.bad(5,'b_path_hex','004100000042')
    def test_phase_swap_rejected(self):self.bad(3,'phase','both_alive')
    def test_missing_extra_rows_rejected(self):
        for r in (fixture()[:-1],fixture()+fixture()[:1]):
            with self.assertRaises(ValueError):validate(r)
    def test_nonzero_exit_never_pass(self):
        with self.assertRaises(ValueError):validate(fixture(),2)
    def test_false_proof_flags_are_typed(self):
        for k in FLAGS:
            for value in (True,0,'false',None):self.bad(6,k,value)
    def test_reuse_claim_denied(self):self.bad(6,'pid_reuse_test_performed',True)
    def test_atomicity_claim_denied(self):self.bad(6,'atomic_snapshot',True)
    def test_no_increased_query_rights(self):self.bad(6,'query_handle_rights',0x1fffff)
    def test_model_node_independence(self):
        text=(ROOT/'r138_independent.mjs').read_text();self.assertNotIn('r138_oracle',text)
        actual=json.loads(subprocess.check_output(['node',str(ROOT/'r138_independent.mjs')],text=True))
        self.assertEqual(actual,o.result());self.assertEqual(actual['states'],480);self.assertEqual(actual['eligible'],1)
    def test_source_pins_match_script(self):
        raw=(ROOT/'r138_same_image_siblings.rs').read_bytes();s=(ROOT/'FlowBridge-R138-SiblingBinding.ps1').read_text()
        self.assertIn(hashlib.sha256(raw).hexdigest(),s);self.assertIn(hashlib.sha1(f'blob {len(raw)}\0'.encode()+raw).hexdigest(),s)
        self.assertIn(o.result()['sha256'],s)
    def test_api_allowlist(self):
        s=(ROOT/'r138_same_image_siblings.rs').read_text()
        blocks=re.findall(r'unsafe extern "system" \{(.*?)\n    \}',s,re.S)
        self.assertEqual(set(re.findall(r'fn (\w+)\(',''.join(blocks))),{'OpenProcess','CloseHandle','GetProcessId','GetProcessTimes','QueryFullProcessImageNameW','GetDriveTypeW','WaitForSingleObject','GetExitCodeProcess','GetLastError','FwpmGetAppIdFromFileName0','FwpmFreeMemory0'})
    def test_only_owned_helpers_and_no_network(self):
        s=(ROOT/'r138_same_image_siblings.rs').read_text()
        for required in ('OpenProcess(0x0010_1000,0,own.child.id())','std::env::current_exe()','Helper::spawn("23")','Helper::spawn("29")','let after_a=appid(&na)?','Duration::from_secs(45)','wait(self.child.as_raw_handle(),10000)','not(test)'):
            self.assertIn(required,s)
        for banned in ('std::net','FwpmFilterAdd','Fwps','TerminateProcess','VirtualAlloc','SetFileInformation','CreateHardLink'):
            self.assertNotIn(banned,s)
    def test_exact_rust_test_count(self):self.assertEqual((ROOT/'r138_same_image_siblings.rs').read_text().count('#[test]'),20)
    def test_script_native_opt_in(self):
        s=(ROOT/'FlowBridge-R138-SiblingBinding.ps1').read_text()
        for term in ('if ($RunOwnSiblingProbe)',"@('--own-siblings')",'20 passed; 0 failed; 0 ignored;',"$s.binding_mask -ne $binding",'WriteAllBytes','WaitForExit(120000)'):
            self.assertIn(term,s)
        for term in ('Set-ExecutionPolicy','Start-Service','New-NetFirewallRule','rustup install','git checkout'):
            self.assertNotIn(term,s)
    def test_ffi_sizes_independent(self):
        class FT(ctypes.Structure):_fields_=[('low',ctypes.c_uint32),('high',ctypes.c_uint32)]
        class Blob(ctypes.Structure):_fields_=[('size',ctypes.c_uint32),('data',ctypes.c_void_p)]
        self.assertEqual(ctypes.sizeof(FT),8);self.assertEqual(ctypes.sizeof(Blob),16);self.assertEqual(Blob.data.offset,8)
    def test_source_mutants_rejected_by_pin(self):
        raw=(ROOT/'r138_same_image_siblings.rs').read_bytes();h=hashlib.sha256(raw).digest()
        for x in (raw[:-1],raw+b' ',raw.replace(b'\n',b'\r\n'),b'\xef\xbb\xbf'+raw):self.assertNotEqual(hashlib.sha256(x).digest(),h)
    def test_weak_gate_counterexamples(self):
        self.assertFalse(o.admit(7,11,8,11,258,258,259,True))
        self.assertFalse(o.admit(7,11,7,11,0,0,23,True))
        self.assertFalse(o.admit(7,11,7,12,258,258,259,True))
    def test_warning_accepted_without_changing_hypothesis(self):
        r=json.loads((ROOT/'R137_RECEIVED_ACCEPTANCE.json').read_text())
        self.assertEqual(r['raw_api_codes'],[2,2]);self.assertEqual(r['diagnostic_exit'],4)
        self.assertEqual(r['absent_path_hypothesis'],'NOT_CONFIRMED_ON_THIS_HOST')
        self.assertIn('test-build.stderr.txt',r['compiler_warnings'])
    def test_archive_validator_has_no_extract_execute(self):
        s=(ROOT/'validate_r137_archive.py').read_text()
        self.assertNotIn('extractall(',s);self.assertNotIn('subprocess',s)
        self.assertIn('duplicate JSON key',s);self.assertIn('2_000_000',s)

if __name__=='__main__':unittest.main(verbosity=2)
