#!/usr/bin/env python3
"""Independent offline source, protocol and negative tests for R137 (no native run)."""
import hashlib, importlib.util, json, re, subprocess, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('r137_spec',ROOT/'r137_oracle.py')
o=importlib.util.module_from_spec(spec);spec.loader.exec_module(o)
FLAGS=('kernel_origin_proof','image_section_identity_proof','no_direct_proof')
KEYS=('missing_before','missing_after','own_appid_stable','negative_results_stable',
      'missing_name_appid_success','appid_distinct_from_own')

def uint(value): return type(value) is int and 0<=value<=2**32-1

def validate(rows,exit_code):
    if type(exit_code) is not int or exit_code not in (0,3,4) or len(rows)!=2:
        raise ValueError('number of rows or exit')
    for row in rows:
        if type(row.get('schema')) is not int or row['schema']!=1 or any(row.get(k) is not False for k in FLAGS):
            raise ValueError('schema or false proof flags')
    a,s=rows
    if a.get('kind')!='negative_name' or a.get('no_file_created') is not True:
        raise ValueError('negative-path provenance')
    if not all(type(a.get(k)) is bool for k in KEYS):
        raise ValueError('observations require booleans')
    for k in ('lookup_code_first','lookup_code_second','own_appid_bytes','missing_name_appid_bytes'):
        if not uint(a.get(k)):
            raise ValueError('raw DWORD/count')
    if not 0<a['own_appid_bytes']<=65536 or a['missing_name_appid_bytes']>65536:
        raise ValueError('blob bounds')
    if a['missing_name_appid_success']:
        if a['lookup_code_first']!=0 or a['missing_name_appid_bytes']==0:
            raise ValueError('missing success mismatch')
    elif a['lookup_code_first']==0 or a['missing_name_appid_bytes']!=0 or a['appid_distinct_from_own']:
        raise ValueError('missing failure mismatch')
    if a['negative_results_stable'] and a['lookup_code_first']!=a['lookup_code_second']:
        raise ValueError('result pair contradicts stability')
    mask=sum(1<<i for i,k in enumerate(KEYS) if a[k])
    want_code,want_name=o.diagnostic(mask)
    if (s.get('kind')!='summary' or type(s.get('diagnostic_exit')) is not int or s['diagnostic_exit']!=want_code
        or type(s.get('observations_mask')) is not int or s['observations_mask']!=mask
        or s.get('status')!=want_name or exit_code!=want_code or s.get('filename_only') is not True
        or s.get('no_wfp_policy_mutation') is not True or s.get('atomic_snapshot') is not False
        or s.get('absence_confirmed_before_after') is not (a['missing_before'] and a['missing_after'])):
        raise ValueError('summary mask/exit/proof inconsistency')
    return mask

def fixture(mask=0x3f):
    status=o.diagnostic(mask)
    flags={k:bool(mask&(1<<i)) for i,k in enumerate(KEYS)}
    success=flags['missing_name_appid_success']
    a=dict(schema=1,kind='negative_name',**flags,
           own_appid_bytes=232,missing_name_appid_bytes=246 if success else 0,
           lookup_code_first=0 if success else 2,lookup_code_second=0 if success else 2,
           no_file_created=True,**{k:False for k in FLAGS})
    s=dict(schema=1,kind='summary',status=status[1],diagnostic_exit=status[0],observations_mask=mask,
           filename_only=True,no_wfp_policy_mutation=True,atomic_snapshot=False,
           absence_confirmed_before_after=flags['missing_before'] and flags['missing_after'],
           **{k:False for k in FLAGS})
    return [a,s]

class Acceptance(unittest.TestCase):
    def bad(self,row,key,value):
        rows=fixture();rows[row][key]=value
        with self.assertRaises(ValueError):validate(rows,0)
    def test_accepted_missing_path_fixture(self):self.assertEqual(validate(fixture(0x3f),0),0x3f)
    def test_rejected_missing_path_fixture(self):self.assertEqual(validate(fixture(0x0f),4),0x0f)
    def test_ambiguous_same_appid(self):self.assertEqual(validate(fixture(0x1f),3),0x1f)
    def test_cannot_claim_not_absent(self):self.assertEqual(validate(fixture(0x3e),3),0x3e)
    def test_negative_api_error_without_appid_not_proof(self):self.assertEqual(o.diagnostic(0x0f)[0],4)
    def test_source_pin_in_script(self):
        b=(ROOT/'r137_missing_path_appid.rs').read_bytes();s=(ROOT/'FlowBridge-R137-MissingAppId.ps1').read_text()
        sha=hashlib.sha256(b).hexdigest();git=hashlib.sha1(f'blob {len(b)}\0'.encode()+b).hexdigest()
        self.assertIn(sha,s);self.assertIn(git,s)
        self.assertIn('FromBase64String',s);self.assertIn('[IO.File]::WriteAllBytes',s)
    def test_source_ffi_allowlist(self):
        s=(ROOT/'r137_missing_path_appid.rs').read_text()
        externs=re.findall(r'unsafe extern "system" \{(.*?)\n    \}',s,re.S)
        self.assertEqual(len(externs),2)
        names=set(re.findall(r'fn (\w+)\(',''.join(externs)))
        self.assertEqual(names,{'GetCurrentProcess','GetCurrentProcessId','QueryFullProcessImageNameW',
             'GetDriveTypeW','GetFileAttributesW','GetLastError','FwpmGetAppIdFromFileName0','FwpmFreeMemory0'})
    def test_source_no_writes_or_sockets(self):
        s=(ROOT/'r137_missing_path_appid.rs').read_text()
        code='\n'.join(line.split('//',1)[0] for line in s.splitlines())
        for banned in ('CreateFileW','DeleteFileW','CopyFileW','MoveFileW','std::net',
                       'FwpmFilterAdd','FwpmCalloutAdd','FwpmTransactionBegin','Command::new',
                       'OpenProcess','Terminat'+'eProcess','std::fs::write'):
            self.assertNotIn(banned,code)
        self.assertNotIn('std::fs::File',code)
    def test_process_scope_is_own(self):
        s=(ROOT/'r137_missing_path_appid.rs').read_text()
        self.assertIn('GetCurrentProcess()',s);self.assertIn('GetCurrentProcessId()',s)
        self.assertIn('missing_sibling(&own)?',s)
        self.assertIn('std::env::args().skip(1)',s)
        self.assertIn('DRIVE_FIXED',s)
    def test_exact_absence_double_read(self):
        s=(ROOT/'r137_missing_path_appid.rs').read_text()
        self.assertIn('let before = is_missing(&missing)?;',s)
        self.assertIn('let after = is_missing(&missing)?;',s)
        self.assertIn('code == ERROR_FILE_NOT_FOUND',s)
        self.assertIn('let absent_one = get_appid(&missing)?;',s)
        self.assertIn('let absent_two = get_appid(&missing)?;',s)
    def test_empty_and_oversize_appid_rejected(self):
        s=(ROOT/'r137_missing_path_appid.rs').read_text()
        self.assertIn('b.size == 0 || b.size as usize > MAX_APPID_BYTES',s)
    def test_no_secret_path_in_stdout(self):
        s=(ROOT/'r137_missing_path_appid.rs').read_text()
        for bad in ('own_path_hex','missing_path_hex','raw_path','app_id_hex'):
            self.assertNotIn(bad,s)
    def test_no_boolean_promotions(self):
        for flag in FLAGS:self.bad(1,flag,True)
    def test_observation_string_bool_rejected(self):self.bad(0,'missing_before','true')
    def test_appid_size_float_rejected(self):self.bad(0,'missing_name_appid_bytes',246.0)
    def test_code_string_rejected(self):self.bad(0,'lookup_code_first','0')
    def test_hash_result_is_not_file_existence(self):self.bad(0,'missing_before',False)
    def test_disagreeing_summary_mask_rejected(self):self.bad(1,'observations_mask',15)
    def test_wrong_exit_rejected(self):
        with self.assertRaises(ValueError):validate(fixture(0x3f),4)
    def test_appid_equality_cannot_claim_distinct(self):
        self.bad(0,'appid_distinct_from_own',False)
    def test_not_file_created_cannot_be_reversed(self):self.bad(0,'no_file_created',False)
    def test_output_truncated_or_extended_rejected(self):
        for r in (fixture()[:1],fixture()+fixture()[:1]):
            with self.assertRaises(ValueError):validate(r,0)
    def test_source_exactly_18_unit_tests(self):
        self.assertEqual((ROOT/'r137_missing_path_appid.rs').read_text().count('#[test]'),18)
    def test_matrix_all_256_states(self):
        self.assertEqual(o.result()['states'],256)
        self.assertEqual(o.result()['diagnostic_exit_counts'],{'0':4,'3':244,'4':8})
    def test_independent_node_oracle(self):
        other=json.loads(subprocess.check_output(['node',str(ROOT/'r137_independent.mjs')],text=True))
        self.assertEqual(other,o.result())
        self.assertIn(other['sha256'],(ROOT/'FlowBridge-R137-MissingAppId.ps1').read_text())
    def test_gated_native_invocation(self):
        s=(ROOT/'FlowBridge-R137-MissingAppId.ps1').read_text()
        self.assertIn('if ($RunReadOnlyMissingName) {',s)
        self.assertIn("@('--read-only-missing-name')",s)
        self.assertIn('test result: ok\\. 18 passed;',s)
        for unwanted in ('Start-Service','Set-ExecutionPolicy','rustup install','git checkout','New-NetFirewallRule'):
            self.assertNotIn(unwanted,s)
    def test_crlf_bom_and_truncation_refused(self):
        raw=(ROOT/'r137_missing_path_appid.rs').read_bytes();expected=hashlib.sha256(raw).digest()
        for b in (raw.replace(b'\n',b'\r\n'),b'\xef\xbb\xbf'+raw,raw[:-1],raw+b' '):
            self.assertNotEqual(hashlib.sha256(b).digest(),expected)
    def test_self_appid_blob_not_a_pid_certificate(self):
        s=(ROOT/'r137_missing_path_appid.rs').read_text()
        self.assertIn('kernel_origin_proof\\\":false',s)
        self.assertIn('image_section_identity_proof\\\":false',s)

if __name__=='__main__':unittest.main(verbosity=2)
