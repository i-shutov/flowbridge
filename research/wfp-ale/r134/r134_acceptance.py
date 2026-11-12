#!/usr/bin/env python3
"""Scope/pin/JSON negative tests, NOT a Rust or Windows execution claim."""
import copy,hashlib,importlib.util,json,re,subprocess,unittest,ctypes
from pathlib import Path
ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('o',ROOT/'r134_oracle.py')
o=importlib.util.module_from_spec(spec);spec.loader.exec_module(o)
FLAGS=('kernel_origin_proof','image_section_identity_proof','no_direct_proof')
def integer(x):return type(x) is int and 0<=x<=0xffffffff
def hx(x,n):return type(x) is str and len(x)==n and re.fullmatch('[0-9A-F]+',x) is not None
def wide(x):return type(x) is str and len(x)<=131068 and re.fullmatch('(?:[0-9A-F]{4})+',x) and all(x[i:i+4]!='0000' for i in range(0,len(x),4))
def opaque(x):return type(x) is str and len(x)<=131072 and re.fullmatch('(?:[0-9A-F]{2})+',x)
def validate(rows,exit_code):
    if len(rows)!=5 or type(exit_code) is not int or exit_code not in (0,3):raise ValueError('cardinality/exit')
    for r in rows:
        if type(r.get('schema')) is not int or r['schema']!=1 or any(r.get(k) is not False for k in FLAGS):raise ValueError('schema/proof')
    p,a,b,apps,s=rows
    if p.get('kind')!='self_process' or not integer(p.get('pid')) or not p['pid'] or not wide(p.get('dos_name_hex')) or not wide(p.get('native_name_hex')) or type(p.get('names_stable')) is not bool:raise ValueError('process')
    for i,f in enumerate((a,b)):
        if f.get('kind')!='file' or type(f.get('index')) is not int or f['index']!=i:raise ValueError('file index')
        for k,n in [('volume_before',16),('volume_after',16),('id_before',32),('id_after',32)]:
            if not hx(f.get(k),n):raise ValueError('file identifier')
        if not wide(f.get('final_dos_hex')) or not wide(f.get('final_native_hex')):raise ValueError('name format')
    if apps.get('kind')!='appid' or type(apps.get('queries')) is not int or apps['queries']!=4 or apps.get('opaque_bytes') is not True:raise ValueError('appid header')
    for k in ('process_path_before','final_path_before','process_path_after','final_path_after'):
        if not opaque(apps.get(k)):raise ValueError('opaque bytes')
    usable=a['id_before']!='0'*32 and b['id_before']!='0'*32
    same=usable and a['volume_before']==b['volume_before'] and a['id_before']==b['id_before']
    stable=all(f['volume_before']==f['volume_after'] and f['id_before']==f['id_after'] for f in (a,b))
    stable_app=apps['process_path_before']==apps['process_path_after'] and apps['final_path_before']==apps['final_path_after']
    equal_app=apps['process_path_before']==apps['final_path_before']
    equal_native=p['native_name_hex']==a['final_native_hex']==b['final_native_hex']
    bits=(usable,same,stable,True,stable_app,equal_app,p['names_stable'],equal_native)
    mask=sum(2**i for i,v in enumerate(bits) if v);code=o.exit_for(mask)
    status='SELF_IMAGE_FILE_APPID_OBSERVED_NOT_ALE_PROOF' if code==0 else 'OBSERVATION_MISMATCH_NO_PROOF'
    if s.get('kind')!='summary' or s.get('status')!=status or exit_code!=code or s.get('atomic_snapshot') is not False:raise ValueError('summary boundary')
    for k,v in [('observations_mask',mask),('diagnostic_exit',code),('share_mode',1),('file_id_class',18),('read_only_file_handles',2)]:
        if type(s.get(k)) is not int or s[k]!=v:raise ValueError('summary consistency')
    return mask

def fixture():
    f=dict(schema=1,**{k:False for k in FLAGS});names=dict(final_dos_hex='0043003A005C0061',final_native_hex='005C004400650076')
    rows=[dict(f,kind='self_process',pid=7,dos_name_hex=names['final_dos_hex'],native_name_hex=names['final_native_hex'],names_stable=True)]
    for i in (0,1):rows.append(dict(f,kind='file',index=i,volume_before='0'*15+'1',volume_after='0'*15+'1',id_before='02'*16,id_after='02'*16,**names))
    rows.append(dict(f,kind='appid',queries=4,opaque_bytes=True,process_path_before='FF00D8',final_path_before='FF00D8',process_path_after='FF00D8',final_path_after='FF00D8'))
    rows.append(dict(f,kind='summary',status='SELF_IMAGE_FILE_APPID_OBSERVED_NOT_ALE_PROOF',observations_mask=255,diagnostic_exit=0,share_mode=1,file_id_class=18,read_only_file_handles=2,atomic_snapshot=False))
    return rows

class Acceptance(unittest.TestCase):
    def bad(self,row,key,value):
        r=fixture();r[row][key]=value
        with self.assertRaises(ValueError):validate(r,0)
    def test_valid_fixture(self):self.assertEqual(validate(fixture(),0),255)
    def test_volume_mismatch_not_same_file(self):self.bad(2,'volume_before','0'*15+'2')
    def test_id_mismatch_not_same_file(self):self.bad(2,'id_before','03'*16)
    def test_zero_ids_not_positive(self):self.bad(1,'id_before','0'*32)
    def test_id_after_change_invalidates_positive(self):self.bad(1,'id_after','03'*16)
    def test_appid_different_across_paths(self):self.bad(3,'final_path_before','AA')
    def test_appid_changed_between_reads(self):self.bad(3,'process_path_after','BB')
    def test_different_names_not_force_identity_failure(self):
        r=fixture();r[0]['native_name_hex']='00410042';r[-1]['observations_mask']=127;self.assertEqual(validate(r,0),127)
    def test_unknown_file_class_rejected(self):self.bad(4,'file_id_class',0)
    def test_mask_not_trusted(self):self.bad(4,'observations_mask',127)
    def test_string_boolean_rejected(self):self.bad(4,'atomic_snapshot','false')
    def test_bool_is_not_pid(self):self.bad(0,'pid',True)
    def test_duplicate_index_rejected(self):self.bad(2,'index',0)
    def test_unsigned_and_exact_types(self):
        for v in (-1,2**32,'7',7.0):self.bad(0,'pid',v)
    def test_odd_opaque_byte_count_allowed(self):self.assertEqual(validate(fixture(),0),255)
    def test_hex_not_utf16_requirement(self):
        r=fixture();
        for k in ['process_path_before','final_path_before','process_path_after','final_path_after']:r[3][k]='00'
        self.assertEqual(validate(r,0),255)
    def test_invalid_hex_rejected(self):
        for v in ('','fF','F','GG'):self.bad(3,'process_path_before',v)
    def test_embedded_nul_name_rejected(self):self.bad(0,'dos_name_hex','004100000042')
    def test_proof_promotions_rejected(self):
        for k in FLAGS:self.bad(4,k,True)
    def test_query_failure_not_pass(self):
        with self.assertRaises(ValueError):validate(fixture(),2)
    def test_extra_missing_rows_rejected(self):
        for r in (fixture()[:-1],fixture()+fixture()[:1]):
            with self.assertRaises(ValueError):validate(r,0)
    def test_negative_diagnostic_is_valid_when_consistent(self):
        r=fixture();r[2]['volume_before']='0'*15+'2';r[2]['volume_after']='0'*15+'2';r[4].update(observations_mask=253,diagnostic_exit=3,status='OBSERVATION_MISMATCH_NO_PROOF');self.assertEqual(validate(r,3),253)
    def test_source_pins_actual_bytes(self):
        b=(ROOT/'r134_self_image_file_appid.rs').read_bytes();p=(ROOT/'FlowBridge-R134-SelfImage.ps1').read_text()
        self.assertIn(hashlib.sha256(b).hexdigest(),p);self.assertIn(hashlib.sha1(f'blob {len(b)}\0'.encode()+b).hexdigest(),p)
    def test_exact_apis_allowlist(self):
        s=(ROOT/'r134_self_image_file_appid.rs').read_text();blocks=re.findall(r'unsafe extern "system" \{(.*?)\n    \}',s,re.S)
        names=set(re.findall(r'fn (\w+)\(',''.join(blocks)))
        self.assertEqual(names,{'GetCurrentProcess','GetCurrentProcessId','QueryFullProcessImageNameW','GetDriveTypeW','CreateFileW','GetFileInformationByHandleEx','GetFinalPathNameByHandleW','CloseHandle','GetLastError','FwpmGetAppIdFromFileName0','FwpmFreeMemory0'})
    def test_readonly_open_and_local_scope(self):
        s=(ROOT/'r134_self_image_file_appid.rs').read_text()
        for required in ['CreateFileW(p.as_ptr(),0x80000000,SHARE_READ,ptr::null(),3,0,ptr::null_mut())','if kind!=3','let pdos=process_name(0)?','FILE_ID_INFO: i32 = 18','const SHARE_READ: u32 = 1']:
            self.assertIn(required,s)
        for banned in ['std::net','Command::new','CreateHardLink','SetFileInformation','FwpmFilterAdd','Fwps']:
            self.assertNotIn(banned,s)
    def test_struct_layout_independent(self):
        class Id(ctypes.Structure):_fields_=[('volume',ctypes.c_uint64),('id',ctypes.c_ubyte*16)]
        self.assertEqual(ctypes.sizeof(Id),24);self.assertEqual(Id.id.offset,8);self.assertEqual(ctypes.alignment(Id),8)
    def test_exact_test_count(self):self.assertEqual((ROOT/'r134_self_image_file_appid.rs').read_text().count('#[test]'),18)
    def test_matrix_oracles_agree(self):
        j=json.loads(subprocess.check_output(['node',str(ROOT/'r134_independent.mjs')],text=True));self.assertEqual(j,o.result())
        self.assertIn(j['sha256'],(ROOT/'FlowBridge-R134-SelfImage.ps1').read_text())
    def test_weakened_gate_negative_controls(self):
        for omitted in range(7):
            m=127^(1<<omitted);self.assertEqual(o.exit_for(m),3)
            self.assertTrue(all(bool(m&(1<<i)) for i in range(7) if i!=omitted))
    def test_source_changes_not_accepted(self):
        b=(ROOT/'r134_self_image_file_appid.rs').read_bytes();h=hashlib.sha256(b).digest()
        for x in (b.replace(b'\n',b'\r\n'),b[:-1],b'\xef\xbb\xbf'+b,b+b' '):self.assertNotEqual(hashlib.sha256(x).digest(),h)
    def test_script_guard_and_no_system_mutation(self):
        s=(ROOT/'FlowBridge-R134-SelfImage.ps1').read_text()
        for v in ('Start-Service','Set-ExecutionPolicy','rustup install','git checkout','New-NetFirewallRule'):self.assertNotIn(v,s)
        for v in ('if ($RunSelfImageProbe)','FromBase64String','[IO.File]::WriteAllBytes','18 passed; 0 failed; 0 ignored;','GetCurrentProcess'): # last is only Rust
            if v!='GetCurrentProcess':self.assertIn(v,s)
        self.assertIn('not(test)',(ROOT/'r134_self_image_file_appid.rs').read_text())

if __name__=='__main__':unittest.main(verbosity=2)
