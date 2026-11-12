#!/usr/bin/env python3
"""Independent test oracle, raw-JSON mutants and source/guard inspection."""
import copy,ctypes,hashlib,importlib.util,json,re,subprocess,unittest
from pathlib import Path
import r136_oracle as oracle
import validate_r136_receipt as receipt
ROOT=Path(__file__).resolve().parent
NO_PROOF={k:False for k in receipt.FLAGS}
def w(s):return ''.join(f'{ord(c):04X}' for c in s)
def fixture():
    native=w(r'\Device\HarddiskVolume3\a.exe');dos=w(r'C:\a.exe')
    p=dict(schema=1,kind='self',pid=100,win32_before=dos,win32_after=dos,native_before=native,native_after=native,module_name=dos,**NO_PROOF)
    m=dict(schema=1,kind='mapping',mapped_native_before=native,mapped_native_after=native,state=4096,type=0x1000000,
        module_base_hex='0000000000400000',allocation_base_hex='0000000000400000',**NO_PROOF)
    f=dict(schema=1,kind='file',final_native=native,final_dos=dos,volume_before='0123456789ABCDEF',volume_after='0123456789ABCDEF',
        id_before='12'*16,id_after='12'*16,app0='FF00AA',app1='FF00AA',app2='FF00AA',app3='FF00AA',**NO_PROOF)
    s=dict(schema=1,kind='summary',status='MAPPED_IMAGE_NAME_CONCORDANT_NOT_SECTION_FILE_ID_PROOF',observation_mask=255,
        diagnostic_exit=0,mem_image_constant=0x1000000,file_id_class=18,atomic_snapshot=False,**NO_PROOF)
    return [p,m,f,s]
def mutate(r,i,key,val):r=copy.deepcopy(r);r[i][key]=val;return r

class R136Acceptance(unittest.TestCase):
    def fail_pass(self,i,key,val):
        with self.assertRaises(ValueError):receipt.raw_rows(mutate(fixture(),i,key,val),0)
    def test_positive_fixture(self):self.assertEqual(receipt.raw_rows(fixture(),0),255)
    def test_mbi_type_mismatch(self):self.fail_pass(1,'type',0x40000)
    def test_mbi_not_committed(self):self.fail_pass(1,'state',8192)
    def test_allocation_base_not_module(self):self.fail_pass(1,'allocation_base_hex','0000000000500000')
    def test_mapped_name_drift(self):self.fail_pass(1,'mapped_native_after',w('Changed'))
    def test_process_native_drift(self):self.fail_pass(0,'native_after',w('Changed'))
    def test_mapped_vs_process_mismatch(self):self.fail_pass(0,'native_before',w('Changed'))
    def test_mapped_vs_file_mismatch(self):self.fail_pass(2,'final_native',w('Changed'))
    def test_file_id_modified(self):self.fail_pass(2,'id_after','13'*16)
    def test_zero_file_id_not_accepted(self):self.fail_pass(2,'id_before','0'*32)
    def test_zero_volume_not_accepted(self):self.fail_pass(2,'volume_before','0'*16)
    def test_appid_drift(self):self.fail_pass(2,'app3','BB')
    def test_appid_cross_name(self):self.fail_pass(2,'app1','BB')
    def test_process_win32_drift(self):self.fail_pass(0,'win32_after',w('Changed'))
    def test_module_filename_diagnostic_only(self):
        r=mutate(fixture(),0,'module_name',w('DIFFERENT'))
        r[3]['observation_mask']=127
        self.assertEqual(receipt.raw_rows(r,0),127)
    def test_negative_consistent_is_accepted_as_negative(self):
        r=mutate(fixture(),1,'type',0x40000)
        r[-1].update(status='MAPPING_OBSERVATION_MISMATCH_NO_PROOF',observation_mask=254,diagnostic_exit=3)
        self.assertEqual(receipt.raw_rows(r,3),254)
    def test_no_proof_promotion(self):
        for f in receipt.FLAGS:self.fail_pass(3,f,True)
    def test_boolean_pid_is_not_number(self):self.fail_pass(0,'pid',True)
    def test_negative_pid(self):self.fail_pass(0,'pid',-3)
    def test_string_mem_type_rejected(self):self.fail_pass(1,'type','16777216')
    def test_bad_utf16_hex_length_rejected(self):self.fail_pass(0,'native_before','F')
    def test_utf16_zero_unit_rejected(self):self.fail_pass(2,'final_native','00410000')
    def test_bad_opaque_byte_rejected(self):self.fail_pass(2,'app2','G0')
    def test_json_duplicate_keys_rejected(self):
        with self.assertRaises(ValueError):receipt.decode(b'{"schema":1,"schema":1}')
    def test_extra_rows_rejected(self):
        with self.assertRaises(ValueError):receipt.raw_rows(fixture()+fixture()[:1],0)
    def test_one_required_bit_missing(self):
        for i in range(7):self.assertEqual(oracle.outcome(127^(1<<i)),3)
    def test_optional_bit_not_required(self):self.assertEqual(oracle.outcome(127),0);self.assertEqual(oracle.outcome(255),0)
    def test_matrix_and_node_agree(self):
        py=oracle.result();js=json.loads(subprocess.check_output(['node',str(ROOT/'r136_independent.mjs')],text=True))
        self.assertEqual(py,js);self.assertEqual(py['states'],256);self.assertEqual(py['consistent'],2)
        self.assertEqual(py['sha256'],'bae850d1de8c78c1acbf4aee36fb1a1a67a54c6b72c7c6e09677c774442385ec')
    def test_struct_layout(self):
        class FileId(ctypes.Structure):_fields_=[('volume',ctypes.c_uint64),('id',ctypes.c_ubyte*16)]
        class Mbi(ctypes.Structure):_fields_=[('base',ctypes.c_void_p),('allocation_base',ctypes.c_void_p),('allocation_protect',ctypes.c_uint32),
          ('partition_id',ctypes.c_uint16),('align',ctypes.c_uint16),('region_size',ctypes.c_size_t),('state',ctypes.c_uint32),
          ('protect',ctypes.c_uint32),('kind',ctypes.c_uint32),('pad',ctypes.c_uint32)]
        self.assertEqual(ctypes.sizeof(FileId),24);self.assertEqual(FileId.id.offset,8)
        self.assertEqual(ctypes.sizeof(Mbi),48);self.assertEqual(Mbi.kind.offset,40);self.assertEqual(Mbi.allocation_base.offset,8)
    def test_windows_api_surface(self):
        source=(ROOT/'r136_mapped_self_image.rs').read_text()
        sections=re.findall(r'unsafe extern "system" \{(.*?)\n    \}',source,re.S)
        calls=set(re.findall(r'fn (\w+)\(',''.join(sections)))
        self.assertEqual(calls,{'GetCurrentProcess','GetCurrentProcessId','GetModuleHandleW','GetModuleFileNameW',
          'QueryFullProcessImageNameW','K32GetMappedFileNameW','VirtualQuery','GetDriveTypeW','CreateFileW',
          'GetFileInformationByHandleEx','GetFinalPathNameByHandleW','CloseHandle','GetLastError',
          'FwpmGetAppIdFromFileName0','FwpmFreeMemory0'})
        self.assertNotIn('FwpmFilterAdd',source)
        self.assertNotIn('FwpsCalloutRegister',source)
        self.assertNotIn('CreateProcessW',source)
        self.assertNotIn('std::net',source)
    def test_rust_21_tests_present(self):self.assertEqual((ROOT/'r136_mapped_self_image.rs').read_text().count('#[test]'),21)
    def test_pinned_source_exact(self):
        b=(ROOT/'r136_mapped_self_image.rs').read_bytes();ps=(ROOT/'FlowBridge-R136-SelfMappedImage.ps1').read_text()
        s=hashlib.sha1(f'blob {len(b)}\0'.encode()+b).hexdigest();sha=hashlib.sha256(b).hexdigest()
        self.assertEqual(s,receipt.SRC_GIT);self.assertEqual(sha,receipt.SRC_SHA)
        self.assertIn(s,ps);self.assertIn(sha,ps)
    def test_readonly_guard(self):
        rust=(ROOT/'r136_mapped_self_image.rs').read_text();ps=(ROOT/'FlowBridge-R136-SelfMappedImage.ps1').read_text()
        for mark in ('CreateFileW(p.as_ptr(),0x80000000,1,ptr::null(),3,0,ptr::null_mut())','GetModuleHandleW(ptr::null())',
                     'VirtualQuery(base.cast_const()','K32GetMappedFileNameW','id_stable(id0,id1)'):
            self.assertIn(mark,rust)
        for banned in ('Set-ExecutionPolicy','Start-Service','New-NetFirewallRule','rustup install','git checkout'):
            self.assertNotIn(banned,ps)
        self.assertIn('if ($RunSelfMappedImage)',ps)
    def test_source_byte_mutants_rejected(self):
        b=(ROOT/'r136_mapped_self_image.rs').read_bytes();h=hashlib.sha256(b).digest()
        for corrupt in (b[:-1],b+b' ',b'\xef\xbb\xbf'+b,b.replace(b'\n',b'\r\n')):
            self.assertNotEqual(hashlib.sha256(corrupt).digest(),h)

if __name__=='__main__':unittest.main(verbosity=2)
