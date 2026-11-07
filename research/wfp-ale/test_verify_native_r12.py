import copy
import io
import os
import json
import unittest
from pathlib import Path
from zipfile import ZipFile
import verify_native_r12 as v

ROOT=Path(__file__).resolve().parent
ZIP=Path(os.environ.get('FLOWBRIDGE_R12_ZIP',str(ROOT/'fixtures/r12-native-windows.zip')))
SRC=Path(os.environ.get('FLOWBRIDGE_R12_SOURCE',str(ROOT/'handle_appid_probe.py')))

class ReadonlyEvidenceQA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with ZipFile(ZIP) as z:cls.data=json.loads(z.read('native-result.json'))
    def test_real_full_archive_verifies(self):
        result=v.audit(ZIP.read_bytes(),SRC.read_bytes())
        self.assertTrue(result['native_findings']['actual_native_windows_API_execution_proved'])
        self.assertFalse(result['release_accepted'])
    def test_win_line_endings_pinned(self):
        raw=SRC.read_bytes()
        self.assertNotEqual(v.sha256(raw),v.EXPECTED_SOURCE_CHECKOUT_SHA256)
        self.assertEqual(v.sha256(raw.replace(b'\n',b'\r\n')),v.EXPECTED_SOURCE_CHECKOUT_SHA256)
    def test_identity_tampering_rejected(self):
        d=copy.deepcopy(self.data)
        d['source_sha256']='0'*64
        with self.assertRaises(v.RejectedEvidence):v.audit_record(d)
    def test_promotion_rejected(self):
        for field in ('kernel_pid_epoch_bound','ndisrd_packetbound','system_no_direct','release_accepted'):
            d=copy.deepcopy(self.data);d[field]=True
            with self.subTest(field=field),self.assertRaises(v.RejectedEvidence):v.audit_record(d)
    def test_forged_matrix_rejected(self):
        for name in ('same_name_different_directory','hardlink','symlink','case_variant'):
            d=copy.deepcopy(self.data)
            for c in d['cases']:
                if c['case']==name:c['supplied_pair_appid_equal']=not c['supplied_pair_appid_equal']
            with self.subTest(name=name),self.assertRaises(v.RejectedEvidence):v.audit_record(d)
    def test_changed_native_field_rejected(self):
        for x in ('resolved_appid_is_handle_device_path','supplied_appid_is_handle_device_path','supplied_vs_resolved_appid_equal'):
            d=copy.deepcopy(self.data)
            d['cases'][0]['first'][x]=not d['cases'][0]['first'][x]
            with self.subTest(field=x),self.assertRaises(v.RejectedEvidence):v.audit_record(d)
    def test_partial_cases_rejected(self):
        d=copy.deepcopy(self.data);d['cases'].pop()
        with self.assertRaises(v.RejectedEvidence):v.audit_record(d)
    def test_synthetic_archive_checksum_cannot_mint_evidence(self):
        raw=bytearray(ZIP.read_bytes());raw[10]^=1
        with self.assertRaises(v.RejectedEvidence):v.audit(bytes(raw),SRC.read_bytes())
    def test_raw_paths_cannot_be_added(self):
        d=copy.deepcopy(self.data);d['cases'][0]['first']['path']='C:\\secret'
        with self.assertRaises(v.RejectedEvidence):v.audit_record(d)
if __name__=='__main__':unittest.main(verbosity=2)
