"""Independent adversarial contract checks. No Win32 calls or ZIP extraction."""
from copy import deepcopy
import io
import json
from pathlib import Path
import unittest
import zipfile
import verify_native_r14 as v

ARCHIVE=Path(__file__).parent/'fixtures'/'r14-native-windows.zip'
SOURCE=Path(__file__).parent/'appid_namespace_r14.py'

def original():
    with zipfile.ZipFile(ARCHIVE) as z:
        return json.loads(z.read('native-result.json'))

class NegativeNativeProof(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not ARCHIVE.is_file():
            raise unittest.SkipTest('pinned archive absent')
        cls.data=original()

    def test_real_archive(self):
        out=v.verify_archive(ARCHIVE.read_bytes(),SOURCE.read_bytes())
        self.assertTrue(out['ok'])
        self.assertTrue(out['hardlink_same_file_id_but_distinct_appid'])
        self.assertFalse(out['release_accepted'])
        self.assertFalse(out['native_windows_10_11_tested'])

    def test_native_record_accepted_only_at_correct_scope(self):
        result=v.verify_record(self.data)
        self.assertTrue(result['getlongpathname_not_enough_for_directory_symlink'])
        self.assertFalse(result['release_accepted'])

    def test_tampered_archive_rejected(self):
        raw=bytearray(ARCHIVE.read_bytes());raw[20]^=1
        with self.assertRaises(v.EvidenceRejected):
            v.verify_archive(bytes(raw),SOURCE.read_bytes())

    def test_tampered_source_rejected(self):
        with self.assertRaises(v.EvidenceRejected):
            v.verify_archive(ARCHIVE.read_bytes(),SOURCE.read_bytes()+b' ') 

    def test_false_release_or_kernel_owner_rejected(self):
        for k in ('release_accepted','kernel_owner_proved','ndisrd_packetbound_proved',
                  'system_no_direct_proved','wfp_driver_or_filter_modified'):
            x=deepcopy(self.data);x[k]=True
            with self.subTest(field=k),self.assertRaises(v.EvidenceRejected):v.verify_record(x)

    def test_missing_case_or_swapped_order_rejected(self):
        x=deepcopy(self.data);x['cases'].pop()
        with self.assertRaises(v.EvidenceRejected):v.verify_record(x)
        x=deepcopy(self.data);x['cases'][0],x['cases'][1]=x['cases'][1],x['cases'][0]
        with self.assertRaises(v.EvidenceRejected):v.verify_record(x)

    def test_8dot3_discrepancy_must_survive(self):
        for f,val in [('supplied_matches_lexical_device_path',False),
                      ('expanded_matches_handle_appid',False),
                      ('long_dos_path_changed',False)]:
            x=deepcopy(self.data);x['cases'][0]['left'][f]=val
            with self.subTest(f=f),self.assertRaises(v.EvidenceRejected):v.verify_record(x)

    def test_hardlink_fileid_enforced(self):
        x=deepcopy(self.data);x['cases'][2]['same_physical_file_by_volume_file_index']=False
        with self.assertRaises(v.EvidenceRejected):v.verify_record(x)

    def test_hardlink_appid_inequality_enforced(self):
        x=deepcopy(self.data);x['cases'][2]['same_supplied_appid']=True
        with self.assertRaises(v.EvidenceRejected):v.verify_record(x)

    def test_copy_fileid_distinction_enforced(self):
        x=deepcopy(self.data);x['cases'][1]['same_physical_file_by_volume_file_index']=True
        with self.assertRaises(v.EvidenceRejected):v.verify_record(x)

    def test_symlink_is_not_longname_equivalent_to_handle(self):
        x=deepcopy(self.data);x['cases'][3]['right']['expanded_matches_handle_appid']=True
        with self.assertRaises(v.EvidenceRejected):v.verify_record(x)

    def test_symlink_flag_stays_distinct(self):
        x=deepcopy(self.data);x['cases'][3]['right']['supplied_matches_lexical_device_path']=True
        with self.assertRaises(v.EvidenceRejected):v.verify_record(x)

    def test_missing_shape_or_extra_pii_field(self):
        x=deepcopy(self.data);x['cases'][0]['right']['input_vs_handle_structure'].pop('short_name_divergence')
        with self.assertRaises(v.EvidenceRejected):v.verify_record(x)
        x=deepcopy(self.data);x['username']='do-not-output'
        with self.assertRaises(v.EvidenceRejected):v.verify_record(x)

    def test_truthy_integer_not_boolean(self):
        x=deepcopy(self.data);x['cases'][0]['same_physical_file_by_volume_file_index']=1
        with self.assertRaises(v.EvidenceRejected):v.verify_record(x)

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(v.EvidenceRejected):
            json.loads('{"release_accepted":false,"release_accepted":true}',object_pairs_hook=v.strict_obj)

    def test_shortname_count_not_promoted(self):
        x=deepcopy(self.data)
        x['cases'][0]['left']['input_vs_handle_structure']['component_mismatch_count']=7
        with self.assertRaises(v.EvidenceRejected):v.verify_record(x)

if __name__=='__main__':unittest.main(verbosity=2)
