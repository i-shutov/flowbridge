"""Independent negative controls; never executes Windows APIs."""
import json, unittest,zipfile
from pathlib import Path
from copy import deepcopy
import verify_native_r15 as v

D=Path(__file__).parent
ARCH=D/'fixtures'/'r15-native-rust-windows.zip'

def original():
 with zipfile.ZipFile(ARCH) as z:return json.loads(z.read('native-result.json'))

class NativeR15Witness(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  if not ARCH.is_file():raise unittest.SkipTest('pinned archive absent')
  cls.base=original()

 def test_exact_native_run_and_source(self):
  outcome=v.verify_archive(ARCH.read_bytes(),{k:(D/k).read_bytes() for k in v.SOURCES})
  self.assertTrue(outcome['rust_built_and_executed']);self.assertFalse(outcome['release_accepted'])

 def test_count_and_case_order(self):
  self.assertEqual(v.validate(self.base)['independent_ffi_equivalence_and_length_checks'],5)

 def test_missing_or_added_field_rejected(self):
  for mutate in ('missing','added'):
   x=deepcopy(self.base)
   if mutate=='missing':del x['rust_probe_built_and_executed']
   else:x['secret_path']='C:/...'
   with self.assertRaises(v.Rejected):v.validate(x)

 def test_false_positive_security_flag(self):
  for field in ('release_accepted','kernel_process_epoch_proved','driver_or_filter_changed','no_direct_proved'):
   x=deepcopy(self.base);x[field]=True
   with self.assertRaises(v.Rejected):v.validate(x)

 def test_rust_not_run_or_downgraded(self):
  for key,value in (('rust_probe_built_and_executed',False),('evidence_level','native_api_only'),('rust_pairwise_crosscheck_complete',False)):
   x=deepcopy(self.base);x[key]=value
   with self.assertRaises(v.Rejected):v.validate(x)

 def test_invalid_native_api_count(self):
  for wrong in (0,9,True,'10'):
   x=deepcopy(self.base);x['native_api_reads']=wrong
   with self.assertRaises(v.Rejected):v.validate(x)

 def test_swapped_sibling_appid_result(self):
  x=deepcopy(self.base);x['comparisons'][1]['appid_equal']=True
  with self.assertRaises(v.Rejected):v.validate(x)

 def test_rust_python_disagreement_rejected(self):
  x=deepcopy(self.base);x['comparisons'][2]['rust_and_ctypes_agree']=False
  with self.assertRaises(v.Rejected):v.validate(x)

 def test_netsh_read_only_path_still_required(self):
  x=deepcopy(self.base);x['netsh_readonly'][1]['successful']=False
  with self.assertRaises(v.Rejected):v.validate(x)

 def test_source_mismatch_rejected(self):
  x=deepcopy(self.base);x['source_sha256']['appid_readonly.rs']='0'*64
  with self.assertRaises(v.Rejected):v.validate(x)

 def test_tampered_archive_and_source_rejected(self):
  d=bytearray(ARCH.read_bytes());d[20]^=1
  with self.assertRaises(v.Rejected):v.verify_archive(bytes(d),{k:(D/k).read_bytes() for k in v.SOURCES})
  with self.assertRaises(v.Rejected):v.verify_archive(ARCH.read_bytes(),{k:((D/k).read_bytes()+b' ') for k in v.SOURCES})

 def test_duplicate_json_rejected(self):
  with self.assertRaises(v.Rejected):json.loads('{"ok":true,"ok":false}',object_pairs_hook=v.strict)

if __name__=='__main__':unittest.main(verbosity=2)
