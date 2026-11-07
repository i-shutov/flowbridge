"""Adversarial evidence-reader tests; never runs a driver or executable."""
import copy,os,struct,unittest,zipfile
from pathlib import Path
import verify_redirect_r23 as v
class Audit(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  keys=['R23_KERNEL_ZIP','R23_SSH_ZIP','R23_SOCKET_ZIP']
  if not all(os.environ.get(k) for k in keys):raise unittest.SkipTest('Provide all pinned artifacts; no native claim')
  cls.raw=[Path(os.environ[k]).read_bytes() for k in keys]
  k=v.unpack(cls.raw[0],v.PINS['kernel']);s=v.unpack(cls.raw[1],v.PINS['ssh'])
  cls.driver=k['flowbridge_g2_witness.sys'];cls.broker=k['flowbridge-redirect-broker.exe']
  cls.docs=[v.decode(k['build-result.json']),v.decode(k['broker-negative.json']),v.decode(s['transport-result.json'])]
 def test_actual_archives(self):
  r=v.audit(*self.raw);self.assertTrue(r['ok']);self.assertFalse(r['g2_pass']);self.assertFalse(r['full_origin_kernel_redirect_socket_ssh_chain_executed'])
 def test_each_changed_zip_rejected(self):
  for i in range(3):
   a=list(self.raw);a[i]+=b'x'
   with self.subTest(i=i),self.assertRaises(v.Rejected):v.audit(*a)
 def test_source_cannot_transfer(self):
  for i in (0,2):
   d=copy.deepcopy(self.docs);d[i]['source_sha']='0'*40
   with self.assertRaises(v.Rejected):v.scope(*d)
 def test_full_native_redirect_cannot_be_faked(self):
  d=copy.deepcopy(self.docs);d[2]['kernel_redirect_executed']=True
  with self.assertRaises(v.Rejected):v.scope(*d)
 def test_kernel_load_cannot_be_faked(self):
  d=copy.deepcopy(self.docs);d[0]['kernel_driver_loaded']=True
  with self.assertRaises(v.Rejected):v.scope(*d)
 def test_release_or_g2_promotions_rejected(self):
  for i in range(3):
   d=copy.deepcopy(self.docs);d[i]['g2_pass']=True
   with self.assertRaises(v.Rejected):v.scope(*d)
 def test_truthy_integer_not_boolean(self):
  d=copy.deepcopy(self.docs);d[1]['ok']=1
  with self.assertRaises(v.Rejected):v.scope(*d)
 def test_test_count_cannot_be_string(self):
  d=copy.deepcopy(self.docs);d[2]['rust_tests_passed']='13'
  with self.assertRaises(v.Rejected):v.scope(*d)
 def test_no_cleanup_no_pass(self):
  d=copy.deepcopy(self.docs);d[2]['fixture_processes_and_keys_removed']=False
  with self.assertRaises(v.Rejected):v.scope(*d)
 def test_half_close_required(self):
  d=copy.deepcopy(self.docs);d[2]['half_close']=False
  with self.assertRaises(v.Rejected):v.scope(*d)
 def test_no_synthetic_context_native_promotion(self):
  d=copy.deepcopy(self.docs);d[2]['fixture_context_used']=True
  with self.assertRaises(v.Rejected):v.scope(*d)
 def test_duplicate_json_rejected(self):
  with self.assertRaises(v.Rejected):v.decode(b'{"ok":true,"ok":false}')
 def test_broker_cannot_be_kernel(self):
  with self.assertRaises(v.Rejected):v.PE(self.broker,1)
 def test_pe_machine_subsystem_and_entry(self):
  p=struct.unpack_from('<I',self.driver,60)[0]
  for at,fmt,val in [(p+4,'H',0x14c),(p+24+68,'H',3),(p+24+16,'I',0)]:
   raw=bytearray(self.driver);struct.pack_into('<'+fmt,raw,at,val)
   with self.subTest(at=at),self.assertRaises(v.Rejected):v.PE(bytes(raw),1)
 def test_certificate_bit_is_not_signature(self):
  p=struct.unpack_from('<I',self.driver,60)[0];raw=bytearray(self.driver);struct.pack_into('<I',raw,p+24+144,512)
  with self.assertRaises(v.Rejected):v.PE(bytes(raw),1)
 def test_actual_redirect_and_broker_calls_differ(self):
  k=v.PE(self.driver,1);b=v.PE(self.broker,3)
  self.assertIn('FwpsApplyModifiedLayerData0',k.imports['fwpkclnt.sys'])
  self.assertIn('WSAIoctl',b.imports['ws2_32.dll'])
  self.assertTrue(any(n.startswith('ordinal:') for n in b.imports['ws2_32.dll']))
if __name__=='__main__':unittest.main(verbosity=2)
