"""Adversarial checks of actual artifact reader. Never loads Windows binaries.
The pristine data are from authenticated Actions downloads; mutations are local.
"""
from copy import deepcopy
import io,json,os,struct,unittest,zipfile
from pathlib import Path
import audit_r24 as a

class AuditContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        folder=Path(os.environ.get('FLOWBRIDGE_R24_ARTIFACT_DIR',Path(__file__).parent.parent/'artifacts'))
        names=[folder/f'FlowBridge-R24-{kind}-cf80986e.zip' for kind in ['Kernel-Broker','SSH','Socket']]
        if not all(p.is_file() for p in names):raise unittest.SkipTest('pinned R24 artifacts absent; no acceptance')
        cls.raw=[p.read_bytes() for p in names]
        cls.k=a.readzip(cls.raw[0]);cls.s=a.readzip(cls.raw[1]);cls.sock=a.readzip(cls.raw[2])
        cls.scope=a.decode(cls.k['r24-build-scope.json']);cls.own=a.decode(cls.k['ownership-contract.json']);cls.t=a.decode(cls.s['transport-result.json'])
    def reports(self,scope=None,own=None,t=None):
        return a.verify_report(self.scope if scope is None else scope,self.own if own is None else own,self.t if t is None else t,a.PINS['source_sha'])
    def test_actual_archives_keep_native_gate_open(self):
        r=a.audit(*self.raw);self.assertTrue(r['ok']);self.assertEqual(r['actual_broker_tests_passed'],27);self.assertEqual(r['actual_ssh_rust_tests_passed'],21)
        for flag in ['kernel_driver_loaded','actual_policy_installed','full_native_chain_accepted','g2_pass','release_accepted']:self.assertIs(r[flag],False)
    def test_every_archive_is_pinned(self):
        for i in range(3):
            r=self.raw.copy();r[i]=r[i]+b' '
            with self.subTest(archive=i),self.assertRaises(a.Rejected):a.audit(*r)
    def test_source_sha_not_transferred(self):
        s=deepcopy(self.scope);s['source_sha']='0'*40
        with self.assertRaises(a.Rejected):self.reports(scope=s)
    def test_no_promotion_of_kernel_or_policy_execution(self):
        for field in ['kernel_driver_loaded','actual_policy_installed','full_redirect_chain_executed','g2_pass','release_accepted']:
            s=deepcopy(self.scope);s[field]=True
            with self.subTest(field=field),self.assertRaises(a.Rejected):self.reports(scope=s)
    def test_missing_field_not_false(self):
        s=deepcopy(self.scope);del s['kernel_driver_loaded']
        with self.assertRaises(a.Rejected):self.reports(scope=s)
    def test_truthy_count_and_boolean_not_accepted(self):
        for value in [True,'27',26,28]:
            s=deepcopy(self.scope);s['actual_broker_tests_passed']=value
            with self.subTest(value=value),self.assertRaises(a.Rejected):self.reports(scope=s)
    def test_compile_negative_set_must_be_complete(self):
        for key in self.own['actual_source_compile_checks']:
            o=deepcopy(self.own);o['actual_source_compile_checks'].pop(key)
            with self.subTest(key=key),self.assertRaises(a.Rejected):self.reports(own=o)
    def test_unsafe_adapter_compile_is_not_a_negative_pass(self):
        o=deepcopy(self.own);o['actual_source_compile_checks']['accepted_socket_moved']=False
        with self.assertRaises(a.Rejected):self.reports(own=o)
    def test_ssh_cannot_stand_for_kernel_redirect(self):
        t=deepcopy(self.t);t['kernel_redirect_executed']=True
        with self.assertRaises(a.Rejected):self.reports(t=t)
    def test_ssh_must_use_real_transport_and_cleanup(self):
        for k,v in [('transport','mock'),('half_close',False),('fixture_context_used',True),('fixture_processes_and_keys_removed',False)]:
            t=deepcopy(self.t);t[k]=v
            with self.subTest(field=k),self.assertRaises(a.Rejected):self.reports(t=t)
    def test_socket_error_cannot_be_reported_as_absence(self):
        data=deepcopy(self.sock);d=a.decode(data['ipv4.json']);d['client']['records']['state']='absent';data['ipv4.json']=json.dumps(d).encode()
        with self.assertRaises(a.Rejected):a.verify_socket_archive(data)
    def test_local_endpoint_is_not_original_process(self):
        data=deepcopy(self.sock);d=a.decode(data['ipv6.json']);d['accepted_local']['creation_epoch_bound']=True;data['ipv6.json']=json.dumps(d).encode()
        with self.assertRaises(a.Rejected):a.verify_socket_archive(data)
    def test_wrong_pe_subsystem_rejected(self):
        data=bytearray(self.k['flowbridge_g2_witness.sys']);pe=int.from_bytes(data[60:64],'little');struct.pack_into('<H',data,pe+24+68,3)
        with self.assertRaises(a.Rejected):a.Image(bytes(data),1)
    def test_no_writable_executable_section(self):
        data=bytearray(self.k['flowbridge_g2_witness.sys']);pe=int.from_bytes(data[60:64],'little');size=int.from_bytes(data[pe+20:pe+22],'little');header=pe+24+size
        flags=struct.unpack_from('<I',data,header+36)[0];struct.pack_into('<I',data,header+36,flags|0x80000000|0x20000000)
        with self.assertRaises(a.Rejected):a.Image(bytes(data),1)
    def test_unknown_remote_paths_or_duplicate_json_rejected(self):
        with self.assertRaises(a.Rejected):a.decode(b'{"ok":true,"ok":false}')
        for name in ['../escape.exe','/escape.exe','C:/escape.exe']:
            b=io.BytesIO()
            with zipfile.ZipFile(b,'w') as z:z.writestr(name,b'unexecuted')
            with self.subTest(name=name),self.assertRaises(a.Rejected):a.readzip(b.getvalue())
    def test_original_source_blob_pin_independent_of_manifest(self):
        from unittest.mock import patch
        bad=deepcopy(a.PINS);bad['source_git_blobs']['policy_windows.rs']='0'*40
        with patch.object(a,'PINS',bad),self.assertRaisesRegex(a.Rejected,'source_not_pinned_git_blob'):a.audit(*self.raw)

if __name__=='__main__':unittest.main(verbosity=2)
