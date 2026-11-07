"""Negative synthetic contract fixtures only; NOT a native acceptance test."""
from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[0]
AUDIT = ROOT.parent / 'tools' / 'capture_evidence_audit.py'
spec = importlib.util.spec_from_file_location('capture_evidence_audit', AUDIT)
audit = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(audit)
HEAD, MERGE = 'a' * 40, 'b' * 40


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pe():
    b = bytearray(256)
    b[:2] = b'MZ'
    struct.pack_into('<I', b, 0x3c, 0x80)
    b[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<H', b, 0x84, 0x8664)
    struct.pack_into('<H', b, 0x98, 0x20b)
    return bytes(b)


class SyntheticEvidence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.files = {name: pe() for name in audit.BINARIES}
        self.files['README.md'] = b'QA only'
        self.manifest = dict(schema=1,kind='integration_candidate_NOT_RELEASE',
                             pr_head_sha=HEAD, source_commit=MERGE,
                             payload_sha256={k: digest(v) for k,v in self.files.items()})
        for k in audit.FALSE_CANDIDATE:
            self.manifest[k] = False
        self.wfp = dict(kind='native_wfp_soft_lease_over_persistent_appwide_deny',
                        passed=True, checks={k:True for k in audit.REQUIRED_SOFT})
        for k in audit.FALSE_WFP:self.wfp[k]=False
        self.binary = b'MZ-safe-unsigned-fake-synthetic-only'
        self.installer = dict(kind='unsigned_user_owned_rust_ssh_socks_candidate_installer_NOT_RELEASE',
                              passed=True,qa_fault_fixture=False,qa_abort_stage=None,
                              pr_head_sha=HEAD,source_merge_sha=MERGE,
                              includes_gui=True,gui_scope='same_user_explicit_ssh_socks_only',
                              payload_sha256=self.manifest['payload_sha256'],
                              installer_sha256=digest(self.binary))
        for k in audit.FALSE_INSTALLER:self.installer[k]=False
        self.installed=dict(kind='installed_original_rust_ssh_socks_candidate_windows_server_hosted_only',
                            passed=True, pr_head_sha=HEAD, source_merge_sha=MERGE,
                            installer_sha256=digest(self.binary))
        for k in audit.FALSE_INSTALLED:self.installed[k]=False
        for k in audit.TRUE_INSTALLED:self.installed[k]=True
        self.refresh()

    def refresh(self, extra=()):
        self.candidate = self.path/'candidate.zip'
        m = json.dumps(self.manifest).encode()
        with zipfile.ZipFile(self.candidate,'w') as z:
            for name,data in self.files.items():z.writestr(name,data)
            z.writestr('manifest.json',m)
            for name,data in extra:z.writestr(name,data)
        self.installer['candidate_archive_sha256']=digest(self.candidate.read_bytes())
        self.installer['candidate_source_manifest_sha256']=digest(m)
        for name,data in [('wfp.json',self.wfp),('installer.json',self.installer),
                          ('installed.json',self.installed)]:
            (self.path/name).write_text(json.dumps(data),encoding='utf-8')
        (self.path/'installer.exe').write_bytes(self.binary)

    def run_audit(self):
        return audit.audit(self.candidate,self.path/'wfp.json',
                           self.path/'installer.json',self.path/'installed.json',
                           self.path/'installer.exe',HEAD,MERGE)

    def test_valid_synthetic_contract_is_labeled_as_only_synthetic(self):
        d=self.run_audit()
        self.assertTrue(d['passed'])
        self.assertFalse(d['actual_driver_divert_tested'])
        self.assertFalse(d['release_accepted'])

    def test_extra_path_traversal_is_forbidden(self):
        self.refresh([('../driver.sys',b'evil')])
        with self.assertRaisesRegex(ValueError,'ZIP entry'):self.run_audit()

    def test_duplicate_zip_member_is_forbidden(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter('ignore',UserWarning)
            self.refresh([('flowbridge-agent.exe',pe())])
        with self.assertRaisesRegex(ValueError,'ZIP entry'):self.run_audit()

    def test_payload_mismatch_is_forbidden(self):
        self.files['flowbridge-agent.exe']=pe()+b'altered'
        self.refresh()
        with self.assertRaisesRegex(ValueError,'payload SHA'):self.run_audit()

    def test_bad_exe_architecture_is_forbidden(self):
        x=bytearray(pe())
        struct.pack_into('<H',x,0x84,0x14c)
        self.files['flowbridge-agent.exe']=bytes(x)
        self.manifest['payload_sha256']['flowbridge-agent.exe']=digest(x)
        self.refresh()
        with self.assertRaisesRegex(ValueError,'PE32'):self.run_audit()

    def test_missing_established_tcp_revocation_is_forbidden(self):
        self.wfp['checks'].pop('held_tcp_revoked_on_lease_crash')
        self.refresh()
        with self.assertRaisesRegex(ValueError,'missing held TCP'):self.run_audit()

    def test_false_positive_wfp_gate_is_forbidden(self):
        self.wfp['checks']['independent_sublayer_vetoes_soft_permit']=False
        self.refresh()
        with self.assertRaisesRegex(ValueError,'some WFP proof'):self.run_audit()

    def test_release_claim_is_forbidden(self):
        self.installed['release_accepted']=True
        self.refresh()
        with self.assertRaisesRegex(ValueError,'unsafe acceptance'):self.run_audit()

    def test_wrong_merge_sha_is_forbidden(self):
        with self.assertRaisesRegex(ValueError,'SHA mismatch'):
            audit.audit(self.candidate,self.path/'wfp.json',self.path/'installer.json',
                        self.path/'installed.json',self.path/'installer.exe',HEAD,'c'*40)

    def test_modified_installer_is_forbidden(self):
        (self.path/'installer.exe').write_bytes(self.binary+b'tamper')
        with self.assertRaisesRegex(ValueError,'installer binary SHA'):self.run_audit()

    def test_gui_installed_ssh_rollback_must_be_real(self):
        self.installed['successful_real_install_after_two_fault_rollbacks']=False
        self.refresh()
        with self.assertRaisesRegex(ValueError,'unsafe acceptance'):self.run_audit()


if __name__ == '__main__':
    unittest.main()
