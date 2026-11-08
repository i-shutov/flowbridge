"""R38 signing-source negative tests; no signing, driver load or service action."""
import json
import os
from pathlib import Path
import struct
import unittest

import compare_pe_sections_r38 as pe

ROOT=Path(__file__).resolve().parent
BUILD=Path(os.environ.get('GITHUB_WORKSPACE', '/not-in-runner'))/'build'/'g2-kernel-r19'

class SigningScope(unittest.TestCase):
    def test_inf_is_primitive_demand_start_only(self):
        s=(ROOT/'flowbridge_g2_r38.inf').read_text(encoding='utf-8')
        for token in ('[DefaultInstall.NTamd64]', '[DefaultInstall.NTamd64.Services]',
                      'StartType=3', 'ServiceType=1', 'PnpLockdown=1',
                      'ServiceBinary=%13%\\flowbridge_g2_witness.sys',
                      'CatalogFile=FlowBridgeG2R38.cat'):
            self.assertIn(token, s)
        for forbidden in ('[DefaultInstall]\n','[DefaultUninstall', 'StartType=0', 'StartType=1',
                          'StartType=2','AddReg=','CoInstallers'):
            self.assertNotIn(forbidden, s)

    def test_stager_never_signs_or_installs(self):
        s=(ROOT/'prepare_submission_r38.ps1').read_text(encoding='utf-8')
        for token in ('makecab.exe', 'expand.exe', 'Get-FileHash',
                      'SignatureStatus]::NotSigned', 'partner_center_submission_complete = $false'):
            self.assertIn(token,s)
        for forbidden in ('signtool.exe sign', 'Start-Service ', 'New-Service ',
                          'New-NetFirewallRule', 'bcdedit.exe', 'Set-MpPreference'):
            self.assertNotIn(forbidden,s)

    def test_preflight_can_never_admit_a_host(self):
        s=(ROOT/'preflight_r38.ps1').read_text(encoding='utf-8')
        self.assertIn('verify /kp /v /c',s)
        self.assertIn('host_admitted_for_R39 = $false',s)
        self.assertIn('vnc_independently_verified = $false',s)
        self.assertIn('system_rescue_independently_verified = $false',s)
        self.assertIn('exit 2',s)
        for forbidden in ('bcdedit.exe', 'Set-MpPreference', 'Start-Service ', 'sc.exe create'):
            self.assertNotIn(forbidden,s)

    def test_signed_and_unsigned_identical_pe_source_sections(self):
        driver=BUILD/'flowbridge_g2_witness.sys'
        if not driver.is_file():self.skipTest('built driver not present in offline test')
        a=driver.read_bytes()
        result=pe.compare(a,a)
        self.assertTrue(result['all_loadable_section_bytes_equal'])
        self.assertFalse(result['signature_verified'])
        self.assertFalse(result['g2_pass'])

    def test_single_byte_change_in_loadable_section_rejected(self):
        driver=BUILD/'flowbridge_g2_witness.sys'
        if not driver.is_file():self.skipTest('built driver not present in offline test')
        a=driver.read_bytes()
        peoff=struct.unpack_from('<I',a,60)[0]
        optoff=peoff+24
        header=optoff+struct.unpack_from('<H',a,peoff+20)[0]
        first_raw=struct.unpack_from('<I',a,header+20)[0]
        tampered=bytearray(a);tampered[first_raw+16]^=1
        with self.assertRaisesRegex(pe.Rejected,'signed_driver_section_mismatch'):
            pe.compare(a,bytes(tampered))

    def test_not_pe_fails_closed(self):
        with self.assertRaises(pe.Rejected):
            pe.sections(b'not a PE')
        with self.assertRaises(pe.Rejected):
            pe.compare(b'not a PE', b'also not a PE')

    def test_cab_manifest_never_promotes_signature(self):
        report=BUILD/'signing-r38'/'R38_UNSIGNED_SUBMISSION.json'
        if not report.is_file():self.skipTest('unsigned CAB not staged')
        v=json.loads(report.read_text(encoding='utf-8-sig'))
        self.assertTrue(v['ok'])
        for field in ('partner_center_submission_complete','microsoft_kernel_signature_verified',
                      'exact_target_host_preflight_passed','kernel_driver_loaded',
                      'bfe_filters_installed','g2_pass','release_accepted'):
            self.assertIs(v[field],False)
        self.assertEqual(v['source_sha'],os.environ['GITHUB_SHA'])

if __name__ == '__main__':
    unittest.main(verbosity=2)
