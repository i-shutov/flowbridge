"""Independent offline contract checks for R14: DOES NOT execute Windows APIs."""
from __future__ import annotations

import ctypes
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch, call
import appid_namespace_r14 as m

class R14Contract(unittest.TestCase):
    def test_winfiletime_and_structure_layout(self):
        self.assertEqual(ctypes.sizeof(m.WinFileTime), 8)
        self.assertEqual(ctypes.sizeof(m.WinFileInfo), 52)
        self.assertEqual(m.WinFileInfo.volume_serial.offset, 28)
        self.assertEqual(m.WinFileInfo.file_index_low.offset, 48)

    def test_nonwindows_denied(self):
        if os.name != 'nt':
            with self.assertRaisesRegex(m.UnsupportedReadOnlyEnvironment, 'windows_x64_required'):
                m.run_native()
            with self.assertRaisesRegex(m.UnsupportedReadOnlyEnvironment, 'windows_x64_required'):
                m.file_identity(Path('/tmp/no.exe'))

    def test_path_components_do_not_reveal_names(self):
        self.assertEqual(m.path_components(r'\Device\HarddiskVolume7\foo.exe'), ['device','harddiskvolume7','foo.exe'])
        self.assertEqual(m.path_components(None), [])

    def test_lexical_mapping_and_no_device_spoof(self):
        with patch.object(m.base, 'require_local_windows_path'):
            self.assertEqual(m.lexical_device_path(Path(r'C:\TEMP\RUNNER~1\probe.exe'),r'\Device\HarddiskVolume4'),r'\device\harddiskvolume4\temp\runner~1\probe.exe')
            with self.assertRaisesRegex(m.UnsupportedReadOnlyEnvironment,'not_native_volume_name'):
                m.lexical_device_path(Path(r'C:\A\probe.exe'),r'C:\Volume')

    def test_name_form_shape_changes_only_spelling(self):
        a=r'\device\harddiskvolume7\users\runner~1\temp\probe.exe'
        b=r'\device\harddiskvolume7\users\runneradmin\temp\probe.exe'
        r=m.private_shape_diagnostic(a,b)
        self.assertEqual(r,{'both_decoded':True,'exact_equal':False,
                            'same_prefix_volume_shape':True,'component_mismatch_count':1,
                            'short_name_divergence':True})
        self.assertNotIn('runner',json.dumps(r))

    def test_no_short_name_hint_when_mismatch_unrelated(self):
        r=m.private_shape_diagnostic(r'\device\harddiskvolume2\apps\one.exe',r'\device\harddiskvolume2\apps\two.exe')
        self.assertEqual(r['component_mismatch_count'],1)
        self.assertFalse(r['short_name_divergence'])

    def test_missing_decoded_blob_fail_closed(self):
        r=m.private_shape_diagnostic(None,r'\device\harddiskvolume2\probe.exe')
        self.assertFalse(r['both_decoded'])
        self.assertFalse(r['exact_equal'])
        self.assertIsNone(r['component_mismatch_count'])

    def test_component_extra_or_missing(self):
        a=r'\device\harddiskvolume7\a\b\x.exe'
        b=r'\device\harddiskvolume7\a\x.exe'
        self.assertEqual(m.private_shape_diagnostic(a,b)['component_mismatch_count'],2)

    def test_measure_known_8dot3_and_longpath_resolution(self):
        path=Path(r'C:\Users\RUNNER~1\Tmp\probe.exe')
        longpath=Path(r'C:\Users\RunnerAdmin\Tmp\probe.exe')
        handle_nt=r'\Device\HarddiskVolume2\Users\RunnerAdmin\Tmp\probe.exe'
        observed=r'\Device\HarddiskVolume2\Users\RUNNER~1\Tmp\probe.exe'.encode('utf-16-le')
        canonical=handle_nt.encode('utf-16-le')
        with patch.object(m,'ensure_windows'), patch.object(m.base,'require_local_windows_path'):
            with patch.object(m.base,'native_app_id',side_effect=[observed,canonical,canonical]) as native:
                with patch.object(m.r10,'resolved_handle_paths',return_value=(longpath,handle_nt)):
                    with patch.object(m,'get_long_path',return_value=longpath):
                        with patch.object(m,'query_dos_device',return_value=r'\Device\HarddiskVolume2'):
                            v=m.measure_one(path)
        self.assertTrue(v['long_dos_path_changed'])
        self.assertTrue(v['contains_8dot3_short_component'])
        self.assertTrue(v['supplied_matches_lexical_device_path'])
        self.assertFalse(v['supplied_matches_handle_appid'])
        self.assertTrue(v['expanded_matches_handle_appid'])
        self.assertTrue(v['handle_matches_handle_nt_device_path'])
        self.assertTrue(v['input_vs_handle_structure']['short_name_divergence'])
        self.assertEqual(native.call_count,3)
        self.assertNotIn('RunnerAdmin',json.dumps(v))

    def test_no_short_expansion_does_not_forge_finding(self):
        path=Path(r'C:\Temp\probe.exe')
        native=r'\Device\HarddiskVolume2\Temp\probe.exe'
        blob=native.encode('utf-16-le')
        with patch.object(m,'ensure_windows'),patch.object(m.base,'require_local_windows_path'):
            with patch.object(m.base,'native_app_id',return_value=blob):
                with patch.object(m.r10,'resolved_handle_paths',return_value=(path,native)):
                    with patch.object(m,'get_long_path',return_value=path):
                        with patch.object(m,'query_dos_device',return_value=r'\Device\HarddiskVolume2'):
                            result=m.measure_one(path)
        self.assertFalse(result['long_dos_path_changed'])
        self.assertFalse(result['contains_8dot3_short_component'])
        self.assertTrue(result['supplied_matches_handle_appid'])
        self.assertTrue(result['supplied_matches_lexical_device_path'])

    def test_kernel_calls_have_no_bfe_mutation(self):
        source=Path(m.__file__).read_text(encoding='utf-8')
        for token in ('Fwpm'+'FilterAdd', 'Fwpm'+'EngineOpen', 'Fwps'+'CalloutRegister',
                      'Create'+'Service', 'Set'+'WindowsHookEx', 'start'+'capture',
                      'subprocess'+'.run(', 'socket'+'.connect('):
            self.assertNotIn(token,source)
        self.assertIn('GetFileInformationByHandle',source)
        self.assertIn('QueryDosDeviceW',source)
        self.assertIn('GetLongPathNameW',source)

    def test_default_real_cli_has_no_consent(self):
        if os.name != 'nt':
            p=subprocess.run([sys.executable,str(Path(m.__file__)),'--consent',m.CONSENT],capture_output=True,text=True,timeout=10)
            self.assertEqual(p.returncode,2)
            info=json.loads(p.stdout)
            self.assertEqual(info['error'],'windows_x64_required')
            self.assertFalse(info['release_accepted'])

    def test_wrong_consent_does_not_execute_api(self):
        p=subprocess.run([sys.executable,str(Path(m.__file__)),'--consent','NO'],capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,2)
        self.assertEqual(json.loads(p.stdout)['error'],'read_only_consent_missing')

    def test_duplicate_file_hardlink_identity_required(self):
        a,b=Path(r'C:\A\probe.exe'),Path(r'C:\B\hardlink.exe')
        with patch.object(m.base,'pairs',return_value=[('same_file',a,a),('same_name_different_directory',a,b),('hardlink',a,b)]):
            with patch.object(m,'file_identity',side_effect=lambda p: (1,2,3) if p==a else (4,5,6)):
                with patch.object(m.base,'native_app_id',return_value=b'abc'):
                    with patch.object(m,'measure_one',return_value={'release_accepted':False}):
                        with self.assertRaisesRegex(m.UnsupportedReadOnlyEnvironment,'hardlink_fileid_control_failed'):
                            m.inspect_fixtures({'a':a,'b':b,'hardlink':b},{})

    def test_same_file_control_refuses_inconsistent_appid(self):
        a=Path('C:/A.exe')
        with patch.object(m.base,'pairs',return_value=[('same_file',a,a)]):
            with patch.object(m,'file_identity',return_value=(1,1,1)):
                with patch.object(m.base,'native_app_id',side_effect=[b'A',b'B']):
                    with patch.object(m,'measure_one',return_value={}):
                        with self.assertRaisesRegex(m.UnsupportedReadOnlyEnvironment,'same_file_control_failed'):
                            m.inspect_fixtures({'a':a},{})

    def test_success_report_has_nonpromoted_flags(self):
        # Source-level fixed negative assertions are checked separately from any API result.
        text=Path(m.__file__).read_text(encoding='utf-8')
        for field in ('kernel_owner_proved', 'ndisrd_packetbound_proved',
                      'system_no_direct_proved', 'release_accepted'):
            self.assertIn(f"'{field}': False",text)

    def test_8dot3_flags_are_bounded_not_fingerprint(self):
        a='\\Device\\HarddiskVolume777\\'+('secret\\'*200)+'abc~1\\probe.exe'
        b=a.replace('abc~1','VeryLongSecret')
        result=m.private_shape_diagnostic(a,b)
        self.assertEqual(result['component_mismatch_count'],1)
        self.assertTrue(result['short_name_divergence'])
        self.assertNotIn('secret',json.dumps(result))

if __name__=='__main__':
    unittest.main(verbosity=2)
