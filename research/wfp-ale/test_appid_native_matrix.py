#!/usr/bin/env python3
"""Independent offline safety and contract regression for R6 native AppId probe.

No Windows API execution on non-Windows systems. Fakes only boundary results.
"""
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import appid_native_matrix as probe


class R6Contract(unittest.TestCase):
    def test_selftest_is_not_native_proof(self):
        result = probe.selftest()
        self.assertTrue(result['ok'])
        self.assertFalse(result['native_windows_wfp_appid_read'])
        self.assertFalse(result['rust_probe_built_and_executed'])
        self.assertFalse(result['kernel_process_epoch_proved'])
        self.assertFalse(result['driver_or_filter_changed'])

    def test_copy_equal_contents_and_distinct_locations(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)
            original=p/'unexecuted.exe'
            original.write_bytes(b'MZ' + bytes(range(16)))
            paths, _ = probe.prepare_fixtures(p/'sandbox', original)
            self.assertEqual(paths['a'].name, paths['b'].name)
            self.assertNotEqual(paths['a'].resolve(), paths['b'].resolve())
            self.assertEqual(paths['a'].read_bytes(), paths['b'].read_bytes())

    def test_pairs_same_file_and_distinct_basename(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)
            source=p/'source.exe'
            source.write_bytes(b'MZ' + bytes(range(8)))
            paths,_=probe.prepare_fixtures(p/'sandbox',source)
            tests=probe.pairs(paths)
            self.assertEqual(tests[0][0],'same_file')
            self.assertEqual(tests[0][1],tests[0][2])
            self.assertEqual(tests[1][0],'same_name_different_directory')
            self.assertNotEqual(tests[1][1],tests[1][2])

    def test_bad_source_fails(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)
            with self.assertRaises(ValueError):
                probe.prepare_fixtures(p/'out',p/'missing.exe')

    def test_non_windows_fails_closed(self):
        if probe.os.name!='nt':
            with self.assertRaisesRegex(RuntimeError,'Windows required'):
                probe.native_app_id(Path('/tmp/not-an-exe'))
            with self.assertRaisesRegex(RuntimeError,'no_windows_native_executor'):
                probe.run_native()

    def test_rust_contract_is_strict(self):
        obj={'read_only':True,'kernel_owner_proved':False,
             'app_ids_equal':True,'a_bytes':20,'b_bytes':20}
        with patch.object(probe.subprocess,'run',return_value=subprocess.CompletedProcess(
                args=[],returncode=0,stdout=json.dumps(obj),stderr='')):
            out=probe.rust_comparison(Path('/x/probe.exe'),Path('/a.exe'),Path('/b.exe'))
            self.assertTrue(out['app_ids_equal'])
        obj['kernel_owner_proved']=True
        with patch.object(probe.subprocess,'run',return_value=subprocess.CompletedProcess(
                args=[],returncode=0,stdout=json.dumps(obj),stderr='')):
            with self.assertRaisesRegex(RuntimeError,'contract_violation'):
                probe.rust_comparison(Path('/x/probe.exe'),Path('/a.exe'),Path('/b.exe'))

    def test_rust_nonzero_is_failure_not_pass(self):
        with patch.object(probe.subprocess,'run',return_value=subprocess.CompletedProcess(
                args=[],returncode=13,stdout='{}',stderr='sensitive')):
            with self.assertRaisesRegex(RuntimeError,'rust_appid_failed_exit_13'):
                probe.rust_comparison(Path('/x/probe.exe'),Path('/a.exe'),Path('/b.exe'))

    def test_netsh_output_is_sanitized(self):
        with patch.object(probe.shutil,'which',return_value='/fake/netsh'):
            with patch.object(probe.subprocess,'run',return_value=subprocess.CompletedProcess(
                    args=[],returncode=0,stdout=r'\Device\secret\path',stderr='')):
                out=probe.netsh_readonly(Path('/secret/path.exe'))
                self.assertTrue(out['successful'])
                self.assertTrue(out['mentions_device_path'])
                self.assertNotIn('secret',str(out))

    def test_surface_has_no_mutating_wfp_calls(self):
        src=Path(probe.__file__).read_text(encoding='utf-8')
        # Build the forbidden substrings to avoid self-referential false hits.
        for part in ('Fwpm'+'FilterAdd','Fwpm'+'EngineOpen',
                     'Fwps'+'CalloutRegister','Create'+'Service',
                     'netsh wfp '+ 'set', 'netsh wfp '+'capture'):
            self.assertNotIn(part,src)
        self.assertIn('FwpmGetAppIdFromFileName0',src)
        self.assertIn('FwpmFreeMemory0',src)

if __name__=='__main__':
    unittest.main(verbosity=2)
