"""Offline negative checks for native read-only handle/AppId diagnostic.

These tests DO NOT call any Windows API. Reproduces only control logic.
"""
import unittest
from pathlib import Path
from unittest.mock import patch
import handle_appid_probe as h

class HandleProbeContract(unittest.TestCase):
    def test_unicode_device_path_diagnostic(self):
        p='\\Device\\HarddiskVolume2\\Temp\\probe.exe'
        self.assertEqual(h.normalized_device_path((p+'\0').encode('utf-16-le')),p.casefold())
        self.assertEqual(h.normalized_device_path(p.upper().encode('utf-16-le')),p.casefold())

    def test_invalid_utf16_not_accepted(self):
        for blob in (b'',b'x',b'\x00\xd8',b'\x00\x00',b'A\x00\x00\x00B\x00',b'0'*65538):
            with self.subTest(blob=blob[:15]):
                self.assertIsNone(h.normalized_device_path(blob))

    def test_no_windows_rejects_source(self):
        if h.os.name!='nt':
            with self.assertRaisesRegex(h.ProbeError,'no_windows_native_executor'):
                h.resolved_handle_paths(Path('/tmp/no-windows'))
            with self.assertRaisesRegex(h.ProbeError,'no_windows_native_executor'):
                h.run()

    def test_same_file_copy_invariant(self):
        paths={'a':Path('/a/probe.exe'),'b':Path('/b/probe.exe')}
        with patch.object(h.baseline,'native_app_id',side_effect=[b'A',b'A',b'A',b'B']):
            with patch.object(h,'compare_path',return_value={'supplied_vs_resolved_appid_equal':True}):
                # 2 calls for the same file, 2 for b: first pair equal, next pair opposite
                results=h.combine(paths)
        self.assertEqual(len(results),2)
        self.assertTrue(results[0]['supplied_pair_appid_equal'])
        self.assertFalse(results[1]['supplied_pair_appid_equal'])

    def test_mismatched_same_file_rejected(self):
        paths={'a':Path('/a/probe.exe'),'b':Path('/b/probe.exe')}
        with patch.object(h.baseline,'native_app_id',side_effect=[b'A',b'B']):
            with patch.object(h,'compare_path') as cp:
                with self.assertRaisesRegex(h.ProbeError,'same_file_inconsistent'):
                    h.combine(paths)
        cp.assert_called()

    def test_compare_paths_are_read_only_and_redacted(self):
        with patch.object(h.baseline,'native_app_id',side_effect=[r'\Device\HarddiskVolume2\A.exe'.encode('utf-16-le')]*2):
            with patch.object(h,'resolved_handle_paths',return_value=(Path('C:/A.exe'),r'\Device\HarddiskVolume2\A.exe')):
                obj=h.compare_path(Path('C:/A.exe'))
        self.assertTrue(obj['supplied_vs_resolved_appid_equal'])
        self.assertTrue(obj['resolved_appid_is_handle_device_path'])
        self.assertTrue(obj['supplied_appid_is_handle_device_path'])
        self.assertFalse(any('path' in str(v).lower() for v in obj.values()))

    def test_no_consent_is_failure_before_windows(self):
        # Main requires exact consent; this test is independent of any native calls.
        from unittest.mock import patch
        with patch('sys.argv',['probe','--consent','WRONG']):
            self.assertEqual(h.main(),2)

if __name__=='__main__':
    unittest.main(verbosity=2)
