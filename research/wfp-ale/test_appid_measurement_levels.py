"""R8 executable harness tests. Mocked Windows paths are NOT native evidence."""
from contextlib import ExitStack, redirect_stdout
import ctypes
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

import appid_native_matrix as m


class MeasurementContract(unittest.TestCase):
    def fixtures(self, directory):
        root = Path(directory)
        source = root / 'where.exe'
        source.write_bytes(b'MZfixture-not-executed')
        return root, source

    def fake_windows(self, root, stack):
        # Replace this module's os reference only, never the host's os.name.
        shim = SimpleNamespace(name='nt', link=os.link, environ={'TEMP': str(root)})
        stack.enter_context(patch.object(m, 'os', shim))
        stack.enter_context(patch.object(m, 'system_directory', return_value=root))
        stack.enter_context(patch.object(m, 'require_local_windows_path'))

    def test_native_only_never_compiles_or_runs_subprocess(self):
        with tempfile.TemporaryDirectory() as d, ExitStack() as stack:
            root, _ = self.fixtures(d)
            self.fake_windows(root, stack)
            compile_ = stack.enter_context(patch.object(m, 'compile_rust', side_effect=AssertionError))
            child = stack.enter_context(patch.object(m.subprocess, 'run', side_effect=AssertionError))
            stack.enter_context(patch.object(m, 'native_app_id', side_effect=lambda p: str(p).encode()))
            result = m.run_native(native_only=True)
            compile_.assert_not_called()
            child.assert_not_called()
            self.assertEqual(result['evidence_level'], 'native_api_only')
            self.assertTrue(result['temporary_files_removed'])
            self.assertFalse(result['rust_pairwise_crosscheck_complete'])
            self.assertFalse(result['rust_probe_built_and_executed'])
            self.assertFalse(result['independent_native_acceptance'])
            self.assertFalse(result['release_accepted'])
            self.assertTrue(all(c['rust_and_ctypes_agree'] is None for c in result['comparisons']))

    def test_unc_temp_root_rejected_before_fixture_creation(self):
        with tempfile.TemporaryDirectory() as d, ExitStack() as stack:
            root, _ = self.fixtures(d)
            stack.enter_context(patch.object(m, 'os', SimpleNamespace(
                name='nt', environ={'TEMP': r'\\remote\share'})))
            stack.enter_context(patch.object(m, 'system_directory', return_value=root))
            mkdir = stack.enter_context(patch.object(m.tempfile, 'TemporaryDirectory', side_effect=AssertionError))
            with self.assertRaisesRegex(RuntimeError, 'nonlocal_or_ambiguous_path'):
                m.run_native(native_only=True)
            mkdir.assert_not_called()

    def test_absent_temp_root_never_silently_uses_another_directory(self):
        with tempfile.TemporaryDirectory() as d, ExitStack() as stack:
            root, _ = self.fixtures(d)
            stack.enter_context(patch.object(m, 'os', SimpleNamespace(name='nt', environ={})))
            stack.enter_context(patch.object(m, 'system_directory', return_value=root))
            with self.assertRaisesRegex(RuntimeError, 'local_temp_directory_unavailable'):
                m.run_native(native_only=True)

    def test_default_does_not_fallback_after_rust_missing(self):
        with tempfile.TemporaryDirectory() as d, ExitStack() as stack:
            root, _ = self.fixtures(d)
            self.fake_windows(root, stack)
            stack.enter_context(patch.object(m, 'compile_rust', side_effect=RuntimeError('rustc_unavailable')))
            read = stack.enter_context(patch.object(m, 'native_app_id', side_effect=AssertionError))
            with self.assertRaisesRegex(RuntimeError, 'rustc_unavailable'):
                m.run_native()
            read.assert_not_called()

    def test_default_does_not_fallback_after_rust_nonzero(self):
        with tempfile.TemporaryDirectory() as d, ExitStack() as stack:
            root, _ = self.fixtures(d)
            self.fake_windows(root, stack)
            stack.enter_context(patch.object(m, 'compile_rust', side_effect=RuntimeError('rustc_failed_exit_1')))
            with self.assertRaisesRegex(RuntimeError, 'rustc_failed_exit_1'):
                m.run_native()

    def test_native_collection_requires_same_file_stability(self):
        paths = {'a': Path('/A/probe.exe'), 'b': Path('/B/probe.exe')}
        progress = {'native_api_reads': 0, 'rust_probe_executions': 0}
        with patch.object(m, 'native_app_id', side_effect=[b'A', b'B']):
            with self.assertRaisesRegex(RuntimeError, 'same_file_appid_inconsistent'):
                m.collect_comparisons(paths, None, progress)
        self.assertEqual(progress['native_api_reads'], 2)

    def test_crosscheck_mismatch_stops_before_next_pair(self):
        paths = {'a': Path('/A/probe.exe'), 'b': Path('/B/probe.exe')}
        progress = {'native_api_reads': 0, 'rust_probe_executions': 0}
        with patch.object(m, 'native_app_id', return_value=b'A') as native:
            with patch.object(m, 'rust_comparison', return_value={
                    'app_ids_equal': False, 'a_bytes': 1, 'b_bytes': 1}):
                with self.assertRaisesRegex(RuntimeError, 'rust_ctypes_independent_ffi_disagree'):
                    m.collect_comparisons(paths, Path('/fake/probe.exe'), progress)
        self.assertEqual(native.call_count, 2)

    def test_partial_failure_not_reported_as_not_run(self):
        def fail(_native_only, progress):
            progress['native_api_reads'] = 1
            raise RuntimeError('WFP_AppId_null')
        stdout = io.StringIO()
        with patch.object(m, 'run_native', side_effect=fail):
            with patch.object(sys, 'argv', ['probe', '--native-only']), redirect_stdout(stdout):
                status = m.main()
        result = json.loads(stdout.getvalue())
        self.assertEqual(status, 2)
        self.assertEqual(result['evidence_level'], 'native_partial_failed')
        self.assertTrue(result['native_windows_wfp_appid_read'])
        self.assertFalse(result['native_measurement_complete'])
        self.assertFalse(result['release_accepted'])

    def test_native_reads_and_kernel_acceptance_are_separate(self):
        with tempfile.TemporaryDirectory() as d, ExitStack() as stack:
            root, _ = self.fixtures(d)
            self.fake_windows(root, stack)
            stack.enter_context(patch.object(m, 'native_app_id', return_value=b'opaque'))
            result = m.run_native(native_only=True)
        for field in ('kernel_process_epoch_proved', 'transparent_packet_owner_proved',
                      'no_direct_proved', 'release_accepted', 'independent_native_acceptance'):
            self.assertIs(result[field], False)

    def test_secret_even_alphanumeric_is_not_error_code(self):
        for text in ('mysecretvalue', 'PASSWORD123', 'C:\\Users\\private.exe'):
            self.assertEqual(m.safe_error_code(ValueError(text)), 'experiment_execution_failed')
        self.assertEqual(m.safe_error_code(RuntimeError('rustc_unavailable')), 'rustc_unavailable')
        self.assertEqual(m.safe_error_code(RuntimeError('WFP_AppId_error_0x00000005')),
                         'WFP_AppId_error_0x00000005')

    def test_local_drive_paths_are_lexically_accepted(self):
        for path in (r'C:\Temp\A\probe.exe', 'C:/Temp/B/probe.exe', r'D:\Пробы\probe.exe'):
            with self.subTest(path=path):
                m.require_local_windows_path(path)

    def test_remote_relative_ads_and_device_namespaces_rejected(self):
        for path in (r'\\server\share\probe.exe', r'\\?\C:\Temp\probe.exe',
                     r'\\.\C:\Temp\probe.exe', r'\Temp\probe.exe', 'probe.exe',
                     r'C:probe.exe', r'C:\Temp\..\probe.exe', r'C:\Temp\probe.exe:stream',
                     'C:\\Temp\\nul\x00.exe', 'C:\\Temp\\bad?.exe'):
            with self.subTest(path=repr(path)):
                with self.assertRaises(RuntimeError):
                    m.require_local_windows_path(path)

    def test_invalid_unicode_and_large_path_are_rejected(self):
        for path in ('C:\\Temp\\\ud800.exe', 'C:\\' + 'a'*32767):
            with self.assertRaises(RuntimeError):
                m.require_local_windows_path(path)

    def test_blob_layout_uses_uint32_on_this_64bit_host(self):
        self.assertEqual(ctypes.sizeof(m.FwpByteBlob._fields_[0][1]), 4)
        if ctypes.sizeof(ctypes.c_void_p) == 8:
            self.assertEqual(m.FwpByteBlob.data.offset, 8)
            self.assertEqual(ctypes.sizeof(m.FwpByteBlob), 16)

    def test_rust_protocol_rejects_boolean_length_and_overflow(self):
        for length in (True, 0, -1, 65537, '16'):
            data = dict(read_only=True, kernel_owner_proved=False,
                        app_ids_equal=True, a_bytes=length, b_bytes=16)
            with patch.object(m.subprocess, 'run', return_value=subprocess.CompletedProcess(
                    [], 0, json.dumps(data), '')):
                with self.assertRaisesRegex(RuntimeError, 'rust_blob_lengths_invalid'):
                    m.rust_comparison(Path('/probe'), Path('/a'), Path('/b'))

    def test_non_windows_native_only_fails_before_toolchain_or_ffi(self):
        if os.name == 'nt':
            self.skipTest('This regression characterizes the non-Windows denial')
        with patch.object(m, 'compile_rust', side_effect=AssertionError) as compile_:
            with patch.object(m, 'native_app_id', side_effect=AssertionError) as native:
                with self.assertRaisesRegex(RuntimeError, 'no_windows_native_executor'):
                    m.run_native(native_only=True)
        compile_.assert_not_called()
        native.assert_not_called()

    def test_cli_modes_are_exclusive(self):
        result = subprocess.run([sys.executable, m.__file__, '--selftest', '--native-only'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')

    def test_offline_real_cli_never_emits_native_acceptance(self):
        result = subprocess.run([sys.executable, m.__file__, '--selftest'],
                                capture_output=True, text=True, timeout=10, check=True)
        report = json.loads(result.stdout)
        self.assertEqual(report['evidence_level'], 'offline_preflight')
        self.assertFalse(report['native_windows_wfp_appid_read'])
        self.assertFalse(report['release_accepted'])
        self.assertEqual(len(report['source_sha256']['appid_native_matrix.py']), 64)

    def test_native_only_real_cli_on_linux(self):
        if os.name == 'nt':
            self.skipTest('Do not turn offline tests into native execution')
        result = subprocess.run([sys.executable, m.__file__, '--native-only'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertEqual(report['blocker'], 'no_windows_native_executor')
        self.assertEqual(report['native_api_reads'], 0)

    def test_failed_native_lookup_cleans_fixture_directory(self):
        observed = []
        def fail(path):
            observed.append(path.parents[1])
            raise RuntimeError('WFP_AppId_null')
        with tempfile.TemporaryDirectory() as d, ExitStack() as stack:
            root, _ = self.fixtures(d)
            self.fake_windows(root, stack)
            stack.enter_context(patch.object(m, 'native_app_id', side_effect=fail))
            with self.assertRaisesRegex(RuntimeError, 'WFP_AppId_null'):
                m.run_native(native_only=True)
        self.assertEqual(len(observed), 1)
        self.assertFalse(observed[0].exists())


class NativeFfiBoundary(unittest.TestCase):
    """Mock Win32 ABI/lifetime, not a Windows execution claim."""
    def exercise(self, status=0, size=4):
        storage = (ctypes.c_ubyte*4)(1,2,3,4)
        blob = m.FwpByteBlob(size, ctypes.cast(storage, ctypes.POINTER(ctypes.c_ubyte)))
        ptr = ctypes.pointer(blob)
        def get_id(_name, out):
            ctypes.cast(out, ctypes.POINTER(ctypes.POINTER(m.FwpByteBlob)))[0] = ptr
            return status
        free = Mock()
        dll = SimpleNamespace(FwpmGetAppIdFromFileName0=Mock(side_effect=get_id), FwpmFreeMemory0=free)
        with tempfile.TemporaryDirectory() as d, ExitStack() as stack:
            file = Path(d) / 'probe.exe'
            file.write_bytes(b'MZ')
            stack.enter_context(patch.object(m, 'os', SimpleNamespace(name='nt')))
            stack.enter_context(patch.object(m, 'require_local_windows_path'))
            load = stack.enter_context(patch.object(ctypes, 'WinDLL', create=True, return_value=dll))
            try:
                return m.native_app_id(file)
            finally:
                free.assert_called_once()
                load.assert_called_once_with('Fwpuclnt.dll', winmode=0x00000800)

    def test_success_copies_bytes_and_frees_allocation(self):
        self.assertEqual(self.exercise(), b'\x01\x02\x03\x04')

    def test_error_with_allocation_still_frees(self):
        with self.assertRaisesRegex(RuntimeError, 'WFP_AppId_error_0x00000005'):
            self.exercise(status=5)

    def test_invalid_blob_still_frees(self):
        with self.assertRaisesRegex(RuntimeError, 'WFP_AppId_invalid_blob'):
            self.exercise(size=0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
