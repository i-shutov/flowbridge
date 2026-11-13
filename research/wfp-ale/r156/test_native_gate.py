#!/usr/bin/env python3
"""Tests of the launcher only. Mocks are NOT Rust/Windows execution evidence."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import run_r156_native as n
ROOT=Path(__file__).resolve().parent.parent

class NativeGateTests(unittest.TestCase):
    def test_four_pins_match(self):
        self.assertEqual(len(n.sources(ROOT)),4)
    def test_missing_compiler_is_not_pass(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(n.shutil,'which',return_value=None),patch.object(n.subprocess,'run') as command:
            r=n.run(ROOT,Path(tmp)/'out');command.assert_not_called()
            self.assertEqual(r['status'],'NOT_RUN_COMPILER_UNAVAILABLE');self.assertEqual(r['commands'],[])
    def test_preflight_never_invokes_compiler(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(n.subprocess,'run') as command:
            r=n.run(ROOT,Path(tmp)/'out',preflight=True);command.assert_not_called()
            self.assertEqual(r['status'],'PREFLIGHT_ONLY_NOT_COMPILED')
    def test_bad_source_stops_before_child(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(n.subprocess,'run') as command:
            r=n.run(Path(tmp),Path(tmp)/'out');command.assert_not_called();self.assertEqual(r['status'],'FAILED')
    def test_existing_output_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);(p/'sentinel').write_bytes(b'original')
            with self.assertRaises(FileExistsError):n.run(ROOT,p)
            self.assertEqual((p/'sentinel').read_bytes(),b'original')
    def test_crlf_recovery_only_for_exact_pin(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);raw=b'line\n';(p/'x').write_bytes(b'line\r\n')
            with patch.object(n,'PINS',{'x':n.git_blob(raw)}):
                captured=n.sources(p);self.assertEqual(captured[0][1],raw);self.assertTrue(captured[0][2]['crlf_normalized'])
                (p/'x').write_bytes(b'line\r\n ')
                with self.assertRaises(n.NativeGateError):n.sources(p)
    def test_no_driver_inputs_in_compilation_allowlist(self):
        self.assertEqual(set(n.PINS),{'kernel-r19/kernel/src/ledger.rs','kernel-r19/kernel/src/handoff.rs','kernel-r19/kernel/src/action_rights.rs','r156/r156_pure_regressions.rs'})
        self.assertIn(b'#![forbid(unsafe_code)]',(ROOT/'r156/r156_pure_regressions.rs').read_bytes())
        self.assertEqual(n.EXPECTED_TESTS,52)
    def test_compiler_failure_is_recorded(self):
        fail=subprocess.CompletedProcess(['mock-rustc'],1,b'',b'mock compile error')
        with tempfile.TemporaryDirectory() as tmp,patch.object(n.shutil,'which',return_value='mock-rustc'),patch.object(n.subprocess,'run',return_value=fail):
            r=n.run(ROOT,Path(tmp)/'out');self.assertEqual(r['status'],'FAILED')
            self.assertEqual(r['commands'][0]['exit'],1)
            self.assertEqual((Path(tmp)/'out/rustc_version.stderr').read_bytes(),b'mock compile error')
if __name__=='__main__':unittest.main(verbosity=2)
