#!/usr/bin/env python3
"""Offline CLI, resource-limit, provenance and mutation-detection regressions."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
VERIFY = HERE / 'r147_blueprint_verify.py'
R144 = HERE.parent / 'r144' / 'r144_compiled_blueprint_negative.py'


def load(name, source):
    spec = importlib.util.spec_from_file_location(name, source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


v = load('verifier', VERIFY)
g = load('gate', HERE / 'r147_regression_gate.py')


class VerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.good = v.compiler.canonical_bytes(v.compiler.compile_from_bytes())
        cls.compact = json.dumps(json.loads(cls.good), separators=(',', ':')).encode()

    def run_cli(self, raw, optimized=False, jsonl=False):
        args = [sys.executable] + (['-O'] if optimized else []) + ['-B', str(VERIFY)]
        if jsonl:
            args.append('--jsonl')
        return subprocess.run(args + ['-'], input=raw, capture_output=True, timeout=20)

    def test_good_artifact_has_no_runtime_authority(self):
        got = v.verdict(self.good, 4)
        self.assertTrue(got['design_valid'])
        self.assertEqual(got['record'], 4)
        for key in ('native_wfp_executed', 'release_accepted', 'no_direct_proved'):
            self.assertIs(got[key], False)

    def test_compiler_stdout_bytes_survive_crlf_text_stream(self):
        capture = io.BytesIO()
        output = io.TextIOWrapper(capture, encoding='utf-8', newline='\r\n')
        with patch.object(sys, 'stdout', output), patch.object(sys, 'argv', ['r143']):
            v.compiler.main()
        output.flush()
        self.assertEqual(capture.getvalue(), self.good)
        output.detach()

    def test_matrix_stdout_bytes_survive_crlf_text_stream(self):
        capture = io.BytesIO()
        output = io.TextIOWrapper(capture, encoding='utf-8', newline='\r\n')
        with patch.object(sys, 'stdout', output), patch.object(sys, 'argv', ['r143', '--model-matrix']):
            v.compiler.main()
        output.flush()
        self.assertEqual(capture.getvalue(), v.compiler.model_matrix().encode('ascii'))
        output.detach()

    def test_cli_valid_normal(self):
        proc = self.run_cli(self.good)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout.splitlines()[-1])['accepted_designs'], 1)

    def test_cli_valid_optimized(self):
        proc = self.run_cli(self.good, optimized=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_cli_bad_both_modes(self):
        for opt in (False, True):
            proc = self.run_cli(b'{"release_accepted":true}', opt)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(proc.stderr, b'')

    def test_invalid_root_types(self):
        for raw in (b'null', b'[]', b'false', b'0', b'"str"'):
            with self.subTest(raw=raw):
                self.assertFalse(v.verdict(raw, 0)['design_valid'])

    def test_duplicate_root_key(self):
        self.assertFalse(v.verdict(self.compact.replace(b'"schema":1', b'"schema":1,"schema":1'), 0)['design_valid'])

    def test_duplicate_nested_key(self):
        self.assertFalse(v.verdict(self.compact.replace(b'"persistent_flag_combined":false', b'"persistent_flag_combined":false,"persistent_flag_combined":false'), 0)['design_valid'])

    def test_invalid_numbers(self):
        for replacement in (b'NaN', b'Infinity', b'-Infinity', b'1e9999', b'1.0', b'true'):
            self.assertFalse(v.verdict(self.compact.replace(b'"schema":1', b'"schema":' + replacement), 0)['design_valid'])

    def test_invalid_utf8(self):
        self.assertFalse(v.verdict(b'\xff', 0)['design_valid'])

    def test_bom_rejected(self):
        self.assertFalse(v.verdict(b'\xef\xbb\xbf' + self.good, 0)['design_valid'])

    def test_trailing_document(self):
        self.assertFalse(v.verdict(self.good + b'{}', 0)['design_valid'])

    def test_deep_json_is_rejection_not_crash(self):
        self.assertFalse(v.verdict(b'[' * 2000 + b'0' + b']' * 2000, 0)['design_valid'])

    def test_oversize_single_bounded_read(self):
        stream = io.BytesIO(b' ' * (v.MAX_DOCUMENT + 10000))
        rows = list(v.verify_stream(stream))
        self.assertFalse(rows[0]['design_valid'])
        self.assertEqual(stream.tell(), v.MAX_DOCUMENT + 1)

    def test_empty_jsonl_rejected(self):
        self.assertEqual(list(v.verify_stream(io.BytesIO(b''), True))[0]['code'], 'REJECT:EMPTY_STREAM')

    def test_blank_jsonl_record_not_skipped(self):
        rows = list(v.verify_stream(io.BytesIO(self.compact + b'\n\n'), True))
        self.assertEqual([x['design_valid'] for x in rows], [True, False])

    def test_mixed_jsonl_exit_nonzero(self):
        proc = self.run_cli(self.compact + b'\nnull\n', jsonl=True)
        self.assertEqual(proc.returncode, 2)
        summary = json.loads(proc.stdout.splitlines()[-1])
        self.assertEqual((summary['records'], summary['accepted_designs'], summary['rejected']), (2, 1, 1))

    def test_last_jsonl_record_without_newline(self):
        self.assertTrue(list(v.verify_stream(io.BytesIO(self.compact), True))[0]['design_valid'])

    def test_jsonl_oversize_rejects_without_continuing(self):
        raw = b' ' * (v.MAX_DOCUMENT + 2) + b'\n' + self.compact
        rows = list(v.verify_stream(io.BytesIO(raw), True))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['code'], 'REJECT:DOCUMENT_LIMIT')

    def test_jsonl_record_cap(self):
        with patch.object(v, 'MAX_RECORDS', 2):
            rows = list(v.verify_stream(io.BytesIO(b'null\n' * 3), True))
        self.assertEqual(rows[-1]['code'], 'REJECT:RECORD_LIMIT')
        self.assertEqual(len(rows), 3)

    def test_jsonl_total_cap(self):
        with patch.object(v, 'MAX_TOTAL', 8):
            rows = list(v.verify_stream(io.BytesIO(b'null\nnull\n'), True))
        self.assertEqual(rows[-1]['code'], 'REJECT:TOTAL_LIMIT')

    def test_missing_path_is_structured_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run([sys.executable, '-B', str(VERIFY), str(Path(tmp) / 'missing')], capture_output=True, timeout=20)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stderr, b'')
        self.assertEqual(json.loads(proc.stdout.splitlines()[0])['code'], 'REJECT:INPUT_IO_ERROR')

    def test_reference_io_failure_cannot_pass(self):
        with patch.object(v.compiler, 'reference', side_effect=OSError('unavailable')):
            self.assertFalse(v.verdict(self.good, 0)['design_valid'])

    def test_rehashed_proof_promotion_rejected(self):
        doc = json.loads(self.good)
        doc['release_accepted'] = True
        doc['blueprint_sha256'] = v.compiler.digest({k: val for k, val in doc.items() if k != 'blueprint_sha256'})
        self.assertFalse(v.verdict(v.compiler.canonical_bytes(doc), 0)['design_valid'])

    def test_precise_git_blob_and_crlf_normalization(self):
        raw = b'one\ntwo\n'
        want = g.git_blob(raw)
        self.assertEqual(g.normalized(raw, want), (raw, False))
        self.assertEqual(g.normalized(raw.replace(b'\n', b'\r\n'), want), (raw, True))

    def test_attestation_rejects_other_changes(self):
        raw = b'one\ntwo\n'
        for changed in (b'\xef\xbb\xbf' + raw, raw + b' ', raw[:-1], raw.replace(b'one', b'three'), raw.replace(b'\n', b'\r')):
            with self.assertRaises(g.GateFailure):
                g.normalized(changed, g.git_blob(raw))

    def test_snapshot_checks_all_before_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'root'; root.mkdir()
            dest = Path(tmp) / 'snapshot'; dest.mkdir()
            (root / 'a').write_bytes(b'a'); (root / 'b').write_bytes(b'bad')
            with patch.object(g, 'PINS', {'a': g.git_blob(b'a'), 'b': g.git_blob(b'b')}):
                with self.assertRaises(g.GateFailure):
                    g.snapshot_sources(root, dest)
            self.assertEqual(list(dest.iterdir()), [])

    def test_failed_preflight_never_executes_children(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'root'; root.mkdir()
            (root / 'a').write_bytes(b'wrong')
            with patch.object(g, 'PINS', {'a': g.git_blob(b'right')}), patch.object(g.subprocess, 'run') as child:
                result = g.run_gate(root, Path(tmp) / 'out')
            self.assertEqual(result['status'], 'FAILED')
            self.assertEqual(result['commands'], [])
            child.assert_not_called()

    def test_logs_directory_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileExistsError):
                g.run_gate(Path(tmp), Path(tmp))

    def test_unit_report_cannot_hide_missing_tests(self):
        for raw in ('OK', 'Ran 0 tests\nOK', 'Ran 74 tests\nFAILED (failures=1)'):
            with self.assertRaises(g.GateFailure):
                g.parse_unittest(raw, 74)
        g.parse_unittest('Ran 74 tests in 1s\n\nOK\n', 74)

    def test_summary_boolean_integer_substitution_rejected(self):
        self.assertFalse(g.exact_json({'proof': 0}, {'proof': False}))
        self.assertFalse(g.exact_json({'count': 1.0}, {'count': 1}))
        self.assertTrue(g.exact_json({'a': 1, 'b': False}, {'b': False, 'a': 1}))

    def test_timeout_preserves_partial_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'out'
            failure = subprocess.TimeoutExpired(['test'], 120, output=b'partial', stderr=b'error')
            with patch.object(g, 'snapshot_sources', return_value=[]), patch.object(g.shutil, 'which', return_value='node'), patch.object(g.subprocess, 'run', side_effect=failure):
                result = g.run_gate(Path(tmp), out)
            self.assertEqual(result['status'], 'FAILED')
            self.assertTrue(result['commands'][0]['timed_out'])
            self.assertEqual((out / 'r143_normal.stdout').read_bytes(), b'partial')
            self.assertEqual((out / 'r143_normal.stderr').read_bytes(), b'error')

    def test_preflight_is_not_qa_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(g, 'snapshot_sources', return_value=[]), patch.object(g.subprocess, 'run') as child:
                result = g.run_gate(Path(tmp), Path(tmp) / 'out', preflight_only=True)
            self.assertEqual(result['status'], 'PREFLIGHT_ONLY_NOT_TESTED')
            self.assertEqual(result['commands'], [])
            child.assert_not_called()

    def test_r144_detects_permissive_validator_in_both_modes(self):
        snippet = (
            'import importlib.util\n'
            f's=importlib.util.spec_from_file_location("victim", {str(R144)!r})\n'
            'm=importlib.util.module_from_spec(s);s.loader.exec_module(m)\n'
            'm.compiler.validate_blueprint=lambda bp:None\n'
            'm.main()\n')
        for flags in ([], ['-O'], ['-OO']):
            proc = subprocess.run([sys.executable, *flags, '-B', '-c', snippet], capture_output=True, timeout=20)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn(b'tampered rehashed blueprint accepted', proc.stderr)
            self.assertNotIn(b'strict_false_accept=0', proc.stdout)

    def test_r144_detects_missing_cases_in_both_modes(self):
        snippet = (
            'import importlib.util\n'
            f's=importlib.util.spec_from_file_location("victim", {str(R144)!r})\n'
            'm=importlib.util.module_from_spec(s);s.loader.exec_module(m)\n'
            'm.CASES=()\n'
            'm.main()\n')
        for flags in ([], ['-O']):
            proc = subprocess.run([sys.executable, *flags, '-B', '-c', snippet], capture_output=True, timeout=20)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn(b'incomplete negative regression campaign', proc.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
