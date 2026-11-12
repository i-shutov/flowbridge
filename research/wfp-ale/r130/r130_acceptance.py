#!/usr/bin/env python3
"""R130 offline integrity/negative tests, NOT execution of the Rust algorithm."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import unittest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
PINS = json.loads((HERE/'r130_source_pins.json').read_text())
SCRIPT = (HERE/'FlowBridge-R130-ExactLogic.ps1').read_text()
SUITE = (HERE/'r130_exact_logic_suite.rs').read_text()

def git_blob(data):
    return hashlib.sha1(f'blob {len(data)}\0'.encode()+data).hexdigest()

def matches(data, row):
    return git_blob(data) == row['git_blob'] and hashlib.sha256(data).hexdigest() == row['sha256']

def mutated(data):
    for position in [0,len(data)//2,len(data)-1]:
        for bit in [1,2,128]:
            b=bytearray(data);b[position]^=bit;yield bytes(b)
    yield data.replace(b'\n',b'\r\n')
    yield b'\xef\xbb\xbf'+data
    yield data[:-1]

def manifest_result():
    accepted = rejected = 0
    for row in PINS['sources']:
        raw=(REPO/row['path']).read_bytes()
        accepted += int(matches(raw,row))
        rejected += sum(not matches(value,row) for value in mutated(raw))
    return {'sources':len(PINS['sources']), 'accepted_exact':accepted,
            'rejected_mutations':rejected,'rust_execution':'NOT_RUN'}

validator_path=HERE.parent/'r129/r129_negative.py'
assert git_blob(validator_path.read_bytes()) == '6e4d23dac3c2c579760e23632b169067e695e15e'
spec=importlib.util.spec_from_file_location('r129_exact_validator',validator_path)
validator=importlib.util.module_from_spec(spec);spec.loader.exec_module(validator)
OBS=[json.loads(line) for line in (HERE/'R129_OWNER_OBSERVATION.jsonl').read_text().splitlines()]

class Tests(unittest.TestCase):
    def test_all_five_sources_are_exact(self):
        for row in PINS['sources']:
            with self.subTest(path=row['path']):
                self.assertTrue(matches((REPO/row['path']).read_bytes(),row))
    def test_sixty_byte_mutations_rejected(self):
        self.assertEqual(manifest_result(),{'sources':5,'accepted_exact':5,'rejected_mutations':60,'rust_execution':'NOT_RUN'})
    def test_no_lossy_checkout_normalization(self):
        self.assertIn('[IO.File]::WriteAllBytes',SCRIPT)
        self.assertIn('[Convert]::FromBase64String',SCRIPT)
        self.assertNotIn('.Replace("`r`n"',SCRIPT)
    def test_runner_pins_match_manifest(self):
        embedded=json.loads(SCRIPT.split("$files = @'\n",1)[1].split("\n'@ | ConvertFrom-Json",1)[0])
        self.assertEqual(embedded,[{k:r[k] for k in ('path','git_blob','sha256')} for r in PINS['sources']])
    def test_exact_imports_not_kernel_adapter(self):
        imports=re.findall(r'#\[path = "([^"]+)"\]',SUITE)
        self.assertEqual(imports,['../kernel-r19/kernel/src/ledger.rs','../kernel-r19/kernel/src/handoff.rs',
                                  '../kernel-r19/kernel/src/auth_appid.rs','../kernel-r19/policy_plan.rs'])
        self.assertIn('#![forbid(unsafe_code)]',SUITE)
        for row in PINS['sources']:
            text=(REPO/row['path']).read_text()
            self.assertNotRegex(text,r'\bunsafe\s*(?:\{|fn\b|impl\b|extern\b)|\bextern\s+"|#\[link\(|\binclude!\s*\(')
            self.assertNotRegex(text,r'\b(?:TcpStream|TcpListener|UdpSocket|Command|DeviceIoControl|WSAIoctl)\s*(?:::|\()')
    def test_exact_sixty_test_count(self):
        self.assertEqual([r['tests'] for r in PINS['sources']],[7,19,11,9,14])
        self.assertEqual(sum((REPO/r['path']).read_text().count('#[test]') for r in PINS['sources']),60)
        self.assertIn('$expectedTests = 60',SCRIPT)
        self.assertIn('0 failed; 0 ignored; 0 measured; 0 filtered out;',SCRIPT)
    def test_declared_current_boundaries(self):
        self.assertIn('book_alone_is_not_a_process_liveness_proof',SUITE)
        self.assertIn('assert!(b.take(c,3).is_some());',SUITE)
        self.assertIn('SYNTHETIC',SUITE)
        self.assertIn('No Windows API',SUITE)
    def test_no_new_install_or_live_bfe(self):
        for forbidden in ['Start-Service','Stop-Service','New-NetFirewallRule','Set-ExecutionPolicy',
                          'rustup install','cargo build','git clone','git checkout','RunReadOnlyBfe']:
            self.assertNotIn(forbidden,SCRIPT)
        self.assertIn("$env:PATH=$oldPath; $env:RUST_MIN_STACK=$oldStack",SCRIPT)
        self.assertIn('kernel_origin_proof=$false',SCRIPT)
        self.assertIn('bfe_queried=$false',SCRIPT)
    def test_previous_native_result_validated(self):
        validator.validate(OBS,4)
        self.assertEqual([r['api_code'] for r in OBS[:4]],[0x80320003]*4)
        self.assertEqual(OBS[-1]['close_code'],0)
    def test_previous_result_not_kernel_proof(self):
        for row in OBS:
            self.assertIs(row['kernel_proof'],False);self.assertIs(row['no_direct_proof'],False)
        self.assertIs(OBS[-1]['atomic_snapshot'],False)
    def test_forged_native_summary_rejected(self):
        for field,value in [('diagnostic_exit',0),('queries',True),('status','SAFE'),('no_direct_proof',True)]:
            rows=copy.deepcopy(OBS);rows[-1][field]=value
            with self.assertRaises(ValueError): validator.validate(rows,4)
    def test_missing_or_swapped_native_rows_rejected(self):
        with self.assertRaises(ValueError):validator.validate(OBS[:4],4)
        rows=copy.deepcopy(OBS);rows[0],rows[1]=rows[1],rows[0]
        with self.assertRaises(ValueError):validator.validate(rows,4)
    def test_offline_bundle_does_not_fallback_to_download(self):
        self.assertIn("if (-not [string]::IsNullOrWhiteSpace($OfflineBundleRoot))",SCRIPT)
        self.assertIn("'Exact-source attestation failed: '",SCRIPT)
        self.assertNotIn('SkipHash',SCRIPT)
    def test_only_user_mode_test_compiler_flags(self):
        self.assertIn("'--test'",SCRIPT)
        self.assertIn("'--forbid','unsafe_code'",SCRIPT)
        self.assertNotIn('crate-type=dylib',SCRIPT)
        self.assertNotIn('build.rs',SCRIPT)

if __name__=='__main__':
    import sys
    if '--matrix' in sys.argv:print(json.dumps(manifest_result(),sort_keys=True))
    else:unittest.main(verbosity=2)
