#!/usr/bin/env python3
"""Offline R129 contract, source-scope and forged-transcript tests; no Windows calls."""
from __future__ import annotations
import hashlib
import itertools
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent
NAMES = ['FOUND_BY_KEY','NOT_FOUND_RETURNED','ACCESS_DENIED_RETURNED','OTHER_API_ERROR','INVALID_API_RESULT']
LABELS = ['auth_connect_v4','auth_connect_v6','connect_redirect_v4','connect_redirect_v6']
KEYS = [f'1649f03{i}-25b3-4e01-9ca1-5ca803010019' for i in range(4)]
REPRESENTATIVE = [(0, True), (0x80320003, False), (5, False), (1722, False), (0, False)]

def observe(code: int, pointer: bool) -> int:
    if type(code) is not int or not 0 <= code <= 0xffffffff or type(pointer) is not bool:
        raise ValueError('invalid DWORD or pointer-presence type')
    if code == 0:
        return 0 if pointer else 4
    if pointer:
        return 4
    return {0x80320003: 1, 5: 2}.get(code, 3)

def finish(rows: tuple[int, ...], close: int) -> tuple[int, str]:
    if len(rows) != 4 or any(type(x) is not int or not 0 <= x <= 4 for x in rows):
        raise ValueError('exactly four observations required')
    if type(close) is not int or not 0 <= close <= 0xffffffff:
        raise ValueError('invalid close DWORD')
    if close or any(x >= 3 for x in rows):
        return 2, 'QUERY_OR_CLOSE_ERROR'
    if 2 in rows:
        return 5, 'ACCESS_DENIED_OBSERVED'
    if 1 in rows:
        return 4, 'NOT_FOUND_OBSERVED'
    return 3, 'ALL_FOUR_GETS_SUCCEEDED_NOT_PROOF'

def transcript(rows: tuple[int,...], close: int = 0) -> list[dict]:
    out = []
    for i, state in enumerate(rows):
        code, ptr = REPRESENTATIVE[state]
        out.append(dict(schema=1, kind='filter', rule=LABELS[i], key=KEYS[i],
                        api_code=code, api_code_hex=f'0x{code:08X}', pointer_present=ptr,
                        observation=NAMES[state], kernel_proof=False, no_direct_proof=False))
    code, status = finish(rows, close)
    out.append(dict(schema=1, kind='summary', status=status, queries=4, close_code=close,
                    close_code_hex=f'0x{close:08X}', diagnostic_exit=code, kernel_proof=False,
                    no_direct_proof=False, atomic_snapshot=False))
    return out

def validate(records: list[dict], exit_code: int) -> None:
    if len(records) != 5 or type(exit_code) is not int:
        raise ValueError('cardinality/type')
    states = []
    for i, r in enumerate(records[:4]):
        if r.get('kind') != 'filter' or r.get('rule') != LABELS[i] or r.get('key') != KEYS[i]:
            raise ValueError('key/rule order')
        state = observe(r.get('api_code'), r.get('pointer_present'))
        if r.get('observation') != NAMES[state] or r.get('api_code_hex') != f"0x{r['api_code']:08X}":
            raise ValueError('code/observation')
        states.append(state)
    t = records[-1]
    close = t.get('close_code')
    expected_exit, expected_status = finish(tuple(states), close)
    if (t.get('kind') != 'summary' or t.get('status') != expected_status or
        type(t.get('queries')) is not int or t['queries'] != 4 or
        type(t.get('diagnostic_exit')) is not int or t['diagnostic_exit'] != expected_exit or
        exit_code != expected_exit or t.get('close_code_hex') != f'0x{close:08X}' or
        t.get('atomic_snapshot') is not False):
        raise ValueError('terminal inconsistency')
    for r in records:
        if type(r.get('schema')) is not int or r['schema'] != 1 or r.get('kernel_proof') is not False or r.get('no_direct_proof') is not False:
            raise ValueError('schema/proof boundary')

def matrix() -> tuple[dict, str]:
    lines, counts = [], {str(i): 0 for i in (2,3,4,5)}
    for rows in itertools.product(range(5), repeat=4):
        for close in (0,1):
            exit_code, _ = finish(rows, close)
            lines.append(''.join(map(str,rows)) + f':{close}:{exit_code}\n')
            counts[str(exit_code)] += 1
    text = ''.join(lines)
    return dict(states=len(lines), exits=counts, sha256=hashlib.sha256(text.encode()).hexdigest()), text

class Tests(unittest.TestCase):
    def test_exact_missing_not_generic(self):
        self.assertEqual(observe(0x80320003,False),1)
        self.assertEqual(observe(0x80320008,False),3)
    def test_denied_not_missing(self): self.assertEqual(observe(5,False),2)
    def test_success_needs_pointer(self): self.assertEqual(observe(0,False),4)
    def test_error_pointer_not_owned(self):
        for x in (5,1722,0x80320003,0xffffffff): self.assertEqual(observe(x,True),4)
    def test_all_found_is_not_pass(self): self.assertEqual(finish((0,0,0,0),0)[0],3)
    def test_all_missing_is_informative(self): self.assertEqual(finish((1,1,1,1),0)[0],4)
    def test_denied_precedence(self): self.assertEqual(finish((0,1,2,0),0)[0],5)
    def test_close_error_wins(self): self.assertEqual(finish((0,0,0,0),5)[0],2)
    def test_every_valid_matrix_transcript(self):
        for rows in itertools.product(range(5),repeat=4):
            for close in (0,1): validate(transcript(rows,close),finish(rows,close)[0])
    def test_duplicate_key_rejected(self):
        rows=transcript((0,0,0,0)); rows[1]['key']=rows[0]['key']
        with self.assertRaises(ValueError): validate(rows,3)
    def test_string_boolean_rejected(self):
        for value in ('false',0,None):
            rows=transcript((1,1,1,1)); rows[-1]['no_direct_proof']=value
            with self.assertRaises(ValueError): validate(rows,4)
    def test_forged_counters_and_exit(self):
        for field,value in [('queries',True),('queries',3),('diagnostic_exit',0),('close_code',False)]:
            rows=transcript((0,0,0,0)); rows[-1][field]=value
            with self.assertRaises(ValueError): validate(rows,3)
    def test_code_and_type_forgeries(self):
        for value in (True, -1, 0x100000000, '0', 0.0):
            rows=transcript((0,0,0,0)); rows[0]['api_code']=value
            with self.assertRaises(ValueError): validate(rows,3)
    def test_truncation_and_extra_rows_rejected(self):
        rows=transcript((0,0,0,0))
        for r in (rows[:4],rows+rows[:1]):
            with self.assertRaises(ValueError): validate(r,3)
    def test_source_allowlist(self):
        s=(ROOT/'r129_filter_get_by_key.rs').read_text()
        api=set(re.findall(r'fn (Fwpm\w+)\(',s))
        self.assertEqual(api,{'FwpmEngineOpen0','FwpmEngineClose0','FwpmFilterGetByKey0','FwpmFreeMemory0'})
        self.assertNotRegex(s,r'(?m)^\s*(struct|union) FWPM_FILTER')
        self.assertIn('target_arch = "x86_64"',s)
        self.assertIn('code == 0 && !raw.is_null()',s)
        self.assertIn('let close = engine.close();',s)
        self.assertIn('not(test)',s)  # Unit tests cannot enter live module.
    def test_all_four_source_keys(self):
        s=(ROOT/'r129_filter_get_by_key.rs').read_text()
        for k in KEYS: self.assertIn(k,s)
    def test_script_pin_and_no_checkout_transformation(self):
        script=(ROOT/'FlowBridge-R129-ReadOnly-ByKey.ps1').read_text()
        raw=(ROOT/'r129_filter_get_by_key.rs').read_bytes()
        sha=hashlib.sha256(raw).hexdigest()
        blob=hashlib.sha1(f'blob {len(raw)}\0'.encode()+raw).hexdigest()
        self.assertIn(sha,script);self.assertIn(blob,script)
        self.assertIn('FromBase64String',script)
        self.assertIn('[IO.File]::WriteAllBytes',script)
        for banned in ('Set-ExecutionPolicy','Start-Service','Stop-Service','New-NetFirewallRule','git checkout','git reset','rustup install'):
            self.assertNotIn(banned,script)
    def test_matrix_has_no_zero(self):
        result,stream=matrix();self.assertEqual(result['states'],1250)
        self.assertTrue(all(not row.endswith(':0') for row in stream.splitlines()))

if __name__ == '__main__':
    import sys
    if '--matrix' in sys.argv:
        print(json.dumps(matrix()[0],sort_keys=True))
    else:
        unittest.main(verbosity=2)
