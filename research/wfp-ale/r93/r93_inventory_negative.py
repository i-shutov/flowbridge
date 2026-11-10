#!/usr/bin/env python3
"""R93 deterministic negative semantics plus read-only source and exact R19 key guards.
No Windows API, BFE, socket, service, driver or policy changes.
"""
from __future__ import annotations
import hashlib
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HERE = Path(__file__).resolve().parent
S = (HERE / 'r93_readonly_policy_inventory.rs').read_text(encoding='utf-8')
PLAN = (ROOT / 'kernel-r19/policy_plan.rs').read_text(encoding='utf-8')
POLICY = (ROOT / 'kernel-r19/policy_windows.rs').read_text(encoding='utf-8')
KINDS = ('auth_connect_v4', 'auth_connect_v6', 'connect_redirect_v4', 'connect_redirect_v6')
CALL = (0x1649f018, 0x1649f019, 0x1649f014, 0x1649f016)
BASE = 0x1649f030_25b3_4e01_9ca1_5ca803010019


def present(mask: int, valid: int) -> bool:
    """Adversarial oracle, distinct from Rust native code: all eight objects and shape."""
    filter_present = all((mask >> j) & 1 for j in range(4))
    callout_present = all((mask >> (4+j)) & 1 for j in range(4))
    shape_ok = all((valid >> j) & 1 for j in range(4))
    return filter_present and callout_present and shape_ok


def matrix():
    # 4096 rows exercise every missing-object/shape-corruption pattern.
    return [f'{mask:03x},{valid:01x},{int(present(mask,valid))}'
            for mask in range(256) for valid in range(16)]


class Negative(unittest.TestCase):
    def test_exact_install_order_and_guid_derivation(self):
        rules = re.search(r'pub const RULES:\[Rule;4\]=\[(.*?)\];', PLAN, re.S).group(1)
        observed = re.findall(r'Rule\{family:Family::(V[46]),kind:Kind::(\w+)\}', rules)
        self.assertEqual(observed, [('V4','AttestOriginal'),('V6','AttestOriginal'),
                                    ('V4','Redirect'),('V6','Redirect')])
        self.assertIn('0x1649f030_25b3_4e01_9ca1_5ca803010019', POLICY)
        self.assertIn('((n as u128)<<96)', POLICY)
        self.assertEqual([(BASE + (n<<96)) >> 96 for n in range(4)],
                         [0x1649f030, 0x1649f031, 0x1649f032, 0x1649f033])
        self.assertIn('FILTER_BASE + ((i as u128) << 96)', S)
        for key in CALL:
            self.assertIn(f'0x{key:08x}_25b3_4e01_9ca1_5ca803010019',S)

    def test_no_mutating_wfp_functions_or_runtime_calls(self):
        extern_section = S.split('unsafe extern "system" {')[1].split('\n    }')[0]
        names = re.findall(r'fn (Fwpm\w+0)\(', extern_section)
        self.assertEqual(set(names), {'FwpmEngineOpen0','FwpmEngineClose0',
            'FwpmFilterGetByKey0','FwpmCalloutGetByKey0','FwpmFreeMemory0'})
        self.assertIn('FwpmEngineOpen0(ptr::null(), RPC_C_AUTHN_WINNT,',S)
        self.assertIn('ptr::null(), ptr::null(), &mut h)', S)
        self.assertNotIn('FwpmFilterAdd0',S)
        self.assertNotIn('FwpmFilterDelete',S)
        self.assertNotIn('FwpmTransaction',S)
        self.assertNotIn('Fwps',S)
        self.assertNotIn('socket(',S)

    def test_missing_one_never_completes(self):
        for index in range(8):
            self.assertFalse(present(255 ^ (1 << index),15))
        self.assertTrue(present(255,15))
        self.assertFalse(present(0,15))
        for index in range(4):
            self.assertFalse(present(255,15 ^ (1 << index)))

    def test_matrix_is_complete_and_unique(self):
        rows=matrix()
        self.assertEqual(len(rows),4096)
        self.assertEqual(len(set(rows)),4096)
        self.assertEqual(sum(x.endswith(',1') for x in rows),1)

    def test_no_kernel_or_protection_proof(self):
        self.assertIn('"kernel_origin_proof\\\":false',S)
        self.assertIn('"continuous_enforcement_proof\\\":false',S)
        self.assertIn('fv.sub_layer_key == SUB',S)
        self.assertIn('fv.layer_key == cv.applicable_layer',S)
        self.assertIn('fv.flags == 0',S)
        self.assertIn('!filter.0.is_null()',S)
        self.assertIn('!callout.0.is_null()',S)


if __name__ == '__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Negative)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    raw='\n'.join(matrix())+'\n'
    print('R93_MATRIX_SHA256',hashlib.sha256(raw.encode()).hexdigest())
    print('R93_ROWS',len(matrix()),'POSITIVE',sum(x.endswith(',1') for x in matrix()))
    raise SystemExit(0 if result.wasSuccessful() else 1)
