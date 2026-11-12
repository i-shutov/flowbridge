#!/usr/bin/env python3
"""Read-only R123 same-sublayer arbitration negative oracle, offline only.

No WFP, driver, network, Windows, or live filters.  Requires the two patched
source files for static control-flow assertion; the matrix is independently
exercised by r123_lower_weight_continue_independent.mjs.
"""
from __future__ import annotations
import hashlib
import itertools
import json
import pathlib
import sys
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]

def candidate(rule: int, higher: int, equal: int, lower: int) -> bool:
    if higher or equal:
        return True
    # Only the R19 REDIRECT rules use CALLOUT_UNKNOWN, which can CONTINUE.
    return rule in (2, 3) and lower > 0


def original(rule: int, higher: int, equal: int, lower: int) -> bool:
    return higher > 0 or equal > 0


def matrix() -> tuple[list[str], dict]:
    rows = []
    fixed = 0
    candidates = 0
    for rule, h, e, l in itertools.product(range(4), repeat=4):
        before, after = original(rule,h,e,l), candidate(rule,h,e,l)
        if after and not before:
            fixed += 1
        if after:
            candidates += 1
        rows.append(f'{rule},{h},{e},{l},{int(before)},{int(after)}')
    digest = hashlib.sha256(('\n'.join(rows)+'\n').encode('ascii')).hexdigest()
    return rows, dict(cases=len(rows), new_candidates=candidates, corrected_lower_only=fixed,
                      matrix_sha256=digest, native_wfp_observed=False,
                      no_direct_proven=False, kernel_origin_proven=False)


class Checks(unittest.TestCase):
    def test_reproducible_matrix(self):
        _, outcome = matrix()
        self.assertEqual(outcome['cases'],256)
        self.assertEqual(outcome['corrected_lower_only'],6)
        self.assertEqual(outcome['new_candidates'],246)

    def test_lower_only_redirect_surfaced(self):
        for layer in (2,3):
            for count in (1,2,3):
                self.assertFalse(original(layer,0,0,count))
                self.assertTrue(candidate(layer,0,0,count))

    def test_auth_terminating_remains_separate(self):
        for layer in (0,1):
            self.assertFalse(candidate(layer,0,0,1))
            self.assertTrue(candidate(layer,0,1,0))
            self.assertTrue(candidate(layer,1,0,0))

    def test_no_promotion_to_packet_proof(self):
        _, result=matrix()
        self.assertFalse(result['native_wfp_observed'])
        self.assertFalse(result['no_direct_proven'])
        self.assertFalse(result['kernel_origin_proven'])

    def test_rust_source_boundary(self):
        t = (ROOT/'r103'/'r103_readonly_arbitration_inventory.rs').read_text()
        self.assertIn('higher>0 || equal>0 || (index>=2 && lower>0)', t)
        self.assertIn('candidate_for_rule(i,c.greater[i],c.equal[i],c.lower[i])', t)
        self.assertNotIn('candidate|=c.greater[i]>0||c.equal[i]>0;',t)
        self.assertIn('fn r123_lower_only_redirect_is_visible_candidate()',t)
        self.assertIn('FWP_ACTION_CALLOUT_UNKNOWN:u32=0x00004005',t)
        self.assertIn('FWP_ACTION_CALLOUT_TERMINATING:u32=0x00005003',t)

    def test_powershell_source_boundary(self):
        t = (ROOT/'r112'/'R112_WINDOWS_NATIVE_READONLY_CHECK.ps1').read_text()
        self.assertIn('($i -ge 2 -and $item.visible_lower -gt 0)',t)
        self.assertIn('($item.visible_higher -gt 0 -or $item.visible_equal -gt 0 -or',t)
        self.assertIn('single_enum_snapshot',t)
        self.assertIn('no_direct_proof',t)
        self.assertIn('R112 exit code:',t)


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Checks)
    done=unittest.TextTestRunner(verbosity=2).run(suite)
    if not done.wasSuccessful():
        sys.exit(1)
    print('R123_MATRIX '+json.dumps(matrix()[1], sort_keys=True))
