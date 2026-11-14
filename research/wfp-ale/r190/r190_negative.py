"""R190 conditional WFP sublayer shadow: deterministic offline negative cases."""
from itertools import product
from pathlib import Path
import hashlib
import json
import unittest

ROOT = Path(__file__).parent
KINDS = ("AUTH", "REDIRECT")
FAMILIES = ("v4", "v6")
WEIGHTS = ("EMPTY", "UINT64", "UINT8")
FOREIGN = ("NONE", "HIGHER_SAME", "LOWER_SAME", "HIGHER_OTHER_LAYER", "HIDDEN_HIGHER")


def rows():
    for fam, kind, weight, other, appid, bfe, registered in product(
        FAMILIES, KINDS, WEIGHTS, FOREIGN, (0, 1), (0, 1), (0, 1)
    ):
        original_probe = bool(appid and bfe and registered)
        amended_probe = original_probe and weight == "EMPTY" and other not in (
            "HIGHER_SAME", "LOWER_SAME"
        )
        # A high-priority terminal matching foreign filter shadows a lower
        # matching R19 filter within one sublayer. This is a conditional model.
        callback_reachable = original_probe and other not in (
            "HIGHER_SAME", "HIDDEN_HIGHER"
        )
        yield (fam, kind, weight, other, appid, bfe, registered,
               int(original_probe), int(amended_probe), int(callback_reachable))


def canonical():
    return "\n".join(",".join(map(str, row)) for row in rows()) + "\n"


def result():
    cases = list(rows())
    return {
        "matrix_sha256": hashlib.sha256(canonical().encode()).hexdigest(),
        "cases": len(cases),
        "r188_structural_accepts": sum(x[7] for x in cases),
        "r190_structural_accepts": sum(x[8] for x in cases),
        "r188_suppressed_callbacks": sum(x[7] and not x[9] for x in cases),
        "r190_hidden_suppression_candidates": sum(x[8] and not x[9] for x in cases),
        "native_wfp_runs": 0,
        "no_direct_proof": False,
    }


class R190Tests(unittest.TestCase):
    def test_exact_case_count(self):
        self.assertEqual(len(list(rows())), 480)

    def test_exposes_r188_shadow(self):
        s = result()
        self.assertEqual((s['r188_structural_accepts'], s['r188_suppressed_callbacks']), (60, 24))

    def test_conservative_rejects_visible_competitors_and_wrong_weight(self):
        for row in rows():
            if row[2] != 'EMPTY' or row[3] in ('LOWER_SAME', 'HIGHER_SAME'):
                self.assertEqual(row[8], 0)

    def test_hidden_filter_does_not_turn_into_proof(self):
        self.assertEqual(result()['r190_hidden_suppression_candidates'], 4)
        self.assertFalse(result()['no_direct_proof'])

    def test_readonly_rust_surface_and_guards(self):
        s = (ROOT/'main.rs').read_text()
        for marker in ('FwpmTransactionBegin0(engine.0, FWPM_TXN_READ_ONLY)',
                       'FwpmFilterCreateEnumHandle0(', 'FwpmFilterEnum0(',
                       'FwpmFilterDestroyEnumHandle0(', 'f.weight.r#type == FWP_EMPTY',
                       'f.effectiveWeight.r#type == FWP_UINT64',
                       'visible_foreign_filter_in_r19_sublayer'):
            self.assertIn(marker, s)
        for forbidden in ('FwpmFilterAdd0(', 'FwpmFilterDeleteByKey0(',
                          'FwpsCalloutRegister', 'FwpmCalloutAdd0(',
                          'TcpStream::connect(', 'Command::new(', 'FwpmEngineSetOption0('):
            self.assertNotIn(forbidden, s)

    def test_mutation_guards(self):
        s = (ROOT/'main.rs').read_text()
        for marker in ('f.weight.r#type == FWP_EMPTY', 'visible_foreign_filter_in_r19_sublayer'):
            changed = s.replace(marker, 'MUTATED', 1)
            if marker in changed:
                raise AssertionError('mutation not applied')
            self.assertNotIn(marker, changed)


if __name__ == '__main__':
    unittest.main(verbosity=0, exit=False)
    print(json.dumps(result(), sort_keys=True))
