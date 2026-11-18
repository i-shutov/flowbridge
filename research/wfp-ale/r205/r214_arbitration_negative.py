#!/usr/bin/env python3
"""R214: deterministic evidence-level counterexample; NOT a Windows classify."""
import argparse
import hashlib
import pathlib
import unittest

PINNED = {
    "kernel/src/redirect.rs": "a093f049d162987981a957aac90db1014bc6ff09",
    "kernel/src/handoff.rs": "e1d17217db50362ba9c4efc83af820b6beb094cf",
    "policy_windows.rs": "acf60334320d970f58af3349ee75fbaa59826602",
}


def source_gate():
    root = pathlib.Path(__file__).resolve().parents[1] / "kernel-r19"
    code = {}
    for name, expected in PINNED.items():
        raw = (root / name).read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        assert actual == expected, (name, actual, expected)
        code[name] = raw.decode("utf-8")
    redirect = code["kernel/src/redirect.rs"]
    handoff = code["kernel/src/handoff.rs"]
    policy = code["policy_windows.rs"]
    callback = redirect.split("pub unsafe fn auth_classify", 1)[1].split("unsafe fn auth_check", 1)[0]
    assert callback.index("auth_check(values,meta)") < callback.index("actionType=k::FWP_ACTION_PERMIT")
    assert "rights &= !k::FWPS_RIGHT_ACTION_WRITE" in callback
    assert "route.book.attest(identity,original_destination,now())" in redirect
    assert "slot.auth_seen=true" in handoff
    take = handoff.split("pub fn take(", 1)[1].split("pub fn kill(", 1)[0]
    assert "!s.auth_seen" in take and "final" not in take.lower()
    assert "FWP_ACTION_CALLOUT_TERMINATING" in policy
    return True


# This is a source-level model of *evidence* state only. A genuine WFP veto may
# prevent an accepted socket from existing, in which case native CLAIM is moot.
def evidence_model(auth_valid: bool, final_action: str) -> tuple[bool, bool]:
    auth_seen = auth_valid  # Book::attest mutates BEFORE the callout returns
    terminal_claim_if_a_receipt_exists = auth_seen
    strict_final_authorization_evidence = auth_seen and final_action == "PERMIT"
    return terminal_claim_if_a_receipt_exists, strict_final_authorization_evidence


class NegativeEvidenceTests(unittest.TestCase):
    def test_normal_permit_control(self):
        for family in (4, 6):
            with self.subTest(family=family):
                self.assertEqual(evidence_model(True, "PERMIT"), (True, True))

    def test_valid_auth_followed_by_veto_not_final_permission(self):
        for family in (4, 6):
            with self.subTest(family=family):
                self.assertEqual(evidence_model(True, "VETO_BLOCK"), (True, False))

    def test_valid_auth_other_layer_block_not_final_permission(self):
        for family in (4, 6):
            with self.subTest(family=family):
                self.assertEqual(evidence_model(True, "OTHER_LAYER_BLOCK"), (True, False))

    def test_invalid_auth_never_sets_receipt(self):
        for final in ("PERMIT", "VETO_BLOCK", "OTHER_LAYER_BLOCK"):
            self.assertEqual(evidence_model(False, final), (False, False))

    def test_family_is_not_proof_of_final_arbitration(self):
        # The pinned R19 Book::attest and Book::take have no WFP family/final-decision parameter.
        self.assertEqual(evidence_model(True, "VETO_BLOCK"), (True, False))

    def test_mutant_making_attest_depend_on_final_decision_eliminates_counterexample(self):
        for final in ("VETO_BLOCK", "OTHER_LAYER_BLOCK"):
            original, strict = evidence_model(True, final)
            self.assertTrue(original)
            self.assertFalse(strict)
            mutant_auth_seen = True and final == "PERMIT"
            self.assertFalse(mutant_auth_seen)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", action="store_true", help="verify exact source Git blob pins in checkout")
    args = parser.parse_args()
    if args.source:
        source_gate()
        print("R214 source: 3 exact Git blob SHA-1 + 7 structural guards PASS")
    unittest.main(argv=[__file__], verbosity=2)
