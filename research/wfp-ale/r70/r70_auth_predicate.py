#!/usr/bin/env python3
"""R70: clean-room, offline R19 AUTH mask diagnostic, not a Windows/WFP test.

The observable mask is a hypothetical callback with 16 binary fields. No result
is a kernel-origin certificate, proof of owner liveness, or packet disposition.
"""
from __future__ import annotations
import hashlib, json, unittest

# Auth condition bits (separate from real WFP bit values, which are not assumed).
NAMES = (
    "meta_pid", "meta_endpoint", "meta_target_pid", "meta_original_dest",
    "redirect_flag", "original_app_selected", "tcp", "broker_target_matches",
    "original_dest_matches", "current_pid_epoch_exe_matches", "endpoint_matches",
    "lease_ok", "no_reauthorization", "callback_delivered",
    "hidden_historical_owner_matches", "hidden_sibling_direct_possible",
)
NEEDED = (1 << 14) - 1  # all observable positive gates (0..13)
METADATA = 0x000F


def decision(bits: int) -> int:
    """0=unobserved, 1=metadata unavailable, 2=not redirected, 3=other denial, 4=conditional witness."""
    if not bits & (1 << 13):
        return 0
    if bits & METADATA != METADATA:
        return 1
    if not bits & (1 << 4):
        return 2
    if bits & NEEDED != NEEDED:
        return 3
    return 4


def source_redirect_issue(bits: int) -> int:
    """Separate 8-bit model: 3=R19 issues despite unqueried state; 5=queried-clear candidate.

    bit 0: records metadata present; 1: queried clean if present;
    2: current app selected; 3: TCP; 4: lease; 5: current ledger match;
    6: hypothetical hidden foreign-redirect; 7: callback delivered.
    """
    if not bits & 128: return 0  # UNOBSERVED
    if bits & 12 != 12: return 1  # OUT_OF_SCOPE
    if bits & 48 != 48: return 2  # FAIL_HEALTH_OR_OWNER
    if not bits & 1: return 3  # UNQUERIED_ISSUE_CANDIDATE (current R19)
    if not bits & 2: return 4  # QUERY_NOT_CLEAN
    return 5  # QUERIED_CLEAN_ISSUE_CANDIDATE


def sweep() -> dict:
    auth_stream = bytearray()
    redirect_stream = bytearray()
    for family in (4, 6):
        for bits in range(1 << len(NAMES)):
            auth_stream.append(decision(bits))
        for bits in range(1 << 8):
            redirect_stream.append(source_redirect_issue(bits))
    from collections import Counter
    a = Counter(auth_stream)
    r = Counter(redirect_stream)
    return {
        "auth_cases": len(auth_stream),
        "auth_counts": {str(k): a[k] for k in range(5)},
        "auth_sha256": hashlib.sha256(auth_stream).hexdigest(),
        "redirect_cases": len(redirect_stream),
        "redirect_counts": {str(k): r[k] for k in range(6)},
        "redirect_sha256": hashlib.sha256(redirect_stream).hexdigest(),
        "conditional_with_hidden_wrong_owner": 2 * sum(decision(b) == 4 and not (b & (1 << 14)) for b in range(1 << 16)),
        "conditional_with_hidden_sibling_direct_possible": 2 * sum(decision(b) == 4 and bool(b & (1 << 15)) for b in range(1 << 16)),
        "unqueried_with_hidden_foreign_redirect": 2 * sum(source_redirect_issue(b) == 3 and bool(b & 64) for b in range(256)),
    }


class ContractTests(unittest.TestCase):
    def test_both_versions_metadata_present_conditional(self):
        self.assertEqual(decision(NEEDED), 4)
    def test_all_four_required_metadata_bits_independent(self):
        for k in range(4):
            with self.subTest(k=k): self.assertEqual(decision(NEEDED & ~(1 << k)), 1)
    def test_redirect_flag_required(self):
        self.assertEqual(decision(NEEDED & ~(1 << 4)), 2)
    def test_denials_do_not_promise_packet_block(self):
        for k in range(5, 13):
            with self.subTest(k=k): self.assertEqual(decision(NEEDED & ~(1 << k)), 3)
    def test_unobserved_no_claim(self):
        self.assertEqual(decision(NEEDED & ~(1 << 13)), 0)
    def test_historical_owner_not_proved_by_identical_metadata(self):
        self.assertEqual(decision(NEEDED), decision(NEEDED | (1 << 14)))
    def test_sibling_direct_not_proved_by_identical_metadata(self):
        self.assertEqual(decision(NEEDED), decision(NEEDED | (1 << 15)))
    def test_r19_issues_without_redirect_state_query(self):
        self.assertEqual(source_redirect_issue(128 | 12 | 48), 3)
    def test_even_hidden_foreign_redirect_is_indistinguishable_when_handle_missing(self):
        b = 128 | 12 | 48
        self.assertEqual(source_redirect_issue(b), source_redirect_issue(b | 64))
    def test_present_records_nonclean_refused(self):
        self.assertEqual(source_redirect_issue(128 | 12 | 48 | 1), 4)
    def test_present_records_clean_issued(self):
        self.assertEqual(source_redirect_issue(128 | 12 | 48 | 3), 5)
    def test_missing_callback_unobserved(self):
        self.assertEqual(source_redirect_issue(12 | 48 | 3), 0)
    def test_no_wfp_mutation_or_ffi_in_oracle(self):
        import inspect
        src = inspect.getsource(decision) + inspect.getsource(source_redirect_issue)
        self.assertFalse(any(s in src for s in ("ctypes.", "FwpsCallout", "DeviceIoControl", "subprocess.")))
    def test_exhaustive_result_stable(self):
        out = sweep()
        self.assertEqual(out['auth_cases'], 131072)
        self.assertEqual(out['redirect_cases'], 512)
        self.assertEqual(out['auth_counts']['4'], 8)
        self.assertEqual(out['unqueried_with_hidden_foreign_redirect'], 4)


if __name__ == '__main__':
    import sys
    if '--test' in sys.argv:
        sys.argv = [sys.argv[0]]
        unittest.main(verbosity=2)
    else:
        print(json.dumps(sweep(), indent=2, sort_keys=True))
