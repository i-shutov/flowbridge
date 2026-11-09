"""R79 deterministic negative proof: pending WSAIoctl is NOT a finished receipt.

No Windows API, sockets, drivers, filter modifications or dependencies.
"""
import hashlib
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from itertools import product

STATES = ("PENDING", "COMPLETED", "CANCELLED", "FAILED")


def verdict(state, expired, cancel_requested, same_socket, same_epoch, valid_context):
    """Terminal completion is required to reclaim resources; deadline alone is insufficient."""
    if state == "PENDING":
        # A request to cancel is only an attempt; no completion has occurred.
        return "HOLD_PENDING", 1, 0
    if state != "COMPLETED":
        return "REJECT_TERMINAL", 0, 0
    if expired:
        # Late completion cannot revive an expired authorization attempt.
        return "REJECT_LATE", 0, 0
    if not (same_socket and same_epoch and valid_context):
        return "REJECT_CONTEXT", 0, 0
    return "CONDITIONAL_RECEIPT_NOT_PROOF", 0, 1


def matrix():
    totals = {}
    sha = hashlib.sha256()
    unsafe_early_release = 0
    for family, state, expired, cancel, socket, epoch, ctx in product(
            (4, 6), STATES, (0, 1), (0, 1), (0, 1), (0, 1), (0, 1)):
        label, retained, candidate = verdict(state, expired, cancel, socket, epoch, ctx)
        totals[label] = totals.get(label, 0) + 1
        if expired and state == "PENDING":
            unsafe_early_release += 1
        sha.update(f"{family},{state},{expired},{cancel},{socket},{epoch},{ctx}|{label}|{retained}|{candidate}\n".encode())
    return {"cases": sum(totals.values()), "outcomes": totals,
            "naive_release_while_pending": unsafe_early_release, "sha256": sha.hexdigest()}


class R79Tests(unittest.TestCase):
    def test_deadline_does_not_complete_pending(self):
        self.assertEqual(verdict("PENDING", 1, 0, 1, 1, 1), ("HOLD_PENDING", 1, 0))

    def test_cancellation_request_is_not_ack(self):
        self.assertEqual(verdict("PENDING", 1, 1, 1, 1, 1), ("HOLD_PENDING", 1, 0))

    def test_late_success_is_rejected(self):
        self.assertEqual(verdict("COMPLETED", 1, 0, 1, 1, 1)[0], "REJECT_LATE")

    def test_socket_replacement_rejected(self):
        self.assertEqual(verdict("COMPLETED", 0, 0, 0, 1, 1)[0], "REJECT_CONTEXT")

    def test_generation_aba_rejected(self):
        self.assertEqual(verdict("COMPLETED", 0, 0, 1, 0, 1)[0], "REJECT_CONTEXT")

    def test_no_receipt_if_invalid_context(self):
        self.assertEqual(verdict("COMPLETED", 0, 0, 1, 1, 0)[0], "REJECT_CONTEXT")

    def test_valid_completion_still_conditional_not_kernel_proof(self):
        self.assertEqual(verdict("COMPLETED", 0, 0, 1, 1, 1)[0], "CONDITIONAL_RECEIPT_NOT_PROOF")

    def test_failure_reclaims_without_claim(self):
        for state in ("FAILED", "CANCELLED"):
            self.assertEqual(verdict(state, 1, 0, 1, 1, 1), ("REJECT_TERMINAL", 0, 0))

    def test_unfinished_worker_is_not_cancelled_by_wait_timeout(self):
        # Actual stdlib concurrency demonstration, no networking. The synthetic
        # blocking operation returns ONLY when we explicitly release its gate.
        began = threading.Event()
        release = threading.Event()
        with ThreadPoolExecutor(max_workers=1) as pool:
            def blocked():
                began.set()
                assert release.wait(3), "bounded test fixture timed out"
                return "done"
            future = pool.submit(blocked)
            try:
                self.assertTrue(began.wait(1))
                with self.assertRaises(TimeoutError):
                    future.result(timeout=0.002)
                self.assertFalse(future.done())
                self.assertFalse(future.cancel())  # already running
            finally:
                release.set()
            self.assertEqual(future.result(timeout=1), "done")

    def test_exhaustive_safety(self):
        result = matrix()
        self.assertEqual(result["cases"], 256)
        self.assertEqual(result["naive_release_while_pending"], 32)
        self.assertEqual(result["outcomes"]["CONDITIONAL_RECEIPT_NOT_PROOF"], 4)


if __name__ == "__main__":
    import sys
    if "--matrix" in sys.argv:
        print(json.dumps(matrix(), sort_keys=True))
    else:
        unittest.main()
