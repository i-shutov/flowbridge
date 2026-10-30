#!/usr/bin/env python3
"""Negative contracts: no zero-channel pass or invented 512-attempt claims."""
import unittest

from windows_ssh_probe_core import ResourceErrors, probe_capacity


class Socket:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class ProbeTests(unittest.TestCase):
    def run_probe(self, connector, echo=lambda *_: None, **kwargs):
        report = {}
        probe_capacity(connector, echo, lambda: True, lambda _: None, report,
                       held_limit=kwargs.pop("held_limit", 2),
                       min_held=kwargs.pop("min_held", 2),
                       tiers=kwargs.pop("tiers", (1, 2, 192, 256, 512)),
                       recovery_count=kwargs.pop("recovery_count", 2), **kwargs)
        return report

    def test_zero_success_is_not_accepted(self):
        with self.assertRaisesRegex(RuntimeError, "Only 0 real channels"):
            self.run_probe(lambda: None)

    def test_partial_success_below_minimum_is_not_accepted(self):
        first = Socket()
        values = iter([first, None, None, None, None])
        with self.assertRaisesRegex(RuntimeError, "Only 1 real channels"):
            self.run_probe(lambda: next(values))
        self.assertTrue(first.closed)

    def test_capped_tiers_report_actual_not_requested_attempts(self):
        sockets = []
        def connect():
            sockets.append(Socket())
            return sockets[-1]
        report = self.run_probe(connect)
        self.assertEqual(report["actual_connection_attempts"], 4)
        self.assertEqual(report["attempts"][-1]["actual_new_attempts"], 0)
        self.assertEqual(report["attempts"][-1]["requested_tier"], 512)
        self.assertTrue(report["attempts"][-1]["test_ceiling_applied"])
        self.assertEqual(report["recovery_successes"], 2)
        self.assertTrue(all(sock.closed for sock in sockets))

    def test_payload_corruption_fails_and_closes_candidate(self):
        candidate = Socket()
        def bad_echo(*_):
            raise RuntimeError("byte mismatch")
        with self.assertRaisesRegex(RuntimeError, "byte mismatch"):
            self.run_probe(lambda: candidate, echo=bad_echo)
        self.assertTrue(candidate.closed)

    def test_process_alive_but_recovery_dead_is_not_accepted(self):
        values = iter([Socket(), Socket(), None])
        with self.assertRaisesRegex(RuntimeError, "did not recover"):
            self.run_probe(lambda: next(values))

    def test_invalid_limits(self):
        with self.assertRaises(ValueError):
            self.run_probe(lambda: Socket(), min_held=3)

    def test_diagnostics_are_coalesced_and_do_not_keep_private_stderr(self):
        errors = ResourceErrors()
        for _ in range(10000):
            errors.observe(b"PRIVATE_USER PRIVATE_DOMAIN accept: Too many open files")
        self.assertEqual(errors.snapshot(), {"too_many_open_files": 10000})
        self.assertNotIn("PRIVATE", str(vars(errors)))


if __name__ == "__main__":
    unittest.main()
