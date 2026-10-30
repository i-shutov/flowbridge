#!/usr/bin/env python3
"""Negative contracts: no zero-channel pass or invented 512-attempt claims."""
import unittest
from churn_pacing import StartPacer
from windows_ssh_probe_core import ResourceErrors, probe_capacity, expected_raw_backend_fd_saturation


class Socket:
    def __init__(self):
        self.closed = False
    def close(self):
        self.closed = True


class ProbeTests(unittest.TestCase):
    def run_probe(self,connector,echo=lambda *_:None,**kwargs):
        report = {}
        probe_capacity(connector,echo,lambda:True,lambda _:None,report,
                       held_limit=kwargs.pop('held_limit',2),
                       min_held=kwargs.pop('min_held',2),
                       tiers=kwargs.pop('tiers',(1,2,192,256,512)),
                       recovery_count=kwargs.pop('recovery_count',2),**kwargs)
        return report

    def test_zero_success_is_not_accepted(self):
        with self.assertRaisesRegex(RuntimeError,'Only 0 real channels'):
            self.run_probe(lambda:None)

    def test_partial_success_below_minimum_is_not_accepted(self):
        first = Socket()
        values = iter([first,None,None,None,None])
        with self.assertRaisesRegex(RuntimeError,'Only 1 real channels'):
            self.run_probe(lambda:next(values))
        self.assertTrue(first.closed)

    def test_capped_tiers_report_actual_not_requested_attempts(self):
        sockets = []
        def connect():
            sockets.append(Socket())
            return sockets[-1]
        report = self.run_probe(connect)
        self.assertEqual(report['actual_connection_attempts'],4)
        self.assertEqual(report['attempts'][-1]['actual_new_attempts'],0)
        self.assertEqual(report['attempts'][-1]['requested_tier'],512)
        self.assertTrue(report['attempts'][-1]['test_ceiling_applied'])
        self.assertEqual(report['recovery_successes'],2)
        self.assertTrue(all(sock.closed for sock in sockets))

    def test_payload_corruption_fails_and_closes_candidate(self):
        candidate = Socket()
        def bad_echo(*_):
            raise RuntimeError('byte mismatch')
        with self.assertRaisesRegex(RuntimeError,'byte mismatch'):
            self.run_probe(lambda:candidate,echo=bad_echo)
        self.assertTrue(candidate.closed)

    def test_new_open_ssh_channel_reset_at_ceiling_is_measured_not_masked(self):
        sockets = []
        def connect():
            candidate = Socket()
            sockets.append(candidate)
            return candidate
        def echo(sock, nonce):
            if len(sockets) >= 3 and sock is sockets[2] and b'initial' in nonce:
                raise ConnectionResetError(10054, 'new SSH channel reset at capacity')
        report = self.run_probe(connect, echo=echo, held_limit=3, min_held=2,
                                tiers=(1, 2, 3), recovery_count=2)
        self.assertTrue(report['capacity_baseline_verified'])
        self.assertEqual(report['peak_held'], 2)
        self.assertEqual(report['attempts'][-1]['accepted_held'], 2)
        self.assertEqual(report['attempts'][-1]['failed_new'], 1)
        self.assertEqual(report['attempts'][-1]['failed_stage'], 'candidate_initial_echo')
        self.assertEqual(report['attempts'][-1]['failed_error_type'], 'ConnectionResetError')
        self.assertEqual(report['recovery_successes'], 2)
        self.assertTrue(all(sock.closed for sock in sockets))

    def test_new_channel_reset_before_minimum_cannot_pass(self):
        sockets = []
        def connect():
            candidate = Socket()
            sockets.append(candidate)
            return candidate
        def echo(_sock, nonce):
            if b'initial' in nonce:
                raise ConnectionResetError(10054, 'bare SSH backend unavailable')
        with self.assertRaisesRegex(RuntimeError, 'Only 0 real channels'):
            self.run_probe(connect, echo=echo, min_held=2, held_limit=3,
                           tiers=(1, 2, 3), recovery_count=1)
        self.assertTrue(all(sock.closed for sock in sockets))

    def test_existing_held_connection_reset_is_still_hard_failure(self):
        sockets = []
        def connect():
            candidate = Socket()
            sockets.append(candidate)
            return candidate
        def echo(sock, nonce):
            if b'held integrity' in nonce and sock is sockets[0]:
                raise ConnectionResetError(10054, 'established flow lost bytes')
        with self.assertRaises(ConnectionResetError):
            self.run_probe(connect, echo=echo, min_held=1, held_limit=2,
                           tiers=(1, 2), recovery_count=1)
        self.assertTrue(all(sock.closed for sock in sockets))

    def test_only_proven_server_fd_limit_above_safe_tier_can_be_characterized(self):
        valid = {
            'capacity_baseline_verified': True,
            'last_good_verified_held': 192,
            'peak_held': 244,
            'held_integrity_failure': {
                'requested_tier': 256, 'held_at_failure': 244,
                'failed_stream_index': 23, 'error_type': 'ConnectionResetError',
            },
        }
        markers = {'too_many_open_files': 1, 'not_enough_space': 1}
        self.assertTrue(expected_raw_backend_fd_saturation(valid, markers, 128))
        self.assertFalse(expected_raw_backend_fd_saturation(valid, {}, 128))
        self.assertFalse(expected_raw_backend_fd_saturation(valid, markers, 256))
        for field, replacement in (
            ('capacity_baseline_verified', False),
            ('last_good_verified_held', 0),
            ('peak_held', 128),
            ('held_integrity_failure', None),
        ):
            bad = dict(valid, **{field: replacement})
            self.assertFalse(expected_raw_backend_fd_saturation(bad, markers, 128))
        bad = dict(valid, held_integrity_failure=dict(valid['held_integrity_failure'],
                                                       error_type='RuntimeError'))
        self.assertFalse(expected_raw_backend_fd_saturation(bad, markers, 128))
        bad = dict(valid, held_integrity_failure=dict(valid['held_integrity_failure'],
                                                       held_at_failure=128))
        self.assertFalse(expected_raw_backend_fd_saturation(bad, markers, 128))

    def test_existing_held_stream_failure_records_real_level_before_raise(self):
        report = {}
        sockets = []
        def connect():
            sock = Socket()
            sockets.append(sock)
            return sock
        def echo(sock, payload):
            if len(sockets) >= 3 and sock is sockets[0] and b'held integrity' in payload:
                raise ConnectionResetError(10054, 'lost existing channel')
        with self.assertRaises(ConnectionResetError):
            probe_capacity(connect, echo, lambda: True, lambda _: None, report,
                           held_limit=3, min_held=2, tiers=(1, 2, 3),
                           recovery_count=1)
        self.assertTrue(report['capacity_baseline_verified'])
        self.assertEqual(report['last_good_verified_held'], 2)
        self.assertEqual(report['peak_held'], 3)
        self.assertEqual(report['held_integrity_failure']['requested_tier'], 3)
        self.assertEqual(report['held_integrity_failure']['held_at_failure'], 3)
        self.assertTrue(all(sock.closed for sock in sockets))

    def test_process_alive_but_recovery_dead_is_not_accepted(self):
        values = iter([Socket(),Socket(),None])
        with self.assertRaisesRegex(RuntimeError,'did not recover'):
            self.run_probe(lambda:next(values))

    def test_invalid_limits(self):
        with self.assertRaises(ValueError):
            self.run_probe(lambda:Socket(),min_held=3)

    def test_diagnostics_coalesce_without_private_stderr(self):
        errors = ResourceErrors()
        for _ in range(10000):
            errors.observe(b'PRIVATE_USER PRIVATE_DOMAIN accept: Too many open files')
        self.assertEqual(errors.snapshot(),{'too_many_open_files':10000})
        self.assertNotIn('PRIVATE',str(vars(errors)))

    def test_pacing_has_exact_start_spacing(self):
        pacer = StartPacer(10,clock=lambda:100.0)
        for expected in (0.0,0.1,0.2,0.3):
            self.assertAlmostEqual(pacer.delay(),expected)

    def test_pacing_does_not_catch_up_after_a_pause(self):
        now = [1.0]
        pacer = StartPacer(10,clock=lambda:now[0])
        pacer.delay(); pacer.delay()
        now[0] = 20.0
        self.assertEqual(pacer.delay(),0.0)
        self.assertAlmostEqual(pacer.delay(),0.1)

    def test_unpaced_and_invalid_rates(self):
        pacer = StartPacer(0)
        self.assertEqual(pacer.delay(),0.0)
        for value in (-1,float('inf'),float('nan')):
            with self.assertRaises(ValueError):
                StartPacer(value)


if __name__ == '__main__':
    unittest.main()
