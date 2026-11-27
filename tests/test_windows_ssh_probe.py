#!/usr/bin/env python3
"""Negative contracts: no zero-channel pass or invented 512-attempt claims."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
from churn_pacing import StartPacer
from windows_real_ssh_hosted import run_raw_probe
from windows_ssh_probe_core import ResourceErrors, probe_capacity, raw_capacity_verified


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

    def test_postauth_server_pipe_limit_is_counted_without_raw_stderr(self):
        errors = ResourceErrors()
        errors.observe(b'user: PRIVATE: pipe(notify_pipe) failed Too many open files [postauth]')
        errors.observe(b'PRIVATE_CLIENT: Too many open files')
        self.assertEqual(errors.snapshot(), {
            'too_many_open_files': 2, 'postauth_notify_pipe_file_limit': 1,
        })
        self.assertNotIn('PRIVATE', str(vars(errors)))

    def test_strict_raw_gate_requires_full_tier_and_recovery(self):
        final = {'requested_tier': 512, 'target_held': 512, 'accepted_held': 512,
                 'test_ceiling_applied': False}
        complete = {'passed': True, 'minimum_required_held': 512, 'selected_held_ceiling': 512,
                    'peak_held': 512, 'attempts': [final], 'capacity_baseline_verified': True,
                    'recovery_successes': 16, 'resource_recovery_verified': True}
        self.assertTrue(raw_capacity_verified(complete))
        for mutation in ({'minimum_required_held': 128}, {'peak_held': 244},
                         {'recovery_successes': 15}, {'resource_recovery_verified': False},
                         {'passed': False}, {'attempts': [{**final, 'accepted_held': 244}]},
                         {'attempts': [{**final, 'test_ceiling_applied': True}]}):
            with self.subTest(mutation=mutation):
                self.assertFalse(raw_capacity_verified({**complete, **mutation}))

    def test_failed_raw_subprocess_preserves_counts_without_private_output(self):
        report = {'raw_backend_512_stability_proved': False}
        with tempfile.TemporaryDirectory() as temp:
            evidence = Path(temp) / 'raw.json'

            def fail_raw(command, *, env, stdout, stderr):
                self.assertEqual(command[command.index('--held') + 1], '512')
                self.assertEqual(command[command.index('--min-held') + 1], '512')
                self.assertEqual(env['FLOWBRIDGE_SSH_VM'], '1')
                self.assertEqual((stdout, stderr), (subprocess.DEVNULL, subprocess.DEVNULL))
                evidence.write_text(json.dumps({
                    'passed': False, 'peak_held': 244, 'actual_connection_attempts': 245,
                    'recovery_successes': 0, 'error_type': 'ConnectionResetError',
                    'error_winerror': 10054, 'error': 'PRIVATE_PROFILE_PATH',
                }), encoding='utf-8')
                return Mock(wait=Mock(return_value=1))

            with patch('windows_real_ssh_hosted.subprocess.Popen', side_effect=fail_raw):
                with self.assertRaisesRegex(RuntimeError, 'did not verify 512'):
                    run_raw_probe('ssh.exe', 'identity', 'known_hosts', 'fixture_user', 12345, evidence, report)
        self.assertEqual(report['raw_backend_peak_held'], 244)
        self.assertEqual(report['raw_backend_observations']['actual_connection_attempts'], 245)
        self.assertFalse(report['bare_backend_probe_passed'])
        self.assertNotIn('PRIVATE', str(report))

    def test_raw_timeout_targets_only_owned_probe_tree(self):
        report = {'raw_backend_512_stability_proved': False}
        child = Mock(pid=12345, poll=Mock(return_value=None),
                     wait=Mock(side_effect=[subprocess.TimeoutExpired('probe', 180), 1]))
        with tempfile.TemporaryDirectory() as temp:
            with (patch('windows_real_ssh_hosted.subprocess.Popen', return_value=child),
                  patch('windows_real_ssh_hosted.subprocess.run', return_value=Mock(returncode=0)) as kill):
                with self.assertRaisesRegex(RuntimeError, 'probe timed out'):
                    run_raw_probe('ssh.exe', 'identity', 'known_hosts', 'fixture_user', 12345,
                                  Path(temp) / 'raw.json', report)
                kill.assert_called_once_with(['taskkill', '/PID', '12345', '/T', '/F'],
                                             capture_output=True, timeout=15, check=False)
        self.assertEqual(report['raw_backend_timeout_cleanup'], 'owned_process_tree_terminated')
        self.assertFalse(report['raw_backend_512_stability_proved'])

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
