"""Negative controls for Windows managed pool proof and original candidate pins."""
from copy import deepcopy
from pathlib import Path
import errno
import json
import socket
import struct
import tempfile
import unittest

from windows_managed_ssh_pool_capacity import (
    CAPACITY_TIMEOUT, HELD, LIMITS, PER_WORKER, QUEUE_FULL,
    describe_listeners, observe_connect, parse_listener_table, parse_policy, permits_zero,
    verify_active, verify_closed_listeners, verify_overload,
)
from windows_real_ssh_hosted import sha256, verify_candidate

PORTS = (53001, 53003, 53005, 53007)
TARGET = 53100


def observed_snapshot():
    return {
        'status': {'running': True, 'active': HELD},
        'managed_upstream': None,
        'managed_pool': {'aggregate_max_flows': HELD, 'ready_workers': len(PORTS),
                         'workers': [
                             {'endpoint': {'host': '127.0.0.1', 'port': port}, 'ready': True,
                              'admission': {'limits': dict(LIMITS), 'active_including_opening': PER_WORKER,
                                            'opening': 0, 'queued': 0, 'rejected': 0}}
                             for port in PORTS
                         ]},
        'connections': [
            {'id': index * PER_WORKER + offset + 1, 'state': 'active', 'worker_port': port,
             'action': 'proxy:managed-ssh', 'host': '127.0.0.1', 'port': TARGET,
             'bytes_up': 64, 'bytes_down': 64}
            for index, port in enumerate(PORTS) for offset in range(PER_WORKER)
        ],
    }


class ManagedPoolEvidenceTests(unittest.TestCase):
    def test_policy_parser_rejects_old_cap_substituted_handles_and_fabricated_readiness(self):
        owned = [1, 2, 3, 4]
        policy = {'ssh_ids': owned, 'enabled': True, 'limits': dict(LIMITS), 'aggregate_max_flows': HELD}
        self.assertEqual(parse_policy(json.dumps(policy), owned), policy)
        for patch in ({'aggregate_max_flows': 128}, {'ssh_ids': [1, 2, 3, 3]},
                      {'enabled': 1}, {'ready': True}, {'limits': dict(LIMITS, max_flows=32)}):
            with self.subTest(patch=patch), self.assertRaises(RuntimeError):
                parse_policy(json.dumps(dict(policy, **patch)), owned)

    def test_peak_rejects_below_512_and_unowned_or_unverified_stream(self):
        valid = observed_snapshot()
        self.assertEqual(set(verify_active(valid, PORTS, TARGET, PER_WORKER, 64)), set(PORTS))
        valid['connections'].pop()
        valid['status']['active'] -= 1
        with self.assertRaisesRegex(RuntimeError, 'every simultaneously held'):
            verify_active(valid, PORTS, TARGET, PER_WORKER, 64)
        for patch in ({'worker_port': 12345}, {'action': 'direct'}, {'bytes_down': 0}, {'id': 2}):
            with self.subTest(patch=patch), self.assertRaises(RuntimeError):
                invalid = observed_snapshot()
                invalid['connections'][0].update(patch)
                verify_active(invalid, PORTS, TARGET, PER_WORKER, 64)

    def test_peak_rejects_duplicate_workers_or_substituted_per_worker_limit(self):
        valid = observed_snapshot()
        workers = valid['managed_pool']['workers']
        workers[0]['admission']['limits']['max_flows'] = 129
        with self.assertRaisesRegex(RuntimeError, 'limits changed'):
            verify_active(valid, PORTS, TARGET, PER_WORKER, 64)
        workers[0] = deepcopy(workers[1])
        with self.assertRaisesRegex(RuntimeError, 'duplicate'):
            verify_active(valid, PORTS, TARGET, PER_WORKER, 64)

    def test_overload_rejects_missing_or_unexplained_failures_and_wrong_counters(self):
        data = observed_snapshot()
        baseline = deepcopy(verify_active(data, PORTS, TARGET, PER_WORKER, 64))
        for worker in data['managed_pool']['workers']:
            worker['admission']['rejected'] = 20
            port = worker['endpoint']['port']
            for error in [QUEUE_FULL] * 4 + [CAPACITY_TIMEOUT] * 16:
                data['connections'].append({'id': len(data['connections']) + 1, 'worker_port': port,
                                            'state': 'failed', 'error': error})
        verify_overload(data, PORTS, HELD, baseline)
        clone = deepcopy(data)
        clone['connections'].pop()
        with self.assertRaisesRegex(RuntimeError, 'every excess request'):
            verify_overload(clone, PORTS, HELD, baseline)
        clone = deepcopy(data)
        clone['connections'][-1]['error'] = 'Upstream refused'
        with self.assertRaisesRegex(RuntimeError, 'every excess request'):
            verify_overload(clone, PORTS, HELD, baseline)
        data['managed_pool']['workers'][0]['admission']['rejected'] -= 1
        with self.assertRaisesRegex(RuntimeError, 'rejection counters'):
            verify_overload(data, PORTS, HELD, baseline)

    def test_zero_permits_requires_all_workers_and_engine_idle(self):
        observed = observed_snapshot()
        workers = observed['managed_pool']['workers']
        observed['status']['active'] = 0
        for worker in workers:
            worker['admission']['active_including_opening'] = 0
        self.assertTrue(permits_zero(observed, PORTS))
        for key in ('active_including_opening', 'opening', 'queued'):
            with self.subTest(key=key):
                workers[-1]['admission'][key] = 1
                self.assertFalse(permits_zero(observed, PORTS))
                workers[-1]['admission'][key] = 0
        observed['status']['active'] = 1
        self.assertFalse(permits_zero(observed, PORTS))


class CandidateEvidenceTests(unittest.TestCase):
    def test_candidate_source_and_exact_dll_payload_are_both_required(self):
        with tempfile.TemporaryDirectory() as directory:
            dll, manifest_path = (Path(directory) / f for f in ('flowbridge_ffi.dll', 'package.json'))
            dll.write_bytes(b'example FFI')
            digest = sha256(dll)
            source = 'a' * 40
            entry = {'path': dll.name, 'sha256': digest, 'bytes': dll.stat().st_size}
            manifest = {'schema': 'flowbridge-explicit-beta-windows-qa-package-v1',
                        'candidate': '0.3.0-beta.4', 'source_sha': source,
                        'installer_sha256': 'b' * 64, 'explicit_socks_only': True,
                        'payload': [entry]}
            manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
            self.assertEqual(verify_candidate(manifest_path, source, dll, digest)['candidate_source_commit'],
                             source)
            for bad_source, bad_hash in (('c' * 40, digest), (source, 'd' * 64)):
                with self.subTest(source=bad_source, digest=bad_hash), self.assertRaises(RuntimeError):
                    verify_candidate(manifest_path, bad_source, dll, bad_hash)
            manifest['payload'].append(entry)
            manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
            with self.assertRaisesRegex(RuntimeError, 'payload manifest'):
                verify_candidate(manifest_path, source, dll, digest)


class ListenerEvidenceTests(unittest.TestCase):
    def test_ip_helper_ipv4_and_ipv6_listener_table_byte_order_and_truncation(self):
        port, pid = PORTS[0], 432
        ipv4 = struct.pack('<I', 1) + struct.pack(
            '<6I', 2, 0x0100007F, socket.htons(port), 0, 0, pid)
        ipv6 = struct.pack('<I', 1) + struct.pack(
            '<16sII16sIIII', bytes(15) + b'\x01', 0, socket.htons(port), bytes(16), 0, 0, 2, pid)
        for family, table in ((socket.AF_INET, ipv4), (socket.AF_INET6, ipv6)):
            with self.subTest(family=family):
                self.assertEqual(parse_listener_table(table, family, PORTS), [(port, family, pid, True)])
                self.assertEqual(parse_listener_table(table, family, (TARGET,)), [])
                with self.assertRaisesRegex(RuntimeError, 'truncated'):
                    parse_listener_table(table[:-1], family, PORTS)

    def test_listener_gate_rejects_silent_timeout_live_listener_and_wrong_owner(self):
        expected = [('engine', TARGET, 50)] + [
            (f'ssh_worker_{i}', port, 50 + i) for i, port in enumerate(PORTS, start=1)]
        live = [(port, socket.AF_INET, pid, True) for _, port, pid in expected]
        before = describe_listeners(live, expected)
        after = describe_listeners([], expected)
        observed = [{'role': role, 'final_socket_code': 10061} for role, _, _ in expected]
        verify_closed_listeners(before, after, observed)
        for code in (0, 10035, None):
            with self.subTest(code=code), self.assertRaisesRegex(RuntimeError, 'confirmed TCP refusal'):
                verify_closed_listeners(before, after, [dict(observed[0], final_socket_code=code), *observed[1:]])
        with self.assertRaisesRegex(RuntimeError, 'LISTEN socket'):
            verify_closed_listeners(before, describe_listeners([live[-1]], expected), observed)
        wrong = [(TARGET, socket.AF_INET, 999, True), *live[1:]]
        with self.assertRaisesRegex(RuntimeError, 'expected process'):
            verify_closed_listeners(describe_listeners(wrong, expected), after, observed)
        with self.assertRaisesRegex(RuntimeError, 'all four workers'):
            verify_closed_listeners(before[:-1], after, observed)

    def test_nonblocking_completion_distinguishes_real_listener_from_refusal(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
            listener.listen()
            self.assertEqual(observe_connect(port)['final_socket_code'], 0)
            with listener.accept()[0]:
                pass
        observation = observe_connect(port)
        self.assertIn(observation['final_socket_code'], (errno.ECONNREFUSED, 10061))
        self.assertFalse(observation['connect_timed_out'])


if __name__ == '__main__':
    unittest.main()
