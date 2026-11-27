"""Verify 512 simultaneously held streams through the real Win32 owned SSH pool."""
import ctypes
from ctypes import wintypes
from collections import Counter
from contextlib import ExitStack
import errno
import json
from pathlib import Path
import socket
import subprocess

from real_ssh_capacity import exchange
from ssh_real_integration import distinct_free_ports, exact, require, until

WORKERS = 4
PER_WORKER = 128
HELD = WORKERS * PER_WORKER
QUEUE_PER_WORKER = 16
OVERLOAD = WORKERS * (QUEUE_PER_WORKER + 4)
RECOVERY = 16
LIMITS = {'max_flows': PER_WORKER, 'max_opening': 16,
          'max_queued': QUEUE_PER_WORKER, 'wait_timeout_ms': 10000}
SOCKS_OK = b'\x05\x00\x00\x01' + bytes(6)
SOCKS_GENERAL_FAILURE = b'\x05\x01\x00\x01' + bytes(6)
CAPACITY_TIMEOUT = 'managed SSH capacity deadline expired; no direct fallback'
QUEUE_FULL = 'managed SSH queue is full; no direct fallback'
NO_READY_WORKERS = 'all managed SSH pool workers are unavailable; no DIRECT fallback'


def parse_policy(output, ids):
    request = json.loads(output)
    expected = {'ssh_ids': ids, 'enabled': True, 'limits': LIMITS, 'aggregate_max_flows': HELD}
    require(json.dumps(request, sort_keys=True) == json.dumps(expected, sort_keys=True),
            'The actual Win32 policy does not request four 128-flow workers')
    return request


def worker_admission(snapshot, ports, ready=True):
    pool = snapshot['managed_pool']
    require(snapshot['managed_upstream'] is None and pool is not None,
            'Engine snapshot is missing the managed pool')
    require(pool['aggregate_max_flows'] == HELD
            and pool['ready_workers'] == (len(ports) if ready else 0)
            and len(pool['workers']) == len(ports),
            'Managed pool count, readiness or aggregate limit did not match')
    admission = {}
    for worker in pool['workers']:
        endpoint = worker['endpoint']
        port = endpoint['port']
        require(endpoint['host'] == '127.0.0.1' and port in ports and port not in admission
                and worker['ready'] is ready,
                'Pool selected an unknown, duplicate or unexpectedly ready worker')
        counters = worker['admission']
        require(counters['limits'] == LIMITS, 'Worker admission limits changed')
        admission[port] = counters
    return admission


def verify_active(snapshot, ports, target_port, per_worker, min_bytes):
    admission = worker_admission(snapshot, ports)
    active = [row for row in snapshot['connections'] if row['state'] == 'active']
    expected = Counter(dict.fromkeys(ports, per_worker))
    require(snapshot['status']['running'] and snapshot['status']['active'] == sum(expected.values())
            and len(active) == sum(expected.values())
            and len({row['id'] for row in active}) == len(active),
            'Engine did not retain every simultaneously held application stream')
    require(Counter(row.get('worker_port') for row in active) == expected,
            'Active streams do not show the expected real worker distribution')
    require(all(row['action'] == 'proxy:managed-ssh'
                and row['host'] == '127.0.0.1' and row['port'] == target_port
                and row['bytes_up'] >= min_bytes and row['bytes_down'] >= min_bytes
                for row in active),
            'Active route or bidirectional byte evidence is incomplete')
    require(all(counters['active_including_opening'] == per_worker
                and counters['opening'] == counters['queued'] == 0
                for counters in admission.values()),
            'Active streams were not charged to the expected worker budgets')
    return admission


def verify_overload(snapshot, ports, first_overload_id, baseline):
    admission = worker_admission(snapshot, ports)
    rows = [row for row in snapshot['connections'] if row['id'] > first_overload_id]
    expected = Counter({(port, reason): count for port in ports
                        for reason, count in ((QUEUE_FULL, 4), (CAPACITY_TIMEOUT, QUEUE_PER_WORKER))})
    require(Counter((row.get('worker_port'), row['error']) for row in rows) == expected
            and all(row['state'] == 'failed' for row in rows),
            'Engine did not account for every excess request in the expected worker queue')
    require(all(counters['rejected'] - baseline[port]['rejected'] == OVERLOAD // WORKERS
                for port, counters in admission.items()),
            'Worker rejection counters did not increase by the expected amount')
    return admission


def permits_zero(snapshot, ports, ready=True):
    admission = worker_admission(snapshot, ports, ready)
    return snapshot['status']['active'] == 0 and all(
        counters['active_including_opening'] == counters['opening'] == counters['queued'] == 0
        for counters in admission.values())


class WindowsChild:
    """Keep an OS handle to the original process object across Stop and PID reuse."""

    def __init__(self, pid, executable):
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.QueryFullProcessImageNameW.argtypes = (
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD))
        kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
        kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel.CloseHandle.restype = wintypes.BOOL
        self.kernel = kernel
        self.handle = kernel.OpenProcess(0x100000 | 0x1000, False, pid)
        require(self.handle, 'Could not observe the owned Windows SSH process')
        try:
            size = wintypes.DWORD(32768)
            image = ctypes.create_unicode_buffer(size.value)
            require(kernel.QueryFullProcessImageNameW(self.handle, 0, image, ctypes.byref(size)),
                    'Could not observe the owned Windows SSH process image')
            require(Path(image.value).samefile(executable),
                    'Owned process image differs from the approved SSH executable')
            require(self.alive(), 'Owned Windows SSH child exited before measurement')
        except BaseException:
            self.close()
            raise

    def alive(self):
        result = self.kernel.WaitForSingleObject(self.handle, 0)
        require(result in (0, 0x102), 'Could not query the owned SSH process state')
        return result == 0x102

    def close(self):
        self.kernel.CloseHandle(self.handle)


def begin_connect(ingress, target):
    client = socket.create_connection(('127.0.0.1', ingress), timeout=20)
    try:
        client.sendall(b'\x05\x01\x00')
        require(exact(client, 2) == b'\x05\x00', 'Managed SOCKS greeting failed')
        client.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + target.to_bytes(2, 'big'))
        return client
    except BaseException:
        client.close()
        raise


def payload(phase, index):
    return b'FlowBridge owned SSH pool\x00\xff' + bytes([phase]) + index.to_bytes(2, 'big')


def verify_listener_closed(port):
    with socket.socket() as client:
        client.settimeout(2)
        require(client.connect_ex(('127.0.0.1', port))
                in (errno.ECONNREFUSED, 10061),
                'Expected stopped loopback listener to refuse connections')


def run(abi, settings, target_port, policy_executable, output):
    report = {'passed': False, 'stage': 'setup', 'target_held': HELD,
              'peak_held': 0, 'verified_under_overload': 0, 'overload_replies': 0,
              'recovery_successes': 0, 'children': [], 'release_zero_permits': False,
              'stop_zero_permits': False, 'stop_cleared_pool': False,
              'stop_original_children_exited': False, 'stop_listeners_closed': False}
    try:
        with ExitStack() as stack:
            ingress, *ports = distinct_free_ports(WORKERS + 1)
            require(len({settings['port'], target_port, ingress, *ports}) == WORKERS + 3,
                    'Test fixture endpoints collided')
            ids = []
            for port in ports:
                ident = abi.call('fb_ssh_create_json', dict(settings, local_port=port))['ssh_id']
                stack.callback(abi.lib.fb_ssh_destroy, ident)
                ids.append(ident)
            require(len(set(ids)) == WORKERS and all(ids), 'Duplicated SSH supervisor handles')
            policy = subprocess.check_output([str(policy_executable), *map(str, ids)],
                                             text=True, timeout=10)
            request = parse_policy(policy, ids)
            profile = {
                'version': 1, 'listen': f'127.0.0.1:{ingress}',
                'proxies': [{'id': 'managed-ssh', 'kind': 'socks5',
                             'endpoint': {'host': '127.0.0.1', 'port': ports[0]}}],
                'chains': [], 'rules': [], 'default_action': {'type': 'proxy', 'id': 'managed-ssh'},
                # Headroom allows overload to reach the pool's own queues.
                'max_connections': HELD + OVERLOAD, 'connect_timeout_ms': 10000,
                'handshake_timeout_ms': 10000, 'idle_timeout_ms': 300000,
            }
            engine = abi.call('fb_engine_create_json', profile)['engine_id']
            stack.callback(abi.lib.fb_engine_destroy, engine)

            def sync(enabled):
                abi.call('fb_engine_sync_owned_ssh_pool_json', engine, dict(request, enabled=enabled))

            def snapshot():
                return abi.call('fb_engine_snapshot_json', engine)

            def status(ident):
                return abi.call('fb_ssh_snapshot_json', ident)['status']

            sync(False)
            require(permits_zero(snapshot(), ports, ready=False), 'Stopped pool already had permits')
            report['stage'] = 'starting_owned_children'
            children = []
            for ident, port in zip(ids, ports):
                abi.call('fb_ssh_start_json', ident)

                def ready():
                    observed = status(ident)
                    require(observed['state'] != 'failed', 'Owned SSH supervisor failed to start')
                    return observed if observed['state'] == 'ready' and observed['pid'] else False

                observed = until(ready, seconds=45)
                pid = observed['pid']
                require(observed['local_port'] == port
                        and pid not in [item['pid'] for item in report['children']],
                        'Owned supervisors reused a process or listener')
                child = WindowsChild(pid, settings['ssh_executable'])
                stack.callback(child.close)
                children.append(child)
                report['children'].append({'pid': pid, 'worker_port': port,
                                           'version': observed['backend_version']})

            def same_children():
                for ident, child, before in zip(ids, children, report['children']):
                    current = status(ident)
                    require(child.alive() and current['state'] == 'ready'
                            and current['pid'] == before['pid'] and current['restarts'] == 0
                            and current['resource_exhaustion_count'] == 0,
                            'SSH worker exited, restarted or exhausted resources under load')

            sync(True)
            same_children()
            require(permits_zero(snapshot(), ports), 'Ready pool started with nonzero permits')
            abi.call('fb_engine_start_json', engine)
            report['stage'] = 'holding_512'
            held = []
            for index in range(HELD):
                client = stack.enter_context(begin_connect(ingress, target_port))
                require(exact(client, len(SOCKS_OK)) == SOCKS_OK,
                        'Engine rejected a stream inside the reviewed pool limit')
                exchange(client, payload(1, index))
                held.append(client)
                report['peak_held'] = len(held)
            first = snapshot()
            report['admission_peak'] = verify_active(
                first, ports, target_port, PER_WORKER, len(payload(1, 0)))
            same_children()
            first_overload_id = max(row['id'] for row in first['connections'])

            report['stage'] = 'overload'
            excessive = [stack.enter_context(begin_connect(ingress, target_port))
                         for _ in range(OVERLOAD)]
            def full_queue():
                state = worker_admission(snapshot(), ports)
                if all(counters['queued'] == QUEUE_PER_WORKER
                       and counters['active_including_opening'] == PER_WORKER
                       and counters['opening'] == 0 for counters in state.values()):
                    return state
                return False

            report['admission_queue_peak'] = until(full_queue, seconds=5)
            for client in excessive:
                require(exact(client, len(SOCKS_GENERAL_FAILURE)) == SOCKS_GENERAL_FAILURE,
                        'Excess opening did not receive the expected SOCKS general failure')
                client.close()
                report['overload_replies'] += 1
            for index, client in enumerate(held):
                exchange(client, payload(2, index))
                report['verified_under_overload'] += 1
            overloaded = snapshot()
            verify_active(overloaded, ports, target_port, PER_WORKER, 2 * len(payload(1, 0)))
            report['admission_after_overload'] = verify_overload(
                overloaded, ports, first_overload_id, report['admission_peak'])
            same_children()

            report['stage'] = 'release'
            for client in held:
                client.shutdown(socket.SHUT_WR)
                require(client.recv(1) == b'', 'Held stream did not propagate half-close')
                client.close()
            until(lambda: permits_zero(snapshot(), ports), seconds=15)
            report['release_zero_permits'] = True

            report['stage'] = 'recovery_and_pause'
            recovered = []
            for index in range(RECOVERY):
                client = stack.enter_context(begin_connect(ingress, target_port))
                require(exact(client, len(SOCKS_OK)) == SOCKS_OK, 'New SSH stream failed after release')
                exchange(client, payload(3, index))
                recovered.append(client)
                report['recovery_successes'] += 1
            report['admission_recovered'] = verify_active(
                snapshot(), ports, target_port, RECOVERY // WORKERS, len(payload(3, 0)))
            same_children()
            sync(False)
            with begin_connect(ingress, target_port) as client:
                require(exact(client, len(SOCKS_GENERAL_FAILURE)) == SOCKS_GENERAL_FAILURE,
                        'Paused pool did not deny new SOCKS connections')
            def paused_failure():
                state = snapshot()
                recent = max(state['connections'], key=lambda row: row['id'])
                return state if recent['state'] == 'failed' and recent['error'] == NO_READY_WORKERS else False

            paused = until(paused_failure, seconds=5)
            worker_admission(paused, ports, ready=False)
            for index, client in enumerate(recovered):
                exchange(client, payload(4, index))
            report['paused_admission_failed_closed'] = True

            report['stage'] = 'stop'
            abi.call('fb_engine_stop_json', engine)
            stopped = snapshot()
            require(not stopped['status']['running'] and permits_zero(stopped, ports, ready=False),
                    'Stop leaked engine activity or admission permits')
            report['stop_zero_permits'] = True
            for client in recovered:
                try:
                    require(client.recv(1) == b'', 'Stopped engine kept a live relay')
                except ConnectionResetError:
                    pass
            abi.call('fb_engine_set_upstream_gate_json', engine,
                     {'endpoint': None, 'ready': False, 'grace_ms': 0})
            cleared = snapshot()
            require(cleared['managed_pool'] is None and cleared['managed_upstream'] is None,
                    'Stop did not clear the managed pool')
            report['stop_cleared_pool'] = True
            for ident in ids:
                abi.call('fb_ssh_stop_json', ident)
                observed = status(ident)
                require(observed['state'] == 'stopped' and observed['pid'] is None,
                        'Supervisor retained a child after Stop')
            require(all(not child.alive() for child in children), 'Stop leaked an original SSH child')
            report['stop_original_children_exited'] = True
            for port in (ingress, *ports):
                verify_listener_closed(port)
            report['stop_listeners_closed'] = True
        report['stage'] = 'complete'
        report['passed'] = True
        return report
    except Exception as error:
        report['error_type'] = type(error).__name__
        report['error'] = str(error) if not isinstance(error, subprocess.CalledProcessError) else (
            'Win32 pool policy process failed')
        raise
    finally:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'managed_ssh_pool_512': report}), flush=True)
