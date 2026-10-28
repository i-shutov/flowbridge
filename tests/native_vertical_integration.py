#!/usr/bin/env python3
"""Exercise the native capture C ABI through real TCP sockets, without claiming
that this user-mode test loads WFP or activates a macOS system extension.
"""
import argparse
import concurrent.futures
import copy
import ctypes
import json
from pathlib import Path
import socket
import sys
import threading
import time
from ssh_real_integration import ABI, require, until, free_port
from managed_capacity_integration import Upstream, SocksEcho


def configure(abi):
    signatures = {
        'fb_native_create_json': [ctypes.c_char_p, ctypes.c_char_p],
        'fb_native_reload_json': [ctypes.c_uint64, ctypes.c_char_p],
        'fb_native_set_gate_json': [ctypes.c_uint64, ctypes.c_char_p],
        'fb_native_stream_open_json': [ctypes.c_uint64, ctypes.c_char_p],
        'fb_native_snapshot_json': [ctypes.c_uint64],
    }
    for name, args in signatures.items():
        function = getattr(abi.lib, name)
        function.argtypes, function.restype = args, ctypes.c_void_p
    abi.lib.fb_native_destroy.argtypes = [ctypes.c_uint64]
    abi.lib.fb_native_destroy.restype = None
    for name in ('fb_stream_read', 'fb_stream_write'):
        function = getattr(abi.lib, name)
        function.argtypes = [ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t]
        function.restype = ctypes.c_int64
    abi.lib.fb_stream_shutdown_write.argtypes = [ctypes.c_uint64]
    abi.lib.fb_stream_shutdown_write.restype = ctypes.c_int32
    abi.lib.fb_stream_close.argtypes = [ctypes.c_uint64]
    abi.lib.fb_stream_close.restype = None


def exchange(abi, handle, payload):
    deadline = time.monotonic() + 10
    offset = 0
    while offset < len(payload):
        require(time.monotonic() < deadline, 'Native write deadline')
        data = ctypes.create_string_buffer(payload[offset:])
        count = abi.lib.fb_stream_write(handle, data, len(payload) - offset)
        if count == -2:
            continue
        require(count > 0, f'Native write failed: {count}')
        offset += count
    received = bytearray()
    while len(received) < len(payload):
        require(time.monotonic() < deadline, 'Native read deadline')
        data = ctypes.create_string_buffer(len(payload) - len(received))
        count = abi.lib.fb_stream_read(handle, data, len(data))
        if count == -2:
            continue
        require(count > 0, f'Native read failed: {count}')
        received.extend(data.raw[:count])
    require(bytes(received) == payload, 'Native stream bytes changed')


def rejected(abi, name, *arguments):
    try:
        abi.call(name, *arguments)
    except RuntimeError:
        return
    raise AssertionError(name + ' unexpectedly accepted invalid operation')


def actual_ssh(abi, profile, endpoint, target_port):
    """Invoked from isolated OpenSSH test: no local SOCKS ingress is used."""
    configure(abi)
    native_profile = copy.deepcopy(profile)
    action = native_profile['default_action']
    native_profile['rules'] = [{'id': 'native-app', 'enabled': True,
        'applications': ['flowbridge-native-qa'], 'hosts': [], 'networks': [],
        'ports': [], 'action': action}]
    native_profile['default_action'] = {'type': 'block'}
    options = {'managed_endpoint': endpoint, 'ready': True, 'ready_lease_ms': 10000}
    ident = abi.call('fb_native_create_json', native_profile, options)['session_id']
    stream = 0
    try:
        flow = {'application': 'flowbridge-native-qa',
                'destination': {'host': 'localhost', 'port': target_port}, 'resolved_ip': None}
        opened = abi.call('fb_native_stream_open_json', ident, flow)
        stream = opened['stream_id']
        require(opened['decision']['action']['type'] == 'proxy', 'Native application rule not applied')
        exchange(abi, stream, b'native-to-real-ssh\x00\xff' + bytes(range(256)))
        rejected(abi, 'fb_native_stream_open_json', ident, dict(flow, application='unselected'))
        require(abi.lib.fb_stream_shutdown_write(stream) == 0, 'Native half-close failed')
        until(lambda: abi.lib.fb_stream_read(stream, ctypes.create_string_buffer(1), 1) == 0, 5)
    finally:
        if stream:
            abi.lib.fb_stream_close(stream)
        abi.lib.fb_native_destroy(ident)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    library = {'win32': 'flowbridge_ffi.dll', 'darwin': 'libflowbridge_ffi.dylib'}.get(sys.platform, 'libflowbridge_ffi.so')
    abi = ABI(root / 'target/debug' / library)
    configure(abi)
    server = Upstream(('127.0.0.1', 0), SocksEcho)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = {'host': '127.0.0.1', 'port': server.server_address[1]}
    profile = {'version': 1, 'listen': f'127.0.0.1:{free_port()}',
        'proxies': [{'id': 'ssh', 'kind': 'socks5', 'endpoint': endpoint}],
        'chains': [], 'rules': [{'id': 'selected', 'enabled': True,
            'applications': ['qa-selected'], 'hosts': [], 'networks': [], 'ports': [],
            'action': {'type': 'proxy', 'id': 'ssh'}}],
        'default_action': {'type': 'block'}, 'connect_timeout_ms': 2000,
        'handshake_timeout_ms': 2000, 'idle_timeout_ms': 60000, 'max_connections': 8}
    options = {'managed_endpoint': endpoint, 'ready': False, 'ready_lease_ms': 300,
        'pause_grace_ms': 2500, 'limits': {'max_flows': 2, 'max_opening': 1,
            'max_queued': 2, 'wait_timeout_ms': 2000}}
    flow = {'application': 'qa-selected', 'destination': {'host': 'capacity.invalid', 'port': 443}, 'resolved_ip': None}
    sessions, streams = [], []
    report = {'passed': False, 'os_capture_exercised': False, 'checks': []}
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=4)
    try:
        ident = abi.call('fb_native_create_json', profile, options)['session_id']
        sessions.append(ident)
        rejected(abi, 'fb_native_create_json', profile, dict(options, invented=True))
        rejected(abi, 'fb_native_set_gate_json', ident, {'ready': True, 'unverified': 1})
        rejected(abi, 'fb_native_stream_open_json', ident, dict(flow, application='not-selected'))
        pending = pool.submit(abi.call, 'fb_native_stream_open_json', ident, flow)
        time.sleep(.1)
        require(not pending.done() and server.active == 0, 'A paused native route opened upstream')
        abi.call('fb_native_set_gate_json', ident, {'ready': True})
        first = pending.result(timeout=5)['stream_id']
        streams.append(first)
        exchange(abi, first, b'first-native\x00\xff')
        report['checks'].append('Selected native flow waits for SSH; hostname reaches SOCKS, no local ingress required')

        # Upstream-ready is leased; stale UI/service heartbeats cannot stay green.
        time.sleep(.35)
        pending = pool.submit(abi.call, 'fb_native_stream_open_json', ident, flow)
        time.sleep(.1)
        require(not pending.done() and server.active == 1, 'Expired readiness admitted another native flow')
        abi.call('fb_native_set_gate_json', ident, {'ready': True})
        second = pending.result(timeout=5)['stream_id']
        streams.append(second)
        exchange(abi, first, b'old-stream-remains-usable')
        report['checks'].append('Readiness expiry pauses NEW streams without dropping existing data')

        # A second native context shares the same underlying process budget.
        other = abi.call('fb_native_create_json', profile, dict(options, ready=True))['session_id']
        sessions.append(other)
        pending = pool.submit(abi.call, 'fb_native_stream_open_json', other, flow)
        time.sleep(.1)
        require(not pending.done(), 'Second context bypassed the shared capacity')
        start = time.monotonic()
        abi.lib.fb_native_destroy(other)
        sessions.remove(other)
        try:
            pending.result(timeout=1)
            raise AssertionError('Destroyed context returned a stream')
        except RuntimeError:
            pass
        require(time.monotonic() - start < 1, 'Stop did not cancel pending native opening')
        report['checks'].append('Shared upstream limits span native contexts; destruction interrupts waits')

        # Rule replacement does not alter an existing stream's decision.
        changed = copy.deepcopy(profile)
        changed['rules'] = []
        abi.call('fb_native_reload_json', ident, changed)
        rejected(abi, 'fb_native_stream_open_json', ident, flow)
        exchange(abi, first, b'policy-reload-keeps-existing-stream')
        invalid = copy.deepcopy(changed)
        invalid['max_connections'] = 9
        rejected(abi, 'fb_native_reload_json', ident, invalid)
        snapshot = abi.call('fb_native_snapshot_json', ident)
        require(snapshot['status']['bytes_up'] > 0 and snapshot['status']['bytes_down'] > 0, 'Native traffic counters missing')
        report['checks'].append('Live rules affect new flows; transport mutation rejected; real counters present')
        abi.lib.fb_native_destroy(ident)
        sessions.remove(ident)
        require(abi.lib.fb_stream_read(first, ctypes.create_string_buffer(1), 1) < 0, 'Destroyed session retained stream handle')
        report['checks'].append('Stop closes owned streams and removes checked handles')
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        for ident in sessions:
            abi.lib.fb_native_destroy(ident)
        for ident in streams:
            abi.lib.fb_stream_close(ident)
        pool.shutdown(wait=True, cancel_futures=True)
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2), flush=True)

if __name__ == '__main__':
    main()
