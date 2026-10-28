#!/usr/bin/env python3
"""Bounded loopback-only overload QA through two engines and one mock upstream.
Not a measurement of any real OpenSSH backend's capacity.
"""
import argparse
import concurrent.futures
import ctypes
import json
from pathlib import Path
import socket
import socketserver
import sys
import threading
from ssh_real_integration import ABI, exact, require, free_port, until

class Upstream(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 256
    active = 0
    peak = 0
    lock = threading.Lock()

class SocksEcho(socketserver.BaseRequestHandler):
    def handle(self):
        active = False
        try:
            self.request.settimeout(15)
            require(exact(self.request, 3) == b'\x05\x01\x00', 'Bad method negotiation')
            self.request.sendall(b'\x05\x00')
            header = exact(self.request, 4)
            require(header == b'\x05\x01\x00\x03', 'Target hostname was not preserved')
            hostname = exact(self.request, exact(self.request, 1)[0])
            require(hostname == b'capacity.invalid', 'Unexpected target')
            require(exact(self.request, 2) == (443).to_bytes(2, 'big'), 'Unexpected target port')
            with self.server.lock:
                self.server.active += 1
                active = True
                self.server.peak = max(self.server.peak, self.server.active)
            self.request.sendall(b'\x05\x00\x00\x01' + bytes(6))
            while data := self.request.recv(8192):
                self.request.sendall(data)
        except (ConnectionError, OSError):
            pass
        finally:
            if active:
                with self.server.lock:
                    self.server.active -= 1

def connect(port):
    client = socket.create_connection(('127.0.0.1', port), timeout=5)
    try:
        client.sendall(b'\x05\x01\x00')
        require(exact(client, 2) == b'\x05\x00', 'Ingress greeting failed')
        host = b'capacity.invalid'
        client.sendall(b'\x05\x01\x00\x03' + bytes([len(host)]) + host + (443).to_bytes(2, 'big'))
        reply = exact(client, 10)
        require(reply[:1] == b'\x05', 'Invalid SOCKS response')
        return client, reply[1]
    except Exception:
        client.close()
        raise

def check_diagnostics(abi):
    function = abi.lib.fb_diagnostic_report_json
    function.argtypes = [ctypes.c_char_p]
    function.restype = ctypes.c_void_p
    request = {
        'engine': {'status': {'active': 4, 'listen': 'PRIVATE_LISTENER'},
                   'connections': [{'host': 'PRIVATE_HOST'}],
                   'events': [{'message': 'PRIVATE_EVENT'}],
                   'managed_upstream': {'queued': 2, 'limits': {'max_flows': 128}}},
        'ssh': {'status': {'state': 'degraded', 'diagnostic_code': 'ssh_resource_exhausted',
                           'resource_exhaustion_count': 27, 'backend_path': 'PRIVATE_PATH',
                           'last_error': 'PRIVATE_ERROR', 'backend_version': 'OpenSSH_9.9p1, SSL'},
                'stderr': ['PRIVATE_STDERR']},
        'identity_file': 'PRIVATE_KEY',
    }
    for _ in range(32):
        answer = abi.call('fb_diagnostic_report_json', request)['report']
        require('PRIVATE_' not in json.dumps(answer), 'Diagnostic report leaked private fixture data')
        require(answer['engine']['active'] == 4, 'Diagnostic counter lost')
        require(answer['ssh']['resource_exhaustion_count'] == 27, 'Resource diagnostic lost')
        require(answer['managed_upstream']['limits']['max_flows'] == 128, 'Admission limits lost')
        require(answer['coverage']['os_descriptor_count_measured'] is False, 'Invented OS measurement')
    for invalid in [None, b'not json', b'\xff']:
        pointer = function(invalid)
        require(pointer, 'Null error response')
        try:
            require(json.loads(ctypes.string_at(pointer))['ok'] is False, 'Invalid report input accepted')
        finally:
            abi.lib.fb_string_free(pointer)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    library = {'win32': 'flowbridge_ffi.dll', 'darwin': 'libflowbridge_ffi.dylib'}.get(sys.platform, 'libflowbridge_ffi.so')
    abi = ABI(root / 'target/debug' / library)
    report = {'passed': False, 'real_ssh_backend': False, 'checks': [], 'attempted_new_flows': 0}
    engines, clients, ports = [], [], []
    server = Upstream(('127.0.0.1', 0), SocksEcho)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    endpoint = {'host': '127.0.0.1', 'port': server.server_address[1]}
    limits = {'max_flows': 4, 'max_opening': 2, 'max_queued': 8, 'wait_timeout_ms': 150}
    try:
        check_diagnostics(abi)
        report['checks'].append('Diagnostic C ABI export redacts private fields, preserves counters and rejects invalid input')
        for _ in range(2):
            port = free_port()
            require(port not in ports and port != endpoint['port'], 'Ephemeral port collision')
            ports.append(port)
            profile = {'version': 1, 'listen': f'127.0.0.1:{port}',
                       'proxies': [{'id': 'ssh', 'kind': 'socks5', 'endpoint': endpoint}],
                       'chains': [], 'rules': [], 'default_action': {'type': 'proxy', 'id': 'ssh'},
                       'connect_timeout_ms': 3000, 'handshake_timeout_ms': 3000,
                       'idle_timeout_ms': 60000, 'max_connections': 128}
            engine = abi.call('fb_engine_create_json', profile)['engine_id']
            engines.append(engine)
            abi.call('fb_engine_set_upstream_gate_json', engine,
                     {'endpoint': endpoint, 'ready': True, 'grace_ms': 1000, 'limits': limits})
            abi.call('fb_engine_start_json', engine)
        for i in range(4):
            client, code = connect(ports[i % 2])
            clients.append(client)
            require(code == 0, 'Baseline connection failed')
        until(lambda: server.active == 4, 5)
        report['checks'].append('Two engine instances share four upstream slots')

        def reject(i):
            client, code = connect(ports[i % 2])
            client.close()
            require(code == 1, f'Overloaded request unexpectedly succeeded or returned {code}')
        for attempted in [64, 128, 192, 256, 512]:
            with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
                list(pool.map(reject, range(attempted)))
            report['attempted_new_flows'] += attempted
            for engine in engines:
                status = abi.call('fb_engine_snapshot_json', engine)['managed_upstream']
                require(status['active_including_opening'] == 4, 'Shared active budget drifted')
                require(status['queued'] <= 8 and status['opening'] <= 2, 'Budget exceeded')
            for i, client in enumerate(clients):
                payload = b'held-stream\x00\xff' + bytes([i]) + attempted.to_bytes(2, 'big')
                client.sendall(payload)
                require(exact(client, len(payload)) == payload, 'Established stream damaged under load')
            report['checks'].append(f'{attempted} additional attempts rejected; established bytes preserved')
        require(server.peak == 4, f'Upstream peak exceeded limit: {server.peak}')
        for client in clients:
            client.shutdown(socket.SHUT_WR)
            require(client.recv(1) == b'', 'Half-close failed')
            client.close()
        clients.clear()
        until(lambda: server.active == 0, 5)
        until(lambda: all(abi.call('fb_engine_snapshot_json', e)['managed_upstream']['active_including_opening'] == 0 for e in engines), 5)
        client, code = connect(ports[0])
        clients.append(client)
        require(code == 0, 'Admission failed to recover after draining')
        client.sendall(b'recovered')
        require(exact(client, 9) == b'recovered', 'Recovered path failed')
        report['checks'].append('Capacity reclaimed; new flow succeeds after load drains')
        report['upstream_peak'] = server.peak
        report['budget'] = abi.call('fb_engine_snapshot_json', engines[0])['managed_upstream']
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        for client in clients:
            client.close()
        for engine in engines:
            abi.lib.fb_engine_destroy(engine)
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2), flush=True)

if __name__ == '__main__':
    main()
