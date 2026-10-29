#!/usr/bin/env python3
"""Native DNS wire path and UDP/TCP stub on isolated loopback endpoints.
OS resolver settings and native kernel filters are not modified by this test.
"""
import argparse
import copy
import ctypes
import json
from pathlib import Path
import socket
import socketserver
import struct
import sys
import threading
from ssh_real_integration import ABI, exact, free_port, require, until
from native_vertical_integration import configure as native_configure, rejected


def query(ident=0x1234, kind=1):
    return struct.pack('!6H', ident, 0x0100, 1, 0, 0, 0) + b'\x0bonly-on-ssh\x04test\0' + struct.pack('!HH', kind, 1)


def answer(question):
    ident = struct.unpack('!H', question[:2])[0]
    kind = struct.unpack('!H', question[-4:-2])[0]
    payload = socket.inet_pton(socket.AF_INET6, '2001:db8::123') if kind == 28 else socket.inet_aton('192.0.2.123')
    return struct.pack('!6H', ident ^ (1 if ident == 0xbeef else 0), 0x8180, 1, 1, 0, 0) + question[12:] + b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 30, len(payload)) + payload


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 32
    requests = 0
    lock = threading.Lock()


class Resolver(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            length = int.from_bytes(exact(self.request, 2), 'big')
            require(12 <= length <= 4096, 'Unexpected DNS query size')
            message = exact(self.request, length)
            with self.server.lock:
                self.server.requests += 1
            value = answer(message)
            wire = len(value).to_bytes(2, 'big') + value
            self.request.sendall(wire[:1])
            self.request.sendall(wire[1:7])
            self.request.sendall(wire[7:])
        except (OSError, EOFError):
            pass


class ForwardSocks(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            require(exact(self.request, 3) == b'\x05\x01\x00', 'SOCKS greeting')
            self.request.sendall(b'\x05\x00')
            header = exact(self.request, 4)
            require(header == b'\x05\x01\x00\x01', 'Resolver must be an explicit IPv4 endpoint')
            host = socket.inet_ntoa(exact(self.request, 4))
            port = int.from_bytes(exact(self.request, 2), 'big')
            require(host == '127.0.0.1' and port == self.server.resolver_port, 'Unexpected resolver endpoint')
            with self.server.lock:
                self.server.requests += 1
            if self.server.reject:
                self.request.sendall(b'\x05\x05\x00\x01' + bytes(6))
                return
            with socket.create_connection((host, port), timeout=5) as remote:
                self.request.sendall(b'\x05\x00\x00\x01' + bytes(6))
                length = exact(self.request, 2)
                remote.sendall(length + exact(self.request, int.from_bytes(length, 'big')))
                response = exact(remote, 2)
                self.request.sendall(response + exact(remote, int.from_bytes(response, 'big')))
        except (OSError, EOFError):
            pass


def configure(abi):
    native_configure(abi)
    for name in ['fb_native_dns_exchange_json', 'fb_native_dns_start_json']:
        function = getattr(abi.lib, name)
        function.argtypes = [ctypes.c_uint64, ctypes.c_char_p]
        function.restype = ctypes.c_void_p
    abi.lib.fb_native_dns_stop.argtypes = [ctypes.c_uint64]
    abi.lib.fb_native_dns_stop.restype = None
    abi.lib.fb_ssh_remote_dns_json.argtypes = [ctypes.c_uint64]
    abi.lib.fb_ssh_remote_dns_json.restype = ctypes.c_void_p


def start(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def stop(server, thread):
    server.shutdown(); server.server_close(); thread.join(timeout=5)


def verify_stub(abi, ident):
    reply = abi.call('fb_native_dns_start_json', ident, {'listen': '127.0.0.1:0'})
    require(reply['system_dns_modified'] is False, 'Unexpected machine-wide DNS claim')
    port = int(reply['listen'].rsplit(':', 1)[1])
    message = query()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(5)
        client.sendto(message, ('127.0.0.1', port))
        require(client.recvfrom(65535)[0] == answer(message), 'UDP DNS reply changed')
    with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
        message = query(kind=28)
        client.sendall(len(message).to_bytes(2, 'big') + message)
        result = exact(client, int.from_bytes(exact(client, 2), 'big'))
        require(result == answer(message), 'TCP/AAAA DNS reply changed')
    abi.lib.fb_native_dns_stop(ident)
    def closed():
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                return False
        except OSError:
            return True
    until(closed, 2)


def actual_ssh(abi, profile, endpoint, ssh_id, *, limits=None):
    configure(abi)
    servers = abi.call('fb_ssh_remote_dns_json', ssh_id)
    require(servers['source'] == 'remote_resolv_conf' and servers['servers'], 'Remote resolver discovery failed')
    resolver = Server(('127.0.0.1', 0), Resolver); thread = start(resolver)
    ident = 0
    try:
        options = {'managed_endpoint': endpoint, 'ready': True, 'ready_lease_ms': 10000,
                   'dns': {'resolver': {'host': '127.0.0.1', 'port': resolver.server_address[1]}, 'timeout_ms': 3000}}
        if limits is not None:
            options['limits'] = limits
        ident = abi.call('fb_native_create_json', profile, options)['session_id']
        message = query()
        result = abi.call('fb_native_dns_exchange_json', ident, {'query': list(message)})
        require(bytes(result['response']) == answer(message), 'DNS query through real SSH changed')
        verify_stub(abi, ident)
        require(resolver.requests == 3, 'Unexpected DNS request count')
    finally:
        if ident:
            abi.lib.fb_native_destroy(ident)
        stop(resolver, thread)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    library = {'win32': 'flowbridge_ffi.dll', 'darwin': 'libflowbridge_ffi.dylib'}.get(sys.platform, 'libflowbridge_ffi.so')
    abi = ABI(root / 'target/debug' / library); configure(abi)
    resolver = Server(('127.0.0.1', 0), Resolver); resolver_thread = start(resolver)
    proxy = Server(('127.0.0.1', 0), ForwardSocks)
    proxy.resolver_port, proxy.reject = resolver.server_address[1], False
    proxy_thread = start(proxy)
    endpoint = {'host': '127.0.0.1', 'port': proxy.server_address[1]}
    profile = {'version': 1, 'listen': f'127.0.0.1:{free_port()}',
               'proxies': [{'id': 'ssh', 'kind': 'socks5', 'endpoint': endpoint}],
               'chains': [], 'rules': [], 'default_action': {'type': 'block'},
               'connect_timeout_ms': 1000, 'handshake_timeout_ms': 1000,
               'idle_timeout_ms': 60000, 'max_connections': 16}
    options = {'managed_endpoint': endpoint, 'ready': True, 'ready_lease_ms': 10000,
               'dns': {'resolver': {'host': '127.0.0.1', 'port': resolver.server_address[1]}, 'timeout_ms': 300}}
    ident = 0; report = {'passed': False, 'os_dns_changed': False, 'checks': []}
    try:
        invalid = copy.deepcopy(options); invalid['dns']['resolver']['host'] = 'client-dns.invalid'
        rejected(abi, 'fb_native_create_json', profile, invalid)
        ident = abi.call('fb_native_create_json', profile, options)['session_id']
        for message in [query(), query(kind=28)]:
            result = abi.call('fb_native_dns_exchange_json', ident, {'query': list(message)})
            require(bytes(result['response']) == answer(message), 'DNS wire response changed')
            require(result['local_fallback'] is False, 'Local fallback must be disabled')
        report['checks'].append('A/AAAA wire queries travel through SOCKS to explicit remote resolver')
        count = resolver.requests
        for malformed in [b'', query()[:-1], bytes(4097)]:
            rejected(abi, 'fb_native_dns_exchange_json', ident, {'query': list(malformed)})
        require(resolver.requests == count, 'Malformed query reached remote resolver')
        rejected(abi, 'fb_native_dns_exchange_json', ident, {'query': list(query(0xbeef))})
        report['checks'].append('Malformed queries and mismatched response IDs are rejected')
        verify_stub(abi, ident)
        report['checks'].append('Loopback UDP and TCP stub returns correct data; Stop releases listener')
        rejected(abi, 'fb_native_dns_start_json', ident, {'listen': '0.0.0.0:0'})
        count = resolver.requests; proxy.reject = True
        rejected(abi, 'fb_native_dns_exchange_json', ident, {'query': list(query())})
        require(resolver.requests == count, 'Rejected SOCKS query fell back to DIRECT DNS')
        proxy.reject = False
        abi.call('fb_native_set_gate_json', ident, {'ready': False})
        count = proxy.requests
        rejected(abi, 'fb_native_dns_exchange_json', ident, {'query': list(query())})
        require(proxy.requests == count, 'Paused tunnel received a DNS request')
        report['checks'].append('Proxy rejection and paused SSH never trigger local/DIRECT DNS fallback')
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error); raise
    finally:
        if ident:
            abi.lib.fb_native_destroy(ident)
        stop(proxy, proxy_thread); stop(resolver, resolver_thread)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
