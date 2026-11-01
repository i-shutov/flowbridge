#!/usr/bin/env python3
"""Independent real-process UDP DNS -> Rust -> SOCKS5 -> TCP resolver fixture.

Loopback-only sockets, no external DNS, no NDISRD, no selected-app protection.
The fake SOCKS server forwards a real TCP DNS transaction to another listener,
then rejects one CONNECT and recovers. Results contain no DNS payloads or paths.
"""
import argparse
import hashlib
import json
import pathlib
import queue
import socket
import subprocess
import threading


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def read_exact(connection, length):
    result = bytearray()
    while len(result) < length:
        part = connection.recv(length - len(result))
        if not part:
            raise EOFError('TCP peer closed before full DNS transaction')
        result.extend(part)
    return bytes(result)


def question(identifier):
    return identifier.to_bytes(2, 'big') + bytes.fromhex('01000001000000000000') + (
        b'\x03www\x07example\x03com\x00\x00\x01\x00\x01')


def listen():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 0))
    listener.listen(8)
    listener.settimeout(0.5)
    return listener


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--agent', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    resolver, proxy = listen(), listen()
    gate = threading.Event()
    gate.set()
    corrupt_dns_answer = threading.Event()
    stopped = threading.Event()
    counts = {'socks_connects': 0, 'socks_denials': 0, 'resolver_tcp_connections': 0}
    failures = queue.Queue()

    def serve_resolver():
        try:
            while not stopped.is_set():
                try:
                    client, _ = resolver.accept()
                except socket.timeout:
                    continue
                with client:
                    client.settimeout(5)
                    length = int.from_bytes(read_exact(client, 2), 'big')
                    data = read_exact(client, length)
                    require(length >= 17 and data[4:6] == b'\x00\x01',
                            'Resolver did not receive genuine DNS TCP question')
                    counts['resolver_tcp_connections'] += 1
                    reply = bytearray(data)
                    reply[2:4] = bytes.fromhex('8180')
                    if corrupt_dns_answer.is_set():
                        reply[0] ^= 1  # Wrong transaction ID must never reach UDP client.
                        corrupt_dns_answer.clear()
                    client.sendall(len(reply).to_bytes(2, 'big') + reply)
        except Exception as exc:
            failures.put(f'resolver: {type(exc).__name__}')

    def serve_proxy():
        try:
            while not stopped.is_set():
                try:
                    client, _ = proxy.accept()
                except socket.timeout:
                    continue
                with client:
                    client.settimeout(6)
                    require(read_exact(client, 3) == b'\x05\x01\x00',
                            'Invalid SOCKS greeting')
                    client.sendall(b'\x05\x00')
                    header = read_exact(client, 4)
                    require(header == b'\x05\x01\x00\x01',
                            'Unexpected SOCKS command/address family')
                    address = socket.inet_ntoa(read_exact(client, 4))
                    port = int.from_bytes(read_exact(client, 2), 'big')
                    require((address, port) == resolver.getsockname(),
                            'Rust SOCKS target was not the configured resolver')
                    counts['socks_connects'] += 1
                    if not gate.is_set():
                        counts['socks_denials'] += 1
                        client.sendall(b'\x05\x05\x00\x01' + b'\x00' * 6)
                        continue
                    client.sendall(b'\x05\x00\x00\x01' + b'\x00' * 6)
                    length_bytes = read_exact(client, 2)
                    payload = read_exact(client, int.from_bytes(length_bytes, 'big'))
                    with socket.create_connection(resolver.getsockname(), timeout=4) as backend:
                        backend.settimeout(4)
                        backend.sendall(length_bytes + payload)
                        size = read_exact(backend, 2)
                        response = read_exact(backend, int.from_bytes(size, 'big'))
                        client.sendall(size + response)
        except Exception as exc:
            failures.put(f'proxy: {type(exc).__name__}')

    threads = [threading.Thread(target=serve_resolver, daemon=True),
               threading.Thread(target=serve_proxy, daemon=True)]
    for thread in threads:
        thread.start()
    udp_reservation = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_reservation.bind(('127.0.0.1', 0))
    bind_port = udp_reservation.getsockname()[1]
    udp_reservation.close()
    for _ in range(12):
        if bind_port != proxy.getsockname()[1]:
            break
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve_again:
            reserve_again.bind(('127.0.0.1', 0))
            bind_port = reserve_again.getsockname()[1]
    require(bind_port != proxy.getsockname()[1],
            'Could not reserve distinct UDP DNS and SOCKS ports')
    req = {
        'consent': 'DNS_UDP_OVER_SOCKS_LAB',
        'bind': f'127.0.0.1:{bind_port}',
        'upstream': f'127.0.0.1:{proxy.getsockname()[1]}',
        'resolver': f'127.0.0.1:{resolver.getsockname()[1]}',
        'duration_ms': 12000,
        'max_queries': 5,
    }
    process = subprocess.Popen([str(args.agent), 'dns-udp-lab', json.dumps(req)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True)
    try:
        ready = queue.Queue()
        threading.Thread(target=lambda: ready.put(process.stderr.readline()),
                         daemon=True).start()
        require(ready.get(timeout=8).strip() == 'FLOWBRIDGE_DNS_LAB_READY',
                'Rust DNS lab did not confirm loopback UDP bind')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.bind(('127.0.0.1', 0))
            udp.settimeout(2)
            target = ('127.0.0.1', bind_port)

            def exchange(identifier, should_reply, payload=None):
                udp.sendto(payload if payload is not None else question(identifier), target)
                try:
                    received, _ = udp.recvfrom(4096)
                except socket.timeout:
                    received = None
                if should_reply:
                    require(received is not None and received[:2] == identifier.to_bytes(2, 'big')
                            and received[2:4] == bytes.fromhex('8180'),
                            'Valid DNS answer did not traverse Rust/SOCKS/TCP')
                else:
                    require(received is None, 'Refused or malformed DNS got a UDP answer')

            exchange(0x1111, True)
            gate.clear()
            exchange(0x2222, False)
            invalid = bytearray(question(0x3333))
            invalid[5] = 2
            exchange(0x3333, False, bytes(invalid))
            gate.set()
            corrupt_dns_answer.set()
            exchange(0x5555, False)
            exchange(0x4444, True)
        output, errors = process.communicate(timeout=20)
        require(process.returncode == 0, 'DNS laboratory agent returned error')
        report = json.loads(output)
        require(report['loop_completed'] is True
                and report['queries_received'] == 5
                and report['queries_accepted'] == 4
                and report['queries_rejected_before_proxy'] == 1
                and report['replies_returned'] == 2
                and report['upstream_failures_without_direct_retry'] == 1
                and report['invalid_upstream_replies_dropped'] == 1
                and report['direct_resolver_connections'] == 0
                and report['active_relay_slots_at_exit'] == 0,
                'DNS SOCKS gate/return/cleanup counters violated')
        require(counts == {'socks_connects': 4, 'socks_denials': 1,
                           'resolver_tcp_connections': 3},
                'Unexpected real socket counts or DIRECT fallback')
        for name in ('native_ndisrd_interception', 'selected_app_dns_protected',
                     'system_dns_modified', 'dns_leak_free', 'protected_mode',
                     'win10_11_acceptance', 'release_accepted'):
            require(report[name] is False, f'Unsupported release claim: {name}')
        invalid_req = dict(req, consent='NOT_AUTHORIZED')
        rejected = subprocess.run([str(args.agent), 'dns-udp-lab',
                                   json.dumps(invalid_req)], capture_output=True,
                                  text=True, timeout=8)
        require(rejected.returncode != 0 and
                json.loads(rejected.stdout)['ok'] is False,
                'Missing lab consent was not denied')
        require(failures.empty(), 'Socket fixture failure')
        evidence = {
            'kind': 'real_cross_process_udp_to_tcp_via_rust_socks_lab',
            'passed': True, 'agent_sha256': hashlib.sha256(args.agent.read_bytes()).hexdigest(),
            'source_sha': subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                                  text=True).strip(),
            'actual_loopback_udp': True, 'actual_tcp_dns_resolver': True,
            'actual_socks5_connect': True, 'authenticated_ssh_in_this_fixture': False,
            'successful_udp_dns_replies': 2, 'socks_connect_attempts': 4,
            'socks_denials': 1, 'actual_resolver_connections': 3,
            'invalid_query_denied_before_proxy': True,
            'tampered_dns_reply_rejected': True,
            'no_direct_fallback': True, 'consent_denial': True,
            'native_ndisrd_interception': False, 'selected_app_dns_protected': False,
            'dns_leak_free': False, 'release_accepted': False,
            'agent_report': report,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2) + '\n',
                               encoding='utf-8')
        print('REAL_UDP_DNS_VIA_RUST_SOCKS_TCP_PASS', flush=True)
    finally:
        stopped.set()
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
        resolver.close()
        proxy.close()
        for thread in threads:
            thread.join(timeout=2)


if __name__ == '__main__':
    main()
