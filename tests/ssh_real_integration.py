#!/usr/bin/env python3
"""Exercise actual SSH supervision against isolated OpenSSH on disposable CI.

No Internet destination or user credentials are used. Ephemeral keys are never
uploaded. The test verifies new connections after restart, not TCP resumption.
"""
import argparse
import ctypes
import getpass
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def distinct_free_ports(count):
    # Bind every CI-only ephemeral listener concurrently before releasing any.
    # Calling bind(0) and closing independently can return the SAME port three
    # times on Linux. No retry or relaxation of subsequent SSH/byte checks.
    held = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            held.append(sock)
            sock.bind(('127.0.0.1', 0))
        ports = tuple(sock.getsockname()[1] for sock in held)
        require(len(set(ports)) == count, 'Duplicate concurrently held test ports')
        return ports
    finally:
        for sock in held:
            sock.close()


def until(predicate, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.05)
    raise TimeoutError('Condition did not become true within its deadline')


def exact(sock, size):
    data = b''
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError('Unexpected end of SOCKS/TCP stream')
        data += chunk
    return data


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(180)
        while True:
            chunk = self.request.recv(65536)
            if not chunk:
                break
            self.request.sendall(chunk)


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    request_queue_size = 256


class ABI:
    def __init__(self, library):
        self.lib = ctypes.CDLL(str(library.resolve()))
        signatures = {
            'fb_ssh_create_json': [ctypes.c_char_p],
            'fb_ssh_start_json': [ctypes.c_uint64],
            'fb_ssh_stop_json': [ctypes.c_uint64],
            'fb_ssh_snapshot_json': [ctypes.c_uint64],
            'fb_engine_create_json': [ctypes.c_char_p],
            'fb_engine_start_json': [ctypes.c_uint64],
            'fb_engine_stop_json': [ctypes.c_uint64],
            'fb_engine_snapshot_json': [ctypes.c_uint64],
            'fb_engine_set_upstream_gate_json': [ctypes.c_uint64, ctypes.c_char_p],
            'fb_engine_set_upstream_pool_json': [ctypes.c_uint64, ctypes.c_char_p],
            'fb_engine_sync_owned_ssh_pool_json': [ctypes.c_uint64, ctypes.c_char_p],
        }
        for name, arguments in signatures.items():
            function = getattr(self.lib, name)
            function.argtypes = arguments
            function.restype = ctypes.c_void_p
        self.lib.fb_string_free.argtypes = [ctypes.c_void_p]
        self.lib.fb_string_free.restype = None
        for name in ['fb_ssh_destroy', 'fb_engine_destroy']:
            function = getattr(self.lib, name)
            function.argtypes = [ctypes.c_uint64]
            function.restype = None

    def call(self, name, *arguments):
        args = [json.dumps(v).encode() if isinstance(v, dict) else v for v in arguments]
        pointer = getattr(self.lib, name)(*args)
        require(pointer, name + ' returned a null pointer')
        try:
            result = json.loads(ctypes.string_at(pointer))
        finally:
            self.lib.fb_string_free(pointer)
        require(result.get('ok') is True, name + ': ' + str(result))
        return result


def connect(proxy_port, target_port):
    client = socket.create_connection(('127.0.0.1', proxy_port), timeout=20)
    try:
        client.sendall(b'\x05\x01\x00')
        require(exact(client, 2) == b'\x05\x00', 'SOCKS method selection failed')
        host = b'localhost'
        client.sendall(b'\x05\x01\x00\x03' + bytes([len(host)]) + host
                       + target_port.to_bytes(2, 'big'))
        reply = exact(client, 10)
        require(reply == b'\x05\x00\x00\x01' + bytes(6),
                'SOCKS CONNECT failed; reply=' + reply.hex())
        return client
    except Exception:
        client.close()
        raise


def round_trip(proxy_port, target_port):
    payload = b'FlowBridge real SSH\x00\xff' + bytes(range(256)) * 32
    with connect(proxy_port, target_port) as client:
        client.sendall(payload)
        require(exact(client, len(payload)) == payload, 'Payload changed in the SSH tunnel')
        client.shutdown(socket.SHUT_WR)
        require(client.recv(1) == b'', 'Half-close did not finish')


def main(repetition=0):
    require(sys.platform.startswith('linux') and os.environ.get('GITHUB_ACTIONS') == 'true',
            'Run only on a disposable Linux GitHub Actions runner')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output = args.output / f"iteration-{repetition + 1:02d}"
    abi = ABI(args.library)
    args.output.mkdir(parents=True, exist_ok=True)
    report = {'commit': os.environ.get('GITHUB_SHA'), 'passed': False, 'checks': [],
              'existing_tcp_preserved': False}
    supervisor = bad_supervisor = engine = 0
    daemon = capture = None
    echo = Server(('127.0.0.1', 0), Echo)
    threading.Thread(target=echo.serve_forever, daemon=True).start()
    target_port = echo.server_address[1]

    def passed(text):
        print('PASS', text, flush=True)
        report['checks'].append(text)

    with tempfile.TemporaryDirectory(prefix='flowbridge ssh keys ') as temporary:
        root = Path(temporary)
        server_log = (args.output / 'sshd.log').open('wb')
        try:
            for key in ['host_key', 'client_key']:
                subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                                '-f', str(root / key)], check=True, timeout=15)
            ssh_port, socks_port, engine_port = distinct_free_ports(3)
            # The already-live echo target port is excluded by the simultaneous
            # socket binds. Keep the independent four-endpoint invariant.
            require(len({ssh_port, socks_port, engine_port, target_port}) == 4, 'Port collision')
            if os.environ.get('FLOWBRIDGE_TEST_CAPTURE') == '1':
                capture_log = (args.output / 'capture.log').open('wb')
                capture = subprocess.Popen(['sudo', '-n', 'tcpdump', '-i', 'lo', '-nn', '-s', '256', '-U',
                    '-w', str((args.output / 'socks.pcap').resolve()), 'tcp', 'port', str(socks_port)],
                    stdout=capture_log, stderr=subprocess.STDOUT, start_new_session=True)
                time.sleep(0.2)
                require(capture.poll() is None, 'SOCKS packet capture did not start')
            known = root / 'known hosts'
            known.write_text(f'[127.0.0.1]:{ssh_port} ' + (root / 'host_key.pub').read_text())
            config = root / 'sshd_config'
            config.write_text('\n'.join([
                f'Port {ssh_port}', 'ListenAddress 127.0.0.1', 'AddressFamily inet',
                f'HostKey "{root / "host_key"}"', f'PidFile "{root / "sshd.pid"}"',
                f'AuthorizedKeysFile "{root / "client_key.pub"}"',
                f'AllowUsers {getpass.getuser()}', 'PermitRootLogin no',
                'PasswordAuthentication no', 'KbdInteractiveAuthentication no',
                'PubkeyAuthentication yes', 'UsePAM yes', 'StrictModes no',
                'AllowTcpForwarding local', 'PermitOpen any', 'GatewayPorts no',
                'X11Forwarding no', 'AllowAgentForwarding no', 'LogLevel DEBUG3',
            ]) + '\n')
            subprocess.run(['sudo', '-n', '/usr/sbin/sshd', '-t', '-f', str(config)],
                           check=True, timeout=15)
            daemon = subprocess.Popen(['sudo', '-n', '/usr/sbin/sshd', '-D', '-e', '-f', str(config)],
                                      stdout=server_log, stderr=subprocess.STDOUT,
                                      start_new_session=True)

            def listening():
                require(daemon.poll() is None, 'Isolated sshd exited')
                try:
                    with socket.create_connection(('127.0.0.1', ssh_port), timeout=0.2):
                        return True
                except OSError:
                    return False
            until(listening, 10)
            settings = {'host': '127.0.0.1', 'port': ssh_port, 'user': getpass.getuser(),
                        'local_port': socks_port, 'verbose_diagnostics': False, 'identity_file': str(root / 'client_key'),
                        'known_hosts_file': str(known), 'server_alive_interval_secs': 15,
                        'server_alive_count_max': 3, 'health_check_interval_ms': 1000,
                        'health_check_timeout_ms': 3000, 'restart_initial_delay_ms': 300,
                        'restart_max_delay_ms': 1000, 'startup_timeout_ms': 8000, 'max_restarts': 4}
            report['keepalive'] = {'interval_seconds': settings['server_alive_interval_secs'],
                                   'count_max': settings['server_alive_count_max']}
            supervisor = abi.call('fb_ssh_create_json', settings)['ssh_id']
            abi.call('fb_ssh_start_json', supervisor)

            def snapshot():
                result = abi.call('fb_ssh_snapshot_json', supervisor)
                require(result['status']['state'] != 'failed', 'SSH failed: ' + str(result))
                return result['status']
            ready = until(lambda: s if (s := snapshot())['state'] == 'ready' else False)
            endpoint = {'host': '127.0.0.1', 'port': socks_port}
            profile = {'version': 1, 'listen': f'127.0.0.1:{engine_port}',
                       'proxies': [{'id': 'ssh', 'kind': 'socks5', 'endpoint': endpoint}],
                       'chains': [], 'rules': [], 'default_action': {'type': 'proxy', 'id': 'ssh'},
                       'connect_timeout_ms': 10000, 'handshake_timeout_ms': 10000,
                       'idle_timeout_ms': 300000, 'max_connections': 256 if repetition == 0 else 32}
            engine = abi.call('fb_engine_create_json', profile)['engine_id']
            abi.call('fb_engine_start_json', engine)

            # Identical per-process limits across the explicit engine and
            # native FFI sessions are mandatory: they share one canonical
            # managed SSH endpoint and reject conflicting configurations.
            ssh_limits = {'max_flows': 128, 'max_opening': 16,
                          'max_queued': 64, 'wait_timeout_ms': 500}
            def gate(ready):
                abi.call('fb_engine_set_upstream_gate_json', engine,
                         {'endpoint': endpoint, 'ready': ready, 'grace_ms': 15000,
                          'limits': ssh_limits})
            gate(True)
            round_trip(engine_port, target_port)
            passed('Actual OpenSSH authentication, strict enrolled host key, binary traffic and half-close')
            if repetition == 0 and os.environ.get('FLOWBRIDGE_CAPTURE_AGENT'):
                from capture_real_ssh import run as capture_relay

                def capture_gate(ready):
                    # Explicitly closed gate: zero reconnect grace.
                    abi.call('fb_engine_set_upstream_gate_json', engine,
                             {'endpoint': endpoint, 'ready': ready,
                              'grace_ms': 15000 if ready else 0, 'limits': ssh_limits})

                report['capture_relay'] = capture_relay(
                    Path(os.environ['FLOWBRIDGE_CAPTURE_AGENT']), engine_port, capture_gate,
                    ready['pid'], args.output / 'capture-relay-real-ssh.json')
                passed('Rust relay -> FlowBridge SOCKS -> real OpenSSH: half-close, deny and recovery')
            from native_vertical_integration import actual_ssh
            actual_ssh(abi, profile, endpoint, target_port, limits=ssh_limits)
            passed('Native capture ABI: selected application -> real SSH -> target, without SOCKS ingress')
            from native_dns_integration import actual_ssh as actual_dns
            actual_dns(abi, profile, endpoint, supervisor, limits=ssh_limits)
            passed('Native DNS: resolver discovery and UDP/TCP queries through actual SSH')
            if repetition == 0:
                from real_ssh_capacity import run as stress_actual_ssh
                # A real OpenSSH backend (not a mock) holds exactly the
                # conservative default 128 managed admissions while bursts
                # try to exceed it. Run once; 19 remaining iterations still
                # test authentication/reconnect/strict host keys independently.
                result = stress_actual_ssh(
                    abi, engine, engine_port, target_port, snapshot,
                    output=args.output / 'real-ssh-capacity.json',
                    churn=int(os.environ.get('FLOWBRIDGE_SSH_CHURN', '200')),
                )
                report['capacity'] = {
                    'real_openssh': True,
                    'held': result['open_ssh_connections_held'],
                    'rejected': result['attempted_after_capacity'],
                    'churn': result['churn_attempts'],
                    'elapsed_seconds': result['elapsed_seconds'],
                }
                passed('Real OpenSSH: 128 held channels, 64/128/192/256/512 overflow, retained bytes, capacity recovery')
                from real_ssh_pool_integration import run as pool_actual_ssh
                pool_result = pool_actual_ssh(
                    abi, engine, engine_port, target_port, settings, snapshot,
                    ssh_limits, output=args.output / 'real-ssh-pool.json')
                report['pool'] = {
                    'distinct_child_pids': pool_result['distinct_child_pids'],
                    'primary_stream_survived_secondary_death': pool_result['existing_primary_stream_survived_peer_death'],
                    'all_workers_down_fail_closed': pool_result['new_connections_fail_closed_with_all_workers_down']}
                passed('Two independent OpenSSH children: distributed channels, surviving streams, fail-closed and recovery')
                from real_owned_pool_lifecycle import run as owned_lifecycle
                owned_result = owned_lifecycle(
                    abi, target_port, settings,
                    output=args.output / 'real-owned-pool-lifecycle.json')
                report['owned_pool_lifecycle'] = {
                    'passed': owned_result['passed'],
                    'distinct_child_pids': owned_result['distinct_child_pids']}
                passed('Four real owned SSH processes: GUI pool lifecycle, limits, pause and restart')
            old_pid = ready['pid']
            gate(False)
            os.kill(old_pid, signal.SIGKILL)
            result = []
            entered = threading.Event()

            def pending_flow():
                entered.set()
                try:
                    round_trip(engine_port, target_port)
                    result.append('ok')
                except Exception as error:
                    result.append(str(error))
            pending = threading.Thread(target=pending_flow, daemon=True)
            pending.start()
            require(entered.wait(1), 'Pending-flow worker did not start')
            time.sleep(0.2)
            require(not result, 'New connection bypassed a closed upstream gate')
            recovered = until(lambda: s if (s := snapshot())['state'] == 'ready'
                              and s['restarts'] >= 1 and s['pid'] != old_pid else False)
            gate(True)
            pending.join(timeout=20)
            require(result == ['ok'], 'Pending flow did not resume: ' + str(result))
            round_trip(engine_port, target_port)
            passed('Killed real SSH child; watchdog reconnects; pending/new flows use the replacement tunnel')
            report['restarts'] = recovered['restarts']
            stopped = abi.call('fb_ssh_stop_json', supervisor)['status']
            require(stopped['state'] == 'stopped' and stopped['pid'] is None, 'Stop left an SSH child')
            time.sleep(0.4)
            require(abi.call('fb_ssh_snapshot_json', supervisor)['status']['state'] == 'stopped',
                    'Watchdog restarted after Stop')
            abi.call('fb_engine_stop_json', engine)
            passed('Explicit Stop cancels restart supervision and reaps the owned child')
            empty = root / 'untrusted known hosts'
            empty.write_text('')
            bad = dict(settings, known_hosts_file=str(empty))
            bad_supervisor = abi.call('fb_ssh_create_json', bad)['ssh_id']
            abi.call('fb_ssh_start_json', bad_supervisor)

            def rejected():
                state = abi.call('fb_ssh_snapshot_json', bad_supervisor)['status']
                require(state['state'] != 'ready', 'Untrusted host key was accepted')
                return state if state['state'] == 'failed' else False
            rejection = until(rejected, 15)
            require(rejection['restarts'] == 0, 'Permanent host-key failure was retried')
            passed('Missing enrolled host key is rejected permanently; no automatic insecure enrollment')
            report['connection_establishment_retries'] = sum(
                'retrying initial' in event['message']
                for event in abi.call('fb_engine_snapshot_json', engine)['events'])
            report['passed'] = True
        except Exception as error:
            report['error'] = str(error)
            for label, handle, function in [
                ('ssh', supervisor, 'fb_ssh_snapshot_json'),
                ('untrusted_ssh', bad_supervisor, 'fb_ssh_snapshot_json'),
                ('engine', engine, 'fb_engine_snapshot_json'),
            ]:
                if handle:
                    try: report[label] = abi.call(function, handle)
                    except Exception as snapshot_error: report[label] = str(snapshot_error)
            raise
        finally:
            for ident in (supervisor, bad_supervisor):
                if ident:
                    abi.lib.fb_ssh_destroy(ident)
            if engine:
                abi.lib.fb_engine_destroy(engine)
            if daemon:
                subprocess.run(['sudo', '-n', 'kill', '-TERM', '--', f'-{daemon.pid}'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=10, check=False)
                try:
                    daemon.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    subprocess.run(['sudo', '-n', 'kill', '-KILL', '--', f'-{daemon.pid}'],
                                   timeout=10, check=False)
                    daemon.wait(timeout=10)
            if capture:
                subprocess.run(['sudo', '-n', 'kill', '-INT', '--', f'-{capture.pid}'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
                capture.wait(timeout=10)
                capture_log.close()
                with (args.output / 'socks-wire.txt').open('wb') as wire:
                    subprocess.run(['sudo', '-n', 'tcpdump', '-nn', '-tttt', '-XX', '-r',
                        str((args.output / 'socks.pcap').resolve())], stdout=wire,
                        stderr=subprocess.STDOUT, timeout=10, check=False)
            server_log.close()
            echo.shutdown()
            echo.server_close()
            (args.output / 'real-ssh-result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    for repetition in range(20):
        main(repetition)
