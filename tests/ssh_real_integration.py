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


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


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
        self.request.settimeout(15)
        while True:
            chunk = self.request.recv(65536)
            if not chunk:
                break
            self.request.sendall(chunk)


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True


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
    daemon = None
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
            ssh_port, socks_port, engine_port = free_port(), free_port(), free_port()
            require(len({ssh_port, socks_port, engine_port, target_port}) == 4, 'Port collision')
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
                        'local_port': socks_port, 'verbose_diagnostics': repetition % 2 == 1, 'identity_file': str(root / 'client_key'),
                        'known_hosts_file': str(known), 'server_alive_interval_secs': 1,
                        'server_alive_count_max': 2, 'health_check_interval_ms': 1000,
                        'health_check_timeout_ms': 3000, 'restart_initial_delay_ms': 300,
                        'restart_max_delay_ms': 1000, 'startup_timeout_ms': 8000, 'max_restarts': 4}
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
                       'idle_timeout_ms': 300000, 'max_connections': 32}
            engine = abi.call('fb_engine_create_json', profile)['engine_id']
            abi.call('fb_engine_start_json', engine)

            def gate(ready):
                abi.call('fb_engine_set_upstream_gate_json', engine,
                         {'endpoint': endpoint, 'ready': ready, 'grace_ms': 15000})
            gate(True)
            round_trip(engine_port, target_port)
            passed('Actual OpenSSH authentication, strict enrolled host key, binary traffic and half-close')
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
            server_log.close()
            echo.shutdown()
            echo.server_close()
            (args.output / 'real-ssh-result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    for repetition in range(20):
        main(repetition)
