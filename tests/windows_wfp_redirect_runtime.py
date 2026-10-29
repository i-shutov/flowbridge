#!/usr/bin/env python3
"""Actual selected EXE -> loaded WFP callout -> native helper -> SOCKS -> echo.

RUN ONLY on a disposable, user-authorized Windows VM with the separately
installed *signed/test-signed* FlowBridge WFP driver. Does not install a driver,
change security policy, or contact any external network. This is not executed
as a passing step on ordinary GitHub-hosted runners.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import queue
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import uuid


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as file:
        for block in iter(lambda: file.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def require(value, message):
    if not value:
        raise AssertionError(message)


def exact(sock, count):
    data = b''
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise EOFError(f'Expected {count} bytes, got {len(data)}')
        data += chunk
    return data


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        with self.server.lock:
            self.server.accepted += 1
        self.request.settimeout(8)
        try:
            while data := self.request.recv(65536):
                self.request.sendall(data)
        except OSError:
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    address_family = socket.AF_INET
    request_queue_size = 32

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.connects = 0
        self.accepted = 0
        self.connects_by_family = {socket.AF_INET: 0, socket.AF_INET6: 0}
        self.deny = False
        self.lock = threading.Lock()


class V6Server(Server):
    address_family = socket.AF_INET6


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        payload, server_socket = self.request
        server_socket.sendto(payload, self.client_address)


class UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True
    address_family = socket.AF_INET


class V6UDPServer(UDPServer):
    address_family = socket.AF_INET6


class Socks(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        client.settimeout(8)
        try:
            require(exact(client, 3) == b'\x05\x01\x00', 'SOCKS greeting')
            client.sendall(b'\x05\x00')
            header = exact(client, 4)
            require(header[:3] == b'\x05\x01\x00' and header[3] in (1, 4),
                    'Expected IPv4/IPv6 SOCKS CONNECT with a literal IP')
            family = socket.AF_INET if header[3] == 1 else socket.AF_INET6
            destination = socket.inet_ntop(family, exact(client, 4 if family == socket.AF_INET else 16))
            port = int.from_bytes(exact(client, 2), 'big')
            expected = self.server.echo_ports[family]
            require((destination, port) == expected,
                    'Unrecognized test-only destination or changed address family')
            with self.server.lock:
                self.server.connects += 1
                self.server.connects_by_family[family] += 1
                deny = self.server.deny
            if deny:
                client.sendall(b'\x05\x05\x00\x01' + bytes(6))
                return
            with socket.create_connection((destination, port), timeout=5) as upstream:
                client.sendall(b'\x05\x00\x00\x01' + bytes(6))
                stopped = threading.Event()
                def forward(source, target):
                    try:
                        while data := source.recv(32768):
                            target.sendall(data)
                    except OSError:
                        pass
                    finally:
                        try:
                            target.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        stopped.set()
                thread = threading.Thread(target=forward, args=(client, upstream), daemon=True)
                thread.start()
                forward(upstream, client)
                thread.join(timeout=8)
                require(stopped.is_set(), 'SOCKS forwarding worker did not terminate')
        except (ConnectionError, TimeoutError, EOFError, AssertionError):
            pass


def start(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def run_probe(client, host, port, *, protocol='tcp', success=True):
    require(host in ('127.0.0.1', '::1') and protocol in ('tcp', 'udp'),
            'Only literal loopback TCP/UDP probes are accepted')
    p = subprocess.run([str(client), 'probe', host, str(port), protocol],
                       capture_output=True, text=True, timeout=20)
    if success:
        require(p.returncode == 0 and json.loads(p.stdout).get('echo_verified') is True,
                f'{client} did not complete echoed {host}/{protocol}: {p.returncode} {p.stdout} {p.stderr}')
    else:
        require(p.returncode != 0,
                f'Selected EXE bypassed rejected SOCKS via DIRECT ({host}/{protocol})')


def await_helper_ready(child, event_counts=None):
    """Observe the actual helper child without uploading private JSON logs.

    Only pre-approved event names are counted in evidence. Do not store raw
    JSON with executable paths, profile details, destination IPs or SSH keys.
    """
    messages = queue.Queue()
    safe_events = {'ready', 'faulted', 'connected', 'closed',
                   'rejected', 'native_status'}
    def pump():
        try:
            for line in child.stdout:
                try:
                    message = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                event = message.get('event')
                if isinstance(event, str) and event in safe_events and event_counts is not None:
                    event_counts[event] = min(event_counts.get(event, 0) + 1, 1000000)
                if event in ('ready', 'faulted'):
                    messages.put((event, message))
        finally:
            messages.put(('eof', {'exit_code': child.poll()}))
    reader = threading.Thread(target=pump, daemon=True)
    reader.start()
    try:
        outcome, value = messages.get(timeout=45)
    except queue.Empty as error:
        raise AssertionError('Native helper readiness timed out') from error
    require(outcome == 'ready', f'Native capture failed before readiness: {value}')
    return reader


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform == 'win32' and os.environ.get('FLOWBRIDGE_WFP_VM') == '1'
            and ctypes.windll.shell32.IsUserAnAdmin(),
            'Explicit FLOWBRIDGE_WFP_VM=1 and an elevated disposable Windows VM are required')
    helper = args.helper.resolve(strict=True)
    probe_binary = args.probe.resolve(strict=True)
    report = {'passed': False, 'source_commit': os.environ.get('GITHUB_SHA'),
              'binary_sha256': {'helper': sha256_file(helper),
                                'probe': sha256_file(probe_binary)},
              'coverage': {'real_wfp_redirect': False,
             'selected_executable': True, 'external_network': False,
             'ssh_forwarding_tested': False, 'dns_settings_changed': False,
             'dns_interception_tested': False, 'owner_process_death_cleanup': False,
             'ipv4_redirect_verified': False, 'ipv6_redirect_verified': False,
             'selected_udp_bypassed': False, 'selected_ipv6_udp_bypassed': False},
             'platform': platform.platform(), 'checks': [],
             'helper_event_counts': {}, 'socks_connects_by_family': {}}
    event = None
    server_threads = []
    process = None
    owner = None
    reader = None
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateEventW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p]
    kernel.CreateEventW.restype = ctypes.c_void_p
    kernel.SetEvent.argtypes = [ctypes.c_void_p]
    kernel.SetEvent.restype = ctypes.c_int
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    try:
        # This check belongs inside the evidence-producing try/finally. A
        # missing/invalid driver must yield a failed JSON report, not silence.
        preflight = json.loads(subprocess.run([str(helper), '--preflight'], capture_output=True,
                               text=True, timeout=10, check=True).stdout)
        require(preflight.get('kernel_driver_accessible') is True,
                'Signed/test-signed WFP driver not loaded and available to this token')
        report['checks'].append('Driver ABI and access preflight passed; redirect unproven until traffic')
        targets = {}
        udp_targets = {}
        for family, host, tcp_type, udp_type in (
            (socket.AF_INET, '127.0.0.1', Server, UDPServer),
            (socket.AF_INET6, '::1', V6Server, V6UDPServer),
        ):
            echo = tcp_type((host, 0), Echo)
            server_threads.append((echo, start(echo)))
            targets[family] = (host, echo.server_address[1])
            datagram = udp_type((host, 0), UDP)
            server_threads.append((datagram, start(datagram)))
            udp_targets[family] = (host, datagram.server_address[1])
        socks = Server(('127.0.0.1', 0), Socks)
        socks.echo_ports = targets
        server_threads.append((socks, start(socks)))
        event_name = 'Local\\FlowBridgeCaptureStop-' + str(uuid.uuid4())
        event = kernel.CreateEventW(None, True, False, event_name)
        require(event, f'Could not create owned stop event: {ctypes.get_last_error()}')
        with tempfile.TemporaryDirectory(prefix='FlowBridge-redirect-') as directory:
            root = Path(directory)
            selected = root / 'selected' / 'SameNameClient.exe'
            unrelated = root / 'unrelated' / 'SameNameClient.exe'
            for file in [selected, unrelated]:
                file.parent.mkdir()
                shutil.copy2(probe_binary, file)
            config = {'version': 1, 'listen': '127.0.0.1:1081',
                      'proxies': [{'id': 'local-test-socks', 'kind': 'socks5',
                                   'endpoint': {'host': '127.0.0.1', 'port': socks.server_address[1]},
                                   'username': None, 'password_env': None}],
                      'chains': [],
                      'rules': [{'id': 'selected', 'enabled': True,
                                 'applications': ['samenameclient.exe'], 'hosts': [],
                                 'networks': [], 'ports': [],
                                 'action': {'type': 'proxy', 'id': 'local-test-socks'}}],
                      'default_action': {'type': 'direct'}, 'connect_timeout_ms': 4000,
                      'handshake_timeout_ms': 4000, 'idle_timeout_ms': 20000,
                      'max_connections': 16}
            profile = root / 'native-profile.json'
            profile.write_text(json.dumps(config), encoding='utf-8')
            profile_sha256 = hashlib.sha256(profile.read_bytes()).hexdigest()
            mismatch = subprocess.run(
                [str(helper), '--console', '--profile', str(profile),
                 '--capture-app', str(selected), '--gui-owner', str(os.getpid()),
                 '--stop-event', event_name, '--profile-sha256', '0' * 64],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
            require(mismatch.returncode != 0 and
                    'GUI native profile SHA-256 mismatch' in mismatch.stdout,
                    'Elevated helper accepted a modified GUI-owned profile')
            report['checks'].append('Profile tampering across UAC is rejected before WFP is enabled')
            for host, port in targets.values():
                run_probe(selected, host, port)
                run_probe(unrelated, host, port)
            for host, port in udp_targets.values():
                run_probe(selected, host, port, protocol='udp')
            require(socks.connects == 0, 'Selected client used SOCKS before capture')
            report['checks'].append('IPv4/IPv6 TCP and UDP work before WFP capture')
            process = subprocess.Popen([str(helper), '--console', '--profile', str(profile),
                                        '--capture-app', str(selected),
                                        '--gui-owner', str(os.getpid()), '--stop-event', event_name,
                                         '--profile-sha256', profile_sha256],
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            reader = await_helper_ready(process, report['helper_event_counts'])
            for family, (host, port) in targets.items():
                before = socks.connects_by_family[family]
                run_probe(selected, host, port)
                require(socks.connects_by_family[family] > before,
                        f'Selected IPv{4 if family == socket.AF_INET else 6} never entered SOCKS')
                count = socks.connects
                run_probe(unrelated, host, port)
                require(socks.connects == count,
                        'Unrelated full-path EXE with identical basename was captured')
            report['checks'].append('Actual WFP ALE redirect forwards both IPv4 and IPv6 for the selected full EXE path')
            report['coverage']['ipv4_redirect_verified'] = True
            report['coverage']['ipv6_redirect_verified'] = True
            count = socks.connects
            for family, (host, port) in udp_targets.items():
                run_probe(selected, host, port, protocol='udp')
                require(socks.connects == count, 'Selected UDP was incorrectly captured by TCP-only WFP policy')
                report['coverage']['selected_udp_bypassed' if family == socket.AF_INET
                                   else 'selected_ipv6_udp_bypassed'] = True
            report['checks'].append('Selected IPv4 and IPv6 UDP remain unaffected, no SOCKS ingress')
            socks.deny = True
            for host, port in targets.values():
                run_probe(selected, host, port, success=False)
                run_probe(unrelated, host, port)
            report['checks'].append('Explicit SOCKS denial cannot fall back to DIRECT for either IP family')
            require(kernel.SetEvent(event), 'Stop event could not be signaled')
            require(process.wait(timeout=30) == 0, 'Native helper did not cleanly stop')
            for host, port in targets.values():
                run_probe(selected, host, port)
            report['checks'].append('Stop event drops both IPv4 and IPv6 WFP dynamic filters')
            reader.join(timeout=5)
            if process.stdout:
                process.stdout.close()
            process = None

            # Second actual redirect run tests the independent owner-PID
            # lifetime guard without setting the stop event. A disposable
            # child plays the GUI-owner role; no real GUI or user apps are
            # terminated. The selected connection must be restored afterward.
            socks.deny = False
            owner = subprocess.Popen(
                [sys.executable, '-c', 'import time; time.sleep(120)'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW)
            require(kernel.CloseHandle(event), 'Could not release the first stop event')
            event = None
            event_name = 'Local\\FlowBridgeCaptureStop-' + str(uuid.uuid4())
            event = kernel.CreateEventW(None, True, False, event_name)
            require(event, f'Could not create owner-death stop event: {ctypes.get_last_error()}')
            process = subprocess.Popen(
                [str(helper), '--console', '--profile', str(profile),
                 '--capture-app', str(selected), '--gui-owner', str(owner.pid),
                 '--stop-event', event_name, '--profile-sha256', profile_sha256],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW)
            reader = await_helper_ready(process, report['helper_event_counts'])
            before = socks.connects
            for host, port in targets.values():
                run_probe(selected, host, port)
            require(socks.connects >= before + 2,
                    'Owner-lifetime run did not capture both selected IPv4/IPv6 flows')
            owner.terminate()
            owner.wait(timeout=10)
            require(process.wait(timeout=30)==0,
                    'Helper survived abrupt GUI-owner termination')
            reader.join(timeout=5)
            for host, port in targets.values():
                run_probe(selected, host, port)
            report['checks'].append('Abrupt GUI-owner death removes both IPv4 and IPv6 dynamic filters')
            report['coverage']['owner_process_death_cleanup'] = True
            report['socks_connects_by_family'] = {
                'ipv4': socks.connects_by_family[socket.AF_INET],
                'ipv6': socks.connects_by_family[socket.AF_INET6],
            }
            report['coverage']['real_wfp_redirect'] = True
            report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        if event:
            kernel.SetEvent(event)
        if owner and owner.poll() is None:
            owner.terminate()
            owner.wait(timeout=10)
        if process:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
            if process.stdout:
                process.stdout.close()
        if event:
            kernel.CloseHandle(event)
        for server, thread in server_threads:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, indent=2), flush=True)


if __name__ == '__main__':
    main()
