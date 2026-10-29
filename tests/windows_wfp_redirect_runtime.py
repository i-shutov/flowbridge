#!/usr/bin/env python3
"""Actual selected EXE -> loaded WFP callout -> native helper -> SOCKS -> echo.

RUN ONLY on a disposable, user-authorized Windows VM with the separately
installed *signed/test-signed* FlowBridge WFP driver. Does not install a driver,
change security policy, or contact any external network. This is not executed
as a passing step on ordinary GitHub-hosted runners.
"""
import argparse
import ctypes
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
    connects = 0
    deny = False
    lock = threading.Lock()


class Socks(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        client.settimeout(8)
        try:
            require(exact(client, 3) == b'\x05\x01\x00', 'SOCKS greeting')
            client.sendall(b'\x05\x00')
            require(exact(client, 4) == b'\x05\x01\x00\x01', 'Expected IPv4 SOCKS CONNECT')
            destination = socket.inet_ntoa(exact(client, 4))
            port = int.from_bytes(exact(client, 2), 'big')
            require((destination, port) == ('127.0.0.1', self.server.echo_port),
                    'Unrecognized test-only destination')
            with self.server.lock:
                self.server.connects += 1
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


def run_probe(client, port, *, success=True):
    p = subprocess.run([str(client), 'probe', '127.0.0.1', str(port), 'tcp'],
                       capture_output=True, text=True, timeout=20)
    if success:
        require(p.returncode == 0 and json.loads(p.stdout).get('echo_verified') is True,
                f'{client} did not complete echoed bytes: {p.returncode} {p.stdout} {p.stderr}')
    else:
        require(p.returncode != 0, 'Selected EXE bypassed rejected SOCKS (DIRECT leak)')


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
    report = {'passed': False, 'coverage': {'real_wfp_redirect': False,
             'selected_executable': True, 'external_network': False,
             'ssh_forwarding_tested': False, 'dns_settings_changed': False},
             'platform': platform.platform(), 'checks': []}
    preflight = json.loads(subprocess.run([str(helper), '--preflight'], capture_output=True,
                           text=True, timeout=10, check=True).stdout)
    require(preflight.get('kernel_driver_accessible') is True,
            'Signed/test-signed WFP driver not loaded and available to this token')
    event = None
    server_threads = []
    process = None
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateEventW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p]
    kernel.CreateEventW.restype = ctypes.c_void_p
    kernel.SetEvent.argtypes = [ctypes.c_void_p]
    kernel.SetEvent.restype = ctypes.c_int
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    try:
        echo = Server(('127.0.0.1', 0), Echo)
        server_threads.append((echo, start(echo)))
        socks = Server(('127.0.0.1', 0), Socks)
        socks.echo_port = echo.server_address[1]
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
            run_probe(selected, echo.server_address[1])
            run_probe(unrelated, echo.server_address[1])
            require(socks.connects == 0, 'Selected client used SOCKS before capture')
            report['checks'].append('Both identical-basename executables work without capture')
            process = subprocess.Popen([str(helper), '--console', '--profile', str(profile),
                                        '--capture-app', str(selected),
                                        '--gui-owner', str(os.getpid()), '--stop-event', event_name],
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            ready = queue.Queue()
            def pump():
                for line in process.stdout:
                    try:
                        message = json.loads(line)
                        if message.get('event') == 'ready':
                            ready.put(('ready', message))
                        if message.get('event') == 'faulted':
                            ready.put(('faulted', message))
                    except json.JSONDecodeError:
                        continue
            reader = threading.Thread(target=pump, daemon=True)
            reader.start()
            outcome, value = ready.get(timeout=45)
            require(outcome == 'ready', f'Native capture failed before readiness: {value}')
            run_probe(selected, echo.server_address[1])
            require(socks.connects >= 1, 'Selected client did not enter SOCKS through WFP')
            count = socks.connects
            run_probe(unrelated, echo.server_address[1])
            require(socks.connects == count, 'Unrelated same-basename client was captured')
            report['checks'].append('WFP redirect sends only selected EXE through native SOCKS bridge')
            socks.deny = True
            run_probe(selected, echo.server_address[1], success=False)
            run_probe(unrelated, echo.server_address[1])
            report['checks'].append('Explicit SOCKS denial never falls back to direct TCP')
            require(kernel.SetEvent(event), 'Stop event could not be signaled')
            require(process.wait(timeout=30) == 0, 'Native helper did not cleanly stop')
            run_probe(selected, echo.server_address[1])
            report['checks'].append('Stop event closes helper, drops WFP dynamic filters and restores connection')
            report['coverage']['real_wfp_redirect'] = True
            report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        if event:
            kernel.SetEvent(event)
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
