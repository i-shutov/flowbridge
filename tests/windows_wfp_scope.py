#!/usr/bin/env python3
"""Real Windows BFE selection/lifetime QA, NOT a redirect-driver traffic test."""
import argparse
import ctypes
import contextlib
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


class EchoTCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            while data := self.request.recv(4096):
                self.request.sendall(data)
        except OSError:
            pass


class EchoUDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, transport = self.request
        transport.sendto(data, self.client_address)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    executable = args.executable.resolve(strict=True)
    report = {'passed': False, 'os': platform.platform(),
              'commit': os.environ.get('GITHUB_SHA'), 'checks': [],
              'coverage': {'real_bfe': True, 'selector': 'TCP AND full executable path',
                           'layer': 'ALE_AUTH_CONNECT_V4/V6',
                           'redirect_driver_loaded': False, 'ssh_forwarding_tested': False,
                           'dns_settings_changed': False}}
    servers, holders = [], []
    event = None
    try:
        require(sys.platform == 'win32', 'This test must run on Windows, not emulation')
        require(ctypes.windll.shell32.IsUserAnAdmin(), 'Administrator token is required for disposable BFE filters')
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateEventW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p]
        kernel.CreateEventW.restype = ctypes.c_void_p
        kernel.SetEvent.argtypes = [ctypes.c_void_p]
        kernel.SetEvent.restype = ctypes.c_int
        kernel.ResetEvent.argtypes = [ctypes.c_void_p]
        kernel.ResetEvent.restype = ctypes.c_int
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.restype = ctypes.c_int
        event_name = 'Local\\FlowBridgeScopeQA-' + str(uuid.uuid4())
        event = kernel.CreateEventW(None, True, False, event_name)
        require(event, f'CreateEvent failed: {ctypes.get_last_error()}')
        targets = []
        for family, host in [(socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')]:
            for proto in ['tcp', 'udp']:
                base = socketserver.ThreadingTCPServer if proto == 'tcp' else socketserver.ThreadingUDPServer
                kind = type('EchoServer', (base,), {'address_family': family, 'daemon_threads': True})
                server = kind((host, 0), EchoTCP if proto == 'tcp' else EchoUDP)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start(); servers.append((server, thread))
                targets.append((host, server.server_address[1], proto))
        def stop_holders():
            for process in holders:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=10)
        with tempfile.TemporaryDirectory(prefix='FlowBridge scope QA ') as temp, contextlib.ExitStack() as cleanup:
            cleanup.callback(stop_holders)
            copies = []
            for name in ['selected', 'unselected']:
                directory = Path(temp) / name; directory.mkdir()
                path = directory / 'SameNameClient.exe'
                shutil.copy2(executable, path); copies.append(path)
            selected, unselected = copies

            def probe(path, target, denied=False):
                host, port, proto = target
                result = subprocess.run([str(path), 'probe', host, str(port), proto],
                                        capture_output=True, text=True, timeout=10)
                expected = 13 if denied else 0
                require(result.returncode == expected,
                        f'{path.parent.name}/{host}/{proto}: expected {expected}, got '
                        f'{result.returncode}; stdout={result.stdout}; stderr={result.stderr}')
                data = json.loads(result.stdout)
                if denied:
                    require(data.get('connect_error') == 10013, 'Expected WSAEACCES, not an unrelated network failure')
                else:
                    require(data.get('echo_verified') is True, 'Real echoed bytes not verified')

            def hold():
                require(kernel.ResetEvent(event), 'ResetEvent failed')
                process = subprocess.Popen([str(executable), 'hold', str(selected), event_name, str(os.getpid())],
                                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                holders.append(process)
                lines = queue.Queue()
                threading.Thread(target=lambda: lines.put(process.stdout.readline()), daemon=True).start()
                line = lines.get(timeout=15)
                require(line.startswith('{') and json.loads(line).get('ready') is True,
                        f'BFE filter owner failed before ready: {line}')
                return process

            for path in copies:
                for target in targets:
                    probe(path, target)
            report['checks'].append('Both copied clients echo TCP/UDP over IPv4/IPv6 before policy')
            invalid = subprocess.run([str(executable), 'hold', 'relative.exe', event_name, str(os.getpid())],
                                     capture_output=True, text=True, timeout=10)
            require(invalid.returncode == 2 and 'existing absolute' in invalid.stderr,
                    'Relative/nonexistent app path must fail before opening WFP')
            report['checks'].append('Relative or absent executable is rejected before BFE mutation')
            owner = hold()
            for target in targets:
                probe(selected, target, denied=target[2] == 'tcp')
                probe(unselected, target)
            report['checks'].append('Selected full path is blocked for TCP IPv4/IPv6 with WSAEACCES')
            report['checks'].append('Same basename in another directory and selected-client UDP remain unaffected')
            require(kernel.SetEvent(event), 'SetEvent failed')
            require(owner.wait(timeout=10) == 0, 'Graceful filter owner shutdown failed')
            for target in targets:
                probe(selected, target)
            report['checks'].append('Graceful owner stop restores all client TCP/UDP traffic')
            owner = hold()
            for target in targets:
                if target[2] == 'tcp':
                    probe(selected, target, denied=True)
            owner.kill(); owner.wait(timeout=10)
            for target in targets:
                if target[2] != 'tcp':
                    continue
                deadline = time.monotonic() + 10
                while True:
                    try:
                        probe(selected, target); break
                    except AssertionError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.1)
            report['checks'].append('OS removes dynamic filters after abrupt policy-owner termination')
            owner = hold()
            require(kernel.SetEvent(event), 'SetEvent failed')
            require(owner.wait(timeout=10) == 0, 'Second graceful cleanup failed')
            for target in targets:
                probe(selected, target); probe(unselected, target)
            report['checks'].append('Repeated start/stop leaves selected and unrelated copies working')
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        for process in holders:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
            if process.stdout:
                process.stdout.close()
        if event:
            kernel.CloseHandle(event)
        for server, thread in servers:
            server.shutdown(); server.server_close(); thread.join(timeout=5)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, indent=2), flush=True)


if __name__ == '__main__':
    main()
