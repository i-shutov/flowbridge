#!/usr/bin/env python3
"""VM-only actual WFP -> elevated helper -> user-owned FlowBridge -> SOCKS -> echo.

This tests a real installed WFP redirect driver and the real GUI-owner Rust
engine in a *separate process from the elevated helper*, with an isolated mock
for the remote SSH SOCKS endpoint. The VM harness itself requires an admin
token and does NOT prove the normal GUI's medium-integrity security boundary.
It does NOT
test OpenSSH authentication, remote system DNS, DNS interception, TLS or QUIC.
Only loopback sockets and disposable test executables are used.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid

from ssh_real_integration import ABI, free_port, require, until
from windows_wfp_redirect_runtime import (
    Echo, Server, V6Server, Socks, run_probe, start, await_helper_ready,
)


def profile(listen, proxies, default, rules=None):
    return {
        'version': 1, 'listen': listen, 'proxies': proxies, 'chains': [],
        'rules': rules or [], 'default_action': default,
        'connect_timeout_ms': 3000, 'handshake_timeout_ms': 3000,
        'idle_timeout_ms': 20000, 'max_connections': 16,
    }


def configure_kernel():
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateEventW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p]
    kernel.CreateEventW.restype = ctypes.c_void_p
    kernel.SetEvent.argtypes = [ctypes.c_void_p]
    kernel.SetEvent.restype = ctypes.c_int
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    return kernel


def main():
    args_parser = argparse.ArgumentParser(description=__doc__)
    args_parser.add_argument('--helper', type=Path, required=True)
    args_parser.add_argument('--probe', type=Path, required=True)
    args_parser.add_argument('--library', type=Path, required=True)
    args_parser.add_argument('--output', type=Path, required=True)
    args = args_parser.parse_args()
    require(sys.platform == 'win32' and os.environ.get('FLOWBRIDGE_WFP_VM') == '1'
            and ctypes.windll.shell32.IsUserAnAdmin(),
            'Dedicated authorized administrator Windows VM and FLOWBRIDGE_WFP_VM=1 required')
    report = {
        'passed': False, 'commit': os.environ.get('GITHUB_SHA'),
        'platform': platform.platform(), 'checks': [],
        'coverage': {'loaded_wfp_driver_traffic': False,
                     'real_user_owned_ffi_engine': False,
                     'ipv4_redirect': False, 'ipv6_redirect': False,
                     'user_engine_readiness_gate_no_direct': False,
                     'user_engine_loss_filter_cleanup': False,
                     'remote_openssh_authentication': False,
                     'remote_dns_interception': False,
                     'external_network': False,
                     'gui_process_medium_integrity_verified': False,
                     'ssh_keys_read_by_elevated_helper': False}
    }
    helper = args.helper.resolve(strict=True)
    probe = args.probe.resolve(strict=True)
    library = args.library.resolve(strict=True)
    kernel = configure_kernel()
    servers = []
    engine = 0
    process = None
    reader = None
    event = None
    engine_started = False
    try:
        # This ABI lives in the Python GUI-owner stand-in process. The
        # VM's admin token is required here, so this is not a medium-integrity
        # GUI identity test. The helper loads a separate DLL instance.
        abi = ABI(library)
        for host, kind in [('127.0.0.1', Server), ('::1', V6Server)]:
            echo = kind((host, 0), Echo)
            servers.append((echo, start(echo)))
        targets = {socket.AF_INET: ('127.0.0.1', servers[0][0].server_address[1]),
                   socket.AF_INET6: ('::1', servers[1][0].server_address[1])}
        mock = Server(('127.0.0.1', 0), Socks)
        mock.echo_ports = targets
        servers.append((mock, start(mock)))
        target_proxy = {'host': '127.0.0.1', 'port': mock.server_address[1]}
        port = free_port()
        require(port not in (1, mock.server_address[1]), 'Ephemeral GUI port conflict')
        user = profile(f'127.0.0.1:{port}',
                       [{'id': 'managed-ssh', 'kind': 'socks5', 'endpoint': target_proxy,
                         'username': None, 'password_env': None}],
                       {'type': 'proxy', 'id': 'managed-ssh'})
        # A GUI-selected-app profile contains only the verified local listener.
        # There are no user identity keys or unrelated proxies in this helper.
        helper_profile = profile(
            '127.0.0.1:1',
            [{'id': 'gui-owned-socks', 'kind': 'socks5',
              'endpoint': {'host': '127.0.0.1', 'port': port},
              'username': None, 'password_env': None}],
            {'type': 'direct'},
            [{'id': 'selected', 'enabled': True,
              'applications': ['samenameclient.exe'], 'hosts': [], 'networks': [],
              'ports': [], 'action': {'type': 'proxy', 'id': 'gui-owned-socks'}}])
        limits = {'max_flows': 4, 'max_opening': 2,
                  'max_queued': 4, 'wait_timeout_ms': 1500}
        with tempfile.TemporaryDirectory(prefix='FlowBridge-userchain-') as temporary:
            folder = Path(temporary)
            selected = folder / 'selected' / 'SameNameClient.exe'
            other = folder / 'unselected' / 'SameNameClient.exe'
            for item in (selected, other):
                item.parent.mkdir()
                shutil.copy2(probe, item)
            path = folder / 'native-profile.json'
            payload = json.dumps(helper_profile, separators=(',', ':')).encode('utf-8')
            path.write_bytes(payload)
            pinned_sha = hashlib.sha256(payload).hexdigest()

            preflight = json.loads(subprocess.run(
                [str(helper), '--preflight'], capture_output=True,
                text=True, timeout=10, check=True).stdout)
            require(preflight.get('kernel_driver_accessible') is True,
                    'Driver not installed/loaded under authorized VM test token')
            report['checks'].append('Read-only device ABI probe confirms an accessible signed/test-signed driver')
            # The GUI-owner engine owns its actual loopback listener and is
            # the only component with the simulated SSH upstream reference.
            engine = abi.call('fb_engine_create_json', user)['engine_id']
            abi.call('fb_engine_set_upstream_gate_json', engine,
                     {'endpoint': target_proxy, 'ready': True,
                      'grace_ms': 1500, 'limits': limits})
            abi.call('fb_engine_start_json', engine)
            engine_started = True
            until(lambda: abi.call('fb_engine_snapshot_json', engine)['status']['running'], 5)
            report['checks'].append('Real Rust FFI engine in GUI-owner test PID owns the loopback SOCKS listener')

            for host, target_port in targets.values():
                run_probe(selected, host, target_port)
                run_probe(other, host, target_port)
            require(mock.connects == 0, 'Baseline selected EXE unexpectedly reached user-owned SOCKS')

            def new_session():
                nonlocal process, event, reader
                event_name = 'Local\\FlowBridgeCaptureStop-' + str(uuid.uuid4())
                event = kernel.CreateEventW(None, True, False, event_name)
                require(event, 'Cannot create native GUI-owned stop event')
                command = [
                    str(helper), '--console', '--profile', str(path),
                    '--capture-app', str(selected), '--gui-owner', str(os.getpid()),
                    '--stop-event', event_name, '--profile-sha256', pinned_sha,
                ]
                process = subprocess.Popen(
                    command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, creationflags=subprocess.CREATE_NO_WINDOW)
                reader = await_helper_ready(process)

            def stop_session():
                nonlocal process, event, reader
                require(event and kernel.SetEvent(event), 'Failed to stop GUI-owned native helper')
                require(process.wait(timeout=30) == 0, 'Native helper did not stop cleanly')
                reader.join(timeout=5)
                if process.stdout:
                    process.stdout.close()
                process = None
                kernel.CloseHandle(event)
                event = None
                reader = None

            new_session()
            # This is the first actual end-to-end OS capture proof for the
            # user-owned GUI route; the previous hosted CI stops at native ABI.
            for family, (host, target_port) in targets.items():
                before = mock.connects_by_family[family]
                run_probe(selected, host, target_port)
                require(mock.connects_by_family[family] > before,
                        'WFP selected stream bypassed the user-owned GUI engine')
                count = mock.connects
                run_probe(other, host, target_port)
                require(mock.connects == count,
                        'Unselected same-name path unexpectedly entered GUI SOCKS')
            report['coverage']['loaded_wfp_driver_traffic'] = True
            report['coverage']['real_user_owned_ffi_engine'] = True
            report['coverage']['ipv4_redirect'] = True
            report['coverage']['ipv6_redirect'] = True
            report['checks'].append('Real kernel IPv4/IPv6 redirect → helper → user-owned Rust → second SOCKS hop')

            # Gate false must never translate a selected-flow failure into
            # a direct application connection to its original echo port.
            abi.call('fb_engine_set_upstream_gate_json', engine,
                     {'endpoint': target_proxy, 'ready': False,
                      'grace_ms': 1500, 'limits': limits})
            before_mock = mock.connects
            before_echo = {family: servers[0 if family == socket.AF_INET else 1][0].accepted
                           for family in targets}
            for family, (host, target_port) in targets.items():
                run_probe(selected, host, target_port, success=False)
                require(mock.connects == before_mock,
                        'A paused user-level SSH gate opened an upstream SOCKS connection')
                require(servers[0 if family == socket.AF_INET else 1][0].accepted == before_echo[family],
                        'Selected flow reached original target via DIRECT while SSH was paused')
            report['checks'].append('Paused user-owned SSH gate rejects selected IPv4/IPv6 without DIRECT')
            report['coverage']['user_engine_readiness_gate_no_direct'] = True
            abi.call('fb_engine_set_upstream_gate_json', engine,
                     {'endpoint': target_proxy, 'ready': True,
                      'grace_ms': 1500, 'limits': limits})
            for host, target_port in targets.values():
                run_probe(selected, host, target_port)
            report['checks'].append('Both IP families recover for new connections after SSH gate resumes')

            stop_session()
            count = mock.connects
            for host, target_port in targets.values():
                run_probe(selected, host, target_port)
            require(mock.connects == count,
                    'Stopped helper left WFP filters rerouting selected TCP to GUI SOCKS')
            report['checks'].append('Normal stop removes both WFP filters before user-owned engine shutdown')

            # A second kernel capture session verifies listener-loss cleanup.
            new_session()
            for host, target_port in targets.values():
                run_probe(selected, host, target_port)
            abi.call('fb_engine_stop_json', engine)
            engine_started = False
            require(process.wait(timeout=12) != 0,
                    'Helper survived disappearance of its owner-validated GUI SOCKS listener')
            reader.join(timeout=5)
            if process.stdout:
                process.stdout.close()
            process = None
            kernel.CloseHandle(event)
            event = None
            reader = None
            count = mock.connects
            for host, target_port in targets.values():
                run_probe(selected, host, target_port)
            require(mock.connects == count,
                    'Closed user-level GUI listener left stale kernel WFP redirect filters')
            report['coverage']['user_engine_loss_filter_cleanup'] = True
            report['checks'].append('Loss of GUI-owned SOCKS listener withdraws WFP filters (not a system kill-switch)')
            report['mock_socks_connects'] = {
                'ipv4': mock.connects_by_family[socket.AF_INET],
                'ipv6': mock.connects_by_family[socket.AF_INET6],
            }
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
        if engine:
            try:
                if engine_started:
                    abi.call('fb_engine_stop_json', engine)
            finally:
                abi.lib.fb_engine_destroy(engine)
        for server, thread in servers:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, indent=2), flush=True)


if __name__ == '__main__':
    main()
