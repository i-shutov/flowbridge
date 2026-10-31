#!/usr/bin/env python3
"""Explicit VDSina native self-socket -> NDISRD -> Rust -> SOCKS -> SSH canary.

Not a hosted-fixture simulation: this requires a real, separately installed
NDISRD driver, a prearmed independent recovery task and a scoped firewall rule.
All SSH keys are newly generated in TemporaryDirectory and never uploaded.
Only aggregate evidence is persisted; arbitrary app/protected acceptance stays false.
"""
from __future__ import annotations

import argparse
import contextlib
import getpass
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading

from ssh_real_integration import ABI, Echo, Server, free_port, require, until, round_trip
from windows_real_ssh_hosted import secure_test_file


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('agent', 'library', 'ssh', 'sshd', 'keygen', 'context', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform == 'win32' and os.environ.get('FLOWBRIDGE_VPS_NATIVE') == 'OWNER_VNC_CONFIRMED',
            'Explicit dedicated VPS consent is required')
    context = json.loads(args.context.read_text(encoding='utf-8-sig'))
    require(context.get('recovery_armed') is True and context.get('defender_active') is True,
            'Independent safety prerequisites missing')
    target = context['target_ipv4']
    socket.inet_aton(target)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    result = {
        'passed': False,
        'kind': 'actual_self_owned_tcp_ndisrd_reflection_real_flowbridge_socks_openssh',
        'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        'agent_sha256': digest(args.agent),
        'ffi_sha256': digest(args.library),
        'ssh_sha256': digest(args.ssh),
        'sshd_sha256': digest(args.sshd),
        'driver_was_used': False,
        'arbitrary_selected_app_accepted': False,
        'general_packet_pid_proof': False,
        'persistent_fail_closed_accepted': False,
        'dns_leak_free': False,
        'win10_11_acceptance': False,
        'release_accepted': False,
        'packet_payload_or_identity_saved': False,
    }
    abi = ABI(args.library.resolve())
    supervisor = engine = 0
    daemon = None
    echo = Server(('127.0.0.1', 0), Echo)
    echo_thread = threading.Thread(target=echo.serve_forever, daemon=True)
    echo_thread.start()
    temporary = tempfile.TemporaryDirectory(prefix="flowbridge-native-ssh-")
    try:
        with contextlib.nullcontext(temporary.name) as temporary_name:
            root = Path(temporary_name)
            for name in ('host_key', 'client_key'):
                subprocess.run([str(args.keygen), '-q', '-t', 'ed25519', '-N', '', '-f', str(root / name)],
                               check=True, capture_output=True, timeout=15)
                secure_test_file(root / name)
            authorized = root / 'authorized_keys'
            authorized.write_bytes((root / 'client_key.pub').read_bytes())
            secure_test_file(authorized)
            ssh_port, socks_port, ingress = free_port(), free_port(), free_port()
            require(len({ssh_port, socks_port, ingress, echo.server_address[1]}) == 4, 'Fixture ports collide')
            user = getpass.getuser().lower()
            require(user.isascii() and user.replace('_', '').replace('-', '').isalnum(), 'Invalid fixture username')
            known = root / 'known_hosts'
            known.write_text(f'[127.0.0.1]:{ssh_port} ' + (root / 'host_key.pub').read_text(), encoding='ascii')
            config = root / 'sshd_config'
            config.write_text('\n'.join([
                f'Port {ssh_port}', 'ListenAddress 127.0.0.1', 'AddressFamily inet',
                f'HostKey "{(root / "host_key").as_posix()}"',
                f'AuthorizedKeysFile "{authorized.as_posix()}"', f'AllowUsers {user}',
                'PasswordAuthentication no', 'PubkeyAuthentication yes', 'AuthenticationMethods publickey',
                'AllowTcpForwarding local', 'GatewayPorts no',
                f'PermitOpen 127.0.0.1:{echo.server_address[1]} {target}:80',
                'LogLevel ERROR', 'MaxStartups 10:30:20', 'MaxSessions 10', '',
            ]), encoding='ascii')
            secure_test_file(config)
            subprocess.run([str(args.sshd), '-t', '-f', str(config)], check=True, capture_output=True, timeout=15)
            with (root / 'sshd.log').open('wb') as log:
                daemon = subprocess.Popen([str(args.sshd), '-D', '-e', '-f', str(config)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=log,
                    creationflags=subprocess.CREATE_NO_WINDOW)
                def ready():
                    require(daemon.poll() is None, 'Isolated sshd exited')
                    try:
                        with socket.create_connection(('127.0.0.1', ssh_port), timeout=.3):
                            return True
                    except OSError:
                        return False
                until(ready, seconds=20)
                settings = {'host': '127.0.0.1', 'port': ssh_port, 'user': user, 'local_port': socks_port,
                    'ssh_executable': str(args.ssh.resolve()), 'identity_file': str(root / 'client_key'),
                    'known_hosts_file': str(known), 'health_check_interval_ms': 250,
                    'health_check_timeout_ms': 1000, 'startup_timeout_ms': 15000,
                    'restart_initial_delay_ms': 250, 'restart_max_delay_ms': 1000,
                    'max_restarts': 3, 'verbose_diagnostics': False}
                supervisor = abi.call('fb_ssh_create_json', settings)['ssh_id']
                abi.call('fb_ssh_start_json', supervisor)
                def snapshot():
                    return abi.call('fb_ssh_snapshot_json', supervisor)['status']
                def client_ready():
                    status = snapshot()
                    require(status['state'] != 'failed', 'SSH supervisor failed')
                    return status['state'] == 'ready' and status['pid']
                until(client_ready, seconds=30)
                initial_pid = snapshot()['pid']
                endpoint = {'host': '127.0.0.1', 'port': socks_port}
                profile = {'version': 1, 'listen': f'127.0.0.1:{ingress}',
                    'proxies': [{'id': 'ssh', 'kind': 'socks5', 'endpoint': endpoint}], 'chains': [],
                    'rules': [], 'default_action': {'type': 'proxy', 'id': 'ssh'}, 'max_connections': 8,
                    'connect_timeout_ms': 5000, 'handshake_timeout_ms': 5000, 'idle_timeout_ms': 30000}
                engine = abi.call('fb_engine_create_json', profile)['engine_id']
                def gate(allow):
                    abi.call('fb_engine_set_upstream_gate_json', engine, {
                        'endpoint': endpoint, 'ready': allow, 'grace_ms': 0,
                        'limits': {'max_flows': 4, 'max_opening': 2, 'max_queued': 4, 'wait_timeout_ms': 200}})
                gate(True)
                abi.call('fb_engine_start_json', engine)
                round_trip(ingress, echo.server_address[1])
                result['actual_supervised_ssh_authenticated'] = True
                def probe(expect_denied):
                    request = {'adapter_name': context['adapter_name'], 'local_ipv4': context['local_ipv4'],
                        'target': f'{target}:80', 'upstream': f'127.0.0.1:{ingress}',
                        'duration_ms': 12000, 'consent': 'NATIVE_SELF_SOCKET_TCP_REFLECT',
                        'expect_denied': expect_denied}
                    proc = subprocess.run([str(args.agent.resolve()), 'native-self-redirect', json.dumps(request)],
                        capture_output=True, text=True, encoding='utf-8', timeout=20, check=False)
                    report = json.loads(proc.stdout)
                    require(isinstance(report, dict), 'No structured agent report')
                    report['process_exit_code'] = proc.returncode
                    return report
                for phase, deny in [('connected', False), ('gate_closed', True), ('recovered', False)]:
                    gate(not deny)
                    report = probe(deny)
                    result[phase] = report
                    result['driver_was_used'] = result['driver_was_used'] or report.get('actual_ndisrd_tunnel') is True
                    require(report.get('rollback_confirmed') is True, 'Native adapter rollback not confirmed')
                    require(report.get('passed') is True and report.get('process_exit_code') == 0,
                            f'Native {phase} canary did not satisfy all gates')
                    require(report.get('selected_original_frames_sent_to_adapter') == 0,
                            'Selected original packet escaped to physical adapter')
                    require(report.get('self_owned_socket_pid_epoch_consistent') is True,
                            'Self-owned socket epoch not confirmed')
                    require(report.get('release_accepted') is False, 'False release claim')
                require(snapshot()['pid'] == initial_pid, 'SSH restarted unexpectedly')
                result['same_supervised_ssh_across_failure_recovery'] = True
                result['native_self_owned_tcp_to_real_socks_ssh_verified'] = True
                result['passed'] = True
    except Exception as exc:
        result['error_class'] = type(exc).__name__
        result['error'] = str(exc) if isinstance(exc, AssertionError) else 'Native harness failed; inspect stage reports'
        raise
    finally:
        if engine: abi.lib.fb_engine_destroy(engine)
        if supervisor: abi.lib.fb_ssh_destroy(supervisor)
        if daemon and daemon.poll() is None:
            subprocess.run(['taskkill', '/PID', str(daemon.pid), '/T', '/F'], capture_output=True, timeout=15, check=False)
            daemon.wait(timeout=10)
        echo.shutdown(); echo.server_close(); echo_thread.join(timeout=3)
        args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'native_self_redirect': result}), flush=True)
        temporary.cleanup()


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Native self-redirect check failed; sanitized evidence is retained.', file=sys.stderr)
        sys.exit(1)
