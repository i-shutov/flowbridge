#!/usr/bin/env python3
"""Explicit VDSina native self-socket -> NDISRD -> Rust -> SOCKS -> SSH canary.

Requires a real separately installed NDISRD driver, prearmed independent
recovery and a scoped firewall rule. Ephemeral SSH keys are never uploaded.
Only aggregate evidence is saved; arbitrary-app/protected flags stay false.
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
from windows_rust_managed_ssh_control import (
    control as rust_control, make_config as rust_managed_config,
    owned_ssh_listener_pid, wait_for as wait_for_rust,
)
from windows_external_powershell_lab import ExternalPowerShellCanary


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
    source_sha = os.environ.get('FLOWBRIDGE_SOURCE_SHA', '')
    require(len(source_sha) == 40 and all(c in '0123456789abcdef' for c in source_sha),
            'Externally verified source tree SHA is mandatory')
    result = {
        'passed': False,
        'kind': 'actual_self_owned_tcp_ndisrd_reflection_real_flowbridge_socks_openssh',
        'source_commit': source_sha,
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
                f'PermitOpen localhost:{echo.server_address[1]} 127.0.0.1:{echo.server_address[1]} {target}:80',
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
                def probe(expect_denied, source='self'):
                    result['pending_step'] = 'validate_canary_request'
                    require(source in ('self', 'rust-child', 'powershell', 'external-powershell'),
                            'Unrecognized native lab client')
                    consents = {'self': 'NATIVE_SELF_SOCKET_TCP_REFLECT',
                                'rust-child': 'NATIVE_SPAWNED_CHILD_TCP_REFLECT',
                                'powershell': 'NATIVE_POWERSHELL_CHILD_TCP_REFLECT',
                                'external-powershell': 'NATIVE_UNRELATED_OS_POWERSHELL_TCP_REFLECT'}
                    request = {'adapter_name': context['adapter_name'], 'local_ipv4': context['local_ipv4'],
                        'target': f'{target}:80', 'upstream': f'127.0.0.1:{ingress}',
                        'duration_ms': 12000, 'consent': consents[source],
                        'spawned_child': source == 'rust-child',
                        'powershell_child': source == 'powershell',
                        'expect_denied': expect_denied}
                    if source == 'external-powershell':
                        # Sibling to Rust agent: QA owns process creation/lifetime.
                        # Neither PID nor ephemeral ports are saved in reports.
                        result['pending_step'] = 'create_independent_signed_process'
                        with ExternalPowerShellCanary(context['local_ipv4'], target) as external:
                            request['external_client'] = external.request()
                            result['pending_step'] = 'native_agent_execution'
                            proc = subprocess.run([str(args.agent.resolve()), 'native-self-redirect', json.dumps(request)],
                                capture_output=True, text=True, encoding='utf-8', timeout=20, check=False)
                            result['pending_step'] = 'independent_process_exit'
                            external.await_exit()
                    else:
                        proc = subprocess.run([str(args.agent.resolve()), 'native-self-redirect', json.dumps(request)],
                            capture_output=True, text=True, encoding='utf-8', timeout=20, check=False)
                    result['pending_step'] = 'parse_native_report'
                    report = json.loads(proc.stdout)
                    require(isinstance(report, dict), 'No structured agent report')
                    report['process_exit_code'] = proc.returncode
                    return report
                phases = [('connected', False, 'self'), ('gate_closed', True, 'self'),
                          ('recovered', False, 'self'), ('child_connected', False, 'rust-child'),
                          ('child_gate_closed', True, 'rust-child'),
                          ('child_recovered', False, 'rust-child'),
                          ('powershell_connected', False, 'powershell'),
                          ('powershell_gate_closed', True, 'powershell'),
                          ('powershell_recovered', False, 'powershell'),
                          ('unrelated_connected', False, 'external-powershell'),
                          ('unrelated_gate_closed', True, 'external-powershell'),
                          ('unrelated_recovered', False, 'external-powershell')]
                for phase, deny, source in phases:
                    result['pending_phase'] = phase
                    result['pending_step'] = 'upstream_gate'
                    gate(not deny)
                    report = probe(deny, source)
                    result[phase] = report
                    result['driver_was_used'] = result['driver_was_used'] or report.get('actual_ndisrd_tunnel') is True
                    require(report.get('rollback_confirmed') is True, 'Native adapter rollback not confirmed')
                    require(report.get('passed') is True and report.get('process_exit_code') == 0,
                            f'Native {phase} canary did not satisfy all gates')
                    require(report.get('selected_original_frames_sent_to_adapter') == 0,
                            'Selected original packet escaped to physical adapter')
                    evidence_field = {'self': 'self_owned_socket_pid_epoch_consistent',
                                      'rust-child': 'spawned_child_socket_pid_epoch_consistent',
                                      'powershell': 'powershell_child_socket_pid_epoch_consistent',
                                      'external-powershell': 'external_sibling_socket_pid_epoch_consistent'}[source]
                    require(report.get(evidence_field) is True,
                            'Expected pinned live process epoch not confirmed')
                    if source != 'self':
                        require(report.get('self_owned_socket_pid_epoch_consistent') is False,
                                'Child flow was incorrectly reported as parent-owned')
                        authority = {
                            'rust-child': 'parent_spawned_child_live_process_and_bound_port_not_general_packetbound',
                            'powershell': 'parent_spawned_os_powershell_client_and_bound_port_not_general_packetbound',
                            'external-powershell': 'independently_launched_fixed_os_powershell_bound_socket_not_packetbound',
                        }[source]
                        if source == 'external-powershell':
                            require(report.get('external_process_exit_confirmed') is True,
                                    'Unrelated process must exit before restoring normal networking')
                        require(report.get('source_authority') == authority,
                                'Cross-runtime evidence authority exaggerated')
                    require(report.get('arbitrary_app_owner_binding_accepted') is False and
                            report.get('native_owner_binding_accepted') is False,
                            'Cannot promote a controlled canary to PacketBound')
                    require(report.get('release_accepted') is False, 'False release claim')
                    result.pop('pending_phase', None)
                    result.pop('pending_step', None)
                require(snapshot()['pid'] == initial_pid, 'SSH restarted unexpectedly')
                result['same_supervised_ssh_across_failure_recovery'] = True
                # This deliberately stops the REAL supervised ssh.exe rather
                # than just toggling an upstream gate around a still-live SSH.
                # Close the gate BEFORE reaping the child. This is an explicit
                # operator-controlled lab lifecycle, not automatic crash
                # fail-closed or general selected-application protection.
                result['pending_step'] = 'close_gate_then_reap_real_ssh'
                gate(False)
                stopped = abi.call('fb_ssh_stop_json', supervisor)['status']
                require(stopped['state'] == 'stopped' and stopped['pid'] is None,
                        'Explicit real SSH stop did not reap the owned process')
                observed_stop = snapshot()
                require(observed_stop['state'] == 'stopped' and observed_stop['pid'] is None,
                        'Stopped SSH supervisor unexpectedly retained/restarted a child')
                result['controlled_real_ssh_process_stopped'] = True

                def verify_lifecycle_native(report, phase, source, denied):
                    require(report.get('passed') is True and report.get('process_exit_code') == 0,
                            f'Native SSH lifecycle {phase} failed')
                    require(report.get('actual_ndisrd_tunnel') is True
                            and report.get('rollback_confirmed') is True,
                            f'Native SSH lifecycle {phase} lacked real driver/rollback')
                    require(report.get('selected_original_frames_sent_to_adapter') == 0
                            and report.get('fresh_tcp_owner_candidate_denials_dropped') is True
                            and report.get('fresh_owner_candidate_is_not_packetbound') is True,
                            f'Native SSH lifecycle {phase} violated deny/owner boundary')
                    require(report.get('arbitrary_app_owner_binding_accepted') is False
                            and report.get('native_owner_binding_accepted') is False
                            and report.get('protected_redirect_available') is False
                            and report.get('release_accepted') is False,
                            f'Native SSH lifecycle {phase} overstated authorization')
                    field = {'self': 'self_owned_socket_pid_epoch_consistent',
                             'rust-child': 'spawned_child_socket_pid_epoch_consistent',
                             'powershell': 'powershell_child_socket_pid_epoch_consistent',
                             'external-powershell': 'external_sibling_socket_pid_epoch_consistent'}[source]
                    require(report.get(field) is True,
                            f'Native SSH lifecycle {phase} lost exact controlled source witness')
                    if source == 'external-powershell':
                        require(report.get('external_process_exit_confirmed') is True,
                                'Independent PowerShell must exit before adapter mode zero')
                    if denied:
                        require(report.get('upstream_socks_failed') is True
                                and report.get('upstream_socks_connected') is False
                                and report.get('application_received_http') is False,
                                f'Native SSH lifecycle {phase} leaked traffic while SSH stopped')
                    else:
                        require(report.get('upstream_socks_connected') is True
                                and report.get('application_received_http') is True
                                and report.get('application_and_relay_byte_counts_match') is True,
                                f'Native SSH lifecycle {phase} failed after real SSH restart')

                sources = ('self', 'rust-child', 'powershell', 'external-powershell')
                for source in sources:
                    phase = 'ssh_stopped_' + source.replace('-', '_')
                    result['pending_phase'] = phase
                    result['pending_step'] = 'native_traffic_while_real_ssh_stopped'
                    report = probe(True, source)
                    result[phase] = report
                    verify_lifecycle_native(report, phase, source, True)
                    result.pop('pending_phase', None)
                result['real_ssh_stopped_native_denials'] = len(sources)
                result['pending_step'] = 'restart_real_supervised_ssh'
                abi.call('fb_ssh_start_json', supervisor)
                restarted_pid = until(client_ready, seconds=30)
                require(restarted_pid != initial_pid,
                        'SSH restart did not create a distinct supervised OS child')
                gate(True)
                for source in sources:
                    phase = 'ssh_restarted_' + source.replace('-', '_')
                    result['pending_phase'] = phase
                    result['pending_step'] = 'native_traffic_after_real_ssh_restart'
                    report = probe(False, source)
                    result[phase] = report
                    verify_lifecycle_native(report, phase, source, False)
                    result.pop('pending_phase', None)
                result['real_ssh_restarted_native_recoveries'] = len(sources)
                result['new_supervised_ssh_pid_after_explicit_stop'] = True
                result['ssh_lifecycle_gate_was_closed_manually'] = True

                # A separate original Rust control-plane agent now fronts the
                # real signed-NDISRD controlled PowerShell TCP reflection. Its
                # SSH supervisor, not this test, owns automatic admission.
                result['pending_step'] = 'prepare_native_rust_automatic_ssh_crash'
                reserved = {ssh_port, socks_port, ingress, echo.server_address[1]}
                crash_socks = free_port()
                while crash_socks in reserved:
                    crash_socks = free_port()
                reserved.add(crash_socks)
                crash_ingress = free_port()
                while crash_ingress in reserved:
                    crash_ingress = free_port()
                crash_profile = rust_managed_config(
                    args.ssh, root / 'client_key', known, user,
                    ssh_port, crash_socks, crash_ingress)
                # Disposable test delay only, never a production setting.
                crash_profile['ssh']['restart_initial_delay_ms'] = 18000
                crash_profile['ssh']['restart_max_delay_ms'] = 18000
                crash_config = root / 'native-rust-managed.json'
                crash_config.write_text(json.dumps(crash_profile), encoding='utf-8')
                secure_test_file(crash_config)
                crash_agent = subprocess.Popen(
                    [str(args.agent.resolve()), 'control-serve', str(crash_config)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, encoding='utf-8',
                    creationflags=subprocess.CREATE_NO_WINDOW)
                try:
                    def rust_agent_ready():
                        require(crash_agent.poll() is None, 'Original Rust control agent exited')
                        state = rust_control(args.agent, 'status', accept_failure=True)
                        if state is not None and state.get('managed_ssh_gate_ready') is True:
                            require(state['managed_ssh']['socks_ready_observed'] is True,
                                    'Rust gate and supervised listener disagree')
                            return state
                        return None

                    wait_for_rust(rust_agent_ready, seconds=35)
                    ingress = crash_ingress
                    round_trip(ingress, echo.server_address[1])
                    result['pending_phase'] = 'native_rust_auto_crash_connected'
                    baseline = probe(False, 'external-powershell')
                    result['native_rust_auto_crash_connected'] = baseline
                    verify_lifecycle_native(baseline, 'native_rust_auto_crash_connected',
                                            'external-powershell', False)
                    result['pending_step'] = 'verify_exact_owned_ssh_child_and_kill'
                    old_child = owned_ssh_listener_pid(crash_socks, crash_agent.pid)
                    killed = subprocess.run(
                        ['taskkill', '/PID', str(old_child), '/F'],
                        capture_output=True, text=True, timeout=8, check=False)
                    require(killed.returncode == 0, 'Exact owned SSH child kill failed')
                    def rust_gate_closed():
                        state = rust_control(args.agent, 'status', accept_failure=True)
                        if state is not None and state.get('managed_ssh_gate_ready') is False:
                            require(state['managed_ssh']['socks_ready_observed'] is False,
                                    'Rust reported closed gate with live-ready SSH')
                            return state
                        return None

                    result['pending_step'] = 'automatic_rust_gate_close_without_manual_override'
                    wait_for_rust(rust_gate_closed, seconds=5)
                    result['pending_phase'] = 'native_rust_auto_crash_denied'
                    result['pending_step'] = 'actual_ndisrd_denial_after_unexpected_ssh_death'
                    denied = probe(True, 'external-powershell')
                    result['native_rust_auto_crash_denied'] = denied
                    verify_lifecycle_native(denied, 'native_rust_auto_crash_denied',
                                            'external-powershell', True)
                    result['native_unexpected_ssh_death_automatically_closed_gate'] = True
                    result['pending_step'] = 'automatic_ssh_restart_real_child'
                    wait_for_rust(rust_agent_ready, seconds=45)
                    new_child = owned_ssh_listener_pid(crash_socks, crash_agent.pid)
                    require(new_child != old_child, 'SSH restart reused killed child PID')
                    result['pending_phase'] = 'native_rust_auto_crash_recovered'
                    result['pending_step'] = 'actual_ndisrd_tcp_after_automatic_ssh_recovery'
                    recovered = probe(False, 'external-powershell')
                    result['native_rust_auto_crash_recovered'] = recovered
                    verify_lifecycle_native(recovered, 'native_rust_auto_crash_recovered',
                                            'external-powershell', False)
                    result['native_unexpected_ssh_death_automatically_recovered'] = True
                    result['native_auto_crash_gate_was_closed_manually'] = False
                    result['native_auto_crash_packetbound_accepted'] = False
                    result['native_auto_crash_kernel_fail_closed_accepted'] = False
                    result.pop('pending_phase', None)
                finally:
                    if crash_agent.poll() is None:
                        try:
                            rust_control(args.agent, 'stop')
                        except Exception:
                            crash_agent.kill()
                    try:
                        crash_agent.communicate(timeout=15)
                    except subprocess.TimeoutExpired:
                        crash_agent.kill()
                        crash_agent.communicate(timeout=5)
                    require(crash_agent.returncode == 0 or result.get('passed') is False,
                            'Rust control-plane agent failed graceful lab cleanup')
                result['pending_step'] = 'finalize'
                result['native_self_owned_tcp_to_real_socks_ssh_verified'] = True
                result['native_spawned_child_tcp_to_real_socks_ssh_verified'] = True
                result['native_system_powershell_tcp_to_real_socks_ssh_verified'] = True
                result['native_unrelated_powershell_tcp_to_real_socks_ssh_verified'] = True
                result['general_packet_pid_proof'] = False
                result['arbitrary_selected_app_accepted'] = False
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
