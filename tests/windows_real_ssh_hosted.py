#!/usr/bin/env python3
"""Real Windows OpenSSH acceptance on a disposable hosted Windows runner.

A private loopback-only sshd uses ephemeral host/user keys and a dedicated
configuration. No system sshd service, firewall, machine DNS, existing keys,
registry settings, or code-integrity policy are changed. No WFP/NE acceptance.
"""
import argparse
import base64
import getpass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import zipfile

from ssh_real_integration import ABI, Echo, Server, distinct_free_ports, free_port, require, until, round_trip
from windows_openssh_capacity_vm import windows_handle_count


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_pool_fixture(archive, sshd, ssh, keygen):
    expected = 'b67ff8becd203502190ec42ac7787c24c2cd3325ed7700485fe7a1c83d2a7957'
    require(sha256(archive) == expected, 'Official portable OpenSSH fixture archive hash mismatch')
    with zipfile.ZipFile(archive) as fixture:
        for file in (sshd, *(sshd.parent / name for name in
                             ('sshd-auth.exe', 'sshd-session.exe', 'libcrypto.dll'))):
            original = hashlib.sha256(fixture.read(f'OpenSSH-Win64/{file.name}')).hexdigest()
            require(sha256(file) == original, 'Selected SSH server payload differs from the pinned fixture')
    system = Path(os.environ['WINDIR']) / 'System32'
    require(ssh.samefile(system / 'OpenSSH/ssh.exe')
            and keygen.samefile(system / 'OpenSSH/ssh-keygen.exe'),
            'Select the built-in Windows OpenSSH client and keygen')
    powershell = system / 'WindowsPowerShell/v1.0/powershell.exe'
    script = r"""
$ErrorActionPreference = 'Stop'
$env:PSModulePath = Join-Path $PSHOME 'Modules'
Import-Module Microsoft.PowerShell.Security
foreach ($file in @($env:FLOWBRIDGE_FIXTURE_SSHD, $env:FLOWBRIDGE_FIXTURE_SSH, $env:FLOWBRIDGE_FIXTURE_KEYGEN)) {
    $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $file
    if ($signature.Status -ne 'Valid' -or
        $signature.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') { exit 1 }
}
"""
    encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
    result = subprocess.run([str(powershell), '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                            env=dict(os.environ, FLOWBRIDGE_FIXTURE_SSHD=str(sshd),
                                     FLOWBRIDGE_FIXTURE_SSH=str(ssh), FLOWBRIDGE_FIXTURE_KEYGEN=str(keygen)),
                            capture_output=True, timeout=45)
    require(result.returncode == 0, 'Fixture OpenSSH Authenticode did not verify as Microsoft Corporation')
    return expected


def verify_candidate(manifest_path, expected_source, dll, dll_sha):
    require(manifest_path and manifest_path.is_file()
            and re.fullmatch('[0-9a-f]{40}', expected_source or '') is not None,
            'Native pool evidence requires the exact Windows candidate manifest and source pin')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    require(manifest['schema'] == 'flowbridge-explicit-beta-windows-qa-package-v1'
            and manifest['source_sha'] == expected_source and manifest['explicit_socks_only'] is True,
            'Manifest does not describe the pinned explicit Windows candidate')
    matches = [entry for entry in manifest['payload'] if entry['path'] == 'flowbridge_ffi.dll']
    require(len(matches) == 1 and matches[0]['sha256'] == dll_sha
            and matches[0]['bytes'] == dll.stat().st_size,
            'Native FFI differs from the candidate payload manifest')
    return {'candidate_source_commit': expected_source,
            'candidate_version': manifest['candidate'],
            'candidate_installer_sha256': manifest['installer_sha256'],
            'candidate_manifest_sha256': sha256(manifest_path)}


def secure_test_file(path):
    """ACL only this generated file; never touch a user/system SSH directory."""
    owner = subprocess.check_output(['whoami', '/user', '/fo', 'csv', '/nh'], text=True)
    import csv
    sid = list(csv.reader([owner.strip()]))[0][1]
    subprocess.run(['icacls', str(path), '/inheritance:r', '/grant:r',
                    f'*{sid}:F', '*S-1-5-18:F', '*S-1-5-32-544:F'],
                   check=True, capture_output=True, timeout=10)
    # Hosted temporary files may retain an EXPLICIT OWNER RIGHTS ACE even
    # after inheritance is removed. OpenSSH correctly rejects that entry.
    # Remove only that extra principal from this freshly generated file;
    # retain the actual owner's SID, SYSTEM and Administrators permissions.
    subprocess.run(['icacls', str(path), '/remove', '*S-1-3-4'],
                   check=True, capture_output=True, timeout=10)


def windows_resources(pid):
    count = windows_handle_count(pid)
    require(count is not None, 'Windows process HANDLE observation failed')
    return {'source': 'windows_process', 'os_handle_count': count,
            'os_fd_count': None, 'vm_rss_kb': None,
            'internal_openssh_fd_table_measured': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh', type=Path, required=True)
    parser.add_argument('--sshd', type=Path, required=True)
    parser.add_argument('--keygen', type=Path, required=True)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--cli', type=Path, default=Path('target/debug/flowbridge.exe'),
                        help='Exact CLI bytes to test; candidate workflow supplies packaged release CLI')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--churn', type=int, default=10000)
    parser.add_argument('--scenario', required=True, choices=('managed', 'raw', 'managed-pool-512'),
                        help='Managed 128, managed pool 512, or bare OpenSSH characterization')
    parser.add_argument('--pool-policy', type=Path,
                        help='FlowBridgeSshPoolRequest built from the Win32 panel policy at this source')
    parser.add_argument('--fixture-archive', type=Path,
                        help='Pinned official portable sshd ZIP for managed-pool-512')
    parser.add_argument('--expect-source-sha', help='Exact harness Git commit for managed-pool-512')
    parser.add_argument('--expect-ffi-sha256', help='Exact candidate or hosted release DLL SHA-256')
    parser.add_argument('--candidate-manifest', type=Path, help='Exact package manifest for native Win11')
    parser.add_argument('--expect-candidate-source', help='Exact source commit of the native Win11 package')
    args = parser.parse_args()
    require(sys.platform == 'win32' and os.environ.get('GITHUB_ACTIONS') == 'true',
            'Run only on an authorized Windows Actions runner')
    pool_only = args.scenario == 'managed-pool-512'
    native = pool_only and os.environ.get('FLOWBRIDGE_NATIVE_WINDOWS_SSH') == '1'
    if native:
        version = sys.getwindowsversion()
        require(os.environ.get('RUNNER_ENVIRONMENT') == 'self-hosted'
                and version.build >= 22000 and version.product_type == 1,
                'The native pool test requires the authorized Windows 11 workstation runner')
    else:
        require(os.environ.get('FLOWBRIDGE_HOSTED_WINDOWS_SSH') == '1'
                and (not pool_only or os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'),
                'Explicit disposable hosted Windows opt-in required')
    require(0 <= args.churn <= 10000, 'Unbounded churn rejected')
    for name in ('ssh', 'sshd', 'keygen', 'library'):
        value = getattr(args, name).resolve(strict=True)
        require(value.is_file(), 'Required executable/library missing')
        setattr(args, name, value)
    if args.scenario == 'managed':
        args.cli = args.cli.resolve(strict=True)
        require(args.cli.is_file(), 'Exact managed-test CLI missing')
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    ffi_digest = sha256(args.library)
    fixture_digest = None
    candidate = {}
    if pool_only:
        require(re.fullmatch('[0-9a-f]{40}', args.expect_source_sha or '') is not None
                and args.expect_source_sha == source and args.pool_policy and args.pool_policy.is_file(),
                'Exact harness commit and compiled Win32 pool policy are required')
        require(subprocess.run(['git', 'diff', '--quiet', 'HEAD', '--'], check=False).returncode == 0,
                'Tracked files differ from the pinned harness source')
        require(re.fullmatch('[0-9a-f]{64}', args.expect_ffi_sha256 or '') is not None
                and args.expect_ffi_sha256 == ffi_digest,
                'Exact candidate or hosted release FFI SHA-256 required')
        require(args.fixture_archive and args.fixture_archive.is_file(),
                'Pinned portable fixture archive is required')
        if native:
            candidate = verify_candidate(args.candidate_manifest, args.expect_candidate_source,
                                         args.library, ffi_digest)
        fixture_digest = verify_pool_fixture(args.fixture_archive, args.sshd, args.ssh, args.keygen)
    args.output.mkdir(parents=True, exist_ok=True)
    report = {'passed': False, 'source_commit': source if pool_only else os.environ.get('GITHUB_SHA'),
              'platform': platform.platform(), 'hosted_windows_runner': not native,
              'native_windows_11_pool_probe': native,
              'windows_10_11_user_machine_tested': False, 'wfp_driver_loaded': False,
              'native_dns_leaks_verified': False, 'system_configuration_modified': False,
              'network_test_destinations_loopback_only': True,
              'scenario': args.scenario, 'managed_acceptance_proved': False,
              'raw_backend_512_stability_proved': False,
              'ssh_sha256': sha256(args.ssh), 'sshd_sha256': sha256(args.sshd),
              'ffi_sha256': ffi_digest,
              'workflow_run_id': os.environ.get('GITHUB_RUN_ID'),
              'source_tree_sha': subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], text=True).strip(),
              'cli_sha256': sha256(args.cli) if args.scenario == 'managed' else None}
    if pool_only:
        report.update(managed_pool_512_proved=False,
                      win32_gui_interaction_exercised=False,
                      compiled_win32_pool_policy_sha256=sha256(args.pool_policy),
                      pinned_fixture_archive_sha256=fixture_digest,
                      microsoft_fixture_signatures_valid=True)
        report.update(candidate)
    supervisor = engine = 0
    daemon = None
    abi = ABI(args.library)
    echo = Server(('127.0.0.1', 0), Echo)
    echo_thread = threading.Thread(target=echo.serve_forever, daemon=True)
    echo_thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix='flowbridge-isolated-sshd-') as temporary:
            root = Path(temporary)
            for name in ('host_key', 'client_key'):
                subprocess.run([str(args.keygen), '-q', '-t', 'ed25519', '-N', '',
                                '-f', str(root / name)], check=True, capture_output=True, timeout=15)
                secure_test_file(root / name)
            authorized = root / 'authorized_keys'
            authorized.write_bytes((root / 'client_key.pub').read_bytes())
            secure_test_file(authorized)
            ssh_port, socks_port, ingress = distinct_free_ports(3)
            require(len({ssh_port,socks_port,ingress,echo.server_address[1]}) == 4,
                    'Port reservation race')
            user = getpass.getuser().lower()
            require(user.isascii() and user.replace('_','').replace('-','').isalnum(),
                    'Unexpected hosted user name')
            known = root / 'known_hosts'
            known.write_text(f'[127.0.0.1]:{ssh_port} ' +
                             (root / 'host_key.pub').read_text(), encoding='ascii')
            config = root / 'sshd_config'
            config.write_text('\n'.join([
                f'Port {ssh_port}', 'ListenAddress 127.0.0.1', 'AddressFamily inet',
                f'HostKey "{(root / "host_key").as_posix()}"',
                f'AuthorizedKeysFile "{authorized.as_posix()}"',
                f'AllowUsers {user}', 'PasswordAuthentication no',
                'PubkeyAuthentication yes', 'AuthenticationMethods publickey',
                'AllowTcpForwarding local', 'GatewayPorts no',
                'PermitOpen localhost:* 127.0.0.1:* [::1]:*', 'LogLevel VERBOSE',
                'MaxStartups 10:30:20', 'MaxSessions 10', ''
            ]), encoding='ascii')
            secure_test_file(config)
            subprocess.run([str(args.sshd), '-t', '-f', str(config)],
                           check=True, capture_output=True, timeout=15)
            with (root / 'sshd.log').open('wb') as server_log:
                try:
                    daemon = subprocess.Popen([str(args.sshd), '-D', '-e', '-f', str(config)],
                                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                              stderr=server_log,
                                              creationflags=subprocess.CREATE_NO_WINDOW)
                    def ready():
                        require(daemon.poll() is None, 'Isolated sshd exited before readiness')
                        try:
                            with socket.create_connection(('127.0.0.1',ssh_port),timeout=.3):
                                return True
                        except OSError:
                            return False
                    until(ready, seconds=20)
                    settings = {'host':'127.0.0.1','port':ssh_port,'user':user,
                                'local_port':socks_port,'ssh_executable':str(args.ssh),
                                'identity_file':str(root/'client_key'), 'known_hosts_file':str(known),
                                'health_check_interval_ms':250,'health_check_timeout_ms':1000,
                                'startup_timeout_ms':15000,'restart_initial_delay_ms':250,
                                'restart_max_delay_ms':1000,'max_restarts':3,'verbose_diagnostics':True}
                    if pool_only:
                        from windows_managed_ssh_pool_capacity import run as pool_capacity
                        result = pool_capacity(abi, settings, echo.server_address[1],
                                               args.pool_policy.resolve(strict=True),
                                               args.output / 'managed-pool-512.json')
                        require(result['passed'], 'Managed 512-flow gate did not pass')
                        report['managed_pool_512_proved'] = True
                    elif args.scenario == 'managed':
                        from ssh_banner_gate import real_authenticated_ssh
                        report['banner_first_real_ssh'] = real_authenticated_ssh(
                            args.cli, args.ssh, root / 'client_key',
                            known, user, ssh_port, echo.server_address[1], free_port())
                        from ssh_banner_gate import real_supervised_banner_gate
                        report['supervised_banner_first_real_ssh'] = real_supervised_banner_gate(
                            abi, args.cli,
                            {'host':'127.0.0.1', 'port':ssh_port, 'user':user,
                             'ssh_executable':str(args.ssh),
                             'identity_file':str(root / 'client_key'),
                             'known_hosts_file':str(known)},
                            echo.server_address[1], free_port())
                        supervisor = abi.call('fb_ssh_create_json',settings)['ssh_id']
                        abi.call('fb_ssh_start_json',supervisor)
                        def snapshot():
                            return abi.call('fb_ssh_snapshot_json',supervisor)['status']
                        def client_ready():
                            status = snapshot()
                            if status['state'] == 'failed':
                                raise RuntimeError('Windows SSH supervisor failed before readiness')
                            return status['state'] == 'ready' and status['pid']
                        until(client_ready, seconds=30)
                        endpoint = {'host':'127.0.0.1','port':socks_port}
                        profile = {'version':1,'listen':f'127.0.0.1:{ingress}',
                                   'proxies':[{'id':'ssh','kind':'socks5','endpoint':endpoint}],
                                   'chains':[],'rules':[], 'default_action':{'type':'proxy','id':'ssh'},
                                   'max_connections':256,'connect_timeout_ms':10000,
                                   'handshake_timeout_ms':10000,'idle_timeout_ms':300000}
                        engine = abi.call('fb_engine_create_json',profile)['engine_id']
                        abi.call('fb_engine_set_upstream_gate_json',engine, {
                            'endpoint':endpoint,'ready':True,'grace_ms':15000,
                            'limits':{'max_flows':128,'max_opening':16,'max_queued':64,'wait_timeout_ms':500}})
                        abi.call('fb_engine_start_json',engine)
                        round_trip(ingress,echo.server_address[1])
                        if os.environ.get('FLOWBRIDGE_CAPTURE_AGENT'):
                            from windows_rust_managed_ssh_control import run as rust_managed_control
                            report['rust_owned_ssh_control'] = rust_managed_control(
                                Path(os.environ['FLOWBRIDGE_CAPTURE_AGENT']),
                                args.ssh, root / 'client_key', known, user,
                                ssh_port, echo.server_address[1],
                                args.output / 'rust-owned-ssh-control.json',
                                source_banner_helper=args.cli)
                        if os.environ.get('FLOWBRIDGE_CAPTURE_AGENT'):
                            from capture_real_ssh import run as capture_relay

                            def capture_gate(ready):
                                # Explicit denial, not a queued reconnect-grace request.
                                abi.call('fb_engine_set_upstream_gate_json', engine, {
                                    'endpoint': endpoint, 'ready': ready,
                                    'grace_ms': 15000 if ready else 0,
                                    'limits': {'max_flows': 128, 'max_opening': 16,
                                               'max_queued': 64, 'wait_timeout_ms': 500}})

                            report['capture_relay'] = capture_relay(
                                Path(os.environ['FLOWBRIDGE_CAPTURE_AGENT']), ingress, capture_gate,
                                snapshot()['pid'], args.output / 'capture-relay-real-ssh.json')
                            from dns_udp_via_real_ssh import run as dns_ssh_lab
                            report['dns_udp_via_real_ssh'] = dns_ssh_lab(
                                Path(os.environ['FLOWBRIDGE_CAPTURE_AGENT']), ingress,
                                capture_gate, snapshot()['pid'],
                                args.output / 'dns-udp-via-real-ssh.json')
                        from real_ssh_capacity import run as capacity
                        result = capacity(abi,engine,ingress,echo.server_address[1],snapshot,
                                          output=args.output/'managed-capacity.json',churn=args.churn,
                                          resource_sampler=windows_resources)
                        report['managed_capacity'] = {'passed':result['passed'],'held':128,
                            'churn':result['churn_attempts'], 'rejected':result['attempted_after_capacity']}
                        from real_owned_pool_lifecycle import run as pool_lifecycle
                        result = pool_lifecycle(abi,echo.server_address[1],settings,
                                                args.output/'owned-four-worker-lifecycle.json')
                        report['owned_pool'] = {'passed':result['passed'],'independent_children':4}
                        abi.lib.fb_engine_destroy(engine); engine = 0
                        abi.lib.fb_ssh_destroy(supervisor); supervisor = 0
                        report['managed_acceptance_proved'] = True
                    else:
                        command = [sys.executable, str(Path(__file__).with_name('windows_openssh_capacity_vm.py')),
                                   '--ssh',str(args.ssh),'--identity',str(root/'client_key'),
                                   '--known-hosts',str(known),'--user',user,'--ssh-port',str(ssh_port),
                                   '--held','512','--min-held','128',
                                   '--output',str(args.output/'bare-backend-capacity.json')]
                        env = dict(os.environ, FLOWBRIDGE_SSH_VM='1')
                        subprocess.run(command, env=env, check=True, timeout=180)
                        report['bare_backend_probe_passed'] = True
                        raw_evidence = json.loads((args.output/'bare-backend-capacity.json').read_text(encoding='utf-8'))
                        require(raw_evidence.get('passed') is True, 'Bare backend evidence did not pass')
                        report['raw_backend_peak_held'] = raw_evidence.get('peak_held')
                        report['raw_backend_512_stability_proved'] = (raw_evidence.get('peak_held') == 512 and
                            raw_evidence.get('recovery_successes', 0) >= 1)
                    report['passed'] = True
                except Exception:
                    def redact(value):
                        text = str(value)
                        for private in (str(root), root.as_posix(), user, str(args.ssh), str(args.sshd)):
                            for representation in (private, private.replace('\\', '\\\\')):
                                text = text.replace(representation, '<fixture>')
                        return text[-4000:]
                    if supervisor:
                        observed = abi.call('fb_ssh_snapshot_json', supervisor)
                        report['supervisor_failure'] = {
                            key: observed['status'].get(key) for key in
                            ('state','pid','restarts','attempt','diagnostic_code','backend_version')}
                        report['supervisor_failure']['redacted_stderr'] = redact('\n'.join(observed.get('stderr',[])))
                        report['supervisor_failure']['last_error'] = redact(observed['status'].get('last_error'))
                    server_log.flush()
                    with (root/'sshd.log').open('rb') as diagnostics:
                        diagnostics.seek(0,2)
                        diagnostics.seek(max(0, diagnostics.tell()-8192))
                        report['fixture_server_failure'] = redact(diagnostics.read().decode('utf-8',errors='replace'))
                    raise
                finally:
                    if engine:
                        abi.lib.fb_engine_destroy(engine); engine = 0
                    if supervisor:
                        abi.lib.fb_ssh_destroy(supervisor); supervisor = 0
                    if daemon and daemon.poll() is None:
                        subprocess.run(['taskkill','/PID',str(daemon.pid),'/T','/F'],
                                       capture_output=True,timeout=15,check=False)
                        daemon.wait(timeout=10)
    except Exception as error:
        if pool_only:
            report['passed'] = report['managed_pool_512_proved'] = False
        report['error_type'] = type(error).__name__
        report['error'] = str(error) if not isinstance(error,subprocess.CalledProcessError) else 'Fixture subprocess failed'
        raise
    finally:
        echo.shutdown(); echo.server_close(); echo_thread.join(timeout=5)
        (args.output/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
        print(json.dumps({'windows_real_ssh':report}),flush=True)


if __name__ == '__main__':
    main()
