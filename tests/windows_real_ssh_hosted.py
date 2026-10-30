#!/usr/bin/env python3
"""Real Windows OpenSSH acceptance on a disposable hosted Windows runner.

A private loopback-only sshd uses ephemeral host/user keys and a dedicated
configuration. No system sshd service, firewall, machine DNS, existing keys,
registry settings, or code-integrity policy are changed. No WFP/NE acceptance.
"""
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import tempfile
import threading
import time

from ssh_real_integration import ABI, Echo, Server, free_port, require, until, round_trip
from windows_openssh_capacity_vm import windows_handle_count


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def secure_test_file(path):
    """ACL only this generated file; never touch a user/system SSH directory."""
    owner = subprocess.check_output(['whoami', '/user', '/fo', 'csv', '/nh'], text=True)
    import csv
    sid = list(csv.reader([owner.strip()]))[0][1]
    subprocess.run(['icacls', str(path), '/inheritance:r', '/grant:r',
                    f'*{sid}:F', '*S-1-5-18:F', '*S-1-5-32-544:F'],
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
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--churn', type=int, default=10000)
    args = parser.parse_args()
    require(sys.platform == 'win32' and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('FLOWBRIDGE_HOSTED_WINDOWS_SSH') == '1',
            'Explicit disposable hosted Windows opt-in required')
    require(0 <= args.churn <= 10000, 'Unbounded churn rejected')
    for name in ('ssh', 'sshd', 'keygen', 'library'):
        value = getattr(args, name).resolve(strict=True)
        require(value.is_file(), 'Required executable/library missing')
        setattr(args, name, value)
    args.output.mkdir(parents=True, exist_ok=True)
    report = {'passed': False, 'source_commit': os.environ.get('GITHUB_SHA'),
              'platform': platform.platform(), 'hosted_windows_runner': True,
              'windows_10_11_user_machine_tested': False, 'wfp_driver_loaded': False,
              'native_dns_leaks_verified': False, 'system_configuration_modified': False,
              'network_test_destinations_loopback_only': True,
              'ssh_sha256': sha256(args.ssh), 'sshd_sha256': sha256(args.sshd),
              'ffi_sha256': sha256(args.library)}
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
            ssh_port, socks_port, ingress = free_port(), free_port(), free_port()
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
                'PermitOpen localhost:* 127.0.0.1:* [::1]:*', 'LogLevel ERROR',
                'MaxStartups 10:30:20', 'MaxSessions 10', ''
            ]), encoding='ascii')
            secure_test_file(config)
            subprocess.run([str(args.sshd), '-t', '-f', str(config)],
                           check=True, capture_output=True, timeout=15)
            # Local raw server log lives only in temporary fixture directory;
            # no private keys, paths, auth log or known_hosts in published QA.
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
                                'restart_max_delay_ms':1000}
                    supervisor = abi.call('fb_ssh_create_json',settings)['ssh_id']
                    abi.call('fb_ssh_start_json',supervisor)
                    def snapshot():
                        return abi.call('fb_ssh_snapshot_json',supervisor)['status']
                    until(lambda: s if (s:=snapshot())['state']=='ready' and s['pid'] else False,
                          seconds=30)
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
                    # Bare backend capacity is characterized separately from
                    # FlowBridge's enforced 128-flow production admission cap.
                    command = [sys.executable, str(Path(__file__).with_name('windows_openssh_capacity_vm.py')),
                               '--ssh',str(args.ssh),'--identity',str(root/'client_key'),
                               '--known-hosts',str(known),'--user',user,'--ssh-port',str(ssh_port),
                               '--held','512','--min-held','128',
                               '--output',str(args.output/'bare-backend-capacity.json')]
                    env = dict(os.environ, FLOWBRIDGE_SSH_VM='1')
                    subprocess.run(command, env=env, check=True, timeout=180)
                    report['bare_backend_probe_passed'] = True
                    report['passed'] = True
                finally:
                    if engine:
                        abi.lib.fb_engine_destroy(engine); engine = 0
                    if supervisor:
                        abi.lib.fb_ssh_destroy(supervisor); supervisor = 0
                    if daemon and daemon.poll() is None:
                        # Restrict termination to the PID we created and its
                        # children, never Stop-Service or taskkill /IM sshd.
                        subprocess.run(['taskkill','/PID',str(daemon.pid),'/T','/F'],
                                       capture_output=True,timeout=15,check=False)
                        daemon.wait(timeout=10)
    except Exception as error:
        # Deliberately do not publish command argv containing test key paths.
        report['error_type'] = type(error).__name__
        report['error'] = str(error) if not isinstance(error,subprocess.CalledProcessError) else 'Fixture subprocess failed'
        raise
    finally:
        echo.shutdown(); echo.server_close(); echo_thread.join(timeout=5)
        (args.output/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
        print(json.dumps({'windows_real_ssh':report}),flush=True)


if __name__ == '__main__':
    main()
