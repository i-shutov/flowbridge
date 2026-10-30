#!/usr/bin/env python3
"""Capacity acceptance against the actual managed OpenSSH -D process.

Invoked after a disposable localhost sshd and ephemeral-key authentication
have been verified. Linux /proc is the default resource sampler; the isolated
Windows fixture explicitly injects actual Windows process HANDLE observation.
No remote endpoints, user SSH credentials or system DNS changes are used.
"""
import concurrent.futures
import json
import os
from pathlib import Path
import socket
import threading
import time

from ssh_real_integration import connect, exact, require, until


def observed_process_resources(pid):
    """Linux /proc observation only; never equate OS fds to SSH channels."""
    proc = Path('/proc') / str(pid)
    fds = proc / 'fd'
    status = proc / 'status'
    sample = {'source': 'linux_proc', 'os_fd_count': None, 'vm_rss_kb': None}
    if os.name != 'posix' or not fds.is_dir():
        sample['source'] = 'unavailable'
        return sample
    try:
        sample['os_fd_count'] = len(list(fds.iterdir()))
    except OSError:
        pass
    try:
        for line in status.read_text(encoding='ascii').splitlines():
            if line.startswith('VmRSS:'):
                sample['vm_rss_kb'] = int(line.split()[1])
                break
    except (OSError, ValueError, IndexError):
        pass
    return sample


def attempt(proxy_port, target_port):
    """One explicit SOCKS5 hostname connect; no local DNS or DIRECT fallback."""
    client = socket.create_connection(('127.0.0.1', proxy_port), timeout=8)
    try:
        client.settimeout(8)
        client.sendall(b'\x05\x01\x00')
        require(exact(client, 2) == b'\x05\x00', 'Managed ingress greeting changed')
        host = b'localhost'
        client.sendall(b'\x05\x01\x00\x03' + bytes([len(host)]) + host +
                       int(target_port).to_bytes(2, 'big'))
        reply = exact(client, 10)
        require(reply[0] == 5 and reply[1] in (0, 1), 'Unexpected SOCKS answer under pressure')
        if reply[1]:
            client.close()
            return None
        return client
    except BaseException:
        client.close()
        raise


def exchange(client, payload):
    client.sendall(payload)
    require(exact(client, len(payload)) == payload,
            'Established real SSH data were changed while new admissions were rejected')


def run(abi, engine_id, listen_port, target_port, ssh_snapshot, *,
        output, held=128, max_workers=32, churn=200, resource_sampler=None):
    """Hold 128 real SSH streams; exercise exact 64/128/192/256/512 failed opens.

    Global 128 per-SSH admission is configured on the caller's managed engine
    before connecting. This intentionally saturates the configured limit,
    not the OpenSSH operating-system descriptor ceiling.
    """
    require(held == 128 and 1 <= max_workers <= 64 and 0 <= churn <= 10000,
            'Real SSH acceptance must use bounded, reviewed limits')
    report = {
        'passed': False,
        'commit': os.environ.get('GITHUB_SHA'),
        'real_openssh': True, 'open_ssh_connections_held': held,
        'attempted_after_capacity': 0, 'churn_attempts': 0,
        'checks': [], 'no_external_network': True,
        'windows_fd_limit_verified': False, 'multi_worker_pool_verified': False,
    }
    measure_resources = resource_sampler or observed_process_resources
    held_sockets = []
    start_time = time.monotonic()
    output = Path(output)
    try:
        before = ssh_snapshot()
        require(before['state'] == 'ready' and before['pid'], 'Actual OpenSSH not ready for capacity test')
        report['resource_samples'] = {}
        report['resource_samples']['before'] = measure_resources(before['pid'])
        report['ssh_backend'] = {
            'version': before.get('backend_version'),
            'absolute_path_observed': bool(before.get('backend_path')),
            'pid_at_start': before['pid'],
        }
        def open_one(_):
            client = attempt(listen_port, target_port)
            require(client is not None, 'Real SSH could not hold the intended baseline')
            return client
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            held_sockets.extend(pool.map(open_one, range(held)))
        capacity = abi.call('fb_engine_snapshot_json', engine_id)['managed_upstream']
        require(capacity['limits']['max_flows'] == held,
                'Managed admission configuration was not the reviewed 128-flow budget')
        require(capacity['active_including_opening'] == held,
                'Real OpenSSH streams did not consume all managed admissions')
        require(capacity['opening'] == 0, 'Real SSH handshake permit leaked after CONNECT')
        report['resource_samples']['held_128'] = measure_resources(before['pid'])
        report['checks'].append('128 verified real SSH TCP channels held by a single managed backend')

        def rejected(_):
            client = attempt(listen_port, target_port)
            require(client is None, 'Managed engine bypassed full SSH budget on a new request')
        for count in (64, 128, 192, 256, 512):
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
                list(pool.map(rejected, range(count)))
            report['attempted_after_capacity'] += count
            snap = abi.call('fb_engine_snapshot_json', engine_id)['managed_upstream']
            require(snap['active_including_opening'] == held,
                    'Overload changed occupied real SSH channels')
            require(snap['queued'] <= snap['limits']['max_queued'] and
                    snap['opening'] <= snap['limits']['max_opening'],
                    'Managed queue/opening bound exceeded')
            for i in (0, 1, 7, 31, held - 1):
                payload = b'flowbridge-real-ssh-concurrency\x00\xff' + count.to_bytes(2, 'big') + bytes([i])
                exchange(held_sockets[i], payload)
            require(ssh_snapshot()['pid'] == before['pid'],
                    'OpenSSH was unexpectedly restarted while configured capacity was full')
            report['checks'].append(f'{count} rejected new attempts; existing streams unchanged')
        report['resource_samples']['overloaded'] = measure_resources(before['pid'])
        report['admission_at_peak'] = abi.call('fb_engine_snapshot_json', engine_id)['managed_upstream']
        require(report['admission_at_peak']['rejected'] >= report['attempted_after_capacity'],
                'Overload rejection counter did not account for attempted opens')

        for item in held_sockets:
            item.shutdown(socket.SHUT_WR)
            require(item.recv(1) == b'', 'Held real SSH half-close did not propagate')
            item.close()
        held_sockets.clear()
        until(lambda: abi.call('fb_engine_snapshot_json', engine_id)['managed_upstream']
              ['active_including_opening'] == 0, seconds=15)
        report['resource_samples']['after_release'] = measure_resources(before['pid'])
        report['checks'].append('Released 128 actual OpenSSH streams and verified admission permits are zero')

        if churn:
            def one_churn(i):
                client = attempt(listen_port, target_port)
                require(client is not None, 'Actual SSH did not recover new capacity after draining')
                with client:
                    payload = b'churn\x00\xff' + i.to_bytes(4, 'big')
                    exchange(client, payload)
                    client.shutdown(socket.SHUT_WR)
                    require(client.recv(1) == b'', 'Churn EOF/half-close failed')
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
                list(pool.map(one_churn, range(churn)))
            report['churn_attempts'] = churn
            until(lambda: abi.call('fb_engine_snapshot_json', engine_id)['managed_upstream']
                  ['active_including_opening'] == 0, seconds=15)
            report['checks'].append(f'{churn} additional authenticated SSH channels churned with binary echo and half-close')

        require(ssh_snapshot()['pid'] == before['pid'],
                'Real OpenSSH process did not survive bounded load and recovery')
        report['resource_samples']['final'] = measure_resources(before['pid'])
        initial_fd = report['resource_samples']['before']['os_fd_count']
        final_fd = report['resource_samples']['final']['os_fd_count']
        if initial_fd is not None and final_fd is not None:
            require(final_fd <= initial_fd + 32,
                    'Linux OpenSSH final OS descriptor count exceeded baseline + 32')
            report['checks'].append('Measured Linux OS descriptors returned within baseline + 32')
        initial_handles = report['resource_samples']['before'].get('os_handle_count')
        final_handles = report['resource_samples']['final'].get('os_handle_count')
        if initial_handles is not None:
            require(final_handles is not None and final_handles <= initial_handles + 32,
                    'Windows OpenSSH final OS HANDLE count exceeded baseline + 32')
            report['checks'].append('Measured Windows OS HANDLE count returned within baseline + 32; not internal FD slots')
        report['ssh_backend']['pid_at_end'] = before['pid']
        report['admission_final'] = abi.call('fb_engine_snapshot_json', engine_id)['managed_upstream']
        require(report['admission_final']['active_including_opening'] == 0 and
                report['admission_final']['queued'] == 0 and
                report['admission_final']['opening'] == 0,
                'Managed budget permits did not return to zero')
        report['elapsed_seconds'] = round(time.monotonic() - start_time, 3)
        report['passed'] = True
        return report
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        for client in held_sockets:
            client.close()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'real_ssh_load': report}, ensure_ascii=False), flush=True)
