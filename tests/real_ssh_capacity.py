#!/usr/bin/env python3
"""Capacity acceptance against the actual managed OpenSSH -D process.

The Linux default sampler uses /proc. Windows injects actual process HANDLE
observation. OS handles, TCP TIME_WAIT, active budgets and internal SSH FD
slots are distinct. Long Windows churn is explicitly paced, not a rate claim.
"""
import concurrent.futures
from collections import Counter
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time

from ssh_real_integration import exact, require, until
from churn_pacing import StartPacer
from loopback_churn_dialer import LoopbackDialer


def observed_process_resources(pid):
    proc = Path('/proc') / str(pid)
    sample = {'source':'linux_proc','os_fd_count':None,'vm_rss_kb':None}
    if os.name != 'posix' or not (proc/'fd').is_dir():
        sample['source'] = 'unavailable'
        return sample
    try:
        sample['os_fd_count'] = len(list((proc/'fd').iterdir()))
    except OSError:
        pass
    try:
        for line in (proc/'status').read_text(encoding='ascii').splitlines():
            if line.startswith('VmRSS:'):
                sample['vm_rss_kb'] = int(line.split()[1])
                break
    except (OSError,ValueError,IndexError):
        pass
    return sample


def windows_tcp_states():
    """Aggregate read-only numeric TCP counters; never publish endpoints."""
    allowed = {'LISTENING','ESTABLISHED','SYN_SENT','SYN_RECEIVED','FIN_WAIT_1',
               'FIN_WAIT_2','CLOSE_WAIT','CLOSING','LAST_ACK','TIME_WAIT','DELETE_TCB','BOUND'}
    result = {'available':False,'counts':{}}
    if os.name != 'nt':
        return result
    try:
        output = subprocess.run(['netstat','-ano','-p','tcp'],capture_output=True,
                                text=True,timeout=15,check=True).stdout
        counts = Counter()
        for line in output.splitlines():
            fields = line.split()
            if len(fields) == 5 and fields[0] == 'TCP' and fields[3] in allowed:
                counts[fields[3]] += 1
        result.update(available=True,counts=dict(counts))
    except (OSError,subprocess.SubprocessError):
        pass
    return result


def attempt(proxy_port,target_port,*,dialer=None):
    client = (dialer or LoopbackDialer()).connect(proxy_port,timeout=8)
    try:
        client.settimeout(8)
        client.sendall(b'\x05\x01\x00')
        require(exact(client,2) == b'\x05\x00','Managed ingress greeting changed')
        host = b'localhost'
        client.sendall(b'\x05\x01\x00\x03'+bytes([len(host)])+host+
                       int(target_port).to_bytes(2,'big'))
        reply = exact(client,10)
        require(reply[0] == 5 and reply[1] in (0,1),'Unexpected SOCKS answer under pressure')
        if reply[1]:
            client.close()
            return None
        return client
    except BaseException:
        client.close()
        raise


def exchange(client,payload):
    client.sendall(payload)
    require(exact(client,len(payload)) == payload,
            'Established real SSH data changed while new admissions were rejected')


def run(abi,engine_id,listen_port,target_port,ssh_snapshot,*,
        output,held=128,max_workers=32,churn=200,resource_sampler=None):
    require(held == 128 and 1 <= max_workers <= 64 and 0 <= churn <= 10000,
            'Real SSH acceptance must use bounded reviewed limits')
    # All three loopback TCP hops share one Windows machine's ephemeral-port
    # pool. Do not change OS limits to hide that artificial test constraint.
    # Baseline and overload remain unpaced; only long recycling is paced.
    churn_rate = 15.0 if os.name == 'nt' and churn > 500 else 0.0
    dialer = LoopbackDialer()
    report = {'passed':False,'commit':os.environ.get('GITHUB_SHA'),
              'real_openssh':True,'open_ssh_connections_held':held,
              'attempted_after_capacity':0,'churn_attempts':0,
              'churn_started':0,'churn_failed':0,'checks':[],
              'churn_start_limit_per_second':churn_rate,
              'churn_is_throughput_benchmark':False,
              'no_external_network':True,'windows_fd_limit_verified':False,
              'multi_worker_pool_verified':False}
    measure = resource_sampler or observed_process_resources
    held_sockets = []
    start = time.monotonic()
    output = Path(output)
    before = None
    try:
        before = ssh_snapshot()
        require(before['state'] == 'ready' and before['pid'],'Actual OpenSSH not ready for capacity test')
        report['resource_samples'] = {'before':measure(before['pid'])}
        report['ssh_backend'] = {'version':before.get('backend_version'),
            'absolute_path_observed':bool(before.get('backend_path')),'pid_at_start':before['pid']}
        def open_one(_):
            client = attempt(listen_port,target_port,dialer=dialer)
            require(client is not None,'Real SSH could not hold intended baseline')
            return client
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            held_sockets.extend(pool.map(open_one,range(held)))
        capacity = abi.call('fb_engine_snapshot_json',engine_id)['managed_upstream']
        require(capacity['limits']['max_flows'] == held,'Managed budget is not reviewed 128 flows')
        require(capacity['active_including_opening'] == held,'Real SSH streams did not consume all admissions')
        require(capacity['opening'] == 0,'SSH handshake permit leaked after CONNECT')
        report['resource_samples']['held_128'] = measure(before['pid'])
        report['checks'].append('128 verified real SSH TCP channels held by a single managed backend')
        def rejected(_):
            client = attempt(listen_port,target_port,dialer=dialer)
            if client is not None:
                client.close()
                raise RuntimeError('Managed engine bypassed full SSH budget')
        for count in (64,128,192,256,512):
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
                list(pool.map(rejected,range(count)))
            report['attempted_after_capacity'] += count
            snap = abi.call('fb_engine_snapshot_json',engine_id)['managed_upstream']
            require(snap['active_including_opening'] == held,'Overload changed occupied SSH channels')
            require(snap['queued'] <= snap['limits']['max_queued'] and
                    snap['opening'] <= snap['limits']['max_opening'],'Managed queue bound exceeded')
            for index in (0,1,7,31,held-1):
                exchange(held_sockets[index],b'flowbridge-real-ssh\x00\xff'+count.to_bytes(2,'big')+bytes([index]))
            require(ssh_snapshot()['pid'] == before['pid'],'SSH unexpectedly restarted under full capacity')
            report['checks'].append(f'{count} rejected new attempts; existing streams unchanged')
        report['resource_samples']['overloaded'] = measure(before['pid'])
        report['admission_at_peak'] = abi.call('fb_engine_snapshot_json',engine_id)['managed_upstream']
        require(report['admission_at_peak']['rejected'] >= report['attempted_after_capacity'],
                'Rejection counter did not account for attempted opens')
        for item in held_sockets:
            item.shutdown(socket.SHUT_WR)
            require(item.recv(1) == b'','Held real SSH half-close did not propagate')
            item.close()
        held_sockets.clear()
        until(lambda: abi.call('fb_engine_snapshot_json',engine_id)['managed_upstream']
              ['active_including_opening'] == 0,seconds=15)
        report['resource_samples']['after_release'] = measure(before['pid'])
        report['checks'].append('Released 128 actual OpenSSH streams and verified admission permits are zero')
        if churn:
            lock = threading.Lock()
            failed = threading.Event()
            pacer = StartPacer(churn_rate)
            def one_churn(index):
                if failed.is_set() or failed.wait(pacer.delay()):
                    return
                with lock:
                    report['churn_started'] += 1
                try:
                    client = attempt(listen_port,target_port,dialer=dialer)
                    require(client is not None,'Actual SSH did not recover new capacity after draining')
                    with client:
                        exchange(client,b'churn\x00\xff'+index.to_bytes(4,'big'))
                        client.shutdown(socket.SHUT_WR)
                        require(client.recv(1) == b'','Churn EOF/half-close failed')
                    with lock:
                        report['churn_attempts'] += 1
                        if report['churn_attempts'] % 1000 == 0:
                            print(json.dumps({'churn_completed':report['churn_attempts'],
                                              'start_rate_limit':churn_rate}),flush=True)
                except Exception:
                    failed.set()
                    with lock:
                        report['churn_failed'] += 1
                    raise
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
                list(pool.map(one_churn,range(churn)))
            require(report['churn_attempts'] == churn,'Did not complete all requested real channels')
            require(dialer.snapshot()['addrinuse_retries'] <= max(16,(churn+held+1152)//100),
                    'Excess Windows loopback source-port collisions; fixture is not an accepted load test')
            until(lambda: abi.call('fb_engine_snapshot_json',engine_id)['managed_upstream']
                  ['active_including_opening'] == 0,seconds=15)
            report['checks'].append(f'{churn} authenticated SSH channels churned with binary echo and half-close')
        require(ssh_snapshot()['pid'] == before['pid'],'SSH did not survive bounded load and recovery')
        report['resource_samples']['final'] = measure(before['pid'])
        initial_fd = report['resource_samples']['before']['os_fd_count']
        final_fd = report['resource_samples']['final']['os_fd_count']
        if initial_fd is not None and final_fd is not None:
            require(final_fd <= initial_fd+32,'Linux final descriptor count exceeded baseline + 32')
            report['checks'].append('Linux OS descriptors returned within baseline + 32')
        initial_handles = report['resource_samples']['before'].get('os_handle_count')
        final_handles = report['resource_samples']['final'].get('os_handle_count')
        if initial_handles is not None:
            require(final_handles is not None and final_handles <= initial_handles+32,
                    'Windows final OS HANDLE count exceeded baseline + 32')
            report['checks'].append('Windows OS HANDLE count returned within baseline + 32; not internal FD slots')
        report['ssh_backend']['pid_at_end'] = before['pid']
        report['admission_final'] = abi.call('fb_engine_snapshot_json',engine_id)['managed_upstream']
        require(all(report['admission_final'][key] == 0 for key in
                    ('active_including_opening','queued','opening')),'Managed permits did not return to zero')
        report['passed'] = True
        return report
    except Exception as error:
        report['error'] = str(error)
        report['tcp_states_at_failure'] = windows_tcp_states()
        if before:
            try:
                report.setdefault('resource_samples',{})['failure'] = measure(before['pid'])
            except Exception as measurement:
                report['resource_measurement_error'] = type(measurement).__name__
        # Compare autobind and explicit bind to distinguish exhausted Windows
        # source-port reservations; diagnostics never retry the failed request.
        phase = 'socket'
        try:
            with socket.socket() as probe:
                probe.settimeout(2)
                phase = 'bind'
                probe.bind(('127.0.0.1',0))
                phase = 'connect'
                probe.connect(('127.0.0.1',target_port))
                exchange(probe,b'fixture-bind-then-connect\x00\xff')
                report['fixture_explicit_bind_health'] = True
        except OSError as error:
            report['fixture_explicit_bind_health'] = False
            report['fixture_explicit_bind_error'] = {'phase':phase,'winerror':getattr(error,'winerror',None),
                                                     'errno':error.errno}
        try:
            report['admission_failure'] = abi.call('fb_engine_snapshot_json',engine_id)['managed_upstream']
            with socket.create_connection(('127.0.0.1',target_port),timeout=2) as direct:
                exchange(direct,b'isolated-fixture-direct-health\x00\xff')
                report['fixture_echo_direct_health_at_failure'] = True
        except (OSError,RuntimeError) as health_error:
            report['fixture_echo_direct_health_at_failure'] = False
            report['fixture_health_error_type'] = type(health_error).__name__
        raise
    finally:
        for client in held_sockets:
            client.close()
        report['elapsed_seconds'] = round(time.monotonic()-start,3)
        output.parent.mkdir(parents=True,exist_ok=True)
        report['loopback_socket_dialer'] = dialer.snapshot()
        output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
        print(json.dumps({'real_ssh_load':report},ensure_ascii=False),flush=True)
