#!/usr/bin/env python3
"""Two genuine managed OpenSSH -D processes, one Rust SOCKS ingress.

This runs inside ssh_real_integration.py's disposable, key-enrolled localhost
sshd environment on Linux CI. No production credentials, external networks,
system DNS mutations or WFP driver are used. Existing streams never migrate.
"""
import json
import os
from pathlib import Path
import signal
import socket
import time

from ssh_real_integration import connect, exact, free_port, require, until


def run(abi, engine, engine_port, target_port, primary_settings, snapshot,
        limits, *, output):
    report = {
        'passed': False, 'real_openssh_processes': 0,
        'distinct_child_pids': False,
        'existing_primary_stream_survived_peer_death': False,
        'new_connections_fail_closed_with_all_workers_down': False,
        'source_commit': os.environ.get('GITHUB_SHA'),
        'checks': [], 'external_network': False,
    }
    secondary = None
    held = []
    held_worker_ports = []
    primary = {'host': '127.0.0.1', 'port': primary_settings['local_port']}
    secondary_settings = dict(primary_settings, local_port=free_port())
    require(secondary_settings['local_port'] not in
            (engine_port, target_port, primary['port'], primary_settings['port']),
            'Distinct local SSH workers require independent TCP ports')
    second = {'host': '127.0.0.1', 'port': secondary_settings['local_port']}

    def configure(first_ready, second_ready):
        return abi.call('fb_engine_set_upstream_pool_json', engine,
                        {'primary': primary,
                         'workers': [{'endpoint': primary, 'ready': first_ready},
                                     {'endpoint': second, 'ready': second_ready}],
                         'limits': limits, 'aggregate_max_flows': 2 * limits['max_flows']})

    try:
        secondary = abi.call('fb_ssh_create_json', secondary_settings)['ssh_id']
        abi.call('fb_ssh_start_json', secondary)
        def secondary_status():
            return abi.call('fb_ssh_snapshot_json', secondary)['status']
        child = until(lambda: s if (s := secondary_status())['state'] == 'ready' else False)
        first = snapshot()
        require(first['state'] == 'ready' and first['pid'] != child['pid'],
                'The SSH pool reused a process instead of creating independent transports')
        report['real_openssh_processes'] = 2
        report['distinct_child_pids'] = True
        require(abi.call('fb_engine_snapshot_json', engine)['status']['running'],
                'The routed Rust engine must remain live throughout the pool test')
        configure(True, True)

        previous_connections = abi.call('fb_engine_snapshot_json', engine)['connections']
        last_id = max((c['id'] for c in previous_connections), default=0)
        for i in range(16):
            client = connect(engine_port, target_port)
            payload = b'flowbridge-two-real-ssh-workers\x00\xff' + bytes([i])
            client.sendall(payload)
            require(exact(client, len(payload)) == payload, 'Pool stream data was changed')
            held.append(client)
            now = abi.call('fb_engine_snapshot_json', engine)
            matching = [c for c in now['connections'] if c['id'] > last_id and c['state'] == 'active' and c.get('worker_port')]
            require(len(matching) == len(held),
                    'Snapshot did not identify every held connection')
            held_worker_ports.append(max(matching, key=lambda c: c['id'])['worker_port'])

        status = abi.call('fb_engine_snapshot_json', engine)
        active = [c for c in status['connections']
                  if c['id'] > last_id and c['state'] == 'active' and c.get('worker_port')]
        counts = {primary['port']: 0, second['port']: 0}
        for connection in active:
            require(connection['worker_port'] in counts,
                    'An active flow routed to an unapproved worker endpoint')
            counts[connection['worker_port']] += 1
        require(sum(counts.values()) >= 16 and min(counts.values()) >= 4,
                'Ready SSH processes were not both used for new connections')
        report['initial_active_by_worker'] = {
            'primary': counts[primary['port']], 'secondary': counts[second['port']]
        }
        pool = status['managed_pool']
        require(pool['ready_workers'] == 2 and len(pool['workers']) == 2,
                'Pool snapshot omitted owned-worker admission')
        require(all(worker['admission']['active_including_opening'] > 0
                    for worker in pool['workers']),
                'Real SSH streams were not charged to both independent budgets')
        report['checks'].append('16 held real SSH channels distributed over two distinct child PIDs')

        # Kill exactly one owned child; do not restart/replay its TCP streams.
        # Previously established primary streams must be intact and pinned.
        os.kill(child['pid'], signal.SIGKILL)
        configure(True, False)
        # Preserve an explicit per-client worker mapping captured immediately
        # after each successful connection; do not zip a mutable unordered
        # snapshot with client sockets after one worker has been killed.
        primary_streams = [client for client, worker_port in zip(held, held_worker_ports)
                           if worker_port == primary['port']]
        require(len(primary_streams) >= 4, 'No primary-owned survivor streams')
        for i, client in enumerate(primary_streams):
            payload = b'primary-survives-peer-death\x00\xff' + bytes([i])
            client.sendall(payload)
            require(exact(client, len(payload)) == payload,
                    'Killing secondary SSH interrupted an unaffected worker')
        report['existing_primary_stream_survived_peer_death'] = True
        report['checks'].append('Killing one child leaves established streams on other SSH PID intact')
        for client in held:
            client.close()
        held.clear()

        after_kill_id = max((c['id'] for c in abi.call(
            'fb_engine_snapshot_json', engine)['connections']), default=0)
        for _ in range(64):
            with connect(engine_port, target_port) as client:
                payload = b'only-surviving-open-ssh'
                client.sendall(payload)
                require(exact(client, len(payload)) == payload,
                        'New flows did not switch to the surviving SSH worker')
        observed = abi.call('fb_engine_snapshot_json', engine)
        new_connections = [c for c in observed['connections']
                           if c['id'] > after_kill_id and c.get('worker_port')]
        require(len(new_connections) >= 64
                and all(c['worker_port'] == primary['port'] for c in new_connections),
                'A new connection was assigned to the killed SSH worker')
        current = observed['managed_pool']
        require(current['ready_workers'] == 1, 'Offline SSH worker incorrectly marked ready')
        report['checks'].append('64 new TCP flows after secondary loss all used the live OpenSSH PID')
        report['post_failure_new_flows'] = 64
        report['post_failure_unhealthy_assignments'] = 0

        # With no ready SSH child, SOCKS must return failure, not DIRECT. The
        # destination is a real echo server; a leaked DIRECT would succeed.
        configure(False, False)
        blocked = False
        try:
            with connect(engine_port, target_port):
                pass
        except (RuntimeError, OSError, EOFError, TimeoutError):
            blocked = True
        require(blocked, 'Both SSH workers down but ingress allowed a connection')
        require(abi.call('fb_engine_snapshot_json', engine)['managed_pool']['ready_workers'] == 0,
                'All-down pool reported a healthy backend')
        report['new_connections_fail_closed_with_all_workers_down'] = True
        report['checks'].append('No ready child means SOCKS failure without direct fallback')

        # The second supervisor can restart independently. The first PID must
        # never have been restarted because another worker died.
        restored = until(
            lambda: s if (s := secondary_status())['state'] == 'ready'
            and s['pid'] != child['pid'] else False, seconds=30)
        require(snapshot()['pid'] == first['pid'],
                'Failing a secondary process caused the healthy SSH transport to restart')
        configure(True, True)
        with connect(engine_port, target_port) as client:
            client.sendall(b'new-ssh-child-recovered')
            require(exact(client, 23) == b'new-ssh-child-recovered',
                    'Recovered worker pool did not route new data')
        report['replacement_child_pid_distinct'] = restored['pid'] != child['pid']
        for _ in range(16):
            with connect(engine_port, target_port) as client:
                payload = b'recovered-two-worker-pool'
                client.sendall(payload)
                require(exact(client, len(payload)) == payload,
                        'Recovered worker changed TCP payload')
        recovered_snapshot = until(
            lambda: p if (p := abi.call('fb_engine_snapshot_json', engine)['managed_pool'])
            ['ready_workers'] == 2
            and all(w['admission']['active_including_opening'] == 0
                    for w in p['workers']) else False,
            seconds=15)
        require(recovered_snapshot['ready_workers'] == 2,
                'Pool did not restore two ready OpenSSH workers')
        report['checks'].append('Recovery restores both real OpenSSH workers with zero leaked permits')
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        for client in held:
            client.close()
        # Restore the single-SSH route for the surrounding 20-iteration suite.
        try:
            abi.call('fb_engine_set_upstream_gate_json', engine,
                     {'endpoint': primary, 'ready': True, 'grace_ms': 15000,
                      'limits': limits})
        finally:
            if secondary:
                abi.call('fb_ssh_stop_json', secondary)
                abi.lib.fb_ssh_destroy(secondary)
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'real_ssh_pool': report}, ensure_ascii=False), flush=True)
    return report
