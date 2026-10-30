#!/usr/bin/env python3
"""Real independent OpenSSH workers using the EXACT owned-handle GUI C ABI.

Called only from the disposable Linux sshd fixture, once per CI suite.
No user credentials, external endpoints, fabricated readiness, or DIRECT.
"""
import json
from pathlib import Path
from ssh_real_integration import connect, exact, free_port, require, until


def run(abi, target_port, settings, output):
    report = {'passed': False, 'real_openssh_processes': 4,
              'owned_supervisor_api': True, 'transitions': [], 'checks': []}
    ids, held = [], []
    engine = 0
    ingress = free_port()
    ports = set([ingress, target_port, settings['local_port']])
    workers = []
    try:
        for _ in range(4):
            port = free_port()
            while port in ports:
                port = free_port()
            ports.add(port)
            worker = abi.call('fb_ssh_create_json', dict(settings, local_port=port))['ssh_id']
            ids.append(worker)
            workers.append(port)
        profile = {'version': 1, 'listen': f'127.0.0.1:{ingress}',
                   'proxies': [{'id': 'owned', 'kind': 'socks5',
                                'endpoint': {'host': '127.0.0.1', 'port': workers[0]}}],
                   'chains': [], 'rules': [], 'default_action': {'type': 'proxy', 'id': 'owned'},
                   'max_connections': 256, 'connect_timeout_ms': 2000,
                   'handshake_timeout_ms': 2000, 'idle_timeout_ms': 30000}
        engine = abi.call('fb_engine_create_json', profile)['engine_id']

        def pool(count, enabled):
            return abi.call('fb_engine_sync_owned_ssh_pool_json', engine, {
                'ssh_ids': ids[:count], 'enabled': enabled,
                'limits': {'max_flows': 128 // count, 'max_opening': 16,
                           'max_queued': 64 // count, 'wait_timeout_ms': 10000},
                'aggregate_max_flows': 128})

        def snapshot():
            return abi.call('fb_engine_snapshot_json', engine)

        # Mirrors Win32 startup: reserve the final pool while all supervisors
        # are stopped, then independently start them and derive real readiness.
        pool(2, False)
        for ident in ids:
            abi.call('fb_ssh_start_json', ident)
        pids = []
        for ident in ids:
            status = until(lambda: s if (s := abi.call('fb_ssh_snapshot_json', ident)['status'])
                           ['state'] == 'ready' and s['pid'] else False, seconds=30)
            pids.append(status['pid'])
        require(len(set(pids)) == 4, 'Pool collapsed into a shared SSH process')
        report['distinct_child_pids'] = True
        for count in (2, 4, 3, 2):
            # Stop returns only after relays are cancelled. Releasing the live
            # gate THEN permits a deliberate stopped-engine budget change.
            abi.call('fb_engine_stop_json', engine)
            abi.call('fb_engine_set_upstream_gate_json', engine,
                     {'endpoint': None, 'ready': False, 'grace_ms': 0})
            pool(count, False)
            require(snapshot()['managed_pool']['ready_workers'] == 0,
                    'enabled=false still allowed an actually healthy SSH worker')
            pool(count, True)
            require(snapshot()['managed_pool']['ready_workers'] == count,
                    'Owned supervisors did not provide actual readiness')
            abi.call('fb_engine_start_json', engine)
            before_id = max((c['id'] for c in snapshot()['connections']), default=0)
            for index in range(2 * count):
                client = connect(ingress, target_port)
                held.append(client)
                data = b'owned-pool-life-cycle\x00\xff' + bytes([count,index])
                client.sendall(data)
                require(exact(client, len(data)) == data, 'Real SSH stream bytes changed')
            active = [c for c in snapshot()['connections']
                      if c['id'] > before_id and c['state'] == 'active']
            observed_ports = {c.get('worker_port') for c in active}
            require(observed_ports == set(workers[:count]), 'Not all owned workers carried traffic')
            pool(count, False)
            denied = False
            try:
                with connect(ingress, target_port):
                    pass
            except (RuntimeError, OSError, EOFError, TimeoutError):
                denied = True
            require(denied, 'Suspended owned pool leaked DIRECT traffic')
            for client in held:
                data = b'active-stream-survives-admission-pause'
                client.sendall(data)
                require(exact(client, len(data)) == data, 'Pausing new flows killed established bytes')
            pool(count, True)
            for client in held:
                client.close()
            held.clear()
            until(lambda: all(w['admission']['active_including_opening'] == 0
                              for w in snapshot()['managed_pool']['workers']), seconds=15)
            report['transitions'].append({'workers': count, 'flows': 2 * count,
                                          'paused_new_flows_denied': True,
                                          'existing_bytes_retained': True})
        report['checks'].append('stopped -> ready -> pause -> resume via owned supervisors')
        report['checks'].append('2 -> 4 -> 3 -> 2 with zero leaked permits and changed limits')
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        for client in held:
            client.close()
        if engine:
            abi.lib.fb_engine_destroy(engine)
        for ident in ids:
            abi.lib.fb_ssh_destroy(ident)
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
        print(json.dumps({'owned_pool_lifecycle': report}), flush=True)
    return report
