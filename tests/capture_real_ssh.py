"""Real Rust relay -> FlowBridge SOCKS -> isolated OpenSSH -> counted echo.

Imported by both hosted SSH fixtures. Never activates NDISRD or uses user keys.
Closing the upstream gate must reject the probe without reaching the target.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import threading

from ssh_real_integration import Echo, Server, require


def run(agent: Path, ingress_port: int, gate, ssh_pid: int, output: Path) -> dict:
    require(agent.is_file(), "Required Rust capture agent was not built")
    require(isinstance(ssh_pid, int) and ssh_pid > 0, "Missing real supervised SSH process")
    lock = threading.Lock()
    count = [0]

    class CountedEcho(Echo):
        def handle(self):
            with lock:
                count[0] += 1
            super().handle()

    echo = Server(('127.0.0.1', 0), CountedEcho)
    worker = threading.Thread(target=echo.serve_forever, daemon=True)
    worker.start()
    request = json.dumps({
        'upstream': f'127.0.0.1:{ingress_port}',
        'target': f'127.0.0.1:{echo.server_address[1]}',
        'consent': 'LOOPBACK_TCP_PROBE',
    })

    def probe(success):
        result = subprocess.run(
            [str(agent.resolve()), 'relay-probe', request],
            check=False, capture_output=True, text=True, encoding='utf-8', timeout=15,
        )
        require((result.returncode == 0) == success,
                f'Unexpected relay probe exit: {result.returncode}: {result.stdout[-500:]}')
        response = json.loads(result.stdout)
        if success:
            require(response.get('roundtrip_passed') is True, 'No real byte verification')
            require(response.get('sent') == response.get('received') == 4097,
                    'Wrong binary transfer count')
            require(response.get('admission_final') == 0, 'Leaked relay admission')
            require(response.get('ndisrd_opened') is False, 'Probe must not activate driver')
        return response

    try:
        first = probe(True)
        with lock:
            baseline = count[0]
        require(baseline == 1, 'Expected exactly one SSH-forwarded target connection')
        gate(False)
        denied = probe(False)
        with lock:
            require(count[0] == baseline, 'Closed upstream gate fell back to DIRECT target')
        gate(True)
        recovered = probe(True)
        with lock:
            require(count[0] == 2, 'Recovery did not establish exactly one new target stream')
        report = {
            'passed': True,
            'kind': 'rust_capture_relay_real_flowbridge_socks_and_openssh',
            'real_supervised_ssh_pid': ssh_pid,
            'agent_sha256': hashlib.sha256(agent.read_bytes()).hexdigest(),
            'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
            'initial': first,
            'upstream_gate_denied': denied.get('ok') is False,
            'target_connections_while_gate_closed': 0,
            'recovered': recovered,
            'win10_11_driver_acceptance': False,
            'native_packet_owner_proof': False,
            'dns_leak_free': False,
            'release_accepted': False,
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'capture_real_ssh': report}), flush=True)
        return report
    finally:
        gate(True)
        echo.shutdown()
        echo.server_close()
        worker.join(timeout=3)
