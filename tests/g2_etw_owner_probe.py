#!/usr/bin/env python3
"""Independent Windows kernel TCP-owner evidence; NEVER NDISRD PacketBound.

Hosted, explicit, bounded ETW session. Unmodified System32 curl clients and
query-only process handles are independent of the product/IP Helper. Raw ETL,
XML, payload PIDs and paths stay in a private temporary directory and are not
published. No filter, driver mode, audit policy, service or route is changed.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import xml.etree.ElementTree as ET

KERNEL_NETWORK = '7dd42a49-5329-4832-8dfd-43d979153a88'
TCPIP = '2f07e2ee-15db-40f1-90ef-9d7ba282188a'
CORRELATION = '83ed54f0-4d48-4e45-b16e-726ffd1fa4af'
CONSENT = 'G2_HOSTED_ETW_READ_ONLY_NO_DRIVER'
MAX_XML = 64 * 1024 * 1024
DENIED = ('packet_owner_bound', 'protected_redirect_available',
          'native_packet_attribution_proved', 'g2_accepted', 'release_accepted')


class ProbeFailure(Exception):
    """Only a fixed, sanitized error code may escape the private collector."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ProbeFailure(code)


def ticks(value: str) -> int:
    """ETW SystemTime to Windows FILETIME, without floating point rounding."""
    match = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z', value)
    require(match is not None, 'invalid_event_time')
    assert match is not None
    base = datetime.strptime(match[1], '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
    delta = base - datetime(1601, 1, 1, tzinfo=timezone.utc)
    fraction = (match[2] or '').ljust(7, '0')
    require(len(fraction) <= 7 or not any(c != '0' for c in fraction[7:]),
            'event_time_precision_unsupported')
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + int(fraction[:7])


def local_name(tag: str) -> str:
    return tag.rsplit('}', 1)[-1]


def integer(value: str) -> int:
    require(bool(re.fullmatch(r'(?:0[xX][0-9a-fA-F]+|[0-9]+)', value)),
            'invalid_integer_payload')
    return int(value, 16 if value.lower().startswith('0x') else 10)


@dataclass(frozen=True)
class PinnedOwner:
    pid: int
    creation: int
    family: int
    port: int


def audit_xml(raw: bytes, summary: str, owners: list[PinnedOwner], stopped: int) -> dict:
    """Pure verifier. Synthetic callers cannot authorize product routing."""
    require(0 < len(raw) <= MAX_XML, 'trace_xml_size')
    # Reject entity expansion and DTDs even though tracerpt is a trusted producer.
    upper = raw.upper().replace(b'\x00', b'')
    require(b'<!DOCTYPE' not in upper and b'<!ENTITY' not in upper, 'trace_xml_dtd')
    losses = re.findall(r'Total\s+Events\s+Lost\s*[:=]?\s*(\d+)', summary, re.I)
    require(len(losses) == 1, 'trace_loss_accounting_missing_or_ambiguous')
    require(int(losses[0]) == 0, 'trace_events_lost')
    require(len(owners) == 4 and len({o.pid for o in owners}) == 4,
            'independent_owner_set_invalid')
    require(all(o.pid > 0 and o.creation > 0 and 0 < o.port < 65536 for o in owners),
            'pinned_owner_invalid')
    require(sorted(o.family for o in owners) == [4, 4, 6, 6], 'dual_stack_required')
    require(all(o.creation < stopped for o in owners), 'owner_created_after_trace')
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        raise ProbeFailure('trace_xml_invalid') from None
    expected = {o.pid: o for o in owners}
    matched: set[int] = set()
    connection_owners: dict[int, int] = {}
    provider_counts = {KERNEL_NETWORK: 0, TCPIP: 0, CORRELATION: 0}
    activity_events = 0
    payload_owner_events = 0
    for event in root.iter():
        if local_name(event.tag) != 'Event':
            continue
        system = [n for n in event if local_name(n.tag) == 'System']
        if len(system) != 1:
            continue
        fields = {local_name(n.tag): n for n in system[0]}
        provider = fields.get('Provider')
        if provider is None:
            continue
        guid = provider.attrib.get('Guid', '').strip('{}').lower()
        if guid not in provider_counts:
            continue
        provider_counts[guid] += 1
        correlation = fields.get('Correlation')
        if correlation is not None:
            activity = correlation.attrib.get('ActivityID', '').strip('{}').lower()
            related = correlation.attrib.get('RelatedActivityID', '').strip('{}').lower()
            if activity and related and activity != '00000000-0000-0000-0000-000000000000':
                activity_events += 1
        # Only the documented Kernel-Network payload PID is owner evidence.
        # The ETW header Execution/ProcessID may be a logger/DPC, not the owner.
        if guid != KERNEL_NETWORK:
            continue
        event_id = fields.get('EventID')
        if event_id is None or (event_id.text or '').strip() not in ('12', '28'):
            continue  # Only TCP ConnectIPv4/ConnectIPv6; never UDP/send headers.
        event_family = 4 if event_id.text.strip() == '12' else 6
        data: dict[str, str] = {}
        for section in event:
            if local_name(section.tag) != 'EventData':
                continue
            for item in section:
                if local_name(item.tag) != 'Data':
                    continue
                name = item.attrib.get('Name', '')
                require(name not in data, 'duplicate_event_payload_field')
                data[name] = (item.text or '').strip()
        if not {'PID', 'daddr', 'dport', 'connid'} <= data.keys():
            continue
        pid = integer(data['PID'])
        if pid not in expected:
            continue
        owner = expected[pid]
        time_node = fields.get('TimeCreated')
        require(time_node is not None, 'owner_event_time_missing')
        assert time_node is not None
        at = ticks(time_node.attrib.get('SystemTime', ''))
        require(owner.creation <= at <= stopped, 'pid_epoch_or_trace_interval_mismatch')
        try:
            address = ipaddress.ip_address(data['daddr'])
        except ValueError:
            raise ProbeFailure('destination_schema_unsupported') from None
        if (address.is_loopback and address.version == owner.family == event_family
                and integer(data['dport']) == owner.port):
            connection_id = integer(data['connid'])
            require(connection_id != 0, 'kernel_connection_id_missing')
            require(connection_id not in connection_owners or connection_owners[connection_id] == pid,
                    'kernel_connection_owner_ambiguous')
            connection_owners[connection_id] = pid
            matched.add(pid)
            payload_owner_events += 1
    require(set(expected) == matched, 'kernel_payload_owner_evidence_incomplete')
    require(len(connection_owners) == 4, 'kernel_connection_ids_not_distinct')
    return {
        'ok': True, 'kind': 'kernel_connection_owner_observation_not_packet_authority',
        'independent_clients': 4, 'ipv4_client_owners_verified': 2,
        'ipv6_client_owners_verified': 2, 'payload_owner_events': payload_owner_events,
        'kernel_network_events': provider_counts[KERNEL_NETWORK],
        'tcpip_events': provider_counts[TCPIP],
        'correlation_events': provider_counts[CORRELATION],
        'activity_transfer_events': activity_events,
        'trace_events_lost': 0, 'payload_pid_used_not_header_pid': True,
        'process_epoch_verified': True, 'iphelper_used': False,
        'distinct_kernel_connection_ids': 4,
        'ndisrd_opened': False, 'filter_policy_modified': False,
        'etw_to_ndisrd_delivery_token_available': False,
        'identities_endpoints_and_raw_trace_published': False,
        **dict.fromkeys(DENIED, False),
    }


class Windows:
    def __init__(self) -> None:
        self.k = ctypes.WinDLL('kernel32', use_last_error=True)
        self.k.GetSystemDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
        self.k.GetSystemDirectoryW.restype = wintypes.UINT
        self.k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.k.OpenProcess.restype = wintypes.HANDLE
        self.k.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        self.k.GetProcessTimes.restype = wintypes.BOOL
        self.k.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                                   wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        self.k.QueryFullProcessImageNameW.restype = wintypes.BOOL
        self.k.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.k.WaitForSingleObject.restype = wintypes.DWORD
        self.k.CloseHandle.argtypes = [wintypes.HANDLE]
        self.k.CloseHandle.restype = wintypes.BOOL
        self.k.GetSystemTimeAsFileTime.argtypes = [ctypes.POINTER(wintypes.FILETIME)]
        self.k.GetSystemTimeAsFileTime.restype = None
        value = ctypes.create_unicode_buffer(32768)
        n = self.k.GetSystemDirectoryW(value, len(value))
        require(0 < n < len(value), 'system_directory_unavailable')
        self.root = Path(value.value)

    @staticmethod
    def filetime(value: wintypes.FILETIME) -> int:
        return value.dwHighDateTime << 32 | value.dwLowDateTime

    def now(self) -> int:
        result = wintypes.FILETIME()
        self.k.GetSystemTimeAsFileTime(ctypes.byref(result))
        return self.filetime(result)

    def identity(self, handle: int, expected_path: Path) -> int:
        require(self.k.WaitForSingleObject(handle, 0) == 258, 'pinned_process_not_live')
        times = [wintypes.FILETIME() for _ in range(4)]
        require(bool(self.k.GetProcessTimes(handle, *(ctypes.byref(t) for t in times))),
                'process_times_unavailable')
        size = wintypes.DWORD(32768)
        text = ctypes.create_unicode_buffer(size.value)
        require(bool(self.k.QueryFullProcessImageNameW(handle, 0, text, ctypes.byref(size))),
                'process_image_unavailable')
        require(os.path.normcase(text.value) == os.path.normcase(str(expected_path)),
                'process_image_mismatch')
        require(self.k.WaitForSingleObject(handle, 0) == 258, 'pinned_process_died')
        return self.filetime(times[0])


def native_probe() -> dict:
    require(os.name == 'nt' and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted',
            'requires_disposable_hosted_windows')
    win = Windows()
    commands = {name: win.root / (name + '.exe') for name in ('logman', 'tracerpt', 'curl')}
    require(all(p.is_file() for p in commands.values()), 'system_tool_missing')
    session = 'FlowBridge-G2-' + uuid.uuid4().hex
    release = threading.Event()
    listeners, threads, clients, handles, received = [], [], [], [], []
    active = False
    cleanup_ok = True

    def run(args: list[str], code: str, timeout: int = 12) -> None:
        try:
            p = subprocess.run(args, capture_output=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise ProbeFailure(code) from None
        require(p.returncode == 0, code)

    with tempfile.TemporaryDirectory(prefix='flowbridge-g2-private-') as temp:
        private = Path(temp)
        trace, xml, summary = (private / f for f in ('trace.etl', 'trace.xml', 'summary.txt'))
        providers = private / 'providers.txt'
        providers.write_text(''.join(f'{{{p}}} 0xFFFFFFFFFFFFFFFF 5\n'
                                     for p in (KERNEL_NETWORK, TCPIP, CORRELATION)), encoding='ascii')
        report = None
        try:
            active = True  # A partial/timed-out start must still be cleaned up.
            run([str(commands['logman']), 'create', 'trace', session, '-pf', str(providers),
                 '-o', str(trace), '-f', 'bin', '-max', '16', '-bs', '64', '-nb', '16', '64',
                 '-ct', 'perf', '-ets'], 'etw_session_start_failed')
            active = True
            owners = []
            for family, addr in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
                for _ in range(2):
                    listener = socket.socket(family, socket.SOCK_STREAM)
                    listeners.append(listener)
                    listener.bind((addr, 0))
                    listener.listen(1)
                    listener.settimeout(10)
                    port = listener.getsockname()[1]
                    ready = threading.Event()
                    received.append(ready)

                    def serve(sock=listener, signal=ready):
                        try:
                            connection, _ = sock.accept()
                            with connection:
                                connection.settimeout(10)
                                buf = b''
                                while b'\r\n\r\n' not in buf and len(buf) < 4096:
                                    part = connection.recv(1024)
                                    if not part:
                                        return
                                    buf += part
                                if b'\r\n\r\n' not in buf:
                                    return
                                signal.set()
                                release.wait(40)
                                connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n'
                                                   b'Connection: close\r\n\r\nOK')
                        except OSError:
                            pass  # Parent requires every signal and client result.

                    thread = threading.Thread(target=serve, daemon=True)
                    thread.start()
                    threads.append(thread)
                    host = '[' + addr + ']' if family == socket.AF_INET6 else addr
                    process = subprocess.Popen([str(commands['curl']), '--noproxy', '*', '--silent',
                                                '--show-error', '--max-time', '40',
                                                f'http://{host}:{port}/'],
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    clients.append(process)
                    handle = win.k.OpenProcess(0x1000 | 0x100000, False, process.pid)
                    require(bool(handle), 'process_pin_failed')
                    handles.append(handle)
                    epoch = win.identity(handle, commands['curl'])
                    owners.append(PinnedOwner(process.pid, epoch, 6 if family == socket.AF_INET6 else 4, port))
            deadline = time.monotonic() + 10
            require(all(e.wait(max(0, deadline - time.monotonic())) for e in received),
                    'independent_clients_did_not_connect')
            run([str(commands['logman']), 'stop', session, '-ets'], 'etw_session_stop_failed')
            active = False
            stopped = win.now()
            run([str(commands['tracerpt']), str(trace), '-of', 'XML', '-o', str(xml),
                 '-summary', str(summary), '-y'], 'etw_decode_failed', 20)
            require(xml.is_file() and summary.is_file(), 'etw_outputs_missing')
            require(xml.stat().st_size <= MAX_XML, 'trace_xml_size')
            raw_summary = summary.read_bytes()
            encoding = 'utf-16' if raw_summary.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig'
            report = audit_xml(xml.read_bytes(), raw_summary.decode(encoding), owners, stopped)
            for handle, owner in zip(handles, owners, strict=True):
                require(win.identity(handle, commands['curl']) == owner.creation,
                        'process_epoch_changed_during_audit')
            release.set()
            for process in clients:
                stdout, _ = process.communicate(timeout=5)
                require(process.returncode == 0 and stdout == b'OK', 'independent_client_response_failed')
            report['query_only_process_handles_revalidated'] = True
            report['exact_loopback_responses'] = 4
        finally:
            # Cleanup is not a retry of the experiment. Only this random session.
            if active:
                try:
                    run([str(commands['logman']), 'stop', session, '-ets'], 'etw_cleanup_failed')
                except ProbeFailure:
                    cleanup_ok = False
            release.set()
            for process in clients:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=5)
            for handle in handles:
                cleanup_ok = bool(win.k.CloseHandle(handle)) and cleanup_ok
            for listener in listeners:
                listener.close()
            for thread in threads:
                thread.join(timeout=2)
                cleanup_ok = not thread.is_alive() and cleanup_ok
            require(cleanup_ok, 'owned_resources_cleanup_failed')
        require(report is not None, 'native_report_missing')
        report['owned_etw_session_stopped'] = True
    report['raw_private_trace_deleted'] = not private.exists()
    require(report['raw_private_trace_deleted'], 'private_trace_cleanup_failed')
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--consent', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        require(args.consent == CONSENT, 'explicit_probe_consent_required')
        report = native_probe()
    except ProbeFailure as error:
        report = {'ok': False, 'error_code': str(error), **dict.fromkeys(DENIED, False)}
    except Exception:
        report = {'ok': False, 'error_code': 'unexpected_collector_failure', **dict.fromkeys(DENIED, False)}
    # Never serialize exception text or raw Windows/ETW identity data.
    for key, env in (('source_sha', 'PR_HEAD_SHA'), ('workflow_run_id', 'GITHUB_RUN_ID')):
        value = os.environ.get(env, '')
        if re.fullmatch(r'[0-9a-f]{40}' if key == 'source_sha' else r'[0-9]+', value):
            report[key] = value
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    print('G2_ETW_CONNECTION_EVIDENCE=' + ('PASS' if report['ok'] else 'FAIL'))
    print('G2_PACKET_BOUND=UNPROVED')
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
