#!/usr/bin/env python3
"""R17: query a caller-owned socket, never join a tuple to a PID.

Read-only user-mode Winsock/BFE APIs. No filters, driver, capture, socket
redirection, traffic forwarding, process lookup, registry or service changes.
The optional native harness opens only one IPv4/IPv6 loopback TCP pair.
This is an independent probe, NOT production Rust and NOT a G2 authority.
"""
from __future__ import annotations
import argparse
import ctypes as C
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import socket
import sys

CONSENT = 'G2_SOCKET_ENDPOINT_READONLY'
# Microsoft WinSock SDK constants: _WSAIOR(IOC_VENDOR,205), _WSAIOW(...,220/221).
QUERY_ENDPOINT = 0x580000CD
QUERY_RECORDS = 0x980000DC
QUERY_CONTEXT = 0x980000DD
CAP = 65536

class ProbeError(RuntimeError):
    """All messages are fixed, redacted identifiers, never native input text."""

class Address(C.Union):
    _fields_ = [('v4', C.c_uint32), ('v6', C.c_ubyte * 16)]

class ByteBlob(C.Structure):
    _fields_ = [('size', C.c_uint32), ('data', C.POINTER(C.c_ubyte))]

class EndpointProperties(C.Structure):
    _fields_ = [
        ('endpointId', C.c_uint64), ('ipVersion', C.c_int32),
        ('localAddress', Address), ('remoteAddress', Address),
        ('ipProtocol', C.c_uint8), ('localPort', C.c_uint16),
        ('remotePort', C.c_uint16), ('localTokenModifiedId', C.c_uint64),
        ('mmSaId', C.c_uint64), ('qmSaId', C.c_uint64),
        ('ipsecStatus', C.c_uint32), ('flags', C.c_uint32), ('appId', ByteBlob),
    ]

@dataclass(frozen=True, repr=False)
class Snapshot:
    endpoint: int
    ip_version: int
    protocol: int
    app_id: bytes = field(repr=False)

@dataclass(frozen=True, repr=False)
class Query:
    data: bytes = field(repr=False)
    error: int = 0

@dataclass(frozen=True, repr=False)
class Observation:
    endpoint: int
    app_id: bytes = field(repr=False)
    records: Query = field(repr=False)
    context: Query = field(repr=False)

    def redacted(self) -> dict:
        def view(q: Query) -> dict:
            # An API error is not proof that redirect data are absent.
            return {'state': 'present_unattributed' if not q.error else 'query_error',
                    'bytes': len(q.data) if not q.error else 0, 'win32_error': q.error}
        return {
            'local_socket_endpoint_appid_observed': True,
            'attribution_scope': 'queried_local_endpoint_only',
            'records': view(self.records), 'context': view(self.context),
            'original_process_identity_proved': False,
            'process_start_key_bound': False, 'creation_epoch_bound': False,
            'ndisrd_frame_bound': False, 'redirect_admission_allowed': False,
            'g2_pass': False, 'system_no_direct_proved': False, 'release_accepted': False,
        }


def decode_endpoint(q: Query) -> int:
    if q.error or len(q.data) != 8:
        raise ProbeError('endpoint_ioctl_failed_or_short')
    value = int.from_bytes(q.data, 'little')
    if not value:
        raise ProbeError('zero_endpoint')
    return value


def collect(sock: socket.socket, api) -> Observation:
    """No numeric foreign handle input; caller retains an open socket throughout.

    Repeated endpoint queries reject an obvious rebind but are NOT a kernel
    lifetime proof and cannot detect every same-ID recycle. No PID is inferred.
    """
    if (sock.family not in (socket.AF_INET, socket.AF_INET6)
            or sock.type != socket.SOCK_STREAM or sock.fileno() < 0):
        raise ProbeError('connected_tcp_socket_required')
    try:
        sock.getpeername()  # Check connected; no packet is sent.
    except OSError:
        raise ProbeError('connected_tcp_socket_required') from None
    endpoint = decode_endpoint(api.query(sock.fileno(), QUERY_ENDPOINT, 8))
    info = api.properties(endpoint)
    if info.endpoint != endpoint:
        raise ProbeError('endpoint_property_mismatch')
    if info.protocol != 6 or info.ip_version != (0 if sock.family == socket.AF_INET else 1):
        raise ProbeError('endpoint_family_protocol_mismatch')
    if type(info.app_id) is not bytes or not 0 < len(info.app_id) <= CAP:
        raise ProbeError('invalid_endpoint_appid')
    records = api.query(sock.fileno(), QUERY_RECORDS, CAP)
    context = api.query(sock.fileno(), QUERY_CONTEXT, CAP)
    if decode_endpoint(api.query(sock.fileno(), QUERY_ENDPOINT, 8)) != endpoint:
        raise ProbeError('endpoint_changed_during_query')
    # Do not parse optional opaque metadata as a PID/epoch or a trusted ticket.
    return Observation(endpoint, info.app_id, records, context)


class Native:
    """Only the documented user-mode functions from system DLLs are loaded."""
    def __init__(self):
        if os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
            raise ProbeError('windows_x64_required')
        if C.sizeof(EndpointProperties) != 104 or EndpointProperties.appId.offset != 88:
            raise ProbeError('unsupported_endpoint_abi')
        self.engine = C.c_void_p()
        self.ws = C.WinDLL('ws2_32.dll', winmode=0x800)
        self.fw = C.WinDLL('fwpuclnt.dll', winmode=0x800)
        self.ioctl = self.ws.WSAIoctl
        self.ioctl.argtypes = [C.c_size_t, C.c_uint32, C.c_void_p, C.c_uint32,
                              C.c_void_p, C.c_uint32, C.POINTER(C.c_uint32),
                              C.c_void_p, C.c_void_p]
        self.ioctl.restype = C.c_int
        self.last_error = self.ws.WSAGetLastError
        self.last_error.argtypes = []
        self.last_error.restype = C.c_int
        try:
            self.get = self.fw.FwpsAleEndpointGetById0
        except AttributeError:
            raise ProbeError('endpoint_api_unavailable') from None
        self.get.argtypes = [C.c_void_p, C.c_uint64, C.POINTER(C.POINTER(EndpointProperties))]
        self.get.restype = C.c_uint32
        self.free = self.fw.FwpmFreeMemory0
        self.free.argtypes = [C.POINTER(C.c_void_p)]
        self.free.restype = None
        self.open = self.fw.FwpmEngineOpen0
        self.open.argtypes = [C.c_wchar_p, C.c_uint32, C.c_void_p, C.c_void_p, C.POINTER(C.c_void_p)]
        self.open.restype = C.c_uint32
        self.close = self.fw.FwpmEngineClose0
        self.close.argtypes = [C.c_void_p]
        self.close.restype = C.c_uint32

    def __enter__(self):
        status = self.open(None, 10, None, None, C.byref(self.engine))
        if status or not self.engine.value:
            if self.engine.value:
                self.close(self.engine)
                self.engine = C.c_void_p()
            raise ProbeError('bfe_query_session_unavailable')
        return self

    def __exit__(self, exc_type, exc, tb):
        handle, self.engine = self.engine, C.c_void_p()
        if handle.value and self.close(handle) and exc_type is None:
            raise ProbeError('bfe_query_session_close_failed')

    def query(self, raw_socket: int, code: int, size: int) -> Query:
        if code not in (QUERY_ENDPOINT, QUERY_RECORDS, QUERY_CONTEXT) or not 0 < size <= CAP:
            raise ProbeError('query_not_allowlisted')
        data = (C.c_ubyte * size)()
        count = C.c_uint32()
        status = self.ioctl(raw_socket, code, None, 0, data, size, C.byref(count), None, None)
        if status:
            error = self.last_error()
            if error <= 0:
                raise ProbeError('invalid_winsock_error')
            return Query(b'', error)  # No realloc/retry and no treating error as absence.
        if not 0 < count.value <= size:
            raise ProbeError('invalid_ioctl_output_length')
        return Query(bytes(data[:count.value]))

    def properties(self, endpoint: int) -> Snapshot:
        if not self.engine.value:
            raise ProbeError('bfe_session_not_open')
        ptr = C.POINTER(EndpointProperties)()
        try:
            status = self.get(self.engine, endpoint, C.byref(ptr))
            if status or not ptr:
                raise ProbeError('endpoint_property_lookup_failed')
            p = ptr.contents
            if not p.appId.data or not 0 < p.appId.size <= CAP:
                raise ProbeError('invalid_endpoint_appid')
            return Snapshot(p.endpointId, p.ipVersion, p.ipProtocol,
                            C.string_at(p.appId.data, p.appId.size))
        finally:
            if ptr:
                raw = C.cast(ptr, C.c_void_p)
                self.free(C.byref(raw))


def run_native(family: int) -> dict:
    # Native is constructed before any socket operation: non-Windows fails here.
    with Native() as api:
        host = '127.0.0.1' if family == socket.AF_INET else '::1'
        with socket.socket(family, socket.SOCK_STREAM) as listener:
            listener.settimeout(5)
            listener.bind((host, 0))
            listener.listen(1)
            with socket.socket(family, socket.SOCK_STREAM) as client:
                client.settimeout(5)
                client.connect(listener.getsockname())
                accepted, _ = listener.accept()
                with accepted:
                    accepted.settimeout(5)
                    outgoing = collect(client, api)
                    ingress = collect(accepted, api)
                    result = {
                        'ok': True, 'native_windows_called': True,
                        'evidence_level': 'local_socket_endpoint_readonly',
                        'family': 'ipv4' if family == socket.AF_INET else 'ipv6',
                        'scope': 'owned_loopback_sockets_no_payload',
                        'client': outgoing.redacted(), 'accepted_local': ingress.redacted(),
                        'endpoint_ids_equal_observation': outgoing.endpoint == ingress.endpoint,
                        'endpoint_appids_equal_observation': outgoing.app_id == ingress.app_id,
                        'socket_endpoint_join_native_observed': True,
                        'original_unprepared_exe_tested': False,
                        'g2_pass': False, 'release_accepted': False,
                        'driver_or_filter_modified': False,
                    }
    result['owned_sockets_and_bfe_session_closed'] = True
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--consent', required=True)
    parser.add_argument('--family', choices=('ipv4', 'ipv6'), default='ipv4')
    args = parser.parse_args()
    if args.consent != CONSENT:
        print(json.dumps({'ok': False, 'error': 'consent_required', 'g2_pass': False}))
        return 2
    try:
        result = run_native(socket.AF_INET if args.family == 'ipv4' else socket.AF_INET6)
    except ProbeError as error:
        result = {'ok': False, 'error': str(error), 'g2_pass': False, 'release_accepted': False}
    except Exception:
        result = {'ok': False, 'error': 'native_query_failed', 'g2_pass': False, 'release_accepted': False}
    result['source_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    print(json.dumps(result, sort_keys=True))
    return 0 if result['ok'] else 2

if __name__ == '__main__':
    sys.exit(main())
