"""R17 oracle and FFI harness: all Windows calls here are mocked.

No native Windows acceptance, remote experiment or actual network is performed.
"""
import ctypes as C
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

import socket_endpoint_r17 as p

class Sock:
    family = socket.AF_INET
    type = socket.SOCK_STREAM
    def fileno(self): return 23
    def getpeername(self): return ('not-exported', 0)

class Api:
    def __init__(self, version=0):
        self.calls = []
        self.ids = [77, 77]
        self.snapshot = p.Snapshot(77, version, 6, b'private-appid')
        self.records = p.Query(b'', 10022)
        self.context = p.Query(b'', 10022)
    def query(self, sock, op, size):
        self.calls.append((sock, op, size))
        if op == p.QUERY_ENDPOINT:
            return p.Query(self.ids.pop(0).to_bytes(8, 'little'))
        return self.records if op == p.QUERY_RECORDS else self.context
    def properties(self, endpoint):
        self.calls.append(('property', endpoint))
        return self.snapshot

class CollectorContract(unittest.TestCase):
    def test_exact_socket_endpoint_lookup_not_tuple_scan(self):
        api = Api(); o = p.collect(Sock(), api)
        self.assertEqual(api.calls, [(23, p.QUERY_ENDPOINT, 8), ('property', 77),
            (23, p.QUERY_RECORDS, p.CAP), (23, p.QUERY_CONTEXT, p.CAP), (23, p.QUERY_ENDPOINT, 8)])
        self.assertFalse(o.redacted()['g2_pass'])

    def test_ipv6_uses_distinct_fwp_ip_version(self):
        s = Sock(); s.family = socket.AF_INET6
        self.assertTrue(p.collect(s, Api(1)).redacted()['local_socket_endpoint_appid_observed'])
        with self.assertRaisesRegex(p.ProbeError, 'family_protocol'):
            p.collect(s, Api(0))

    def test_foreign_property_endpoint_rejected(self):
        api = Api(); api.snapshot = p.Snapshot(88, 0, 6, b'private')
        with self.assertRaisesRegex(p.ProbeError, 'property_mismatch'):
            p.collect(Sock(), api)

    def test_endpoint_changes_after_query_rejected(self):
        api = Api(); api.ids = [77, 88]
        with self.assertRaisesRegex(p.ProbeError, 'changed_during_query'):
            p.collect(Sock(), api)

    def test_zero_endpoint_rejected_before_bfe_query(self):
        api = Api(); api.ids = [0]
        with self.assertRaisesRegex(p.ProbeError, 'zero_endpoint'):
            p.collect(Sock(), api)
        self.assertEqual(len(api.calls), 1)

    def test_partial_or_failed_endpoint_not_authority(self):
        for q in (p.Query(b''), p.Query(b'\x01'*7), p.Query(b'\x01'*9), p.Query(b'\x01'*8, 10038)):
            with self.subTest(size=len(q.data), error=q.error), self.assertRaises(p.ProbeError):
                p.decode_endpoint(q)

    def test_empty_oversized_or_wrong_type_appid(self):
        for appid in (b'', b'a' * (p.CAP+1), None, 'not-bytes'):
            api = Api(); api.snapshot = p.Snapshot(77, 0, 6, appid)
            with self.assertRaisesRegex(p.ProbeError, 'invalid_endpoint_appid'):
                p.collect(Sock(), api)

    def test_udp_and_unknown_family_not_admitted(self):
        for family, kind in ((socket.AF_INET, socket.SOCK_DGRAM), (socket.AF_UNIX, socket.SOCK_STREAM)):
            s = Sock(); s.family = family; s.type = kind
            with self.assertRaisesRegex(p.ProbeError, 'connected_tcp'):
                p.collect(s, Api())

    def test_closed_or_disconnected_socket_not_admitted(self):
        s = Sock(); s.fileno = lambda: -1
        with self.assertRaises(p.ProbeError): p.collect(s, Api())
        s = Sock(); s.getpeername = Mock(side_effect=OSError('sensitive'))
        with self.assertRaisesRegex(p.ProbeError, '^connected_tcp_socket_required$'):
            p.collect(s, Api())

    def test_property_udp_proto_is_not_tcp(self):
        api = Api(); api.snapshot = p.Snapshot(77, 0, 17, b'private')
        with self.assertRaisesRegex(p.ProbeError, 'family_protocol'):
            p.collect(Sock(), api)

    def test_redirect_error_not_reported_as_absence(self):
        result = p.collect(Sock(), Api()).redacted()
        self.assertEqual(result['records'], {'state': 'query_error', 'bytes': 0, 'win32_error': 10022})
        self.assertFalse(result['original_process_identity_proved'])

    def test_even_both_blobs_do_not_mint_owner_or_admission(self):
        api = Api(); api.records = p.Query(b'opaque-record'); api.context = p.Query(b'forged-or-foreign-context')
        out = p.collect(Sock(), api).redacted()
        self.assertEqual(out['records']['state'], 'present_unattributed')
        for flag in ('original_process_identity_proved', 'process_start_key_bound',
                     'creation_epoch_bound', 'ndisrd_frame_bound', 'redirect_admission_allowed',
                     'g2_pass', 'system_no_direct_proved', 'release_accepted'):
            self.assertIs(out[flag], False)

    def test_no_private_paths_ids_or_blobs_in_output(self):
        api = Api(); api.context = p.Query(b'private-path-secret')
        observation = p.collect(Sock(), api)
        text = json.dumps(observation.redacted())
        for secret in ('private-path-secret', 'private-appid', 'endpointId', 'processId'):
            self.assertNotIn(secret, text)
        self.assertNotIn('private-appid', repr(observation))

    def test_no_process_fields_in_documented_endpoint_abi(self):
        self.assertEqual(C.sizeof(p.EndpointProperties), 104)
        self.assertEqual(p.EndpointProperties.appId.offset, 88)
        self.assertEqual(p.EndpointProperties.localTokenModifiedId.offset, 56)
        names = {name for name, _ in p.EndpointProperties._fields_}
        self.assertFalse(names & {'processId', 'creationTime', 'processStartKey', 'EPROCESS'})

    def test_nonwindows_fails_before_any_socket_creation(self):
        if os.name == 'nt': self.skipTest('non-Windows guard only')
        with patch.object(p.socket, 'socket', side_effect=AssertionError) as create:
            with self.assertRaisesRegex(p.ProbeError, 'windows_x64_required'):
                p.run_native(socket.AF_INET)
        create.assert_not_called()

    def test_wrong_consent_has_no_native_side_effect(self):
        output = io.StringIO()
        with patch.object(sys, 'argv', ['probe', '--consent', 'WRONG']), patch.object(p, 'run_native', side_effect=AssertionError) as native, patch('sys.stdout', output):
            self.assertEqual(p.main(), 2)
        native.assert_not_called()
        self.assertFalse(json.loads(output.getvalue())['g2_pass'])

    def test_real_linux_cli_is_not_native_pass(self):
        if os.name == 'nt': self.skipTest('no native execution in offline suite')
        result = subprocess.run([sys.executable, p.__file__, '--consent', p.CONSENT],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        data = json.loads(result.stdout)
        self.assertEqual(data['error'], 'windows_x64_required')
        self.assertFalse(data['release_accepted'])

class NativeBoundary(unittest.TestCase):
    """Exercises actual ctypes wrapper paths with mock OS functions and memory."""
    def make(self):
        api = object.__new__(p.Native)
        api.engine = C.c_void_p(1)
        api.free = Mock()
        api.close = Mock(return_value=0)
        return api

    def lookup(self, *, status=0, size=3, pointer=True):
        api = self.make()
        data = (C.c_ubyte * 3)(1, 2, 3)
        value = p.EndpointProperties()
        value.endpointId = 77; value.ipVersion = 0; value.ipProtocol = 6
        value.appId = p.ByteBlob(size, C.cast(data, C.POINTER(C.c_ubyte)))
        def get(engine, endpoint, out):
            if pointer:
                C.cast(out, C.POINTER(C.POINTER(p.EndpointProperties)))[0] = C.pointer(value)
            return status
        api.get = get
        return api

    def test_valid_properties_copy_before_free(self):
        api = self.lookup()
        snap = api.properties(77)
        self.assertEqual(snap.app_id, b'\x01\x02\x03')
        api.free.assert_called_once()

    def test_error_with_allocation_frees(self):
        api = self.lookup(status=5)
        with self.assertRaisesRegex(p.ProbeError, 'lookup_failed'): api.properties(77)
        api.free.assert_called_once()

    def test_null_result_not_dereferenced(self):
        api = self.lookup(pointer=False)
        with self.assertRaises(p.ProbeError): api.properties(77)
        api.free.assert_not_called()

    def test_invalid_blob_frees_once(self):
        for size in (0, p.CAP+1):
            api = self.lookup(size=size)
            with self.assertRaisesRegex(p.ProbeError, 'invalid_endpoint_appid'): api.properties(77)
            api.free.assert_called_once()

    def test_session_must_be_open(self):
        api = self.lookup(); api.engine = C.c_void_p()
        with self.assertRaisesRegex(p.ProbeError, 'not_open'): api.properties(77)
        api.free.assert_not_called()

    def ioctl(self, *, status=0, count=8, error=10022):
        api = self.make()
        def call(raw, code, unused, zero, buf, size, returned, ov, completion):
            C.cast(returned, C.POINTER(C.c_uint32))[0] = count
            if count <= size and count > 0: C.memmove(buf, b'\x01' * count, count)
            return status
        api.ioctl = Mock(side_effect=call)
        api.last_error = Mock(return_value=error)
        return api

    def test_query_success_length(self):
        api = self.ioctl()
        self.assertEqual(len(api.query(23, p.QUERY_ENDPOINT, 8).data), 8)
        api.last_error.assert_not_called()

    def test_zero_or_overlong_ioctl_output_denied(self):
        for n in (0, 9):
            with self.assertRaisesRegex(p.ProbeError, 'output_length'):
                self.ioctl(count=n).query(23, p.QUERY_ENDPOINT, 8)

    def test_api_error_preserved_not_retried(self):
        api = self.ioctl(status=-1, count=p.CAP+10, error=122)
        q = api.query(23, p.QUERY_RECORDS, p.CAP)
        self.assertEqual(q, p.Query(b'', 122))
        api.ioctl.assert_called_once()

    def test_unknown_or_mutating_ioctl_denied_before_api(self):
        api = self.ioctl()
        for code, size in ((0x980000DE, 8), (p.QUERY_CONTEXT, 0), (p.QUERY_CONTEXT, p.CAP+1)):
            with self.assertRaisesRegex(p.ProbeError, 'not_allowlisted'): api.query(23, code, size)
        api.ioctl.assert_not_called()

    def test_invalid_native_error_code_denied(self):
        with self.assertRaisesRegex(p.ProbeError, 'winsock_error'):
            self.ioctl(status=-1, error=0).query(23, p.QUERY_CONTEXT, 8)

    def test_close_on_exception(self):
        api = self.make()
        api.__exit__(ValueError, ValueError(), None)
        api.close.assert_called_once()
        self.assertIsNone(api.engine.value)

    def test_close_failure_is_not_success(self):
        api = self.make(); api.close.return_value = 5
        with self.assertRaisesRegex(p.ProbeError, 'close_failed'):
            api.__exit__(None, None, None)

    def test_open_failure_with_handle_attempts_cleanup(self):
        api = self.make(); api.open = Mock(return_value=5)
        with self.assertRaisesRegex(p.ProbeError, 'session_unavailable'): api.__enter__()
        api.close.assert_called_once()

class NoMutationSurface(unittest.TestCase):
    def test_python_has_no_filter_process_or_driver_path(self):
        source = Path(p.__file__).read_text()
        for text in ('Fwpm'+'FilterAdd', 'Fwps'+'CalloutRegister', 'Open'+'Process(',
                     'GetExtended'+'TcpTable', 'subprocess'+'.', 'SIO_SET'+'_WFP'):
            self.assertNotIn(text, source)

    def test_rust_entrypoint_borrows_stream_and_cannot_mint_owner(self):
        src = Path(p.__file__).with_suffix('.rs').read_text()
        self.assertIn('pub fn inspect(stream: &TcpStream)', src)
        self.assertIn('original_process_identity_proved: false', src)
        self.assertIn('g2_admission_allowed: false', src)
        for text in ('Fwpm'+'FilterAdd', 'Fwps'+'CalloutRegister', 'pub fn from_raw', 'GetExtended'+'TcpTable'):
            self.assertNotIn(text, src)

if __name__ == '__main__': unittest.main(verbosity=2)
