import ctypes
import io
import json
import unittest
from contextlib import closing, redirect_stdout
from types import SimpleNamespace
from unittest.mock import Mock, patch

import windows_ale_endpoint_handle_probe as probe


class EndpointProbeTests(unittest.TestCase):
    def test_ioctl_uses_sdk_code_and_uint64_buffer(self):
        connection = Mock()
        connection.fileno.return_value = 91
        expected_handle = 0xFEDCBA9876543210

        def winsock_ioctl(sock, code, input_buffer, input_size, output, size,
                          length, overlapped, completion):
            self.assertEqual(sock, 91)
            self.assertEqual(code, 0x580000CD)
            self.assertEqual((input_buffer, input_size, size), (None, 0, 8))
            self.assertIsNone(overlapped)
            self.assertIsNone(completion)
            ctypes.cast(output, ctypes.POINTER(ctypes.c_uint64))[0] = expected_handle
            ctypes.cast(length, ctypes.POINTER(ctypes.c_uint32))[0] = 8
            return 0

        self.assertEqual(probe.query_endpoint(winsock_ioctl, connection), (8, expected_handle))
        with self.assertRaisesRegex(probe.ProbeFailure, "^ioctl_failed$"):
            probe.query_endpoint(Mock(return_value=-1), connection)

    def test_distinct_handles_remain_stable_on_the_same_socket(self):
        first, second = object(), object()
        query = Mock(side_effect=[(8, 41), (8, 42), (8, 41), (8, 42)])
        report = {"queries_completed": 0}
        probe.observe_endpoints(query, [first, second], report)
        self.assertEqual([call.args[0] for call in query.call_args_list],
                         [first, second, first, second])
        self.assertEqual(report, {
            "queries_completed": 4,
            "returned_length_valid": True,
            "all_nonzero": True,
            "stable_per_socket": True,
            "distinct_between_sockets": True,
        })

    def test_invalid_length_zero_unstable_and_same_handle_fail(self):
        cases = (
            ("unexpected_return_length", (4, 8, 8, 8), (41, 42, 41, 42)),
            ("unexpected_return_length", (8, 8, 9, 8), (41, 42, 41, 42)),
            ("zero_endpoint_handle", (8, 8, 8, 8), (0, 42, 0, 42)),
            ("unstable_endpoint_handle", (8, 8, 8, 8), (41, 42, 43, 42)),
            ("duplicate_endpoint_handle", (8, 8, 8, 8), (41, 41, 41, 41)),
        )
        for reason, lengths, handles in cases:
            with self.subTest(reason=reason, lengths=lengths):
                query = Mock(side_effect=zip(lengths, handles))
                with self.assertRaisesRegex(probe.ProbeFailure, f"^{reason}$"):
                    probe.observe_endpoints(query, [object(), object()], {"queries_completed": 0})

    def test_unexpected_loopback_peer_is_never_queried(self):
        listener, client, accepted = Mock(), Mock(), Mock()
        for connection in (listener, client, accepted):
            connection.close = Mock()

        listener.getsockname.return_value = ("127.0.0.1", 50001)
        client.getsockname.return_value = ("127.0.0.1", 50002)
        listener.accept.return_value = (closing(accepted), ("127.0.0.1", 50003))
        query = Mock()
        report = {"accepted_connections": 0, "owned_sockets_closed": False}
        with patch.object(probe.socket, "socket", side_effect=[closing(listener), closing(client)]):
            with self.assertRaisesRegex(probe.ProbeFailure, "^unexpected_loopback_peer$"):
                probe.observe_loopback(query, report)
        query.assert_not_called()
        self.assertEqual(report["accepted_connections"], 0)
        self.assertTrue(report["owned_sockets_closed"])
        for connection in (listener, client, accepted):
            connection.close.assert_called_once_with()

    def test_win10_stops_before_socket_observation(self):
        runner = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REPOSITORY": "i-shutov/flowbridge",
            "RUNNER_ENVIRONMENT": "self-hosted",
            "RUNNER_NAME": "win11-flowbridge",
        }
        version = SimpleNamespace(product_type=1, build=19045)
        with (
            patch.dict(probe.os.environ, runner),
            patch.object(probe.sys, "platform", "win32"),
            patch.object(probe.sys, "getwindowsversion", return_value=version, create=True),
            patch.object(probe.socket, "gethostname", return_value=probe.EXPECTED_HOST),
            patch.object(probe, "observe_loopback") as observe,
            redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(probe.main(), 1)
        observe.assert_not_called()
        result = json.loads(output.getvalue())
        self.assertEqual(result["reason"], "runner_guard")
        self.assertFalse(result["g2_accepted"])

    def test_proof_remains_scoped_and_exceptions_are_redacted(self):
        with (
            patch.object(probe, "require_expected_win11"),
            patch.object(probe, "load_ioctl"),
            patch.object(probe, "observe_loopback") as observe,
            redirect_stdout(io.StringIO()) as output,
        ):
            observe.side_effect = OSError("private address:port and handle")
            self.assertEqual(probe.main(), 1)
        result = json.loads(output.getvalue())
        self.assertEqual(result["reason"], "unexpected_probe_error")
        self.assertFalse(result["g2_accepted"])
        self.assertFalse(result["packet_owner_bound"])
        self.assertFalse(result["origin_process_bound"])
        self.assertNotIn("private", output.getvalue())


if __name__ == "__main__":
    unittest.main()
