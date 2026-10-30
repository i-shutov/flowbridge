"""Strict regressions for Windows disposable load-probe socket collisions."""
import unittest
from unittest.mock import patch

from loopback_churn_dialer import LoopbackDialer


class FakeSocket:
    def __init__(self, failure=None):
        self.failure = failure
        self.closed = False
        self.bound = None
        self.connected = None
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def bind(self, address):
        self.bound = address

    def connect(self, address):
        if self.failure is not None:
            raise self.failure
        self.connected = address

    def close(self):
        self.closed = True


class DialerTests(unittest.TestCase):
    @staticmethod
    def factory(failures):
        created = []
        iterator = iter(failures)

        def build(*_args):
            sock = FakeSocket(next(iterator))
            created.append(sock)
            return sock

        return build, created

    def test_two_windows_10048_collisions_are_bounded_and_observed(self):
        factory, created = self.factory([OSError(10048, "busy"),
                                         OSError(10048, "busy"), None])
        dialer = LoopbackDialer(windows=True, socket_factory=factory,
                               sleep=lambda _: None)
        client = dialer.connect(64369)
        self.assertIs(client, created[2])
        self.assertTrue(all(item.closed for item in created[:2]))
        self.assertFalse(client.closed)
        self.assertEqual(client.bound, ("127.0.0.1", 0))
        self.assertEqual(client.connected, ("127.0.0.1", 64369))
        self.assertEqual(dialer.snapshot()["addrinuse_retries"], 2)
        self.assertEqual(dialer.snapshot()["logical_connections"], 1)

    def test_transport_failure_never_retried(self):
        factory, created = self.factory([OSError(10061, "refused"), None])
        dialer = LoopbackDialer(windows=True, socket_factory=factory,
                               sleep=lambda _: self.fail("unexpected sleep"))
        with self.assertRaises(OSError):
            dialer.connect(43210)
        self.assertEqual(len(created), 1)
        self.assertTrue(created[0].closed)
        self.assertEqual(dialer.snapshot()["addrinuse_retries"], 0)

    def test_persistent_10048_is_failure_not_false_pass(self):
        factory, created = self.factory([OSError(10048, "busy")] * 3)
        dialer = LoopbackDialer(windows=True, socket_factory=factory,
                               sleep=lambda _: None, max_addrinuse_retries=2)
        with self.assertRaises(OSError):
            dialer.connect(43210)
        self.assertEqual(len(created), 3)
        self.assertTrue(all(s.closed for s in created))
        self.assertEqual(dialer.snapshot()["addrinuse_exhaustions"], 1)
        self.assertEqual(dialer.snapshot()["logical_connections"], 0)

    def test_no_bind_for_normal_posix_path(self):
        dialer = LoopbackDialer(windows=False)
        sock = FakeSocket()
        with patch("loopback_churn_dialer.socket.create_connection",
                   return_value=sock) as mocked:
            self.assertIs(dialer.connect(12345, timeout=7), sock)
        mocked.assert_called_once_with(("127.0.0.1", 12345), timeout=7)
        self.assertFalse(dialer.snapshot()["explicit_windows_loopback_bind"])

    def test_invalid_limits_fail_before_socket_open(self):
        with self.assertRaises(ValueError):
            LoopbackDialer(max_addrinuse_retries=100)
        dialer = LoopbackDialer(windows=True)
        with self.assertRaises(ValueError):
            dialer.connect(0)
        self.assertEqual(dialer.snapshot()["logical_connections"], 0)


if __name__ == "__main__":
    unittest.main()
