"""Real loopback sockets + synthetic SOCKS faults; NEVER signed-NDISRD evidence."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import socket
import socketserver
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from g1_controlled_origin import (
    ControlledOrigin, OriginError, OriginSpec, REQUEST, SCHEMA,
    _exact, controls, observe, response,
)
import windows_ndisrd_self_redirect as native

NONCE = "ab" * 16


@contextlib.contextmanager
def origin(**kwargs):
    server = ControlledOrigin("127.0.0.1", 0, NONCE, "127.0.0.1", seconds=15, **kwargs)
    thread = threading.Thread(target=server.run)
    thread.start()
    try:
        yield server, OriginSpec("127.0.0.1", server.server_address[1], NONCE)
    finally:
        server.stop.set()
        thread.join(6)
        if thread.is_alive():
            raise AssertionError("Bounded origin did not stop")


class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        end = time.monotonic() + 4
        if _exact(self.request, 3, end) != b"\x05\x01\x00":
            raise AssertionError("Unexpected method request")
        self.request.sendall(b"\x05\x00")
        req = _exact(self.request, 10, end)
        expected = b"\x05\x01\x00\x01" + socket.inet_aton(self.server.target.address)
        expected += self.server.target.port.to_bytes(2, "big")
        self.server.destinations.append(req == expected)
        if self.server.mode == "reject":
            self.request.sendall(b"\x05\x05\x00\x01" + bytes(6))
            return
        if self.server.mode == "truncated":
            self.request.sendall(b"\x05\x00")
            return
        self.request.sendall(b"\x05\x00\x00\x01" + bytes(6))
        if self.server.mode == "empty":
            if _exact(self.request, len(REQUEST), end) != REQUEST:
                raise AssertionError("Request changed")
            self.request.shutdown(socket.SHUT_WR)
            return
        with socket.create_connection((self.server.target.address, self.server.target.port), timeout=3) as upstream:
            def copy(a, b):
                try:
                    while True:
                        block = a.recv(2048)
                        if not block:
                            b.shutdown(socket.SHUT_WR)
                            break
                        b.sendall(block)
                except OSError:
                    pass
            forward = threading.Thread(target=copy, args=(self.request, upstream))
            forward.start()
            copy(upstream, self.request)
            forward.join(4)
            if forward.is_alive():
                raise AssertionError("Proxy fixture failed to half-close")


@contextlib.contextmanager
def proxy(target, mode="forward"):
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), ProxyHandler)
    server.target, server.mode, server.destinations = target, mode, []
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .05})
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def config():
    return {"target_ipv4": "10.123.0.2", "local_ipv4": "10.123.0.1",
            "controlled_origin": {"schema": SCHEMA, "owner_authorized": True,
                                  "ipv4": "10.123.0.2", "port": 80, "run_nonce": NONCE}}


class ControlledOriginTests(unittest.TestCase):
    def test_original_request_and_direct_normal_and_half_close(self):
        self.assertEqual(len(REQUEST), 57)
        with origin() as (server, spec):
            outcomes = controls(spec)
            self.assertTrue(all(x["passed"] for x in outcomes))
        self.assertEqual(len(server.events), 2)
        self.assertTrue(all(x["request_received"] and x["response_write_completed"] for x in server.events))
        text = json.dumps(server.events)
        self.assertNotIn("127.0.0.1", text)
        self.assertNotIn("HEAD /", text)

    def test_real_loopback_socks_forward_preserves_destination_and_half_close(self):
        with origin() as (server, spec), proxy(spec) as socks:
            outcomes = controls(spec, socks_port=socks.server_address[1])
            self.assertTrue(all(x["passed"] for x in outcomes))
        self.assertEqual(socks.destinations, [True, True])
        self.assertEqual(len(server.events), 2)

    def test_successful_connect_then_zero_response_is_not_success_or_direct_retry(self):
        with origin() as (server, spec), proxy(spec, "empty") as socks:
            report = observe(spec, socks_port=socks.server_address[1])
            self.assertFalse(report["passed"])
            self.assertEqual(report["outcome"], "upstream_eof_without_response")
        self.assertEqual(len(server.events), 0)
        self.assertEqual(socks.destinations, [True])

    def test_socks_rejection_and_truncation_fail_without_direct_fallback(self):
        with origin() as (server, spec):
            for mode, outcome in (("reject", "socks_connect_rejected"), ("truncated", "socks_reply_truncated")):
                with self.subTest(mode=mode), proxy(spec, mode) as socks:
                    report = observe(spec, socks_port=socks.server_address[1])
                    self.assertFalse(report["passed"])
                    self.assertEqual(report["outcome"], outcome)
        self.assertEqual(server.events, [])

    def test_stale_origin_nonce_is_rejected(self):
        with origin() as (server, spec):
            stale = OriginSpec(spec.address, spec.port, "cd" * 16)
            report = observe(stale)
            self.assertFalse(report["passed"])
            self.assertEqual(report["outcome"], "unexpected_origin_response")

    def test_native_config_rejects_legacy_local_override_and_noncanonical_inputs(self):
        self.assertEqual(OriginSpec.from_native_context(config()).port, 80)
        high_port = config()
        high_port["controlled_origin"]["port"] = 18080
        self.assertEqual(OriginSpec.from_native_context(high_port).port, 18080)
        bad = [dict(config(), controlled_origin=None), dict(config(), target_ipv4="10.123.0.3"),
               dict(config(), local_ipv4="10.123.0.2")]
        for change in ({"owner_authorized": False}, {"owner_authorized": 1}, {"port": 8080},
                       {"ipv4": "example.com"}, {"ipv4": "127.0.0.1"}, {"ipv4": "192.0.2.1"},
                       {"ipv4": "224.0.0.1"}, {"run_nonce": "x"}, {"unknown": True}):
            c = config()
            c["controlled_origin"].update(change)
            if "ipv4" in change:
                c["target_ipv4"] = change["ipv4"]
            bad.append(c)
        for item in bad:
            with self.subTest(item=item), self.assertRaises(OriginError):
                OriginSpec.from_native_context(item)

    def test_missing_origin_stops_before_ffi_ssh_and_driver(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "not-an-executable"
            binary.write_bytes(b"read-only digest fixture")
            context = root / "context.json"
            context.write_text(json.dumps({"target_ipv4": "10.123.0.2", "local_ipv4": "10.123.0.1",
                                           "recovery_armed": True, "defender_active": True}))
            output = root / "result.json"
            argv = ["native-harness"]
            for name in ("agent", "library", "ssh", "sshd", "keygen"):
                argv += ["--" + name, str(binary)]
            argv += ["--context", str(context), "--output", str(output)]
            with patch.object(native.sys, "argv", argv), patch.object(native.sys, "platform", "win32"), \
                 patch.dict(native.os.environ, {"FLOWBRIDGE_VPS_NATIVE": "OWNER_VNC_CONFIRMED",
                                                "FLOWBRIDGE_SOURCE_SHA": "a" * 40}), \
                 patch.object(native, "ABI") as ffi, patch.object(native.subprocess, "Popen") as start, \
                 contextlib.redirect_stdout(io.StringIO()), self.assertRaises(OriginError):
                native.main()
            ffi.assert_not_called()
            start.assert_not_called()
            report = json.loads(output.read_text())
            self.assertFalse(report["passed"])
            self.assertFalse(report["driver_was_used"])
            self.assertEqual(report["pending_step"], "controlled_origin_preflight")

    def test_origin_peer_scope_lifetime_and_exclusive_receipts(self):
        with self.assertRaises(OriginError):
            ControlledOrigin("0.0.0.0", 0, NONCE, "127.0.0.1")
        with self.assertRaises(OriginError):
            ControlledOrigin("127.0.0.1", 0, NONCE, "127.0.0.1", seconds=3601)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipts.jsonl"
            with origin(receipts=path) as (server, spec):
                self.assertTrue(observe(spec)["passed"])
            events = [json.loads(x) for x in path.read_text().splitlines()]
            self.assertEqual(len(events), 1)
            with self.assertRaises(FileExistsError):
                ControlledOrigin("127.0.0.1", 0, NONCE, "127.0.0.1", receipts=path)
        self.assertEqual(response(NONCE).count(b"X-FlowBridge-G1-Run:"), 1)


if __name__ == "__main__":
    unittest.main()
