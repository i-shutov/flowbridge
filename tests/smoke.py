#!/usr/bin/env python3
"""Black-box CLI tests. All network traffic stays on loopback; no external services.

Run after `cargo build --workspace`: python3 tests/smoke.py
Override FLOWBRIDGE_BIN for a release binary. Tests also run on Windows/macOS.
"""
from __future__ import annotations
import contextlib
import copy
import json
import os
import pathlib
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = pathlib.Path(os.environ.get("FLOWBRIDGE_BIN", ROOT / "target" / "debug" / ("flowbridge.exe" if os.name == "nt" else "flowbridge")))
BASE = json.loads((ROOT / "examples" / "direct.json").read_text())


def exact(sock, count):
    value = b""
    while len(value) < count:
        data = sock.recv(count - len(value))
        if not data:
            raise EOFError(f"expected {count} bytes, received {len(value)}")
        value += data
    return value


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class MockServer:
    def __init__(self, handler):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.handler = handler
        self.hits = 0
        self.errors = []
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stopped.is_set():
            try:
                sock, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.hits += 1
            with sock:
                sock.settimeout(5)
                try:
                    self.handler(sock)
                except Exception as error:
                    self.errors.append(error)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.stopped.set()
        self.sock.close()
        self.thread.join(timeout=6)
        if self.errors:
            raise self.errors[0]


def echo(sock):
    while data := sock.recv(65536):
        sock.sendall(data)
    sock.sendall(b"after-half-close")


@contextlib.contextmanager
def server(profile):
    config = copy.deepcopy(profile)
    port = unused_port()
    config["listen"] = f"127.0.0.1:{port}"
    config["connect_timeout_ms"] = 1500
    config["handshake_timeout_ms"] = 1500
    with tempfile.TemporaryDirectory(prefix="flowbridge-smoke-") as folder:
        path = pathlib.Path(folder) / "config.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        # File output avoids pipe backpressure when clients generate many logs.
        with (pathlib.Path(folder) / "server.log").open("w+b") as logs:
            process = subprocess.Popen([str(BIN), "serve", "--config", str(path)], stdout=logs, stderr=logs)
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        logs.seek(0)
                        raise AssertionError(logs.read().decode("utf-8", "replace"))
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except OSError:
                        time.sleep(0.02)
                else:
                    raise AssertionError("SOCKS listener did not become ready")
                yield port
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGINT) if os.name != "nt" else process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def socks(port, host, target_port, command=1):
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.settimeout(5)
    sock.sendall(b"\x05\x01\x00")
    if exact(sock, 2) != b"\x05\x00":
        sock.close()
        raise AssertionError("unexpected SOCKS method")
    encoded = host.encode("ascii")
    sock.sendall(bytes([5, command, 0, 3, len(encoded)]) + encoded + struct.pack("!H", target_port))
    reply = exact(sock, 4)
    if reply[3] == 1:
        exact(sock, 6)
    elif reply[3] == 4:
        exact(sock, 18)
    elif reply[3] == 3:
        exact(sock, exact(sock, 1)[0] + 2)
    else:
        raise AssertionError("invalid reply address type")
    return sock, reply[1]


class Smoke(unittest.TestCase):
    def test_examples_validate_and_capabilities_are_honest(self):
        for name in ["direct.json", "ssh-socks.json", "chain.json"]:
            result = subprocess.run([str(BIN), "validate", "--config", str(ROOT / "examples" / name)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)["ok"])
        result = subprocess.run([str(BIN), "capabilities"], capture_output=True, text=True, check=True, timeout=10)
        capabilities = json.loads(result.stdout)
        self.assertFalse(capabilities["transparent_interception"])
        self.assertFalse(capabilities["system_kill_switch"])
        self.assertFalse(capabilities["udp"])

    def test_direct_binary_transfer_and_half_close(self):
        with MockServer(echo) as target, server(BASE) as port:
            client, code = socks(port, "127.0.0.1", target.port)
            with client:
                self.assertEqual(code, 0)
                payload = bytes(range(256)) * 512
                client.sendall(payload)
                self.assertEqual(exact(client, len(payload)), payload)
                client.shutdown(socket.SHUT_WR)
                self.assertEqual(exact(client, 16), b"after-half-close")
                self.assertEqual(client.recv(1), b"")

    def test_block_rule_never_opens_target(self):
        config = copy.deepcopy(BASE)
        config["default_action"] = {"type": "block"}
        with MockServer(echo) as target, server(config) as port:
            client, code = socks(port, "127.0.0.1", target.port)
            client.close()
            self.assertEqual(code, 2)
            self.assertEqual(target.hits, 0)

    def test_hostname_reaches_upstream_without_local_dns(self):
        seen = []
        def upstream(sock):
            self.assertEqual(exact(sock, 3), b"\x05\x01\x00")
            sock.sendall(b"\x05\x00")
            self.assertEqual(exact(sock, 4), b"\x05\x01\x00\x03")
            hostname = exact(sock, exact(sock, 1)[0]).decode("ascii")
            dest_port = struct.unpack("!H", exact(sock, 2))[0]
            seen.append((hostname, dest_port))
            sock.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            echo(sock)
        with MockServer(upstream) as proxy:
            config = copy.deepcopy(BASE)
            config["proxies"] = [{"id": "up", "kind": "socks5", "endpoint": {"host": "127.0.0.1", "port": proxy.port}, "username": None, "password_env": None}]
            config["default_action"] = {"type": "proxy", "id": "up"}
            with server(config) as port:
                client, code = socks(port, "must-not-resolve.invalid", 443)
                with client:
                    self.assertEqual(code, 0)
                    client.sendall(b"remote-dns")
                    self.assertEqual(exact(client, 10), b"remote-dns")
                    client.shutdown(socket.SHUT_WR)
                    self.assertEqual(exact(client, 16), b"after-half-close")
            self.assertEqual(seen, [("must-not-resolve.invalid", 443)])

    def test_remote_dns_checkbox_off_rejects_hostname_without_contacting_upstream(self):
        # The OFF state is intentionally numeric-IP-only. It never silently
        # asks the Windows/macOS resolver and never falls back to DIRECT.
        with MockServer(echo) as upstream:
            config = copy.deepcopy(BASE)
            config["proxies"] = [{"id": "up", "kind": "socks5",
                "endpoint": {"host": "127.0.0.1", "port": upstream.port},
                "username": None, "password_env": None}]
            config["default_action"] = {"type": "proxy", "id": "up"}
            config["remote_dns_via_ssh"] = False
            with server(config) as port:
                for hostname in ["uncached-name.invalid", "localhost"]:
                    client, code = socks(port, hostname, 443)
                    client.close()
                    self.assertEqual(code, 2, "Unchecked DNS mode allowed hostname routing")
            self.assertEqual(upstream.hits, 0, "Unchecked DNS mode contacted the upstream proxy")

    def test_failed_proxy_never_falls_back_to_direct(self):
        config = copy.deepcopy(BASE)
        config["proxies"] = [{"id": "dead", "kind": "socks5", "endpoint": {"host": "127.0.0.1", "port": unused_port()}, "username": None, "password_env": None}]
        config["default_action"] = {"type": "proxy", "id": "dead"}
        with MockServer(echo) as target, server(config) as port:
            client, code = socks(port, "127.0.0.1", target.port)
            client.close()
            self.assertNotEqual(code, 0)
            self.assertEqual(target.hits, 0)

    def test_proxied_loopback_target_is_remote_not_our_listener(self):
        seen = []
        def upstream(sock):
            self.assertEqual(exact(sock, 3), b"\x05\x01\x00")
            sock.sendall(b"\x05\x00")
            self.assertEqual(exact(sock, 4), b"\x05\x01\x00\x03")
            host = exact(sock, exact(sock, 1)[0]).decode("ascii")
            target_port = struct.unpack("!H", exact(sock, 2))[0]
            seen.append((host, target_port))
            sock.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            echo(sock)
        with MockServer(upstream) as proxy:
            config = copy.deepcopy(BASE)
            config["proxies"] = [{"id": "up", "kind": "socks5", "endpoint": {"host": "127.0.0.1", "port": proxy.port}, "username": None, "password_env": None}]
            config["default_action"] = {"type": "proxy", "id": "up"}
            with server(config) as port:
                client, code = socks(port, "localhost", port)
                with client:
                    self.assertEqual(code, 0)
                    client.shutdown(socket.SHUT_WR)
                    self.assertEqual(exact(client, 16), b"after-half-close")
                self.assertEqual(seen, [("localhost", port)])

    def test_udp_and_recursion_rejected(self):
        with server(BASE) as port:
            for host, target_port, command, expected in [("example.invalid", 443, 3, 7), ("localhost", port, 1, 2)]:
                client, code = socks(port, host, target_port, command)
                client.close()
                self.assertEqual(code, expected)

    def test_application_rules_cannot_silently_run_in_socks_mode(self):
        config = copy.deepcopy(BASE)
        config["rules"] = [{"id": "app", "enabled": True, "applications": ["browser.exe"], "hosts": [], "networks": [], "ports": [], "action": {"type": "block"}}]
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "app.json"
            path.write_text(json.dumps(config))
            result = subprocess.run([str(BIN), "serve", "--config", str(path)], capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot authenticate", result.stderr)
            result = subprocess.run([str(BIN), "explain", "--config", str(path), "--application", "browser.exe", "--host", "example.com", "--port", "443"], capture_output=True, text=True, check=True, timeout=10)
            self.assertEqual(json.loads(result.stdout)["decision"]["action"]["type"], "block")


if __name__ == "__main__":
    if not BIN.is_file():
        raise SystemExit(f"Build the CLI first: {BIN}")
    unittest.main(verbosity=2)
