#!/usr/bin/env python3
"""Bounded, owner-controlled HTTP fixture and G1 upstream discriminator.

QA only: no driver, firewall, route, SSH configuration, or product policy changes.
The fixed 57-byte historical request is retained; its Host header is NOT resolved.
Origin write completion proves a local send, not delivery to the native client.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import socket
import socketserver
import threading
import time

REQUEST = b"HEAD / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n"
REQUEST_SHA256 = hashlib.sha256(REQUEST).hexdigest()
SCHEMA = "flowbridge_g1_controlled_origin_v1"
MAX_REPLY = 8192


class OriginError(ValueError):
    """Only fixed, payload/identity-free messages may leave the fixture."""


def nonce(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{32}", value) is None:
        raise OriginError("Controlled origin requires a fresh 128-bit run nonce")
    return value


def ipv4(value: object) -> str:
    try:
        address = ipaddress.IPv4Address(value) if isinstance(value, str) else None
    except ipaddress.AddressValueError:
        address = None
    if address is None or str(address) != value:
        raise OriginError("Controlled origin requires a canonical literal IPv4 address")
    return str(address)


def response(run_nonce: str) -> bytes:
    return ("HTTP/1.0 204 No Content\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "X-FlowBridge-G1-Run: " + nonce(run_nonce) + "\r\n\r\n").encode("ascii")


class OriginSpec:
    def __init__(self, address: str, port: int, run_nonce: str):
        self.address = ipv4(address)
        if type(port) is not int or not 1 <= port <= 65535:
            raise OriginError("Controlled origin port is invalid")
        self.port = port
        self.run_nonce = nonce(run_nonce)
        self.expected = response(self.run_nonce)

    @classmethod
    def from_native_context(cls, context: dict) -> "OriginSpec":
        raw = context.get("controlled_origin")
        required = {"schema", "owner_authorized", "ipv4", "port", "run_nonce"}
        if not isinstance(raw, dict) or set(raw) != required:
            raise OriginError("Explicit controlled-origin configuration is missing or has unknown fields")
        if raw["schema"] != SCHEMA or raw["owner_authorized"] is not True:
            raise OriginError("Owner authorization for the controlled origin is required")
        spec = cls(raw["ipv4"], raw["port"], raw["run_nonce"])
        a = ipaddress.IPv4Address(spec.address)
        forbidden = ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "192.0.2.0/24",
                     "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3")
        if any(a in ipaddress.IPv4Network(n) for n in forbidden):
            raise OriginError("Native origin must be a real non-loopback unicast endpoint")
        if spec.port not in (80, 18080):
            raise OriginError("Native Rust origin port must be 80 or 18080")
        if context.get("target_ipv4") != spec.address:
            raise OriginError("Original packet destination and controlled origin must be identical")
        if ipv4(context.get("local_ipv4")) == spec.address:
            raise OriginError("A local origin cannot prove physical-adapter interception")
        return spec

    def metadata(self) -> dict:
        return {"schema": SCHEMA, "run_nonce": self.run_nonce,
                "request_sha256": REQUEST_SHA256,
                "response_sha256": hashlib.sha256(self.expected).hexdigest(),
                "independent_origin_receipts_required": True}


def _deadline(sock: socket.socket, end: float) -> None:
    left = end - time.monotonic()
    if left <= 0:
        raise TimeoutError("Bounded origin exchange expired")
    sock.settimeout(left)


def _exact(sock: socket.socket, size: int, end: float) -> bytes:
    data = bytearray()
    while len(data) < size:
        _deadline(sock, end)
        block = sock.recv(size - len(data))
        if not block:
            raise EOFError("Incomplete SOCKS reply")
        data.extend(block)
    return bytes(data)


def observe(spec: OriginSpec, *, socks_port: int | None = None,
            half_close: bool = True, timeout: float = 3.0) -> dict:
    """One attempt; a failed SOCKS path is NEVER retried DIRECT.

    Direct observations are separate unselected QA controls, not fallbacks.
    No address, PID, payload, credentials or raw exception is returned.
    """
    if not 0 < timeout <= 5:
        raise OriginError("Origin exchange timeout is outside its bound")
    if socks_port is not None and (type(socks_port) is not int or not 1 <= socks_port <= 65535):
        raise OriginError("SOCKS control port is invalid")
    result = {"route": "direct_control" if socks_port is None else "socks_control",
              "half_close": half_close, "passed": False, "outcome": "not_started",
              "request_sha256": REQUEST_SHA256, "response_sha256": None}
    end = time.monotonic() + timeout
    stage = "connect"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            _deadline(sock, end)
            sock.connect((spec.address, spec.port) if socks_port is None else ("127.0.0.1", socks_port))
            if socks_port is not None:
                stage = "socks_handshake"
                _deadline(sock, end)
                sock.sendall(b"\x05\x01\x00")
                if _exact(sock, 2, end) != b"\x05\x00":
                    result["outcome"] = "socks_method_rejected"
                    return result
                _deadline(sock, end)
                sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(spec.address)
                             + spec.port.to_bytes(2, "big"))
                header = _exact(sock, 4, end)
                if header[0] != 5 or header[2] != 0 or header[1] > 8:
                    result["outcome"] = "socks_invalid_reply"
                    return result
                if header[1] != 0:
                    result["outcome"] = "socks_connect_rejected"
                    return result
                length = {1: 4, 4: 16}.get(header[3])
                if header[3] == 3:
                    length = _exact(sock, 1, end)[0]
                if not length:
                    result["outcome"] = "socks_invalid_reply"
                    return result
                _exact(sock, length + 2, end)
            stage = "request"
            _deadline(sock, end)
            sock.sendall(REQUEST)
            if half_close:
                sock.shutdown(socket.SHUT_WR)
            stage = "response"
            reply = bytearray()
            while len(reply) <= MAX_REPLY:
                _deadline(sock, end)
                block = sock.recv(min(2048, MAX_REPLY + 1 - len(reply)))
                if not block:
                    break
                reply.extend(block)
            result["response_sha256"] = hashlib.sha256(reply).hexdigest()
            if not reply:
                result["outcome"] = "upstream_eof_without_response"
            elif bytes(reply) != spec.expected:
                result["outcome"] = "unexpected_origin_response"
            else:
                result.update(passed=True, outcome="exact_origin_response")
    except TimeoutError:
        result["outcome"] = stage + "_timeout"
    except EOFError:
        result["outcome"] = "socks_reply_truncated"
    except OSError:
        result["outcome"] = stage + "_transport_error"
    return result


def controls(spec: OriginSpec, *, socks_port: int | None = None) -> list[dict]:
    return [observe(spec, socks_port=socks_port, half_close=mode) for mode in (False, True)]


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = self.server
        end = min(server.ends_at, time.monotonic() + 5.0)
        event = {"kind": "flowbridge_g1_origin_receipt_v1", "run_nonce": server.run_nonce,
                 "request_received": False, "response_write_completed": False,
                 "request_sha256": None, "response_sha256": None,
                 "outcome": "request_rejected"}
        try:
            data = _exact(self.request, len(REQUEST), end)
            if data != REQUEST:
                return
            event.update(request_received=True, request_sha256=REQUEST_SHA256)
            reply = response(server.run_nonce)
            _deadline(self.request, end)
            self.request.sendall(reply)
            self.request.shutdown(socket.SHUT_WR)
            event.update(response_write_completed=True,
                         response_sha256=hashlib.sha256(reply).hexdigest(),
                         outcome="response_written_not_delivery_proof")
            # Drain only a bounded amount. Never wait for FIN before replying:
            # ordinary HTTP clients wait for the response before closing.
            _deadline(self.request, end)
            if self.request.recv(1):
                event["outcome"] = "extra_request_data_rejected"
        except (OSError, EOFError, TimeoutError):
            if not event["response_write_completed"]:
                event["outcome"] = "bounded_transport_failure"
        finally:
            server.record(event)


class ControlledOrigin(socketserver.ThreadingTCPServer):
    """Explicit bind/peer allowlist, no forwarding, bounded connections/lifetime."""
    allow_reuse_address = False
    daemon_threads = False
    block_on_close = True
    request_queue_size = 8

    def __init__(self, address: str, port: int, run_nonce: str, allow_peer: str,
                 *, seconds: float = 900, max_connections: int = 256,
                 receipts: Path | None = None):
        address, allow_peer = ipv4(address), ipv4(allow_peer)
        for value in (address, allow_peer):
            a = ipaddress.IPv4Address(value)
            if a.is_unspecified or a.is_multicast or a.is_reserved:
                raise OriginError("Wildcard, multicast or reserved origin/peer refused")
        if type(port) is not int or not 0 <= port <= 65535:
            raise OriginError("Origin listener port invalid")
        if not 0 < seconds <= 3600 or type(max_connections) is not int or not 1 <= max_connections <= 512:
            raise OriginError("Origin lifetime or connection budget invalid")
        self.run_nonce, self.allow_peer = nonce(run_nonce), allow_peer
        self.ends_at = time.monotonic() + seconds
        self.max_connections, self.accepted = max_connections, 0
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(4)
        self.events: list[dict] = []
        # Exclusive creation prevents accidentally combining evidence runs.
        self.journal = receipts.open("x", encoding="utf-8") if receipts else None
        try:
            super().__init__((address, port), _Handler)
        except BaseException:
            if self.journal:
                self.journal.close()
            raise
        self.timeout = .1

    def verify_request(self, request: socket.socket, client_address: tuple) -> bool:
        self.accepted += 1
        return (self.accepted <= self.max_connections and client_address[0] == self.allow_peer
                and time.monotonic() < self.ends_at)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # socketserver's default traceback includes endpoint information.
        self.record({"kind": "flowbridge_g1_origin_receipt_v1", "run_nonce": self.run_nonce,
                     "request_received": False, "response_write_completed": False,
                     "outcome": "fixture_handler_failed"})

    def record(self, event: dict) -> None:
        with self.lock:
            self.events.append(event)
            if self.journal:
                self.journal.write(json.dumps(event, sort_keys=True) + "\n")
                self.journal.flush()

    def run(self) -> None:
        try:
            while not self.stop.is_set() and time.monotonic() < self.ends_at and self.accepted < self.max_connections:
                self.handle_request()
        finally:
            self.server_close()
            if self.journal:
                self.journal.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="Run only on an explicitly authorized origin host")
    serve.add_argument("--bind", required=True)
    serve.add_argument("--port", type=int, default=80)
    serve.add_argument("--allow-peer", required=True)
    serve.add_argument("--run-nonce", required=True)
    serve.add_argument("--seconds", type=int, default=900)
    serve.add_argument("--output", type=Path, required=True)
    serve.add_argument("--owner-authorized", action="store_true")
    probe = commands.add_parser("probe", help="One ordinary/half-close control pair per path; no driver")
    probe.add_argument("--context", type=Path, required=True)
    probe.add_argument("--source-sha", required=True)
    probe.add_argument("--socks-port", type=int)
    probe.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "serve":
        if not args.owner_authorized:
            parser.error("Explicit owner authorization is required; no host is provisioned automatically")
        server = ControlledOrigin(args.bind, args.port, args.run_nonce, args.allow_peer,
                                  seconds=args.seconds, receipts=args.output)
        print("CONTROLLED_ORIGIN_READY_NO_DRIVER_OR_FIREWALL_CHANGES", flush=True)
        server.run()
        return
    if re.fullmatch(r"[0-9a-f]{40}", args.source_sha) is None:
        parser.error("An exact source SHA is required")
    spec = OriginSpec.from_native_context(json.loads(args.context.read_text(encoding="utf-8-sig")))
    with args.output.open("x", encoding="utf-8") as stream:
        observations = controls(spec)
        if args.socks_port is not None:
            observations += controls(spec, socks_port=args.socks_port)
        passed = all(item["passed"] is True for item in observations)
        report = {"kind": "g1_controlled_origin_preflight_not_native", "passed": passed,
                  "source_sha": args.source_sha, "origin": spec.metadata(),
                  "observations": observations, "native_test_executed": False,
                  "release_accepted": False}
        stream.write(json.dumps(report, indent=2) + "\n")
    if not passed:
        raise SystemExit("Controlled-origin preflight failed; native acceptance is not established")


if __name__ == "__main__":
    try:
        main()
    except (OriginError, OSError, json.JSONDecodeError):
        raise SystemExit("Controlled origin refused input or could not bind; no network policy was changed") from None
