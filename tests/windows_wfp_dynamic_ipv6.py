#!/usr/bin/env python3
"""Strict real Windows BFE IPv6 selected-only TCP/UDP; ::1 high-port QA only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import socket
import subprocess
import tempfile
import threading
import time

CONSENT = {"tcp": "DYNAMIC_WFP_QA_TCP6_APP_PORT_ONLY",
           "udp": "DYNAMIC_WFP_QA_UDP6_APP_PORT_ONLY"}


class Echo:
    def __init__(self, proto):
        self.proto = proto
        self.sock = socket.socket(socket.AF_INET6,
                                  socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM)
        self.sock.bind(("::1", 0))
        if proto == "tcp":
            self.sock.listen(8)
        self.sock.settimeout(.15)
        self.port = self.sock.getsockname()[1]
        self.received = 0
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def serve(self):
        while not self.stop.is_set():
            try:
                if self.proto == "tcp":
                    peer, _ = self.sock.accept()
                    with peer:
                        peer.settimeout(1.2)
                        with self.lock:
                            self.received += 1
                        data = bytearray()
                        while len(data) <= 32:
                            chunk = peer.recv(32)
                            if not chunk:
                                break
                            data.extend(chunk)
                        if data == b"probe":
                            peer.sendall(b"done")
                else:
                    data, address = self.sock.recvfrom(32)
                    with self.lock:
                        self.received += 1
                    if data == b"probe":
                        self.sock.sendto(b"done", address)
            except (socket.timeout, OSError):
                continue

    def count(self):
        with self.lock:
            return self.received

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.sock.close()
        self.thread.join(timeout=2)


def rust_client(path, proto, port):
    r = subprocess.run([str(path), f"wfp-qa-{proto}6-client", str(port), CONSENT[proto]],
                       capture_output=True, text=True, encoding="utf-8", timeout=6)
    data = json.loads(r.stdout)
    if r.returncode == 0:
        assert data.get("ok") is True and data.get(f"real_{proto}_ipv6") is True
        assert data.get("ndisrd_touched") is False
        return True
    assert data.get("ok") is False
    return False


def python_client(proto, port):
    with socket.socket(socket.AF_INET6,
                       socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM) as s:
        s.settimeout(2)
        if proto == "tcp":
            s.connect(("::1", port))
            s.sendall(b"probe")
            s.shutdown(socket.SHUT_WR)
            return s.recv(8) == b"done"
        s.bind(("::1", 0))
        s.sendto(b"probe", ("::1", port))
        value, sender = s.recvfrom(8)
        return value == b"done" and sender[0] == "::1" and sender[1] == port


def guard_ready(proc, proto):
    messages = queue.Queue(maxsize=1)
    threading.Thread(target=lambda: messages.put(proc.stdout.readline()), daemon=True).start()
    try:
        line = messages.get(timeout=7)
    except queue.Empty:
        raise RuntimeError("IPv6 temporary BFE guard readiness timeout") from None
    assert line and proc.poll() is None
    data = json.loads(line)
    assert data["ok"] and data["bfe_filter_readback_verified"]
    assert data["ipv6_ale_layer"] and data["app_id_scoped"]
    assert data["app_id_from_canonical_file_handle"] is True
    assert data["ip_protocol"] == (6 if proto == "tcp" else 17)
    assert data["filter_persistent"] is False and data["ndisrd_touched"] is False
    assert data["crash_persistent_fail_closed"] is False
    assert data["tcp_port_scoped"] if proto == "tcp" else data["udp_ipv6_port_scoped"]


def phase(agent, selected, sibling, proto):
    flags = {k: False for k in (
        "pre_selected", "pre_sibling", "pre_python", "bfe_readback",
        "selected_denied", "selected_not_seen_at_server",
        "sibling_allowed", "python_allowed", "guard_killed", "selected_recovered")}
    guard = None
    try:
        with Echo(proto) as server:
            assert 1025 <= server.port <= 65534
            flags["pre_selected"] = rust_client(selected, proto, server.port)
            flags["pre_sibling"] = rust_client(sibling, proto, server.port)
            flags["pre_python"] = python_client(proto, server.port)
            assert flags["pre_selected"] and flags["pre_sibling"] and flags["pre_python"]
            guard = subprocess.Popen(
                [str(agent), f"wfp-qa-{proto}6-guard",
                 str(selected), str(server.port), CONSENT[proto]],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                encoding="utf-8", text=True)
            guard_ready(guard, proto)
            flags["bfe_readback"] = True
            before = server.count()
            flags["selected_denied"] = not rust_client(selected, proto, server.port)
            time.sleep(.15)
            flags["selected_not_seen_at_server"] = server.count() == before
            flags["sibling_allowed"] = rust_client(sibling, proto, server.port)
            flags["python_allowed"] = python_client(proto, server.port)
            guard.kill()
            guard.wait(timeout=4)
            guard = None
            flags["guard_killed"] = True
            flags["selected_recovered"] = rust_client(selected, proto, server.port)
    finally:
        if guard is not None:
            guard.kill()
            try:
                guard.wait(timeout=4)
            except subprocess.TimeoutExpired:
                pass
    assert all(flags.values()), f"Strict real IPv6 {proto} enforcement failed"
    return flags


def main():
    if os.name != "nt":
        raise RuntimeError("Real Windows WFP is required; IPv6 cannot be skipped")
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    agent = args.agent.resolve(strict=True)
    report = {
        "kind": "actual_windows_ipv6_tcp_udp_selected_only_bfe",
        "passed": False, "tcp": None, "udp": None,
        "scope": "::1_high_ports_only", "ipv6_unavailable_is_failure": True,
        "ndisrd_modified": False, "persistent_wfp_filter": False,
        "arbitrary_packet_pid_proved": False, "dns_leak_free": False,
        "protected_fail_closed": False, "win10_11_accepted": False,
        "release_accepted": False
    }
    try:
        with tempfile.TemporaryDirectory(prefix="fb-wfp-v6-") as folder:
            selected = Path(folder) / "FlowBridgeWfpLabClient.exe"
            sibling = Path(folder) / "FlowBridgeWfpOtherClient.exe"
            shutil.copyfile(agent, selected)
            shutil.copyfile(agent, sibling)
            assert hashlib.sha256(selected.read_bytes()).digest() == hashlib.sha256(sibling.read_bytes()).digest()
            report["tcp"] = phase(agent, selected, sibling, "tcp")
            report["udp"] = phase(agent, selected, sibling, "udp")
            report["passed"] = True
    except Exception as exc:
        report["error_class"] = type(exc).__name__
        raise
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report))


if __name__ == "__main__":
    main()
