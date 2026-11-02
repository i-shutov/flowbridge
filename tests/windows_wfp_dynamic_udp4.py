#!/usr/bin/env python3
"""Native Windows WFP ALE selected-only UDP/IPv4 DENY and real-socket recovery.

This disposable, high-port localhost test is NOT NDISRD packet ownership,
crash-persistent fail-closed, selected-app DNS containment, or Win10/11 QA.
No network, process identity or raw AppId data enters machine-readable output.
"""
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

CONSENT = "DYNAMIC_WFP_QA_UDP4_APP_PORT_ONLY"


class Echo:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.15)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.received = 0
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def serve(self):
        while not self.stop.is_set():
            try:
                data, peer = self.sock.recvfrom(32)
            except socket.timeout:
                continue
            except OSError:
                break
            if data == b"probe":
                with self.lock:
                    self.received += 1
                self.sock.sendto(b"done", peer)

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


def rust_client(path, port):
    result = subprocess.run(
        [str(path), "wfp-qa-udp4-client", str(port), CONSENT],
        capture_output=True, text=True, encoding="utf-8", timeout=5)
    report = json.loads(result.stdout)
    if result.returncode == 0:
        assert report.get("ok") is True and report.get("real_udp_ipv4") is True
        assert report.get("ndisrd_touched") is False
        return True
    assert report.get("ok") is False, "Client failure was not explicit"
    return False


def python_client(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(1.5)
        sock.sendto(b"probe", ("127.0.0.1", port))
        data, peer = sock.recvfrom(8)
        return data == b"done" and peer == ("127.0.0.1", port)


def guard_ready(proc):
    messages = queue.Queue(maxsize=1)
    def read_once():
        messages.put(proc.stdout.readline())
    threading.Thread(target=read_once, daemon=True).start()
    try:
        line = messages.get(timeout=7)
    except queue.Empty:
        raise RuntimeError("Disposable WFP UDP guard readiness timeout") from None
    if not line or proc.poll() is not None:
        raise RuntimeError("Disposable WFP UDP guard exited before readiness")
    data = json.loads(line)
    assert data["ok"] is True and data["bfe_filter_readback_verified"] is True
    assert data["app_id_scoped"] is True
    assert data["ip_protocol"] == 17 and data["udp_ipv4_port_scoped"] is True
    assert data["filter_persistent"] is False and data["ndisrd_touched"] is False
    assert data["crash_persistent_fail_closed"] is False
    # Ephemeral filter ID remains process-local and is NOT serialized.
    return True


def main():
    if os.name != "nt":
        raise RuntimeError("This test requires actual native Windows WFP")
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    agent = args.agent.resolve(strict=True)
    result = {
        "kind": "actual_windows_wfp_selected_only_udp_ipv4_dynamic_lab",
        "passed": False,
        "pre_guard_selected_healthy": False,
        "pre_guard_sibling_healthy": False,
        "pre_guard_python_healthy": False,
        "active_bfe_filter_readback_verified": False,
        "selected_denied": False,
        "selected_denial_did_not_reach_udp_server": False,
        "sibling_allowed": False,
        "python_allowed": False,
        "guard_killed": False,
        "selected_recovered_after_guard_death": False,
        "network_test_scope": "127.0.0.1_ephemeral_udp_only",
        "driver_changed": False, "persistent_filter_created": False,
        "native_ndisrd_packet_owner_proved": False,
        "crash_persistent_fail_closed": False,
        "selected_app_dns_leak_free": False, "win10_11_accepted": False,
        "release_accepted": False
    }
    guard = None
    try:
        with tempfile.TemporaryDirectory(prefix="fb-wfp-udp4-") as folder:
            selected = Path(folder) / "FlowBridgeWfpLabClient.exe"
            sibling = Path(folder) / "FlowBridgeWfpOtherClient.exe"
            shutil.copyfile(agent, selected)
            shutil.copyfile(agent, sibling)
            assert hashlib.sha256(selected.read_bytes()).digest() == hashlib.sha256(sibling.read_bytes()).digest()
            with Echo() as echo:
                assert 1025 <= echo.port <= 65534, "Explicit high ephemeral UDP port required"
                result["pre_guard_selected_healthy"] = rust_client(selected, echo.port)
                result["pre_guard_sibling_healthy"] = rust_client(sibling, echo.port)
                result["pre_guard_python_healthy"] = python_client(echo.port)
                assert all(result[k] for k in (
                    "pre_guard_selected_healthy", "pre_guard_sibling_healthy",
                    "pre_guard_python_healthy")), "Unfiltered UDP control unavailable"
                guard = subprocess.Popen(
                    [str(agent), "wfp-qa-udp4-guard", str(selected),
                     str(echo.port), CONSENT],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    text=True, encoding="utf-8")
                result["active_bfe_filter_readback_verified"] = guard_ready(guard)
                # The selected executable is blocked by the KERNEL, not by
                # a Python predicate or a mocked Rust authorization result.
                before = echo.count()
                result["selected_denied"] = not rust_client(selected, echo.port)
                time.sleep(0.12)
                result["selected_denial_did_not_reach_udp_server"] = echo.count() == before
                result["sibling_allowed"] = rust_client(sibling, echo.port)
                result["python_allowed"] = python_client(echo.port)
                guard.kill()
                guard.wait(timeout=4)
                guard = None
                result["guard_killed"] = True
                result["selected_recovered_after_guard_death"] = rust_client(selected, echo.port)
        result["passed"] = all(result[key] is True for key in (
            "pre_guard_selected_healthy", "pre_guard_sibling_healthy",
            "pre_guard_python_healthy", "active_bfe_filter_readback_verified",
            "selected_denied", "selected_denial_did_not_reach_udp_server",
            "sibling_allowed", "python_allowed", "guard_killed",
            "selected_recovered_after_guard_death"))
    except Exception as exc:
        result["error_class"] = type(exc).__name__
        raise
    finally:
        if guard is not None:
            guard.kill()
            try:
                guard.wait(timeout=4)
            except subprocess.TimeoutExpired:
                pass
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result))
    if not result["passed"]:
        raise RuntimeError("Real selected-only UDP AppId denial did not pass")


if __name__ == "__main__":
    main()
