#!/usr/bin/env python3
"""Real two-hop SOCKS integration for GUI-owned SSH / elevated WFP bridge split.

Actual TCP: native selected-flow C ABI -> user-level FlowBridge SOCKS listener
-> managed SSH-compatible SOCKS upstream -> binary echo. No kernel WFP driver,
UAC, real remote SSH, external DNS or OS extension is exercised here.
"""
import argparse
import concurrent.futures
import json
from pathlib import Path
import sys
import threading
import time

from ssh_real_integration import ABI, free_port, require, until
from managed_capacity_integration import Upstream, SocksEcho
from native_vertical_integration import configure, exchange, rejected


def profile(port, proxies, action, rules=None):
    return {
        "version": 1, "listen": f"127.0.0.1:{port}",
        "proxies": proxies, "chains": [], "rules": rules or [],
        "default_action": action, "connect_timeout_ms": 3000,
        "handshake_timeout_ms": 3000, "idle_timeout_ms": 30000,
        "max_connections": 16,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    library = {
        "win32": "flowbridge_ffi.dll",
        "darwin": "libflowbridge_ffi.dylib",
    }.get(sys.platform, "libflowbridge_ffi.so")
    abi = ABI(root / "target/debug" / library)
    configure(abi)
    server = Upstream(("127.0.0.1", 0), SocksEcho)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = {"host": "127.0.0.1", "port": server.server_address[1]}
    local_port = free_port()
    require(local_port not in (endpoint["port"], 1), "Loopback test ports overlap")
    gui = profile(local_port, [{"id": "managed-ssh", "kind": "socks5",
                                "endpoint": endpoint}],
                  {"type": "proxy", "id": "managed-ssh"})
    native = profile(1, [{"id": "gui-owned-socks", "kind": "socks5",
                          "endpoint": {"host": "127.0.0.1", "port": local_port}}],
                     {"type": "direct"}, [{
                         "id": "selected", "enabled": True,
                         "applications": ["qa-selected"], "hosts": [],
                         "networks": [], "ports": [],
                         "action": {"type": "proxy", "id": "gui-owned-socks"},
                     }])
    selection = {"application": "qa-selected",
                 "destination": {"host": "capacity.invalid", "port": 443},
                 "resolved_ip": None}
    report = {"passed": False, "real_wfp_driver_tested": False,
              "real_ssh_backend_tested": False, "checks": [], "platform": sys.platform}
    engine = 0
    session = 0
    streams = []
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=2)
    try:
        # The managed SSH endpoint is deliberately owned by the GUI engine.
        engine = abi.call("fb_engine_create_json", gui)["engine_id"]
        shared_limits = {"max_flows": 4, "max_opening": 2,
                         "max_queued": 4, "wait_timeout_ms": 3000}
        abi.call("fb_engine_set_upstream_gate_json", engine, {
            "endpoint": endpoint, "ready": True, "grace_ms": 1000,
            "limits": shared_limits,
        })
        abi.call("fb_engine_start_json", engine)
        session = abi.call("fb_native_create_json", native, {})["session_id"]
        opened = abi.call("fb_native_stream_open_json", session, selection)
        first = opened["stream_id"]
        streams.append(first)
        require(opened["decision"]["action"] == {"type": "proxy", "id": "gui-owned-socks"},
                "Selected WFP-like flow did not enter the user-owned local listener")
        until(lambda: server.active == 1, 5)
        payload = b"wfp-to-gui-to-ssh\x00\xff" + bytes(range(256)) * 4
        exchange(abi, first, payload)
        report["checks"].append("Selected flow reached the genuine GUI engine and a second SOCKS hop; binary echo preserved")

        # The unelevated engine, not the privileged helper, gates all new SSH
        # traffic during reconnect. A pending selected flow must not go DIRECT.
        abi.call("fb_engine_set_upstream_gate_json", engine, {
            "endpoint": endpoint, "ready": False, "grace_ms": 3000,
            "limits": shared_limits,
        })
        pending = pool.submit(abi.call, "fb_native_stream_open_json", session, selection)
        time.sleep(0.15)
        require(not pending.done(), "SSH outage unexpectedly admitted a new native flow")
        require(server.active == 1, "Selected flow bypassed the user-level readiness gate")
        abi.call("fb_engine_set_upstream_gate_json", engine, {
            "endpoint": endpoint, "ready": True, "grace_ms": 3000,
            "limits": shared_limits,
        })
        second = pending.result(timeout=10)["stream_id"]
        streams.append(second)
        exchange(abi, second, b"recovered\x00\xff" + bytes(range(64)))
        exchange(abi, first, b"established-stream-preserved")
        report["checks"].append("Reconnect gate blocks new flows without DIRECT fallback and preserves an existing stream")

        for stream in streams:
            abi.lib.fb_stream_close(stream)
        streams.clear()
        until(lambda: server.active == 0, 5)
        before = server.peak
        abi.call("fb_engine_stop_json", engine)
        rejected(abi, "fb_native_stream_open_json", session, selection)
        require(server.active == 0 and server.peak == before,
                "Stopped user-owned engine was bypassed to reach upstream")
        report["checks"].append("With GUI engine stopped, privileged native profile cannot leak DIRECT")
        snapshot = abi.call("fb_native_snapshot_json", session)
        require(snapshot["status"]["bytes_up"] >= len(payload) and
                snapshot["status"]["bytes_down"] >= len(payload),
                "Two-hop native traffic counters were not preserved")
        report["checks"].append("Native counters reflect actual two-hop bytes")
        report["passed"] = True
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        for stream in streams:
            abi.lib.fb_stream_close(stream)
        if session:
            abi.lib.fb_native_destroy(session)
        if engine:
            abi.lib.fb_engine_destroy(engine)
        pool.shutdown(wait=True, cancel_futures=True)
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2), flush=True)


if __name__ == "__main__":
    main()
