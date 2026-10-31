#!/usr/bin/env python3
"""Real Windows SCM start/STOP, protected-disabled Rust SOCKS and IPC test.

Creates only an on-demand, test-named user-mode service, never installs a driver.
Always deletes the temporary service even on assertion failures. Not Win10/11
native NDISRD capture, DNS containment or production protected-mode acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import socket
import subprocess
import tempfile
import time

NAME = "FlowBridgeRustCandidateCI"


def sc(*args: str, ok: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        ["sc.exe", *args], text=True, capture_output=True, timeout=20, check=False,
    )
    if ok and proc.returncode != 0:
        raise AssertionError(f"sc {' '.join(args[:2])} failed ({proc.returncode}): {proc.stdout[-400:]} {proc.stderr[-400:]}")
    return proc


def control(agent: pathlib.Path, action: str) -> dict:
    proc = subprocess.run(
        [str(agent), "control", action],
        text=True, capture_output=True, timeout=8, check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(f"control {action} exit {proc.returncode}: {proc.stdout[-300:]}")
    return json.loads(proc.stdout)


def wait_status(agent: pathlib.Path, expected: bool, seconds: float = 12) -> dict | None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            data = control(agent, "status")
            if expected and data["engine"]["running"]:
                return data
        except (AssertionError, OSError, ValueError, KeyError):
            if not expected:
                return None
        time.sleep(0.15)
    raise AssertionError(f"control pipe did not reach expected availability={expected}")


def port_blocked(port: int) -> None:
    for _ in range(20):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                time.sleep(0.1)
        except OSError:
            return
    raise AssertionError("SOCKS listener unexpectedly survived service stop")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--agent", required=True, type=pathlib.Path)
    p.add_argument("--output", required=True, type=pathlib.Path)
    a = p.parse_args()
    agent = a.agent.resolve()
    if sc("query", NAME, ok=False).returncode == 0:
        raise AssertionError("test service already exists: do not overwrite it")
    with tempfile.TemporaryDirectory(prefix="flowbridge-scm-") as temp:
        config = pathlib.Path(temp) / "config.json"
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        value = {
            "version": 1, "listen": f"127.0.0.1:{port}",
            "proxies": [], "chains": [], "rules": [],
            "default_action": {"type": "block"},
            "connect_timeout_ms": 1500, "handshake_timeout_ms": 1500,
            "idle_timeout_ms": 1500, "max_connections": 8, "remote_dns_via_ssh": True,
        }
        config.write_text(json.dumps(value), encoding="utf-8")
        binary = f'"{agent}" service-run "{config.resolve()}"'
        sc("create", NAME, "binPath=", binary, "start=", "demand", "type=", "own")
        try:
            sc("start", NAME)
            data = wait_status(agent, True)
            if not (
                data.get("mode") == "scm_explicit_socks_only"
                and data.get("scm_service_running") is True
                and data.get("protected_redirect_available") is False
                and data.get("driver_capture_active") is False
                and data.get("dns_leak_free") is False
                and data["engine"]["generation"] == 1
            ):
                raise AssertionError(f"SCM source status not safe: {data}")
            with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
                sock.settimeout(3)
                sock.sendall(b"\x05\x01\x00")
                if sock.recv(2) != b"\x05\x00":
                    raise AssertionError("SCM service did not serve real SOCKS negotiation")
            value["rules"] = [{
                "id": "block-all", "enabled": True, "applications": [],
                "hosts": [], "networks": [], "ports": [],
                "action": {"type": "block"},
            }]
            config.write_text(json.dumps(value), encoding="utf-8")
            result = control(agent, "reload")
            if result["engine"]["generation"] != 2:
                raise AssertionError("SCM engine did not atomically reload policy")
            sc("stop", NAME)
            wait_status(agent, False)
            port_blocked(port)
            # Only SCM can restart this process. Test IPC stop independently
            # after a second successful start of exactly the same installed service.
            sc("start", NAME)
            data = wait_status(agent, True)
            if data["engine"]["generation"] != 1:
                raise AssertionError("new SCM process reused stale generation")
            stopped = control(agent, "stop")
            if stopped["engine"]["running"]:
                raise AssertionError("IPC stop failed to terminate SCM engine")
            wait_status(agent, False)
            port_blocked(port)
            result = {
                "passed": True,
                "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
                "agent_sha256": hashlib.sha256(agent.read_bytes()).hexdigest(),
                "hosted_windows_scm_real": True, "on_demand_local_service": True,
                "service_restart_clean_generation": True,
                "scm_stop_closed_real_socks": True, "pipe_stop_closed_real_socks": True,
                "policy_reload_generation_two": True,
                "driver_installed_by_test": False,
                "driver_capture_active": False, "native_packet_process_binding": False,
                "protected_redirect_available": False, "dns_leak_free": False,
                "win10_11_acceptance": False, "release_accepted": False,
            }
            a.output.parent.mkdir(parents=True, exist_ok=True)
            a.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(result))
        finally:
            sc("stop", NAME, ok=False)
            # Wait until the OS releases the SCM service object before deletion.
            for _ in range(30):
                result = sc("delete", NAME, ok=False)
                if result.returncode == 0:
                    break
                time.sleep(0.2)
            else:
                raise AssertionError("failed to remove temporary SCM test service")


if __name__ == "__main__":
    main()
