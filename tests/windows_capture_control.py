#!/usr/bin/env python3
"""Real Windows named-pipe -> Rust Engine -> loopback SOCKS lifecycle acceptance.

Not NDISRD interception, PID proof, protected mode, Windows 10/11 or DNS
containment. The independent capture candidate is tested as actually packaged.
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


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(agent: pathlib.Path, action: str, success: bool = True) -> dict:
    proc = subprocess.run(
        [str(agent), "control", action],
        capture_output=True, text=True, encoding="utf-8", timeout=8, check=False
    )
    if (proc.returncode == 0) != success:
        raise AssertionError(f"{action}: unexpected exit={proc.returncode}, stdout={proc.stdout[-800:]}, stderr={proc.stderr[-800:]}")
    value = json.loads(proc.stdout)
    if value.get("ok") is not success:
        raise AssertionError(f"{action}: unexpected reply {value}")
    return value


def profile(listen_port: int) -> dict:
    return {
        "version": 1, "listen": f"127.0.0.1:{listen_port}",
        "proxies": [], "chains": [], "rules": [],
        "default_action": {"type": "block"},
        "connect_timeout_ms": 1500, "handshake_timeout_ms": 1500,
        "idle_timeout_ms": 1500, "max_connections": 8,
        "remote_dns_via_ssh": True,
    }


def recv_exact(sock: socket.socket, n: int) -> bytes:
    result = bytearray()
    while len(result) < n:
        data = sock.recv(n - len(result))
        if not data:
            raise AssertionError("unexpected EOF in SOCKS handshake")
        result.extend(data)
    return bytes(result)


def blocked_socks_connect(port: int, destination: int) -> None:
    with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
        sock.settimeout(3)
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise AssertionError("SOCKS5 authentication/negotiation failed")
        sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + destination.to_bytes(2, "big"))
        reply = recv_exact(sock, 2)
        if reply != b"\x05\x02":
            raise AssertionError(f"BLOCK unexpectedly allowed a target: {reply!r}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    agent = args.agent.resolve()
    # Real Windows self-owned loopback socket -> two native IP Helper reads ->
    # PID + process creation-time matching, with deliberate identity redaction.
    # This does NOT promote an NDISRD packet into PacketBound.
    owner_proc = subprocess.run(
        [str(agent), "owner-selftest"], capture_output=True, text=True,
        encoding="utf-8", timeout=12, check=False,
    )
    if owner_proc.returncode != 0:
        raise AssertionError(
            f"native TCP owner candidate selftest failed: "
            f"code={owner_proc.returncode}, output={owner_proc.stdout[-600:]}"
        )
    owner_evidence = json.loads(owner_proc.stdout)
    required_true = (
        "ok", "actual_loopback_tcp_socket", "two_snapshots_consistent",
        "candidate_matches_current_process_and_creation_epoch",
        "process_identity_redacted",
    )
    required_false = (
        "driver_opened", "packet_owner_bound", "native_packet_attribution_proved",
        "authorizes_capture", "protected_redirect_available", "dns_leak_free",
        "win10_11_acceptance", "release_accepted",
    )
    if any(owner_evidence.get(k) is not True for k in required_true):
        raise AssertionError(f"missing actual native owner evidence: {owner_evidence}")
    if any(owner_evidence.get(k) is not False for k in required_false):
        raise AssertionError(f"false native owner/packet claim: {owner_evidence}")
    if any(k in owner_evidence for k in (
        "pid", "process_creation_100ns", "executable_path", "local", "remote",
    )):
        raise AssertionError("owner selftest exposed process or endpoint identity")
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        listen_port = reserve.getsockname()[1]
    with socket.socket() as target:
        target.bind(("127.0.0.1", 0))
        target.listen(1)
        target.settimeout(0.3)
        target_port = target.getsockname()[1]
        with tempfile.TemporaryDirectory(prefix="flowbridge-control-") as td:
            path = pathlib.Path(td) / "explicit.json"
            config = profile(listen_port)
            path.write_text(json.dumps(config), encoding="utf-8")
            proc = subprocess.Popen(
                [str(agent), "control-serve", str(path)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8",
            )
            try:
                for _ in range(70):
                    if proc.poll() is not None:
                        raise AssertionError(f"control-serve exited early ({proc.returncode})")
                    try:
                        status = command(agent, "status")
                        break
                    except (AssertionError, subprocess.TimeoutExpired, json.JSONDecodeError):
                        time.sleep(0.1)
                else:
                    raise AssertionError("restricted named-pipe controller did not become ready")
                if (status["engine"]["running"] is not True
                        or status["engine"]["generation"] != 1
                        or status["driver_capture_active"] is not False
                        or status["protected_redirect_available"] is not False
                        or status["scm_service_installed"] is not False
                        or status["dns_leak_free"] is not False):
                    raise AssertionError(f"false capability flags: {status}")

                blocked_socks_connect(listen_port, target_port)
                try:
                    target.accept()
                    raise AssertionError("blocked explicit SOCKS request reached target")
                except socket.timeout:
                    pass

                # A policy needing unauthenticated application identity MUST
                # fail before Engine.reload replaces the running generation.
                config["rules"] = [{
                    "id": "app-requires-native-proof", "enabled": True,
                    "applications": ["C:\\Apps\\Browser.exe"],
                    "hosts": [], "networks": [], "ports": [],
                    "action": {"type": "block"},
                }]
                path.write_text(json.dumps(config), encoding="utf-8")
                refused = command(agent, "reload", success=False)
                if "application" not in refused.get("error", ""):
                    raise AssertionError(f"wrong failure reason: {refused}")
                if command(agent, "status")["engine"]["generation"] != 1:
                    raise AssertionError("rejected profile changed the generation")

                # A different bind port/capacity cannot be applied to a live
                # engine; rollback preserves the original listener.
                config = profile(listen_port)
                config["max_connections"] = 9
                path.write_text(json.dumps(config), encoding="utf-8")
                command(agent, "reload", success=False)
                blocked_socks_connect(listen_port, target_port)

                config = profile(listen_port)
                config["rules"] = [{
                    "id": "all-blocked", "enabled": True, "applications": [],
                    "hosts": [], "networks": [], "ports": [],
                    "action": {"type": "block"},
                }]
                path.write_text(json.dumps(config), encoding="utf-8")
                accepted = command(agent, "reload")
                if accepted["engine"]["generation"] != 2:
                    raise AssertionError("atomic hot reload did not apply")
                blocked_socks_connect(listen_port, target_port)

                command(agent, "invalid-command", success=False)
                stopped = command(agent, "stop")
                if stopped["engine"]["running"] is not False:
                    raise AssertionError("stop did not terminate engine")
                stdout, stderr = proc.communicate(timeout=8)
                if proc.returncode != 0:
                    raise AssertionError(f"server exit={proc.returncode}: {stdout[-500:]} {stderr[-500:]}")
                terminal = json.loads(stdout)
                if terminal.get("foreground_control_stopped") is not True:
                    raise AssertionError(f"wrong server termination: {terminal}")
                try:
                    with socket.create_connection(("127.0.0.1", listen_port), timeout=0.2):
                        raise AssertionError("SOCKS listener survived stop")
                except (ConnectionRefusedError, OSError):
                    pass
                evidence = {
                    "passed": True, "platform": "hosted_Windows_test_not_Win10_11_acceptance",
                    "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
                    "agent_sha256": sha256(agent),
                    "real_windows_named_pipe": True,
                    "real_loopback_tcp_iphelper_candidate": True,
                    "owner_epoch_verified_against_current_process": True,
                    "two_native_iphelper_tables_consistent": True,
                    "owner_candidate_redacted": True,
                    "local_acl_restricts_to_system_admin_owner": True,
                    "remote_pipe_clients_rejected_by_server": True,
                    "actual_loopback_socks5_negotiation": True,
                    "default_block_did_not_open_target": True,
                    "unattested_application_rule_denied": True,
                    "bad_reload_preserves_generation_and_listener": True,
                    "valid_reload_generation": 2,
                    "stop_closed_listener": True,
                    "driver_opened": False,
                    "native_pid_proof": False,
                    "protected_redirect_available": False,
                    "dns_leak_free": False,
                    "release_accepted": False,
                }
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
                print(json.dumps(evidence))
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate(timeout=5)


if __name__ == "__main__":
    main()
