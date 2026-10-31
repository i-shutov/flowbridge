#!/usr/bin/env python3
"""Real native Rust SCM stage/replace/remove and live SOCKS integration.

Only the fixed on-demand test service is touched. The Rust candidate performs
SCM mutations, and Python checks actual Windows SCM and TCP/pipe behavior.
No driver, proxy sidecar, credential, or protected route is installed.
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


def run(*args: str, ok: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(args, capture_output=True, text=True, timeout=18, check=False)
    if (proc.returncode == 0) != ok:
        raise AssertionError(
            f"unexpected command result {args[1:3]}: exit={proc.returncode}, "
            f"stdout_tail={proc.stdout[-300:]}, stderr_tail={proc.stderr[-200:]}"
        )
    return proc


def agent_command(agent: pathlib.Path, *args: str, ok: bool = True) -> dict:
    proc = run(str(agent), *args, ok=ok)
    result = json.loads(proc.stdout)
    if result.get("ok") != ok:
        raise AssertionError(f"Rust SCM command returned incorrect verdict: {args[0]}")
    if result.get("protected_redirect_available") is not False and ok:
        raise AssertionError("SCM command must not claim protected routing")
    return result


def sc(*args: str, ok: bool = True) -> str:
    return run("sc.exe", *args, ok=ok).stdout


def await_engine(agent: pathlib.Path, up: bool) -> dict | None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        proc = subprocess.run(
            [str(agent), "control", "status"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if up and proc.returncode == 0:
            value = json.loads(proc.stdout)
            if value.get("engine", {}).get("running") is True:
                return value
        if not up and proc.returncode != 0:
            return None
        time.sleep(0.2)
    raise AssertionError(f"live SCM engine failed to reach up={up}")


def wait_stopped() -> None:
    for _ in range(70):
        output = subprocess.run(
            ["sc.exe", "query", NAME],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if output.returncode == 0 and "STOPPED" in output.stdout:
            return
        time.sleep(0.2)
    raise AssertionError("SCM service did not stop")


def port() -> int:
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return int(reservation.getsockname()[1])


def socks_handshake(address: int) -> None:
    with socket.create_connection(("127.0.0.1", address), timeout=3) as sock:
        sock.settimeout(3)
        sock.sendall(b"\x05\x01\x00")
        if sock.recv(2) != b"\x05\x00":
            raise AssertionError("real Rust SCM socket rejected SOCKS5 negotiation")


def port_closed(address: int) -> None:
    for _ in range(15):
        try:
            with socket.create_connection(("127.0.0.1", address), timeout=0.2):
                time.sleep(0.1)
        except OSError:
            return
    raise AssertionError("stopped/previous SCM SOCKS listener remained reachable")


def profile(path: pathlib.Path, listen: str) -> None:
    path.write_text(json.dumps({
        "version": 1,
        "listen": listen,
        "proxies": [], "chains": [], "rules": [],
        "default_action": {"type": "block"},
        "connect_timeout_ms": 1400, "handshake_timeout_ms": 1400,
        "idle_timeout_ms": 1400, "max_connections": 8,
        "remote_dns_via_ssh": True,
    }), encoding="utf-8")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--agent", type=pathlib.Path, required=True)
    p.add_argument("--output", type=pathlib.Path, required=True)
    options = p.parse_args()
    agent = options.agent.resolve()
    if run("sc.exe", "query", NAME, ok=False).returncode == 0:
        raise AssertionError("service already exists: never overwrite it")
    staged = False
    config_in_use: pathlib.Path | None = None
    with tempfile.TemporaryDirectory(prefix="flowbridge-rust-staging-") as temp:
        directory = pathlib.Path(temp)
        old = directory / "v1.json"
        new = directory / "v2.json"
        invalid = directory / "remote.json"
        p1, p2 = port(), port()
        if p1 == p2:
            raise AssertionError("distinct listener ports required")
        profile(old, f"127.0.0.1:{p1}")
        profile(new, f"127.0.0.1:{p2}")
        profile(invalid, "0.0.0.0:7777")

        try:
            agent_command(agent, "service-stage", str(invalid), ok=False)
            if run("sc.exe", "query", NAME, ok=False).returncode == 0:
                raise AssertionError("invalid profile unexpectedly created service")

            staged_result = agent_command(agent, "service-stage", str(old))
            if staged_result.get("action") != "staged_manual_only":
                raise AssertionError("service was not staged explicitly/manual only")
            staged, config_in_use = True, old

            agent_command(agent, "service-stage", str(new), ok=False)
            agent_command(agent, "service-remove", str(new), ok=False)
            sc("start", NAME)
            status = await_engine(agent, True)
            if status["mode"] != "scm_explicit_socks_only":
                raise AssertionError("SCM engine mode does not match explicit SOCKS")
            socks_handshake(p1)
            agent_command(agent, "service-replace", str(old), str(new), ok=False)
            # Staging an upgrade while running is forbidden even for valid
            # profiles, so live listener and policy remain unchanged.
            socks_handshake(p1)

            sc("stop", NAME)
            wait_stopped()
            await_engine(agent, False)
            port_closed(p1)

            agent_command(agent, "service-replace", str(old), str(invalid), ok=False)
            # An invalid replacement must leave the exact previous SCM binary
            # path intact, proved by an exact-match ownership removal denial.
            agent_command(agent, "service-remove", str(new), ok=False)

            result = agent_command(agent, "service-replace", str(old), str(new))
            if result.get("action") != "replaced_stopped_only":
                raise AssertionError("Rust SCM stopped-only replacement unverified")
            config_in_use = new
            agent_command(agent, "service-remove", str(old), ok=False)

            sc("start", NAME)
            second = await_engine(agent, True)
            if second["engine"]["generation"] != 1:
                raise AssertionError("SCM replacement reused an old live generation")
            socks_handshake(p2)
            port_closed(p1)
            stop = agent_command(agent, "control", "stop")
            if stop["engine"]["running"] is not False:
                raise AssertionError("local IPC failed to stop replaced service")
            wait_stopped()
            await_engine(agent, False)
            port_closed(p2)

            removed = agent_command(agent, "service-remove", str(new))
            if removed.get("action") != "removed_stopped_only":
                raise AssertionError("Rust SCM remove did not finish")
            staged, config_in_use = False, None
            for _ in range(30):
                check = subprocess.run(
                    ["sc.exe", "query", NAME], capture_output=True, text=True, timeout=5
                )
                if check.returncode != 0:
                    break
                time.sleep(0.2)
            else:
                raise AssertionError("SCM service record survived Rust removal")

            report = {
                "passed": True,
                "source_commit": run("git", "rev-parse", "HEAD").stdout.strip(),
                "agent_sha256": hashlib.sha256(agent.read_bytes()).hexdigest(),
                "scm_stage_via_original_rust": True,
                "scm_validated_manual_only": True,
                "invalid_profile_prevented_creation": True,
                "preexisting_service_not_overwritten": True,
                "running_service_upgrade_denied": True,
                "invalid_upgrade_preserved_prior_config": True,
                "stopped_service_replaced_and_live_port_changed": True,
                "old_service_record_not_removed_by_wrong_expected_config": True,
                "real_socks_negotiation_before_after_upgrade": True,
                "scm_and_local_pipe_stop_verified": True,
                "rust_scm_remove_verified": True,
                "driver_installed_by_test": False,
                "driver_capture_active": False,
                "native_packet_process_binding": False,
                "protected_redirect_available": False,
                "dns_leak_free": False,
                "win10_11_acceptance": False,
                "release_accepted": False,
            }
            options.output.parent.mkdir(parents=True, exist_ok=True)
            options.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(report))
        finally:
            if staged and config_in_use is not None:
                # Safe cleanup: only remove exactly the record we created
                # and only after SCM reports STOPPED. Never delete a foreign
                # service or force stop an unexpected service instance.
                try:
                    sc("stop", NAME, ok=False)
                    wait_stopped()
                    agent_command(agent, "service-remove", str(config_in_use))
                except (AssertionError, OSError, ValueError) as error:
                    raise AssertionError(
                        "safe test cleanup could not prove exact service ownership"
                    ) from error


if __name__ == "__main__":
    main()
