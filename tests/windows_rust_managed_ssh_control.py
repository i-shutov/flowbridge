#!/usr/bin/env python3
"""Real Windows process-level Rust OpenSSH -> SOCKS control acceptance.

Shares an existing disposable, Microsoft-signed OpenSSH fixture. The Rust
agent is a separate same-user process with a restricted named pipe; both the
SSH child and SOCKS listener belong to that process. No native NDISRD capture,
driver mode, firewall, system DNS, user keys or machine service changes.
"""
from __future__ import annotations

import copy
import hashlib
import json
import shutil
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

from ssh_real_integration import free_port, require, round_trip
from windows_real_ssh_hosted import secure_test_file


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def control(agent: Path, command: str, *, accept_failure: bool = False):
    proc = subprocess.run([str(agent), "control", command],
                          capture_output=True, text=True, encoding="utf-8",
                          timeout=5, check=False)
    if proc.returncode != 0:
        if accept_failure:
            return None
        raise AssertionError("Rust restricted pipe control request failed")
    result = json.loads(proc.stdout)
    require(result.get("ok") is True, "Rust control response was not successful")
    return result


def wait_for(predicate, seconds=25):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        answer = predicate()
        if answer is not None:
            return answer
        time.sleep(.1)
    raise AssertionError("Rust-managed OpenSSH control timed out")


def read_exact(sock, length):
    buffer = bytearray()
    while len(buffer) < length:
        received = sock.recv(length - len(buffer))
        if not received:
            raise AssertionError("Unexpected EOF in SOCKS response")
        buffer.extend(received)
    return bytes(buffer)


def socks_connect_rejected(port: int, target_port: int):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
        sock.settimeout(4)
        sock.sendall(b"\x05\x01\x00")
        require(read_exact(sock, 2) == b"\x05\x00", "No SOCKS5 greeting")
        request = (b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1")
                   + target_port.to_bytes(2, "big"))
        sock.sendall(request)
        response = read_exact(sock, 2)
        require(response[0] == 5 and response[1] != 0,
                "Missing failed SOCKS CONNECT under a closed SSH gate")


def owned_ssh_listener_pid(socks_port: int, agent_pid: int) -> int:
    """Identify ONLY the agent's real Microsoft OpenSSH -D child by its bound
    loopback TCP listener and OS parent PID, before a test-induced kill.
    Never enumerate/terminate an unrelated machine SSH session.
    """
    require(1 <= socks_port <= 65535 and agent_pid > 0, "Invalid owned SSH identity")
    script = (
        "$ErrorActionPreference='Stop'; "
        f"$owners=@(Get-NetTCPConnection -State Listen -LocalPort {socks_port} "
        "| Where-Object {$_.LocalAddress -eq '127.0.0.1'} "
        "| Select-Object -ExpandProperty OwningProcess -Unique); "
        "if ($owners.Count -ne 1) {exit 11}; "
        "$candidate=Get-CimInstance Win32_Process "
        "-Filter \"ProcessId=$($owners[0])\"; "
        f"if ($null -eq $candidate -or $candidate.Name -ine 'ssh.exe' "
        f"-or $candidate.ParentProcessId -ne {agent_pid}) {{exit 12}}; "
        "Write-Output $candidate.ProcessId"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, encoding="utf-8", timeout=15,
        check=False,
    )
    require(result.returncode == 0 and result.stdout.strip().isdigit(),
            "SOCKS listener is not uniquely owned by the supervised SSH child")
    return int(result.stdout.strip())


def make_config(ssh: Path, identity: Path, known: Path, user: str,
                ssh_port: int, socks: int, ingress: int,
                banner_cli: Path | None = None):
    profile = {
        "consent": "RUST_MANAGED_SSH_SOCKS_CANDIDATE",
        "engine": {
            "version": 1, "listen": f"127.0.0.1:{ingress}",
            "proxies": [{"id": "owned-ssh", "kind": "socks5",
                         "endpoint": {"host": "127.0.0.1", "port": socks}}],
            "chains": [], "rules": [], "default_action": {"type": "proxy", "id": "owned-ssh"},
            "remote_dns_via_ssh": True, "max_connections": 8,
            "connect_timeout_ms": 3000, "handshake_timeout_ms": 3000,
            "idle_timeout_ms": 30000,
        },
        "ssh": {
            "host": "127.0.0.1", "user": user, "port": ssh_port,
            "local_port": socks, "identity_file": str(identity.resolve()),
            "known_hosts_file": str(known.resolve()),
            "ssh_executable": str(ssh.resolve()),
            "health_check_interval_ms": 200, "health_check_timeout_ms": 1000,
            "startup_timeout_ms": 10000, "connect_timeout_secs": 3,
            "restart_initial_delay_ms": 250, "restart_max_delay_ms": 500,
            "max_restarts": 3,
        }
    }
    if banner_cli is not None:
        profile["ssh"].update({
            "banner_gate_executable": str(banner_cli.resolve(strict=True)),
            "banner_gate_consent": "BANNER_FIRST_EXPERIMENTAL",
            "banner_gate_timeout_ms": 5000,
        })
    return profile


def run(agent: Path, ssh: Path, identity: Path, known: Path, user: str,
        ssh_port: int, target_port: int, output: Path,
        installed_banner_helper: Path | None = None,
        source_banner_helper: Path | None = None) -> dict:
    require(sys.platform == "win32", "This process-level acceptance requires Windows")
    agent = agent.resolve(strict=True)
    ssh = ssh.resolve(strict=True)
    require(agent.is_file() and ssh.is_file(), "Rust or OpenSSH executable missing")
    used = {ssh_port, target_port}
    ports = []
    for _ in range(20):
        port = free_port()
        if port not in used:
            ports.append(port)
            used.add(port)
        if len(ports) == 5:
            break
    require(len(ports) == 5, "Not enough distinct isolated loopback ports")
    ingress, socks, bad_ingress, bad_socks, dead_ssh = ports
    report = {
        "passed": False, "kind": "rust_owned_ssh_supervisor_and_restricted_windows_socks_ipc",
        "agent_sha256": sha256(agent), "ssh_sha256": sha256(ssh),
        "no_driver_installed_or_modified": True,
        "actual_signed_ssh_fixture": True, "authenticated_ssh_traffic": False,
        "closed_gate_direct_attempts": 0, "native_packet_pid_proof": False,
        "persistent_protected_mode": False, "dns_leak_free": False,
        "windows_10_11_accepted": False, "release_accepted": False,
    }
    with tempfile.TemporaryDirectory(prefix="flowbridge-rust-ssh-control-") as td:
        # Exercise the actual original-Rust helper from an installation-like
        # Windows path with spaces, not a hand-written Python ProxyCommand.
        if installed_banner_helper is None:
            source_cli = (source_banner_helper or Path("target/debug/flowbridge.exe")).resolve(strict=True)
            require(source_cli.name.lower() in ("flowbridge.exe", "flowbridge-cli.exe"),
                    "Unrecognized original Rust CLI name")
            helper = Path(td) / "FlowBridge Program Files" / source_cli.name
            helper.parent.mkdir(parents=True)
            shutil.copy2(source_cli, helper)
            secure_test_file(helper)
            require(sha256(source_cli) == sha256(helper),
                    "Rust banner helper copy or SHA fixture invalid")
        else:
            # Exercise the *actually installed* original-Rust NSIS payload.
            # No development-tree CLI, Python ProxyCommand or copied sidecar.
            helper = installed_banner_helper.resolve(strict=True)
            require(helper.name.lower() == "flowbridge.exe" and helper.is_file(),
                    "Installed Rust banner executable is missing or renamed")
        require(" " in str(helper), "Banner helper path-with-spaces was not exercised")
        report["banner_helper_sha256"] = sha256(helper)
        report["installed_banner_helper_exercised"] = installed_banner_helper is not None
        config_path = Path(td) / "managed.json"
        def write(profile):
            config_path.write_text(json.dumps(profile), encoding="utf-8")
            secure_test_file(config_path)

        def launch(profile):
            write(profile)
            return subprocess.Popen(
                [str(agent), "control-serve", str(config_path)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW)

        def stop(process):
            if process.poll() is None:
                control(agent, "stop")
            stdout, stderr = process.communicate(timeout=15)
            require(process.returncode == 0, "Rust managed control exited unsuccessfully")
            require(not stderr or "password" not in stderr.lower(),
                    "Sensitive configuration appeared in stderr")

        good = make_config(ssh, identity, known, user, ssh_port, socks, ingress,
                           banner_cli=helper)

        def reject_profile(profile, reason):
            child = launch(profile)
            try:
                child.communicate(timeout=7)
                require(child.returncode != 0, reason)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=5)

        missing_consent = copy.deepcopy(good)
        del missing_consent["ssh"]["banner_gate_consent"]
        reject_profile(missing_consent, "Rust Banner First accepted without opt-in")
        report["banner_gate_no_consent_rejected"] = True

        shell_injection = copy.deepcopy(good)
        shell_injection["ssh"]["banner_gate_executable"] += " & whoami"
        reject_profile(shell_injection, "Rust Banner First accepted shell metacharacters")
        report["banner_gate_shell_injection_rejected"] = True

        ads_injection = copy.deepcopy(good)
        ads_injection["ssh"]["banner_gate_executable"] += ":other"
        reject_profile(ads_injection, "Rust Banner First accepted Windows ADS alias")
        report["banner_gate_ads_rejected"] = True

        invalid = copy.deepcopy(good)
        invalid["engine"]["default_action"] = {"type": "direct"}
        proc = launch(invalid)
        try:
            proc.communicate(timeout=7)
            require(proc.returncode != 0, "Managed SSH wrongly accepted DIRECT")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=5)
        report["invalid_direct_profile_rejected"] = True

        broken = make_config(ssh, identity, known, user, dead_ssh, bad_socks,
                             bad_ingress, banner_cli=helper)
        proc = launch(broken)
        try:
            def unready():
                if proc.poll() is not None:
                    raise AssertionError("Rust-managed SSH service exited during closed gate")
                status = control(agent, "status", accept_failure=True)
                if status is not None and status["engine"]["running"]:
                    require(status["managed_ssh_gate_ready"] is False,
                            "Unreachable SSH incorrectly admitted upstream traffic")
                    return status
                return None
            wait_for(unready)
            socks_connect_rejected(bad_ingress, target_port)
            report["ssh_unreachable_rejected_without_direct"] = True
        finally:
            if proc.poll() is None:
                stop(proc)

        proc = launch(good)
        try:
            def ready():
                if proc.poll() is not None:
                    raise AssertionError("Rust managed SSH exited before ready")
                status = control(agent, "status", accept_failure=True)
                if status is not None and status.get("managed_ssh_gate_ready") is True:
                    require(status["managed_ssh"]["socks_ready_observed"] is True,
                            "Managed SSH status and gate disagree")
                    return status
                return None
            wait_for(ready, seconds=35)
            round_trip(ingress, target_port)
            report["authenticated_ssh_traffic"] = True
            report["actual_binary_half_close"] = True
            report["windows_banner_first_spaced_helper_authenticated"] = True
            revised = copy.deepcopy(good)
            revised["engine"]["idle_timeout_ms"] = 35000
            write(revised)
            result = control(agent, "reload")
            require(result["engine"]["generation"] == 2,
                    "Valid managed SOCKS reload did not commit")
            round_trip(ingress, target_port)
            report["live_socks_reload_without_carrier_change"] = True
            altered = copy.deepcopy(revised)
            altered["ssh"]["port"] = dead_ssh
            write(altered)
            require(control(agent, "reload", accept_failure=True) is None,
                    "Live SSH carrier swap was accepted")
            status = control(agent, "status")
            require(status["engine"]["generation"] == 2,
                    "Rejected SSH carrier swap changed config generation")
            round_trip(ingress, target_port)
            report["carrier_change_rejected_and_existing_connection_survived"] = True
        finally:
            if proc.poll() is None:
                stop(proc)
        try:
            with socket.create_connection(("127.0.0.1", ingress), timeout=.5):
                raise AssertionError("Rust SOCKS listener survived explicit stop")
        except OSError:
            report["listener_closed_after_stop"] = True

        # Unplanned death of the ACTUAL Microsoft OpenSSH client, without
        # calling IPC stop or manually closing the managed upstream gate.
        # This exercises the automatic Rust supervisor -> SOCKS gate coupling.
        # The long retry delay applies ONLY to this disposable test profile
        # so the closed-gate transition can be independently observed.
        crash_profile = copy.deepcopy(good)
        crash_profile["ssh"]["restart_initial_delay_ms"] = 8000
        crash_profile["ssh"]["restart_max_delay_ms"] = 8000
        proc = launch(crash_profile)
        try:
            def crash_client_ready():
                if proc.poll() is not None:
                    raise AssertionError("Rust agent exited before SSH child crash canary")
                state = control(agent, "status", accept_failure=True)
                if state is not None and state.get("managed_ssh_gate_ready") is True:
                    require(state["managed_ssh"]["socks_ready_observed"] is True,
                            "Rust supervisor incorrectly advertised a ready SSH child")
                    return state
                return None
            wait_for(crash_client_ready, seconds=35)
            round_trip(ingress, target_port)
            ssh_pid = owned_ssh_listener_pid(socks, proc.pid)
            killed = subprocess.run(
                ["taskkill", "/PID", str(ssh_pid), "/F"],
                capture_output=True, text=True, timeout=8, check=False,
            )
            require(killed.returncode == 0, "Exact owned SSH child kill failed")
            def automatic_gate_closed():
                state = control(agent, "status", accept_failure=True)
                if state is not None and state.get("managed_ssh_gate_ready") is False:
                    require(state["managed_ssh"]["socks_ready_observed"] is False,
                            "Agent claimed closed gate with live-ready SSH status")
                    return state
                return None
            wait_for(automatic_gate_closed, seconds=5)
            socks_connect_rejected(ingress, target_port)
            report["unexpected_ssh_child_death_automatically_closed_gate"] = True
            wait_for(crash_client_ready, seconds=40)
            recovered_pid = owned_ssh_listener_pid(socks, proc.pid)
            require(recovered_pid != ssh_pid,
                    "SSH restart failed to replace the killed OS process")
            round_trip(ingress, target_port)
            report["unexpected_ssh_child_death_recovered_real_ssh_without_direct"] = True
        finally:
            if proc.poll() is None:
                stop(proc)

        # A real forced termination (not graceful IPC stop) must close the
        # independent OpenSSH -D child through Windows JOB_OBJECT kill-on-close.
        # This proves only user-mode listener cleanup, NOT kernel fail-closed.
        proc = launch(good)
        try:
            def crash_ready():
                if proc.poll() is not None:
                    raise AssertionError("Crash acceptance SSH process exited before ready")
                status = control(agent, "status", accept_failure=True)
                if status is not None and status.get("managed_ssh_gate_ready") is True:
                    return True
                return None
            wait_for(crash_ready, seconds=35)
            round_trip(ingress, target_port)
            proc.kill()
            proc.communicate(timeout=15)
            require(proc.returncode != 0, "Agent was not force-terminated")

            def both_owned_listeners_closed():
                for port in (ingress, socks):
                    try:
                        probe = socket.create_connection(("127.0.0.1", port),
                                                         timeout=.2)
                    except OSError:
                        continue
                    probe.close()
                    return None
                return True
            wait_for(both_owned_listeners_closed, seconds=12)
            report["forced_agent_crash_closed_rust_and_openssh_listeners"] = True
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate(timeout=5)
    report["passed"] = all(report.get(key) is True for key in (
        "banner_gate_no_consent_rejected", "banner_gate_shell_injection_rejected",
        "banner_gate_ads_rejected", "windows_banner_first_spaced_helper_authenticated",
        "invalid_direct_profile_rejected", "ssh_unreachable_rejected_without_direct",
        "authenticated_ssh_traffic", "actual_binary_half_close",
        "live_socks_reload_without_carrier_change",
        "carrier_change_rejected_and_existing_connection_survived",
        "listener_closed_after_stop",
        "unexpected_ssh_child_death_automatically_closed_gate",
        "unexpected_ssh_child_death_recovered_real_ssh_without_direct",
        "forced_agent_crash_closed_rust_and_openssh_listeners"))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    require(report["passed"], "Rust-owned SSH Windows control acceptance failed")
    return report
