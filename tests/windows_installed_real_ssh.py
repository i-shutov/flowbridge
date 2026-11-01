#!/usr/bin/env python3
"""Installed Rust-only NSIS payload -> Microsoft signed OpenSSH -> SOCKS test.

Disposable GitHub-hosted Windows Server loopback only. The host/user keys
are ephemeral test files and are removed; never add their contents to reports.
This does not exercise native driver interception or Windows 10/11 acceptance.
"""
from __future__ import annotations

import getpass
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading

from ssh_real_integration import Echo, Server, free_port, require, until
from windows_real_ssh_hosted import secure_test_file
from windows_rust_managed_ssh_control import run as managed_control


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(installed_agent: Path, installed_cli: Path, ssh: Path, sshd: Path,
        keygen: Path, output: Path) -> dict:
    require(sys.platform == "win32"
            and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("FLOWBRIDGE_HOSTED_WINDOWS_SSH") == "1",
            "Installed SSH test requires explicit disposable Windows-hosted consent")
    agent = installed_agent.resolve(strict=True)
    cli = installed_cli.resolve(strict=True)
    ssh = ssh.resolve(strict=True)
    sshd = sshd.resolve(strict=True)
    keygen = keygen.resolve(strict=True)
    require(agent.is_file() and cli.is_file() and ssh.is_file()
            and sshd.is_file() and keygen.is_file(),
            "One or more required exact installed/official binaries are absent")
    require(cli.parent == agent.parent and " " in str(cli),
            "Both Rust binaries must come from the same installed spaced directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "kind": "real_windows_server_hosted_installed_original_rust_banner_ssh_socks",
        "passed": False,
        "installed_rust_agent_sha256": sha256(agent),
        "installed_rust_banner_cli_sha256": sha256(cli),
        "microsoft_ssh_client_sha256": sha256(ssh),
        "isolated_signed_ssh_server_sha256": sha256(sshd),
        "actual_installed_ssh_authentication": False,
        "actual_installed_binary_half_close": False,
        "installed_helper_not_developer_binary": False,
        "no_direct_on_unready_ssh": False,
        "owned_ssh_and_rust_listeners_closed_after_forced_crash": False,
        "ephemeral_host_user_keys_not_persisted": False,
        "driver_touched": False,
        "arbitrary_app_packet_pid_bound": False,
        "persistent_protected_fail_closed": False,
        "dns_leak_free": False,
        "win10_11_accepted": False,
        "release_accepted": False,
    }
    daemon = None
    echo = Server(("127.0.0.1", 0), Echo)
    echo_thread = threading.Thread(target=echo.serve_forever, daemon=True)
    echo_thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="flowbridge-installed-sshd-",
                                          dir=os.environ["RUNNER_TEMP"]) as directory:
            root = Path(directory)
            try:
                for key in ("host_key", "client_key"):
                    subprocess.run([str(keygen), "-q", "-t", "ed25519",
                                    "-N", "", "-f", str(root / key)],
                                   capture_output=True, check=True, timeout=15)
                    secure_test_file(root / key)
                authorized = root / "authorized_keys"
                authorized.write_bytes((root / "client_key.pub").read_bytes())
                secure_test_file(authorized)
                port = free_port()
                require(port != echo.server_address[1], "SSH port collided with local echo")
                user = getpass.getuser().lower()
                require(user.isascii() and user.replace("_", "").replace("-", "").isalnum(),
                        "Unsafe hosted Windows fixture username")
                known = root / "known_hosts"
                known.write_text(f"[127.0.0.1]:{port} " +
                                 (root / "host_key.pub").read_text(), encoding="ascii")
                config = root / "sshd_config"
                config.write_text("\n".join([
                    f"Port {port}", "ListenAddress 127.0.0.1", "AddressFamily inet",
                    f'HostKey "{(root / "host_key").as_posix()}"',
                    f'AuthorizedKeysFile "{authorized.as_posix()}"',
                    f"AllowUsers {user}", "PasswordAuthentication no",
                    "PubkeyAuthentication yes", "AuthenticationMethods publickey",
                    "AllowTcpForwarding local", "GatewayPorts no",
                    "PermitOpen localhost:* 127.0.0.1:* [::1]:*",
                    "MaxStartups 10:30:20", "MaxSessions 10", ""
                ]), encoding="ascii")
                secure_test_file(config)
                subprocess.run([str(sshd), "-t", "-f", str(config)],
                               check=True, capture_output=True, timeout=15)
                with (root / "sshd.log").open("wb") as log:
                    daemon = subprocess.Popen([str(sshd), "-D", "-e", "-f", str(config)],
                                              stdin=subprocess.DEVNULL,
                                              stdout=subprocess.DEVNULL, stderr=log,
                                              creationflags=subprocess.CREATE_NO_WINDOW)
                    def ready():
                        require(daemon.poll() is None, "Isolated sshd exited before accepting")
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                                return True
                        except OSError:
                            return False
                    until(ready, seconds=20)
                    outcome = managed_control(
                        agent, ssh, root / "client_key", known, user, port,
                        echo.server_address[1],
                        output.parent / "installed-managed-ssh-control.json",
                        installed_banner_helper=cli)
                    require(outcome.get("passed") is True
                            and outcome.get("installed_banner_helper_exercised") is True
                            and outcome.get("banner_helper_sha256") == report["installed_rust_banner_cli_sha256"]
                            and outcome.get("agent_sha256") == report["installed_rust_agent_sha256"],
                            "Authenticated owned-control test did not use exact installed Rust binaries")
                    report["actual_installed_ssh_authentication"] = outcome["authenticated_ssh_traffic"]
                    report["actual_installed_binary_half_close"] = outcome["actual_binary_half_close"]
                    report["installed_helper_not_developer_binary"] = True
                    report["no_direct_on_unready_ssh"] = outcome["ssh_unreachable_rejected_without_direct"]
                    report["owned_ssh_and_rust_listeners_closed_after_forced_crash"] = (
                        outcome["forced_agent_crash_closed_rust_and_openssh_listeners"])
            finally:
                if daemon is not None:
                    daemon.terminate()
                    try:
                        daemon.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        daemon.kill()
                        daemon.wait(timeout=5)
                    daemon = None
        report["ephemeral_host_user_keys_not_persisted"] = not root.exists()
        report["passed"] = all(report[key] is True for key in (
            "actual_installed_ssh_authentication", "actual_installed_binary_half_close",
            "installed_helper_not_developer_binary", "no_direct_on_unready_ssh",
            "owned_ssh_and_rust_listeners_closed_after_forced_crash",
            "ephemeral_host_user_keys_not_persisted",
        ))
        require(report["passed"], "Installed Rust real OpenSSH acceptance incomplete")
        return report
    finally:
        echo.shutdown()
        echo.server_close()
        echo_thread.join(timeout=4)
        output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
