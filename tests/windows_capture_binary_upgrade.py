#!/usr/bin/env python3
"""Real Windows Rust SCM executable upgrade/rollback, not a driver or protected routing test.

An independently built debug agent is copied beside a release agent. The Rust
agent itself verifies the staged x64 PE with Windows CNG SHA-256 and performs
stopped-only, exact-SCM-owner replacement; Python exercises real service/pipe/
SOCKS sockets before and after both directions of the binary transition.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import time

from windows_capture_install import (
    NAME, agent_command, await_engine, port, port_closed, profile,
    run, sc, socks_handshake, wait_stopped,
)


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assert_command_contains(image: pathlib.Path) -> None:
    output = sc("qc", NAME)
    if image.name.lower() not in output.lower():
        raise AssertionError("SCM binary does not match the expected Rust executable")


def ensure_absent() -> None:
    for _ in range(40):
        result = subprocess.run(
            ["sc.exe", "query", NAME],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if result.returncode != 0:
            return
        time.sleep(0.2)
    raise AssertionError("temporary Rust SCM record still exists")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", type=pathlib.Path, required=True)
    parser.add_argument("--next-agent", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    agent = args.agent.resolve(strict=True)
    debug_agent = args.next_agent.resolve(strict=True)
    old_hash = digest(agent)
    new_hash = digest(debug_agent)
    if old_hash == new_hash:
        raise AssertionError("two distinct original Rust builds required")
    if subprocess.run(
        ["sc.exe", "query", NAME],
        capture_output=True, text=True, timeout=5,
    ).returncode == 0:
        raise AssertionError("preexisting SCM candidate must never be replaced")

    # Source and staged binary hashes are identical, but the staged executable
    # must live next to the current agent to satisfy the Rust bounded policy.
    staged_next = agent.parent / f"flowbridge-next-{os.getpid()}.exe"
    malformed = agent.parent / f"flowbridge-malformed-{os.getpid()}.exe"
    if staged_next.exists() or malformed.exists():
        raise AssertionError("refusing to overwrite any preexisting executable")
    installed = False
    installed_binary = agent
    installed_config: pathlib.Path | None = None
    try:
        shutil.copyfile(debug_agent, staged_next)
        malformed.write_bytes(b"not a Windows executable" * 32)
        if digest(staged_next) != new_hash:
            raise AssertionError("staged binary differs from independently built Rust debug exe")

        with tempfile.TemporaryDirectory(prefix="flowbridge-binary-scm-") as temp:
            root = pathlib.Path(temp)
            old_config, new_config = root / "before.json", root / "after.json"
            invalid_config = root / "invalid.json"
            old_port, next_port = port(), port()
            if old_port == next_port:
                raise AssertionError("two unique real SOCKS listener ports required")
            profile(old_config, f"127.0.0.1:{old_port}")
            profile(new_config, f"127.0.0.1:{next_port}")
            profile(invalid_config, "0.0.0.0:7777")
            try:
                agent_command(agent, "service-stage", str(old_config))
                installed, installed_config = True, old_config
                assert_command_contains(agent)

                # The critical negatives occur against the actual stopped
                # Windows SCM record; neither may mutate the binary command.
                agent_command(
                    agent, "service-binary-replace", str(old_config),
                    str(staged_next), str(new_config), "0" * 64, ok=False,
                )
                agent_command(
                    agent, "service-binary-replace", str(old_config),
                    str(malformed), str(new_config), digest(malformed), ok=False,
                )
                agent_command(
                    agent, "service-binary-replace", str(old_config),
                    str(staged_next), str(invalid_config), new_hash, ok=False,
                )
                assert_command_contains(agent)

                sc("start", NAME)
                original = await_engine(agent, True)
                if original["mode"] != "scm_explicit_socks_only":
                    raise AssertionError("running service is not strictly explicit SOCKS")
                socks_handshake(old_port)

                agent_command(
                    agent, "service-binary-replace", str(old_config),
                    str(staged_next), str(new_config), new_hash, ok=False,
                )
                assert_command_contains(agent)
                socks_handshake(old_port)

                sc("stop", NAME)
                wait_stopped()
                await_engine(agent, False)
                port_closed(old_port)

                upgraded = agent_command(
                    agent, "service-binary-replace", str(old_config),
                    str(staged_next), str(new_config), new_hash,
                )
                if (upgraded.get("action") != "binary_and_profile_replaced_stopped_only"
                    or upgraded.get("staged_executable_sha256") != new_hash
                    or upgraded.get("staged_x64_pe_verified") is not True
                    or upgraded.get("service_running_or_started") is not False):
                    raise AssertionError("Rust binary upgrade postcondition missing")
                installed_binary, installed_config = staged_next, new_config
                assert_command_contains(staged_next)
                agent_command(agent, "service-remove", str(old_config), ok=False)

                sc("start", NAME)
                updated = await_engine(agent, True)
                if updated["mode"] != "scm_explicit_socks_only":
                    raise AssertionError("new binary did not run a real SCM SOCKS service")
                socks_handshake(next_port)
                port_closed(old_port)

                sc("stop", NAME)
                wait_stopped()
                await_engine(agent, False)
                port_closed(next_port)
                reverted = agent_command(
                    staged_next, "service-binary-replace", str(new_config),
                    str(agent), str(old_config), old_hash,
                )
                if (reverted.get("staged_executable_sha256") != old_hash
                    or reverted.get("action") != "binary_and_profile_replaced_stopped_only"):
                    raise AssertionError("original Rust binary rollback was not verified")
                installed_binary, installed_config = agent, old_config
                assert_command_contains(agent)

                sc("start", NAME)
                restored = await_engine(agent, True)
                if restored["engine"]["running"] is not True:
                    raise AssertionError("rolled-back Rust SCM engine was not live")
                socks_handshake(old_port)
                port_closed(next_port)
                sc("stop", NAME)
                wait_stopped()
                await_engine(agent, False)
                port_closed(old_port)

                agent_command(agent, "service-remove", str(old_config))
                installed, installed_config = False, None
                ensure_absent()
                report = {
                    "passed": True,
                    "source_commit": run("git", "rev-parse", "HEAD").stdout.strip(),
                    "release_agent_sha256": old_hash,
                    "staged_debug_agent_sha256": new_hash,
                    "both_binary_variants_are_original_rust": True,
                    "staged_hash_verified_independently": True,
                    "rust_cng_sha256_and_pe32plus_verified": True,
                    "running_service_upgrade_denied": True,
                    "wrong_digest_and_non_pe_rejected": True,
                    "invalid_new_profile_rejected": True,
                    "scm_service_command_matches_expected_binary": True,
                    "actual_stopped_binary_switch": True,
                    "original_binary_restored_after_reverse_switch": True,
                    "real_scm_socks5_handshake_old_new_and_rollback": True,
                    "no_implicit_driver_install_or_service_autostart": True,
                    "temporary_scm_service_removed": True,
                    "installer_acl_or_crash_atomicity_accepted": False,
                    "driver_capture_active": False,
                    "native_packet_owner_proved": False,
                    "protected_redirect_available": False,
                    "dns_leak_free": False,
                    "win10_11_acceptance": False,
                    "release_accepted": False,
                }
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
                print(json.dumps(report))
            finally:
                if installed and installed_config is not None:
                    # Never delete or forcibly repoint an unrecognized SCM
                    # entry. Stop this exact CI candidate and remove only its
                    # last independently verified binary + profile tuple.
                    subprocess.run(
                        ["sc.exe", "stop", NAME],
                        capture_output=True, text=True, timeout=7, check=False,
                    )
                    wait_stopped()
                    agent_command(installed_binary, "service-remove", str(installed_config))
                    ensure_absent()
    finally:
        # These two paths were previously verified to be absent. They must
        # not survive after our temporary on-demand SCM record is gone.
        if not installed:
            staged_next.unlink(missing_ok=True)
            malformed.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
