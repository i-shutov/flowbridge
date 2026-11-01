#!/usr/bin/env python3
"""REAL disposable Windows install -> original-Rust process -> uninstall vertical.

Proves only standalone per-user Rust SSH/SOCKS packaging, not a GUI, native
app redirection, Windows 10/11 driver, protected mode, DNS privacy or release.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from ssh_banner_gate import binary_fixture, interactive_kex_fixture, timeout_fixture


def require(ok: bool, why: str) -> None:
    if not ok:
        raise RuntimeError(why)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def hkcu_value(path: str, value: str) -> str | None:
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            return winreg.QueryValueEx(key, value)[0]
    except FileNotFoundError:
        return None


def scm_absent() -> bool:
    result = subprocess.run(["sc.exe", "query", "FlowBridgeRustCandidateCI"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=10, check=False)
    return result.returncode == 1060


def nsis_install(installer: Path, location: Path) -> subprocess.CompletedProcess:
    # NSIS requires /D as the unquoted final argument to its own command line.
    return subprocess.run(f'"{installer}" /S /D={location}', executable=str(installer),
                          stdin=subprocess.DEVNULL, capture_output=True,
                          timeout=45, check=False)


def main() -> None:
    require(sys.platform == "win32" and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_OS") == "Windows" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
            "Refusing installation outside disposable GitHub-hosted Windows")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--installer", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ssh", type=Path, required=True)
    parser.add_argument("--sshd", type=Path, required=True)
    parser.add_argument("--keygen", type=Path, required=True)
    args = parser.parse_args()
    for executable in ("ssh", "sshd", "keygen"):
        path = getattr(args, executable).resolve(strict=True)
        require(path.is_file(), "Missing explicitly verified Windows OpenSSH fixture")
        setattr(args, executable, path)
    evidence = json.loads(args.report.read_text(encoding="utf-8"))
    installer = args.installer.resolve(strict=True)
    candidate = args.candidate.resolve(strict=True)
    require(evidence.get("candidate_archive_sha256") == sha(candidate),
            "Candidate ZIP does not match exact installer builder input")
    require(evidence.get("kind") == "unsigned_user_owned_rust_ssh_socks_candidate_installer_NOT_RELEASE"
            and evidence.get("installer_sha256") == sha(installer)
            and evidence.get("passed") is True and evidence.get("signed") is False
            and evidence.get("release_accepted") is False
            and evidence.get("qa_fault_fixture") is False
            and evidence.get("qa_abort_stage") is None,
            "Installer provenance does not match exact Rust candidate")
    cfgkey = r"Software\FlowBridgeRustCandidate"
    uninstallkey = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\FlowBridgeRustCandidate"
    require(hkcu_value(cfgkey, "InstallDir") is None and
            hkcu_value(uninstallkey, "DisplayName") is None and scm_absent(),
            "Refusing to change pre-existing candidate installation or SCM service")

    result = {
        "kind": "installed_original_rust_ssh_socks_candidate_windows_server_hosted_only",
        "passed": False, "installer_sha256": sha(installer),
        "source_merge_sha": evidence["source_merge_sha"],
        "pr_head_sha": evidence["pr_head_sha"],
        "installed_hashes_match_manifest": False,
        "real_windows_ssh_banner_transport": False,
        "real_windows_pipe_socks_reload_stop": False,
        "installed_real_authenticated_banner_ssh_socks": False,
        "installed_native_rust_panel_operated_real_socks": False,
        "occupied_destination_rejected_without_mutation": False,
        "fault_injected_partial_copy_rolled_back": False,
        "fault_injected_written_uninstaller_rolled_back": False,
        "successful_real_install_after_two_fault_rollbacks": False,
        "qa_fault_installers_not_product_artifacts": False,
        "reinstall_refused_without_partial_mutation": False,
        "uninstaller_preserved_user_profile": False,
        "registry_removed": False,
        "scm_service_unmodified": False,
        "driver_installed_or_modified": False,
        "includes_gui": True, "gui_scope": "same_user_ssh_socks_only", "protected_fail_closed": False,
        "native_packet_pid_proof": False, "dns_leak_free": False,
        "win10_11_acceptance": False, "release_accepted": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="flowbridge-rust-install-",
                                          dir=os.environ["RUNNER_TEMP"]) as temporary:
            base = Path(temporary)
            # The directory selector must NEVER overwrite an existing file,
            # even if HKCU has no prior candidate registration.
            occupied = base / "Occupied Rust Candidate With Spaces"
            occupied.mkdir()
            marker = occupied / "flowbridge.exe"
            marker.write_bytes(b"UNRELATED USER FILE - NEVER OVERWRITE\n")
            personal = occupied / "my-profile.json"
            personal.write_bytes(b'{"preserve":true}\n')
            occupied_response = nsis_install(installer, occupied)
            require(occupied_response.returncode != 0
                    and marker.read_bytes() == b"UNRELATED USER FILE - NEVER OVERWRITE\n"
                    and personal.read_bytes() == b'{"preserve":true}\n'
                    and not (occupied / "Uninstall.exe").exists()
                    and hkcu_value(cfgkey, "InstallDir") is None
                    and hkcu_value(uninstallkey, "DisplayName") is None,
                    "NSIS overwrote an unregistered existing user directory")
            result["occupied_destination_rejected_without_mutation"] = True
            installed = base / "FlowBridge Rust Candidate With Spaces"

            # Two disposable QA-only installers contain the exact pinned Rust
            # payload and fail at different real NSIS mutation boundaries.
            # Neither fixture is an artifact, release or personal-machine test.
            safe_marker = base / "unrelated-user-file.txt"
            safe_marker.write_bytes(b"UNRELATED - DO NOT ALTER")
            for stage, flag in (("after-cli", "fault_injected_partial_copy_rolled_back"),
                                ("after-uninstaller",
                                 "fault_injected_written_uninstaller_rolled_back")):
                bad_setup = base / ("qa-fault-" + stage + ".exe")
                bad_report = base / ("qa-fault-" + stage + ".json")
                build = subprocess.run([
                    sys.executable, "tools/windows_rust_candidate_installer.py",
                    "--candidate", str(candidate), "--output", str(bad_setup),
                    "--report", str(bad_report), "--qa-abort-stage", stage,
                ], capture_output=True, text=True, timeout=150,
                    cwd=Path(__file__).resolve().parents[1], check=False)
                require(build.returncode == 0 and bad_setup.is_file() and
                        bad_report.is_file(), "QA fault installer build failed")
                provenance = json.loads(bad_report.read_text(encoding="utf-8"))
                require(provenance.get("kind") ==
                        "qa_fault_injected_rust_candidate_installer_NEVER_RELEASE"
                        and provenance.get("qa_fault_fixture") is True
                        and provenance.get("qa_abort_stage") == stage
                        and provenance.get("installer_sha256") == sha(bad_setup)
                        and provenance.get("candidate_archive_sha256") == sha(candidate)
                        and provenance.get("payload_sha256") == evidence["payload_sha256"]
                        and provenance.get("source_merge_sha") == evidence["source_merge_sha"]
                        and provenance.get("pr_head_sha") == evidence["pr_head_sha"],
                        "Fault-injected installer does not match pinned source/payload")
                refused_fault = nsis_install(bad_setup, installed)
                require(refused_fault.returncode ==
                        (46 if stage == "after-cli" else 47),
                        "Expected specific NSIS QA injected-abort code, "
                        "not an unrelated preflight refusal")
                remaining = ([p.name for p in installed.iterdir()]
                             if installed.exists() else [])
                require(not remaining and not installed.exists() and
                        hkcu_value(cfgkey, "InstallDir") is None and
                        hkcu_value(uninstallkey, "DisplayName") is None and
                        scm_absent() and
                        safe_marker.read_bytes() == b"UNRELATED - DO NOT ALTER",
                        "Fault-aborted NSIS left product files/registry or modified a user file")
                result[flag] = True
            result["qa_fault_installers_not_product_artifacts"] = True
            install = nsis_install(installer, installed)
            require(install.returncode == 0,
                    f"NSIS per-user candidate install failed (code={install.returncode})")
            require(hkcu_value(cfgkey, "InstallDir") == str(installed),
                    "Installed registry path does not match expected user directory")
            require(hkcu_value(uninstallkey, "InstallLocation") == str(installed),
                    "Installed uninstall key does not match directory")
            expected = evidence["payload_sha256"]
            require(set(expected) == {"flowbridge.exe", "flowbridge-agent.exe",
                                      "flowbridge-panel.exe", "README.md", "manifest.json", "LICENSE"},
                    "Unexpected product payload file set")
            for name, digest in expected.items():
                path = installed / name
                require(path.is_file() and sha(path) == digest,
                        f"Installed Rust payload SHA mismatch: {name}")
            require((installed / "Uninstall.exe").is_file(), "Uninstaller missing")
            # NTFS paths are case-insensitive: "FlowBridge.exe" is our
            # legitimate "flowbridge.exe", NOT the legacy GUI. Inspect the
            # entire installed file inventory instead of a case-alias check.
            installed_files = [p.name for p in installed.iterdir() if p.is_file()]
            expected_files = set(expected) | {"Uninstall.exe"}
            require(len(installed_files) == len(expected_files) and
                    {n.casefold() for n in installed_files} ==
                    {n.casefold() for n in expected_files},
                    "Unexpected installed file (legacy, vendor or incomplete package)")
            result["installed_hashes_match_manifest"] = True
            require(result["fault_injected_partial_copy_rolled_back"] and
                    result["fault_injected_written_uninstaller_rolled_back"],
                    "Installed product was not preceded by both fault rollbacks")
            result["successful_real_install_after_two_fault_rollbacks"] = True

            cli = installed / "flowbridge.exe"
            agent = installed / "flowbridge-agent.exe"
            for executable, verb in ((cli, "capabilities"), (agent, "status")):
                call = subprocess.run([str(executable), verb], capture_output=True,
                                      text=True, encoding="utf-8", timeout=10,
                                      check=False)
                require(call.returncode == 0 and isinstance(json.loads(call.stdout), dict),
                        f"Installed {executable.name} cannot run")

            # Use *installed* binary under a real Windows spaced path, not the
            # target/debug developer executable or a Python transport adapter.
            bin_report = binary_fixture(cli)
            require(bin_report.get("passed") is True and
                    interactive_kex_fixture(cli) is True and
                    timeout_fixture(cli) is True,
                    "Installed Rust Banner First binary/FIN/KEX transport failed")
            result["real_windows_ssh_banner_transport"] = True

            # True same-user Win32 restricted pipe, native IP Helper candidate,
            # SOCKS5 BLOCK, rejected direct/app reload, accepted reload, stop.
            control_report = base / "installed-control.json"
            control = subprocess.run(
                [sys.executable, "tests/windows_capture_control.py", "--agent", str(agent),
                 "--output", str(control_report)], capture_output=True,
                text=True, encoding="utf-8", timeout=90, check=False,
            )
            require(control.returncode == 0 and control_report.is_file(),
                    "Installed Rust IPC/SOCKS real socket lifecycle failed: " +
                    control.stdout[-500:] + control.stderr[-500:])
            lifecycle = json.loads(control_report.read_text(encoding="utf-8"))
            require(lifecycle.get("passed") is True and
                    lifecycle.get("agent_sha256") == expected["flowbridge-agent.exe"] and
                    lifecycle.get("stop_closed_listener") is True,
                    "Installed Rust process/sockets did not match archive or stop")
            result["real_windows_pipe_socks_reload_stop"] = True

            # Installed native Rust Win32 UI must start and control an actual
            # same-user Rust agent, and observe a genuine denied SOCKS5 socket.
            # Never interpret GUI status as protected native capture.
            gui_report = base / "installed-panel-test.json"
            gui_test = subprocess.run(
                [sys.executable, "tests/windows_rust_panel.py", "--panel",
                 str(installed / "flowbridge-panel.exe"), "--agent", str(agent),
                 "--output", str(gui_report)],
                capture_output=True, text=True, encoding="utf-8", timeout=95,
                check=False,
            )
            require(gui_test.returncode == 0 and gui_report.is_file(),
                    "Installed Rust Win32 panel/pipe/live SOCKS vertical failed: " +
                    gui_test.stdout[-500:] + gui_test.stderr[-500:])
            gui_data = json.loads(gui_report.read_text(encoding="utf-8"))
            require(gui_data.get("passed") is True and
                    gui_data.get("panel_sha256") == expected["flowbridge-panel.exe"] and
                    gui_data.get("agent_sha256") == expected["flowbridge-agent.exe"] and
                    all(gui_data.get(key) is True for key in (
                        "actual_win32_window_and_controls",
                        "gui_start_same_user_rust_agent",
                        "gui_status_live_socks",
                        "actual_socks_block_denied",
                        "gui_reload_atomic_configuration",
                        "gui_stop_closed_listener",
                        "gui_closed_cleanly")) and
                    all(gui_data.get(key) is False for key in (
                        "ndisrd_activated", "native_packet_pid_proof",
                        "protected_fail_closed", "dns_leak_free",
                        "win10_11_acceptance", "release_accepted")),
                    "Actual installed Rust panel failed acceptance or claimed protection")
            result["installed_native_rust_panel_operated_real_socks"] = True

            # The *installed* agent controls actual Microsoft-signed OpenSSH
            # through the *installed* Rust Banner First helper. Strict known
            # hosts, ephemeral keys, SOCKS relay and crash/rollback are real
            # Windows processes; no NDISRD driver, system SSH service or DNS
            # configuration is modified.
            from windows_installed_real_ssh import run as installed_ssh_run
            ssh_result = installed_ssh_run(
                agent, cli, args.ssh, args.sshd, args.keygen,
                args.output.parent / "installed-real-openssh.json")
            require(ssh_result["passed"] is True
                    and ssh_result["installed_rust_agent_sha256"] ==
                        expected["flowbridge-agent.exe"]
                    and ssh_result["installed_rust_banner_cli_sha256"] ==
                        expected["flowbridge.exe"]
                    and ssh_result["actual_installed_ssh_authentication"] is True
                    and ssh_result["no_direct_on_unready_ssh"] is True,
                    "Actually installed Banner First + managed SSH acceptance failed")
            result["installed_real_authenticated_banner_ssh_socks"] = True

            # Explicitly reject in-place reinstallation instead of silently
            # overwriting an installed binary, service image or user profile.
            refused = nsis_install(installer, base / "Different Install Directory")
            require(refused.returncode != 0 and
                    hkcu_value(cfgkey, "InstallDir") == str(installed) and
                    all(sha(installed / n) == h for n, h in expected.items()),
                    "NSIS accepted unsafe in-place or alternate upgrade")
            result["reinstall_refused_without_partial_mutation"] = True

            profile = installed / "personal-user-profile.json"
            profile.write_text('{"keep":true}\n', encoding="utf-8")
            uninstall = subprocess.run([str(installed / "Uninstall.exe"), "/S"],
                                       capture_output=True, timeout=45, check=False)
            require(uninstall.returncode == 0, "NSIS uninstall launcher failed")
            # NSIS self-copy execution is asynchronous: /S returns from the
            # first launcher before its temp uninstaller deletes its own EXE.
            # Observe *actual* file and registry removal, not process exit
            # alone, with a strict deadline (never waive leftovers).
            deadline = time.monotonic() + 20.0
            leftovers = []
            registry_remaining = True
            while True:
                leftovers = [n for n in (*expected, "Uninstall.exe")
                             if (installed / n).exists()]
                registry_remaining = (
                    hkcu_value(cfgkey, "InstallDir") is not None or
                    hkcu_value(uninstallkey, "DisplayName") is not None
                )
                if not leftovers and not registry_remaining:
                    break
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.15)
            require(not leftovers and not registry_remaining,
                    "NSIS uninstall did not finish within 20s: remaining files=" +
                    repr(leftovers) + ", registry_remaining=" + str(registry_remaining))
            require(profile.read_text() == '{"keep":true}\n',
                    "NSIS uninstaller removed user-created profile")
            result["uninstaller_preserved_user_profile"] = True
            result["registry_removed"] = True
            require(scm_absent(), "Rust SCM was installed by the package")
            result["scm_service_unmodified"] = True
            result["passed"] = True
            print(json.dumps(result))
    finally:
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
