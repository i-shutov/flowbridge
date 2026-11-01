#!/usr/bin/env python3
"""Real installed native Rust Win32 panel -> restricted IPC -> Rust SOCKS.

This exercises an actual GUI window, its Start/Refresh/Reload/Stop controls,
and a live loopback SOCKS5 BLOCK connection on disposable hosted Windows.
It does not touch NDISRD, enable protected routing or prove Win10/11 acceptance.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

from windows_capture_control import blocked_socks_connect, command, profile

BM_CLICK = 0x00F5
WM_CLOSE = 0x0010
WM_COMMAND = 0x0111
WM_GETTEXT = 0x000D
SMTO_ABORTIFHUNG = 0x0002
IDYES = 6
ID_PATH = 101
ID_START = 102
ID_REFRESH = 103
ID_RELOAD = 104
ID_STOP = 105
ID_STATUS = 106

user32 = ctypes.WinDLL("user32", use_last_error=True)
user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
user32.FindWindowW.restype = wintypes.HWND
user32.GetDlgItem.argtypes = [wintypes.HWND, ctypes.c_int]
user32.GetDlgItem.restype = wintypes.HWND
user32.SetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPCWSTR]
user32.SetWindowTextW.restype = wintypes.BOOL
# GetWindowTextW cannot read a live EDIT control in another process.
# WM_GETTEXT is a system message and is marshalled across Win32 processes.
user32.SendMessageTimeoutW.argtypes = [
    wintypes.HWND, ctypes.c_uint, ctypes.c_size_t, ctypes.c_size_t,
    ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(ctypes.c_size_t),
]
user32.SendMessageTimeoutW.restype = wintypes.BOOL
# Win32 WPARAM/LPARAM are pointer-sized even on 64-bit Windows. The ctypes
# wintypes aliases can be 32-bit C longs and silently truncate a child HWND.
# A truncated BN_CLICKED LPARAM is correctly REJECTED by the Rust UI's strict
# parent/child validation, leaving the Start action apparently untouched.
user32.PostMessageW.argtypes = [
    wintypes.HWND, ctypes.c_uint, ctypes.c_size_t, ctypes.c_ssize_t,
]
user32.PostMessageW.restype = wintypes.BOOL
user32.SendMessageW.argtypes = [
    wintypes.HWND, ctypes.c_uint, ctypes.c_size_t, ctypes.c_ssize_t,
]
user32.SendMessageW.restype = ctypes.c_ssize_t


def require(ok: bool, message: str) -> None:
    if not ok:
        raise RuntimeError(message)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wait(predicate, seconds: float, description: str):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.075)
    raise AssertionError("Timeout waiting for " + description)


def control(window: int, ident: int) -> int:
    found = user32.GetDlgItem(window, ident)
    require(bool(found), "Original Rust GUI missing native control " + str(ident))
    return found


def text_of(hwnd: int) -> str:
    # This tester is ANOTHER process. GetWindowTextW returns only the
    # cross-process caption/cache and cannot read changing EDIT text.
    # WM_GETTEXT is natively marshalled; timeout bounds a hung panel.
    buffer = ctypes.create_unicode_buffer(8192)
    copied = ctypes.c_size_t(0)
    sent = user32.SendMessageTimeoutW(
        hwnd, WM_GETTEXT, len(buffer), ctypes.addressof(buffer),
        SMTO_ABORTIFHUNG, 1500, ctypes.byref(copied),
    )
    require(bool(sent) and copied.value < len(buffer),
            "Cross-process WM_GETTEXT failed or status exceeds bounded buffer")
    return buffer.value


def click(hwnd: int) -> None:
    # A posted BM_CLICK can be ignored by a button on the noninteractive
    # hosted runner desktop. Synchronous SendMessage exercises the actual
    # button's Win32 procedure; UI callback starts an asynchronous worker.
    user32.SendMessageW(hwnd, BM_CLICK, 0, 0)


def notify_button(window: int, ident: int) -> None:
    """Queue the same native WM_COMMAND/BN_CLICKED sent by a real button.

    No mouse, keyboard, synthetic owner, NDISRD or privilege assumption:
    this exercises the real UI handler, child-HWND provenance, worker
    serialization and downstream IPC. On a noninteractive hosted desktop,
    BM_CLICK may be ignored; cross-process SendMessageTimeout can also run
    during WM_CREATE. A posted parent notification preserves queue ordering
    while the full-width HWND is validated by the installed Rust panel.
    """
    button = control(window, ident)
    require(bool(user32.PostMessageW(window, WM_COMMAND, ident, button)),
            "Cannot queue pointer-size native Win32 control notification")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--panel", type=Path, required=True)
    parser.add_argument("--agent", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform == "win32" and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("RUNNER_OS") == "Windows",
            "Native GUI acceptance is restricted to disposable hosted Windows")
    panel = args.panel.resolve(strict=True)
    agent = args.agent.resolve(strict=True)
    require(panel.parent == agent.parent and panel.name.lower() == "flowbridge-panel.exe"
            and agent.name.lower() == "flowbridge-agent.exe",
            "Only actually installed sibling Rust panel and agent are accepted")
    require(not panel.is_symlink() and not agent.is_symlink(),
            "Installed Rust executables may not be symlinks")
    report = {
        "kind": "actual_installed_rust_win32_operator_to_restricted_ipc_real_socks",
        "passed": False,
        "panel_sha256": sha(panel), "agent_sha256": sha(agent),
        "actual_win32_window_and_controls": False,
        "gui_start_same_user_rust_agent": False,
        "gui_queued_refresh_after_start": False,
        "gui_status_live_socks": False,
        "actual_socks_block_denied": False,
        "gui_reload_atomic_configuration": False,
        "gui_stop_closed_listener": False,
        "gui_closed_cleanly": False,
        "real_openssh_in_this_test": False,
        "ndisrd_activated": False, "native_packet_pid_proof": False,
        "protected_fail_closed": False, "dns_leak_free": False,
        "win10_11_acceptance": False, "release_accepted": False,
        "physical_button_input_accepted": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="flowbridge-native-panel-",
                                         dir=os.environ["RUNNER_TEMP"]) as temporary:
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            profile_path = Path(temporary) / "gui-explicit-socks-profile.json"
            data = profile(port)
            profile_path.write_text(json.dumps(data), encoding="utf-8")
            # Do not change any live kernel driver or firewall mode.
            command(agent, "status", success=False)
            require(not user32.FindWindowW("FlowBridgeRustPanelV1", None),
                    "Another panel already exists; refusing to interfere")
            process = subprocess.Popen(
                [str(panel)], stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            hwnd = wait(lambda: user32.FindWindowW("FlowBridgeRustPanelV1", None)
                        if process.poll() is None else 0,
                        10, "real Windows Rust panel window")
            status = control(hwnd, ID_STATUS)
            path_edit = control(hwnd, ID_PATH)
            for ident in (ID_START, ID_REFRESH, ID_RELOAD, ID_STOP):
                control(hwnd, ident)
            report["actual_win32_window_and_controls"] = True
            require(bool(user32.SetWindowTextW(path_edit, str(profile_path))),
                    "Win32 JSON profile entry rejected")
            require(text_of(path_edit) == str(profile_path),
                    "Cross-process profile edit did not retain the exact JSON path")
            # Intentionally race the first WM_CREATE status worker. A real
            # user can click Start immediately; no click may be discarded.
            notify_button(hwnd, ID_START)
            notify_button(hwnd, ID_REFRESH)
            try:
                wait(lambda: "SOCKS engine: RUNNING" in text_of(status),
                     15, "panel -> agent start and live status")
            except AssertionError as original:
                # Safe public status only, never reveal config path/key.
                observed = text_of(status)
                state = "running" if observed.startswith("RUST SOCKS") else "not-running"
                # Do not expose profile/SSH identity. Differentiate a failed
                # Win32 action from an incorrect status-control test oracle.
                probe = subprocess.run(
                    [str(agent), "control", "status"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=5, check=False,
                )
                raise AssertionError(
                    f"GUI start failed; panel_status_class={state}; "
                    f"agent_pipe_reachable={probe.returncode == 0}; "
                    f"panel_alive={process.poll() is None}; "
                    f"panel_status_excerpt={observed[:280]!r}"
                ) from original
            report["gui_start_same_user_rust_agent"] = True
            report["gui_queued_refresh_after_start"] = True
            state = command(agent, "status")
            require(state["engine"]["running"] is True and state["engine"]["listen"] ==
                    f"127.0.0.1:{port}" and state["driver_capture_active"] is False
                    and state["protected_redirect_available"] is False,
                    "GUI-launched agent did not own expected live loopback listener")
            notify_button(hwnd, ID_REFRESH)
            wait(lambda: f"127.0.0.1:{port}" in text_of(status),
                 6, "real live SOCKS status refresh")
            shown = text_of(status)
            require("Arbitrary application identity: NOT VERIFIED" in shown
                    and "Persistent protected fail-closed: NOT AVAILABLE" in shown
                    and "DNS/UDP/IPv6 leak-free: NOT PROVEN" in shown
                    and str(profile_path) not in shown,
                    "Panel incorrectly claimed protection or displayed private path")
            report["gui_status_live_socks"] = True
            with socket.socket() as target:
                target.bind(("127.0.0.1", 0))
                destination = target.getsockname()[1]
            blocked_socks_connect(port, destination)
            report["actual_socks_block_denied"] = True
            data["connect_timeout_ms"] = 1800
            profile_path.write_text(json.dumps(data), encoding="utf-8")
            notify_button(hwnd, ID_RELOAD)
            wait(lambda: "Config generation: 2" in text_of(status),
                 6, "atomic config reload through panel and pipe")
            require(command(agent, "status")["engine"]["generation"] == 2,
                    "Native GUI reload did not update live Rust engine")
            report["gui_reload_atomic_configuration"] = True

            # Post BM_CLICK rather than blocking on SendMessage. Then accept
            # the real native modal STOP confirmation through its Win32 YES.
            notify_button(hwnd, ID_STOP)
            dialog = wait(lambda: user32.FindWindowW(
                "#32770", "FlowBridge candidate - stop"), 6,
                "native explicit STOP confirmation")
            click(control(dialog, IDYES))
            wait(lambda: "Stop requested" in text_of(status),
                 8, "controlled stop acknowledgement")
            command(agent, "status", success=False)
            with socket.socket() as closed:
                closed.settimeout(0.5)
                require(closed.connect_ex(("127.0.0.1", port)) != 0,
                        "Agent listener survived GUI Stop")
            report["gui_stop_closed_listener"] = True
            require(bool(user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)),
                    "Cannot close Rust panel native window")
            require(process.wait(timeout=8) == 0, "GUI did not exit normally")
            report["gui_closed_cleanly"] = True
            report["passed"] = True
            print(json.dumps(report))
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        # Only the current test's same-user control pipe can be stopped.
        try:
            command(agent, "stop")
        except Exception:
            pass
        args.output.write_text(json.dumps(report, indent=2) + "\n",
                               encoding="utf-8")

def run_managed_ssh(panel: Path, agent: Path, cli: Path, ssh: Path,
                    identity: Path, known: Path, user: str, ssh_port: int,
                    echo_port: int, output: Path) -> dict:
    """Installed Win32 GUI -> queued Start -> real Rust agent -> authenticated
    OpenSSH Banner First -> SOCKS echo -> GUI reload/reject/confirmed stop.

    Shares the already-verified ephemeral *loopback* SSH fixture. No NDISRD
    or arbitrary application identity is involved.
    """
    import copy
    from ssh_real_integration import free_port, round_trip
    from windows_rust_managed_ssh_control import (
        control as pipe_command, make_config,
    )
    require(sys.platform == "win32" and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("FLOWBRIDGE_HOSTED_WINDOWS_SSH") == "1",
            "Installed GUI SSH vertical restricted to disposable hosted Windows")
    panel, agent, cli = (p.resolve(strict=True) for p in (panel, agent, cli))
    require(panel.parent == agent.parent == cli.parent
            and " " in str(panel) and all(p.is_file() and not p.is_symlink()
                                          for p in (panel, agent, cli)),
            "GUI / agent / Banner First must be original installed siblings")
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "kind": "installed_win32_panel_to_rust_ipc_real_banner_first_openssh_socks",
        "passed": False,
        "panel_sha256": sha(panel), "agent_sha256": sha(agent),
        "banner_cli_sha256": sha(cli),
        "gui_immediate_start_not_lost": False,
        "gui_real_authenticated_ssh_socks": False,
        "gui_reloaded_live_authenticated_ssh": False,
        "gui_denied_ssh_carrier_swap": False,
        "gui_confirmed_stop_closes_ssh_and_socks": False,
        "gui_did_not_display_identity_paths": False,
        "ndisrd_activated": False, "native_packet_pid_proof": False,
        "protected_fail_closed": False, "dns_leak_free": False,
        "win10_11_acceptance": False, "release_accepted": False,
        "physical_button_input_accepted": False,
    }
    process = None
    hwnd = None
    try:
        with tempfile.TemporaryDirectory(prefix="flowbridge-installed-gui-ssh-",
                                         dir=os.environ["RUNNER_TEMP"]) as temp:
            forbidden = {int(ssh_port), int(echo_port)}
            chosen = []
            for _ in range(30):
                candidate = free_port()
                if candidate not in forbidden:
                    chosen.append(candidate)
                    forbidden.add(candidate)
                if len(chosen) == 2:
                    break
            require(len(chosen) == 2, "Cannot reserve distinct GUI SSH fixture ports")
            ingress, socks = chosen
            config = make_config(ssh, identity, known, user, ssh_port,
                                 socks, ingress, banner_cli=cli)
            profile_path = Path(temp) / "explicit-managed-ssh.json"
            profile_path.write_text(json.dumps(config), encoding="utf-8")
            require(pipe_command(agent, "status", accept_failure=True) is None,
                    "Refusing to control unrelated same-user Rust agent")
            require(not user32.FindWindowW("FlowBridgeRustPanelV1", None),
                    "Refusing to reuse or close an unrelated Rust GUI window")
            process = subprocess.Popen(
                [str(panel)], stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            hwnd = wait(lambda: user32.FindWindowW("FlowBridgeRustPanelV1", None)
                        if process.poll() is None else 0,
                        12, "installed Rust GUI SSH window")
            status = control(hwnd, ID_STATUS)
            path_edit = control(hwnd, ID_PATH)
            require(bool(user32.SetWindowTextW(path_edit, str(profile_path))),
                    "Cannot select explicit same-user managed SSH profile")
            require(text_of(path_edit) == str(profile_path),
                    "Cross-process managed SSH JSON profile edit was not retained")
            # Queue Start immediately against WM_CREATE auto-Refresh, then
            # queue another Refresh; none may silently cancel the Start.
            notify_button(hwnd, ID_START)
            notify_button(hwnd, ID_REFRESH)
            next_refresh = [0.0]

            def gui_ready():
                state = pipe_command(agent, "status", accept_failure=True)
                if time.monotonic() >= next_refresh[0]:
                    notify_button(hwnd, ID_REFRESH)
                    next_refresh[0] = time.monotonic() + 0.6
                if (state and state.get("engine", {}).get("running") is True
                        and state.get("managed_ssh_gate_ready") is True
                        and state.get("managed_ssh", {}).get("state") == "ready"):
                    return state
                return None

            state = wait(gui_ready, 30, "GUI-launched real managed OpenSSH readiness")
            require(state["engine"]["listen"] == f"127.0.0.1:{ingress}"
                    and state["driver_capture_active"] is False
                    and state["protected_redirect_available"] is False,
                    "GUI started wrong listener or falsely advertised NDISRD")
            report["gui_immediate_start_not_lost"] = True
            round_trip(ingress, echo_port)
            notify_button(hwnd, ID_REFRESH)
            wait(lambda: "SSH: ready" in text_of(status), 6,
                 "GUI actual SSH state")
            shown = text_of(status)
            require(all(s not in shown for s in
                        (str(identity), str(known), str(profile_path)))
                    and "Persistent protected fail-closed: NOT AVAILABLE" in shown
                    and "DNS/UDP/IPv6 leak-free: NOT PROVEN" in shown,
                    "GUI exposed credential paths or claimed protection")
            report["gui_did_not_display_identity_paths"] = True
            report["gui_real_authenticated_ssh_socks"] = True

            config["engine"]["connect_timeout_ms"] = 2500
            profile_path.write_text(json.dumps(config), encoding="utf-8")
            notify_button(hwnd, ID_RELOAD)
            wait(lambda: "Config generation: 2" in text_of(status), 8,
                 "GUI live managed SSH profile reload")
            round_trip(ingress, echo_port)
            report["gui_reloaded_live_authenticated_ssh"] = True

            unsafe = copy.deepcopy(config)
            unsafe["ssh"]["port"] = ssh_port + 1
            profile_path.write_text(json.dumps(unsafe), encoding="utf-8")
            notify_button(hwnd, ID_RELOAD)
            wait(lambda: "OPERATION: reload" in text_of(status), 8,
                 "GUI rejection of SSH carrier swap")
            retained = pipe_command(agent, "status")
            require(retained["engine"]["generation"] == 2
                    and retained["managed_ssh_gate_ready"] is True,
                    "Denied GUI SSH carrier swap damaged live safe connection")
            round_trip(ingress, echo_port)
            report["gui_denied_ssh_carrier_swap"] = True
            profile_path.write_text(json.dumps(config), encoding="utf-8")

            notify_button(hwnd, ID_STOP)
            dialog = wait(lambda: user32.FindWindowW(
                "#32770", "FlowBridge candidate - stop"), 8,
                "real native GUI SSH stop confirmation")
            click(control(dialog, IDYES))
            wait(lambda: "Stop requested" in text_of(status), 12,
                 "GUI-confirmed managed SSH Stop")
            require(pipe_command(agent, "status", accept_failure=True) is None,
                    "Installed GUI Stop left Rust control pipe accepting requests")

            def closed(port: int) -> bool:
                with socket.socket() as test:
                    test.settimeout(0.4)
                    return test.connect_ex(("127.0.0.1", port)) != 0

            wait(lambda: closed(ingress) and closed(socks), 8,
                 "Rust SOCKS plus owned SSH listeners closed")
            report["gui_confirmed_stop_closes_ssh_and_socks"] = True
            require(bool(user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)),
                    "Cannot close installed Rust GUI")
            require(process.wait(timeout=8) == 0,
                    "Installed Win32 GUI did not exit cleanly")
            report["passed"] = all(report[k] is True for k in (
                "gui_immediate_start_not_lost",
                "gui_real_authenticated_ssh_socks",
                "gui_reloaded_live_authenticated_ssh",
                "gui_denied_ssh_carrier_swap",
                "gui_confirmed_stop_closes_ssh_and_socks",
                "gui_did_not_display_identity_paths"))
            return report
    finally:
        if hwnd and process is not None and process.poll() is None:
            user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        try:
            pipe_command(agent, "stop", accept_failure=True)
        except Exception:
            pass
        output.write_text(json.dumps(report, indent=2) + "\n",
                          encoding="utf-8")


if __name__ == "__main__":
    main()
