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
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetWindowTextW.restype = ctypes.c_int
user32.PostMessageW.argtypes = [wintypes.HWND, ctypes.c_uint, wintypes.WPARAM, wintypes.LPARAM]
user32.PostMessageW.restype = wintypes.BOOL


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
    buffer = ctypes.create_unicode_buffer(8192)
    size = user32.GetWindowTextW(hwnd, buffer, len(buffer))
    require(size >= 0, "Win32 text retrieval failed")
    return buffer.value


def click(hwnd: int) -> None:
    require(bool(user32.PostMessageW(hwnd, BM_CLICK, 0, 0)),
            "Cannot post native button action")


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
        "gui_status_live_socks": False,
        "actual_socks_block_denied": False,
        "gui_reload_atomic_configuration": False,
        "gui_stop_closed_listener": False,
        "gui_closed_cleanly": False,
        "real_openssh_in_this_test": False,
        "ndisrd_activated": False, "native_packet_pid_proof": False,
        "protected_fail_closed": False, "dns_leak_free": False,
        "win10_11_acceptance": False, "release_accepted": False,
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
            click(control(hwnd, ID_START))
            wait(lambda: "SOCKS engine: RUNNING" in text_of(status),
                 15, "panel -> agent start and live status")
            report["gui_start_same_user_rust_agent"] = True
            state = command(agent, "status")
            require(state["engine"]["running"] is True and state["engine"]["listen"] ==
                    f"127.0.0.1:{port}" and state["driver_capture_active"] is False
                    and state["protected_redirect_available"] is False,
                    "GUI-launched agent did not own expected live loopback listener")
            click(control(hwnd, ID_REFRESH))
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
            click(control(hwnd, ID_RELOAD))
            wait(lambda: "Config generation: 2" in text_of(status),
                 6, "atomic config reload through panel and pipe")
            require(command(agent, "status")["engine"]["generation"] == 2,
                    "Native GUI reload did not update live Rust engine")
            report["gui_reload_atomic_configuration"] = True

            # Post BM_CLICK rather than blocking on SendMessage. Then accept
            # the real native modal STOP confirmation through its Win32 YES.
            click(control(hwnd, ID_STOP))
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


if __name__ == "__main__":
    main()
