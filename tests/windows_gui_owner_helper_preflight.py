#!/usr/bin/env python3
"""Actual compiled FlowBridgeCapture CLI negative handshake tests on Windows.

No driver is required or loaded; each command fails BEFORE run() reaches the
driver path. A valid owner epoch is proven to reach the later missing-profile
error, while wrong/absent/malformed incarnation evidence is denied earlier.
NOT native WFP/NDISRD packet-to-owner authorization, nor release evidence.
"""
from __future__ import annotations
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid
from windows_owner_epoch import creation_filetime


def require(ok: bool, msg: str) -> None:
    if not ok:
        raise RuntimeError(msg)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "schema": "flowbridge-windows-gui-owner-helper-cli-v1",
        "status": "FAIL",
        "real_compiled_helper": False,
        "cases": {},
        "native_driver_loaded": False,
        "wfp_filters_changed": False,
        "g2_packet_origin_proved": False,
        "release_accepted": False,
    }
    error = None
    try:
        require(sys.platform == "win32" and ctypes.sizeof(ctypes.c_void_p) == 8, "native_windows_x64_only")
        binary = args.helper.resolve(strict=True)
        report["helper_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        epoch = creation_filetime(os.getpid())
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateEventW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p]
        kernel.CreateEventW.restype = ctypes.c_void_p
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.restype = ctypes.c_int
        event_name = "Local\\FlowBridgeCaptureStop-" + str(uuid.uuid4())
        event = kernel.CreateEventW(None, True, False, event_name)
        require(bool(event), "cannot_create_disposable_stop_event")
        try:
            with tempfile.TemporaryDirectory(prefix="FlowBridge GUI owner negative ") as work:
                nonexistent = str(Path(work) / "profile-never-created.json")
                require(not Path(nonexistent).exists(), "test_profile_not_isolated")
                base = [
                    str(binary), "--console", "--profile", nonexistent,
                    "--capture-app", str(Path(sys.executable).resolve()),
                    "--gui-owner", str(os.getpid()), "--gui-owner-epoch", str(epoch),
                    "--stop-event", event_name, "--profile-sha256", "0" * 64,
                ]
                cases = [
                    ("correct_epoch_reaches_profile_preflight", [], "Profile unavailable or exceeds 1 MiB"),
                    ("wrong_epoch_fails_before_profile", ["--gui-owner-epoch", str(epoch-1)],
                     "GUI owner PID was reused or creation time mismatched"),
                    ("missing_epoch_denied", ["--gui-owner-epoch", ""],
                     "Invalid GUI owner creation epoch"),
                    ("zero_epoch_denied", ["--gui-owner-epoch", "0"],
                     "Empty GUI owner creation epoch"),
                    ("malformed_epoch_denied", ["--gui-owner-epoch", "not-a-number"],
                     "Invalid GUI owner creation epoch"),
                    ("overflow_epoch_denied", ["--gui-owner-epoch", "9"*22],
                     "Invalid GUI owner creation epoch"),
                ]
                for name, replacement, diagnostic in cases:
                    command = base.copy()
                    if replacement:
                        at = command.index("--gui-owner-epoch")
                        command[at:at+2] = replacement
                    outcome = subprocess.run(
                        command, capture_output=True, text=True, timeout=12,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                    lines = (outcome.stdout + outcome.stderr)
                    require(outcome.returncode != 0 and diagnostic in lines and
                            '"event":"ready"' not in lines and
                            "Open signed WFP driver" not in lines,
                            "wrong_helper_rejection_or_driver_started:" + name)
                    report["cases"][name] = "PASS"
                # Remove a required field entirely, rather than supplying an
                # empty value: CLI must reject partial GUI ownership claims.
                command = base.copy()
                at = command.index("--gui-owner-epoch")
                del command[at:at+2]
                outcome = subprocess.run(command, capture_output=True, text=True,
                                         timeout=12, creationflags=subprocess.CREATE_NO_WINDOW)
                require(outcome.returncode != 0 and
                        "GUI owner PID, process creation epoch and stop event must be provided together"
                        in (outcome.stdout+outcome.stderr),
                        "missing_epoch_argument_not_rejected")
                report["cases"]["omitted_epoch_argument_denied"] = "PASS"
                report["real_compiled_helper"] = True
                report["status"] = "PASS_USERMODE_PROCESS_HANDSHAKE_ONLY"
        finally:
            kernel.CloseHandle(event)
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        error = str(exc)[:512]
        report["error_code"] = error
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0 if error is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
