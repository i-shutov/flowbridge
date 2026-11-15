#!/usr/bin/env python3
"""Actual Windows API GUI-epoch QA, plus three source-level mutation killers.

Runs a disposable child process and real GetProcessTimes/GetProcessId APIs on
GitHub-hosted Windows. Does not open/configure NDISRD, WFP or any driver.
Cannot satisfy G2 PacketBound or Windows 1.0 release acceptance.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HEADER = ROOT / "native/windows/gui_owner_epoch.hpp"
PROJECT = ROOT / "tests/windows_owner_epoch"
SCHEMA = "flowbridge-windows-owner-epoch-mutation-v1"

MUTANTS = (
    ("wrong_pid_ignored",
     "if (GetProcessId(owner) != expectedPid)",
     "if (GetProcessId(owner) == 0)", "pid", "pid_mismatch_not_rejected"),
    ("creation_epoch_ignored",
     "if (creationTime(owner) != expectedEpoch)",
     "if (creationTime(owner) == 0)", "epoch", "epoch_mismatch_not_rejected"),
    ("owner_death_ignored",
     "if (WaitForSingleObject(owner, 0) != WAIT_TIMEOUT)",
     "if (WaitForSingleObject(owner, 0) == WAIT_FAILED)", "exit", "exited_owner_not_rejected"),
)


def command(args: list[str], *, timeout: int = 90) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=timeout, check=False)


def require(ok: bool, message: str) -> None:
    if not ok:
        raise RuntimeError(message)


def exe(folder: Path) -> Path:
    return folder / "Release/FlowBridgeGuiOwnerEpochQA.exe"


def build(folder: Path, include: Path | None = None) -> Path:
    args = ["cmake", "-S", str(PROJECT), "-B", str(folder), "-A", "x64"]
    if include is not None:
        args.append("-DGUI_OWNER_EPOCH_HEADER_DIR=" + str(include.resolve()))
    configured = command(args)
    require(configured.returncode == 0, "MSVC configure failed: " + configured.stdout[-1500:] + configured.stderr[-1500:])
    compiled = command(["cmake", "--build", str(folder), "--config", "Release"], timeout=150)
    require(compiled.returncode == 0, "MSVC compile failed: " + compiled.stdout[-1500:] + compiled.stderr[-1500:])
    binary = exe(folder)
    require(binary.is_file(), "Native x64 verification binary missing")
    return binary


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    output = args.output.resolve()
    require(not output.exists(), "Choose a new evidence directory")
    output.mkdir(parents=True)
    report = {
        "schema": SCHEMA, "status": "FAIL", "actual_windows_process_api": False,
        "expected_mutants_rejected": len(MUTANTS), "mutants_rejected": 0,
        "driver_loaded": False, "wfp_changed": False,
        "g2_packet_bound_proved": False, "release_accepted": False,
    }
    code = 1
    try:
        require(sys.platform == "win32", "Windows native execution required")
        source = HEADER.read_text(encoding="utf-8")
        report["production_header_sha256"] = hashlib.sha256(source.encode()).hexdigest()
        actual = build(output / "native-build")
        result = command([str(actual)])
        (output / "actual-process.log").write_text(result.stdout + result.stderr, encoding="utf-8")
        require(result.returncode == 0, "Actual Windows process handle baseline failed")
        native = json.loads(result.stdout)
        require(native["status"] == "PASS_REAL_WIN32_PROCESS_HANDLE_TEST" and
                native["actual_os_creation_time_checked"] is True and
                native["wrong_pid_rejected"] is True and
                native["wrong_creation_epoch_rejected"] is True and
                native["missing_epoch_rejected"] is True and
                native["terminated_process_rejected"] is True and
                native["ndisrd_packet_origin_verified"] is False and
                native["g2_packet_bound_accepted"] is False and
                native["release_accepted"] is False,
                "Real Win32 evidence misstates process or security scope")
        report["actual_windows_process_api"] = True
        for name, anchor, substitute, selected, expected in MUTANTS:
            require(source.count(anchor) == 1, "Production mutation anchor missing: " + name)
            altered = source.replace(anchor, substitute)
            folder = output / "mutant" / name
            include = folder / "include"
            include.mkdir(parents=True)
            (include / "gui_owner_epoch.hpp").write_text(altered, encoding="utf-8")
            binary = build(folder / "build", include)
            failed = command([str(binary), "--case", selected], timeout=20)
            (output / ("mutation-" + name + ".log")).write_text(
                failed.stdout + failed.stderr, encoding="utf-8"
            )
            require(failed.returncode == 1 and expected in failed.stderr,
                    "Mutant was not rejected for the expected security failure: " + name)
            report["mutants_rejected"] += 1
        report["status"] = "PASS_REAL_WIN32_GUI_OWNER_ONLY"
        code = 0
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        report["error"] = str(error)[:1000]
    (output / "owner-epoch-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
