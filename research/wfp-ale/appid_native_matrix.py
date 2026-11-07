#!/usr/bin/env python3
"""FlowBridge R6: read-only WFP AppId matrix, no driver, filters or network.

On Windows, calls ONLY FwpmGetAppIdFromFileName0 / FwpmFreeMemory0,
compares to the independent Rust executable from appid_readonly.rs and
optionally netsh wfp show appid. Never executes the copied EXE fixtures.
Outside Windows, --selftest validates input preparation only (NO native PASS).
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
RUST_SOURCE = ROOT / "appid_readonly.rs"


class FwpByteBlob(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]


def native_app_id(file: Path) -> bytes:
    """Read Windows WFP identity of an existing file; no engine open or filter."""
    if os.name != "nt":
        raise RuntimeError("Windows required")
    if not file.is_absolute() or not file.is_file():
        raise ValueError("absolute existing file required")
    dll = ctypes.WinDLL("Fwpuclnt.dll")
    get_id = dll.FwpmGetAppIdFromFileName0
    get_id.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.POINTER(FwpByteBlob))]
    get_id.restype = wintypes.DWORD
    free = dll.FwpmFreeMemory0
    free.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    free.restype = None
    ptr = ctypes.POINTER(FwpByteBlob)()
    try:
        status = get_id(str(file), ctypes.byref(ptr))
        if status != 0:
            raise RuntimeError(f"WFP_AppId_error_0x{status:08x}")
        if not ptr:
            raise RuntimeError("WFP_AppId_null")
        blob = ptr.contents
        if not (0 < blob.size <= 65536) or not blob.data:
            raise RuntimeError("WFP_AppId_invalid_blob")
        return ctypes.string_at(blob.data, blob.size)
    finally:
        if ptr:
            raw = ctypes.cast(ptr, ctypes.c_void_p)
            free(ctypes.byref(raw))


def prepare_fixtures(root: Path, source: Path) -> tuple[dict[str, Path], dict[str, str]]:
    if not source.is_file():
        raise ValueError("source EXE must already exist")
    a_dir = root / "A"
    b_dir = root / "B"
    a_dir.mkdir(parents=True)
    b_dir.mkdir(parents=True)
    a, b = a_dir / "probe.exe", b_dir / "probe.exe"
    shutil.copyfile(source, a)
    shutil.copyfile(source, b)
    digest = lambda p: hashlib.sha256(p.read_bytes()).digest()
    if digest(source) != digest(a) or digest(a) != digest(b):
        raise RuntimeError("fixture copy altered binary bytes")
    paths: dict[str, Path] = {"a": a, "b": b}
    skip: dict[str, str] = {}
    hard = b_dir / "hardlink.exe"
    try:
        os.link(a, hard)
        paths["hardlink"] = hard
    except OSError:
        skip["hardlink"] = "link_not_permitted"
    alias = root / "directory_alias"
    try:
        alias.symlink_to(a_dir, target_is_directory=True)
        paths["symlink"] = alias / "probe.exe"
    except OSError:
        skip["symlink"] = "link_not_permitted"
    case_variant = Path(str(a).swapcase())
    if case_variant.is_file():
        paths["case_variant"] = case_variant
    else:
        skip["case_variant"] = "case_sensitive_or_unavailable"
    return paths, skip


def pairs(paths: dict[str, Path]) -> list[tuple[str, Path, Path]]:
    result = [("same_file", paths["a"], paths["a"]),
              ("same_name_different_directory", paths["a"], paths["b"])]
    for alias in ("hardlink", "symlink", "case_variant"):
        if alias in paths:
            result.append((alias, paths["a"], paths[alias]))
    return result


def compile_rust(temp: Path) -> Path:
    rustc = shutil.which("rustc")
    if not rustc:
        raise RuntimeError("rustc_unavailable")
    if not RUST_SOURCE.is_file():
        raise RuntimeError("pinned_rust_probe_missing")
    exe = temp / "appid_readonly.exe"
    result = subprocess.run(
        [rustc, "--edition=2021", "-Dwarnings", str(RUST_SOURCE), "-o", str(exe)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    if result.returncode != 0 or not exe.is_file():
        # Never emit raw diagnostic text, which could contain local paths.
        raise RuntimeError(f"rustc_failed_exit_{result.returncode}")
    return exe


def rust_comparison(exe: Path, a: Path, b: Path) -> dict:
    result = subprocess.run([str(exe), str(a), str(b)],
                            capture_output=True, text=True, timeout=30, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"rust_appid_failed_exit_{result.returncode}")
    data = json.loads(result.stdout)
    if data.get("read_only") is not True or data.get("kernel_owner_proved") is not False:
        raise RuntimeError("rust_probe_contract_violation")
    if not isinstance(data.get("app_ids_equal"), bool):
        raise RuntimeError("rust_equality_missing")
    return data


def netsh_readonly(file: Path) -> dict:
    netsh = shutil.which("netsh")
    if not netsh:
        return {"available": False}
    result = subprocess.run([netsh, "wfp", "show", "appid", f"file={file}"],
                            capture_output=True, text=True, timeout=20, check=False)
    # Raw output may contain full local paths: never log or retain it.
    return {"available": True, "successful": result.returncode == 0,
            "mentions_device_path": "\\device\\" in result.stdout.lower()}


def run_native() -> dict:
    if os.name != "nt":
        raise RuntimeError("no_windows_native_executor")
    windir = Path(os.environ.get("SystemRoot", ""))
    source = windir / "System32" / "where.exe"
    if not source.is_file():
        raise RuntimeError("trusted_fixture_source_missing")
    with tempfile.TemporaryDirectory(prefix="flowbridge-appid-r6-") as d:
        temp = Path(d)
        paths, skipped = prepare_fixtures(temp, source)
        rust = compile_rust(temp)
        results = []
        for name, a, b in pairs(paths):
            left, right = native_app_id(a), native_app_id(b)
            rust_result = rust_comparison(rust, a, b)
            match = left == right
            if (rust_result["app_ids_equal"] != match
                    or rust_result.get("a_bytes") != len(left)
                    or rust_result.get("b_bytes") != len(right)):
                raise RuntimeError("rust_ctypes_independent_ffi_disagree")
            if name == "same_file" and not match:
                raise RuntimeError("same_file_appid_inconsistent")
            results.append({"case": name, "appid_equal": match,
                            "rust_and_ctypes_agree": True})
        netsh_results = [netsh_readonly(paths[k]) for k in ("a", "b")]
        return {"ok": True, "native_windows_wfp_appid_read": True,
                "rust_probe_built_and_executed": True,
                "comparisons": results, "optional_aliases_skipped": skipped,
                "netsh_readonly": netsh_results,
                "kernel_process_epoch_proved": False,
                "driver_or_filter_changed": False,
                "transparent_packet_owner_proved": False,
                "no_direct_proved": False}


def selftest() -> dict:
    with tempfile.TemporaryDirectory(prefix="flowbridge-appid-r6-selftest-") as d:
        root = Path(d)
        sample = root / "fixture.exe"
        # Not a runnable program and never executed; only copy/link semantics.
        sample.write_bytes(b"MZ" + bytes(range(64)))
        fixture_root = root / "sandbox"
        paths, skipped = prepare_fixtures(fixture_root, sample)
        matrix = pairs(paths)
        assert len(matrix) >= 2
        assert paths["a"].name == paths["b"].name
        assert paths["a"].resolve() != paths["b"].resolve()
        assert paths["a"].read_bytes() == paths["b"].read_bytes()
        assert matrix[0][1] == matrix[0][2]
        assert all(x[1].is_absolute() and x[2].is_absolute() for x in matrix)
        if "hardlink" in paths:
            assert paths["a"].stat().st_ino == paths["hardlink"].stat().st_ino
        return {"ok": True, "offline_fixture_cases": len(matrix),
                "optional_aliases_skipped": skipped,
                "native_windows_wfp_appid_read": False,
                "rust_probe_built_and_executed": False,
                "kernel_process_epoch_proved": False,
                "driver_or_filter_changed": False}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    try:
        report = selftest() if args.selftest else run_native()
    except Exception as exc:
        # Controlled error identifier only; no local paths, IDs, credentials.
        reason = str(exc)
        if not reason.replace("_", "").replace("-", "").isalnum():
            reason = "experiment_execution_failed"
        report = {"ok": False, "blocker": reason,
                  "native_windows_wfp_appid_read": False, "kernel_process_epoch_proved": False}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    sys.exit(main())
