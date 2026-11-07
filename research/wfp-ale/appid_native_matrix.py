#!/usr/bin/env python3
"""FlowBridge R8: read-only WFP AppId measurement with explicit evidence levels.

On Windows, --native-only reads the real WFP API without Rust or subprocesses.
The default mode STILL requires the Rust cross-check; there is no fallback.
Both modes keep kernel attribution and release acceptance false. Never executes the copied EXE fixtures.
Outside Windows, --selftest validates input preparation only (NO native PASS).
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
import re
from pathlib import Path, PureWindowsPath
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
RUST_SOURCE = ROOT / "appid_readonly.rs"


class FwpByteBlob(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.POINTER(ctypes.c_ubyte))]


def require_local_windows_path(file: Path | str) -> None:
    """Reject UNC/device/relative paths before any filesystem or WFP lookup.

    Preserve spelling: resolving a controlled alias would invalidate the test.
    This is not an EXE signature or canonical object-identity verifier.
    """
    text = str(file)
    path = PureWindowsPath(text)
    if (len(path.drive) != 2 or not path.drive[0].isascii()
            or not path.drive[0].isalpha() or path.drive[1] != ':'
            or path.root != '\\' or ':' in text[2:]
            or any(ord(c) < 32 for c in text)
            or any(c in text for c in '*?<>|"')
            or any(part in ('.', '..') for part in re.split(r'[\\/]', text[3:]))):
        raise RuntimeError('nonlocal_or_ambiguous_path')
    try:
        size = len(text.encode('utf-16-le')) // 2
    except UnicodeError:
        raise RuntimeError('invalid_windows_path_encoding') from None
    if not 3 < size < 32767:
        raise RuntimeError('invalid_windows_path_length')


def system_directory() -> Path:
    """OS-selected System32, not an environment-selected DLL or EXE path."""
    if os.name != 'nt':
        raise RuntimeError('no_windows_native_executor')
    kernel = ctypes.WinDLL('kernel32.dll', winmode=0x00000800)
    get_dir = kernel.GetSystemDirectoryW
    get_dir.argtypes = [wintypes.LPWSTR, ctypes.c_uint32]
    get_dir.restype = ctypes.c_uint32
    buf = ctypes.create_unicode_buffer(32768)
    count = get_dir(buf, len(buf))
    if not 0 < count < len(buf):
        raise RuntimeError('system_directory_unavailable')
    require_local_windows_path(buf.value)
    return Path(buf.value)


def native_app_id(file: Path) -> bytes:
    """Read Windows WFP identity of an existing file; no engine open or filter."""
    if os.name != "nt":
        raise RuntimeError("Windows required")
    require_local_windows_path(file)
    if not file.is_absolute() or not file.is_file():
        raise ValueError("absolute existing file required")
    dll = ctypes.WinDLL("Fwpuclnt.dll", winmode=0x00000800)
    get_id = dll.FwpmGetAppIdFromFileName0
    get_id.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.POINTER(FwpByteBlob))]
    get_id.restype = ctypes.c_uint32
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
    if any(type(data.get(k)) is not int or not 0 < data[k] <= 65536
           for k in ('a_bytes', 'b_bytes')):
        raise RuntimeError('rust_blob_lengths_invalid')
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



def collect_comparisons(paths: dict[str, Path], rust: Path | None,
                        progress: dict[str, int]) -> list[dict]:
    """Only an observation collector; a boolean here never proves ownership."""
    results = []
    for name, a, b in pairs(paths):
        left = native_app_id(a)
        progress['native_api_reads'] += 1
        right = native_app_id(b)
        progress['native_api_reads'] += 1
        match = left == right
        crosscheck = None
        if rust is not None:
            data = rust_comparison(rust, a, b)
            progress['rust_probe_executions'] += 1
            if (data['app_ids_equal'] != match
                    or data['a_bytes'] != len(left) or data['b_bytes'] != len(right)):
                raise RuntimeError('rust_ctypes_independent_ffi_disagree')
            crosscheck = True
        if name == 'same_file' and not match:
            raise RuntimeError('same_file_appid_inconsistent')
        results.append({'case': name, 'appid_equal': match,
                        'rust_and_ctypes_agree': crosscheck})
    return results


def run_native(native_only: bool = False,
               progress: dict[str, int] | None = None) -> dict:
    if os.name != 'nt':
        raise RuntimeError('no_windows_native_executor')
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise RuntimeError('windows_x64_python_required')
    if progress is None:
        progress = {'native_api_reads': 0, 'rust_probe_executions': 0}
    source = system_directory() / 'where.exe'
    if not source.is_file():
        raise RuntimeError('trusted_fixture_source_missing')
    temp_root_text = os.environ.get('TEMP') or os.environ.get('TMP')
    if not temp_root_text:
        raise RuntimeError('local_temp_directory_unavailable')
    # Reject UNC/relative temp roots BEFORE TemporaryDirectory creates anything.
    require_local_windows_path(temp_root_text)
    temp_root = Path(temp_root_text)
    if not temp_root.is_dir():
        raise RuntimeError('local_temp_directory_unavailable')
    # Do not make an implicit downgrade when rustc is missing. Only an explicit
    # --native-only request selects the narrower, single-reader measurement.
    with tempfile.TemporaryDirectory(prefix='flowbridge-appid-r8-', dir=temp_root) as d:
        temp = Path(d)
        require_local_windows_path(temp)
        paths, skipped = prepare_fixtures(temp, source)
        rust = None if native_only else compile_rust(temp)
        results = collect_comparisons(paths, rust, progress)
        # The native-only path has no subprocess dependency at all.
        netsh_results = ([] if native_only else
                         [netsh_readonly(paths[k]) for k in ('a', 'b')])
        report = {
            'ok': True,
            'evidence_level': 'native_api_only' if native_only else 'native_api_plus_rust_pairwise',
            'native_measurement_complete': True,
            'native_windows_wfp_appid_read': True,
            'native_api_reads': progress['native_api_reads'],
            'rust_probe_built_and_executed': not native_only,
            'rust_pairwise_crosscheck_complete': not native_only,
            'rust_crosscheck_kind': None if native_only else 'equality_and_lengths_only',
            'independent_native_acceptance': False,
            'comparisons': results, 'optional_aliases_skipped': skipped,
            'netsh_readonly': netsh_results,
            'kernel_process_epoch_proved': False,
            'driver_or_filter_changed': False,
            'transparent_packet_owner_proved': False,
            'no_direct_proved': False, 'release_accepted': False,
        }
    if temp.exists():
        raise RuntimeError('temporary_cleanup_incomplete')
    report['temporary_files_removed'] = True
    return report


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
        return {"ok": True, "evidence_level": "offline_preflight",
                "native_measurement_complete": False, "release_accepted": False,
                "offline_fixture_cases": len(matrix),
                "optional_aliases_skipped": skipped,
                "native_windows_wfp_appid_read": False,
                "rust_probe_built_and_executed": False,
                "kernel_process_epoch_proved": False,
                "driver_or_filter_changed": False}



SAFE_ERRORS = frozenset({
    'no_windows_native_executor', 'windows_x64_python_required',
    'rustc_unavailable', 'pinned_rust_probe_missing', 'trusted_fixture_source_missing',
    'rust_probe_contract_violation', 'rust_equality_missing', 'rust_blob_lengths_invalid',
    'rust_ctypes_independent_ffi_disagree', 'same_file_appid_inconsistent',
    'WFP_AppId_null', 'WFP_AppId_invalid_blob', 'nonlocal_or_ambiguous_path',
    'invalid_windows_path_encoding', 'invalid_windows_path_length',
    'system_directory_unavailable', 'temporary_cleanup_incomplete',
    'local_temp_directory_unavailable',
})


def safe_error_code(error: Exception) -> str:
    # Never expose an arbitrary exception string even when it is alphanumeric.
    code = str(error)
    if code in SAFE_ERRORS or re.fullmatch(
            r'(?:WFP_AppId_error_0x[0-9a-f]{8}|rust(?:c|_appid)_failed_exit_-?[0-9]+)', code):
        return code
    return 'experiment_execution_failed'


def source_fingerprints() -> dict[str, str]:
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (Path(__file__), RUST_SOURCE) if path.is_file()}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    choice = ap.add_mutually_exclusive_group()
    choice.add_argument('--selftest', action='store_true')
    choice.add_argument('--native-only', action='store_true',
                        help='Real Windows WFP API only; no Rust build, no native acceptance')
    args = ap.parse_args()
    progress = {'native_api_reads': 0, 'rust_probe_executions': 0}
    try:
        report = selftest() if args.selftest else run_native(args.native_only, progress)
    except Exception as exc:
        report = {
            'ok': False, 'blocker': safe_error_code(exc),
            'evidence_level': 'native_partial_failed' if progress['native_api_reads'] else 'not_run',
            'native_measurement_complete': False,
            'native_windows_wfp_appid_read': bool(progress['native_api_reads']),
            'native_api_reads': progress['native_api_reads'],
            'rust_probe_executions': progress['rust_probe_executions'],
            'rust_pairwise_crosscheck_complete': False,
            'independent_native_acceptance': False,
            'kernel_process_epoch_proved': False, 'transparent_packet_owner_proved': False,
            'no_direct_proved': False, 'release_accepted': False,
        }
    report['source_sha256'] = source_fingerprints()
    print(json.dumps(report, sort_keys=True))
    return 0 if report['ok'] else 2


if __name__ == '__main__':
    sys.exit(main())
