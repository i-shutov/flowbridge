#!/usr/bin/env python3
"""R14 read-only Windows AppId namespace diagnostics, no driver/filter/network.

Uses only FwpmGetAppIdFromFileName0 / FwpmFreeMemory0, QueryDosDeviceW,
GetLongPathNameW, GetFinalPathNameByHandleW, GetFileInformationByHandle.
Never executes copied fixture EXEs; never reports raw paths, IDs or AppId.
This is NOT a WFP ALE callout, socket owner, G2 or no-DIRECT proof.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import sys

import appid_native_matrix as base
import handle_appid_probe as r10

MAX_PATH_BUFFER = 32768
CONSENT = 'WFP_APPID_NAMESPACE_READONLY'


class UnsupportedReadOnlyEnvironment(ValueError):
    pass


class WinFileTime(ctypes.Structure):
    _fields_ = [('low', ctypes.c_uint32), ('high', ctypes.c_uint32)]


class WinFileInfo(ctypes.Structure):
    _fields_ = [
        ('attributes', ctypes.c_uint32),
        ('created', WinFileTime),
        ('accessed', WinFileTime),
        ('modified', WinFileTime),
        ('volume_serial', ctypes.c_uint32),
        ('size_high', ctypes.c_uint32),
        ('size_low', ctypes.c_uint32),
        ('link_count', ctypes.c_uint32),
        ('file_index_high', ctypes.c_uint32),
        ('file_index_low', ctypes.c_uint32),
    ]


def ensure_windows() -> None:
    if os.name != 'nt':
        raise UnsupportedReadOnlyEnvironment('windows_x64_required')
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise UnsupportedReadOnlyEnvironment('windows_x64_python_required')


def kernel32():
    ensure_windows()
    return ctypes.WinDLL('kernel32.dll', winmode=0x00000800)


def query_dos_device(drive: str) -> str:
    """Only query a drive already supplied by the controlled local fixture."""
    ensure_windows()
    if not re.fullmatch(r'[A-Za-z]:', drive):
        raise UnsupportedReadOnlyEnvironment('invalid_local_volume')
    fn = kernel32().QueryDosDeviceW
    fn.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_uint32]
    fn.restype = ctypes.c_uint32
    buf = ctypes.create_unicode_buffer(MAX_PATH_BUFFER)
    count = fn(drive, buf, len(buf))
    if not 0 < count < len(buf) or not buf.value.casefold().startswith('\\device\\'):
        raise UnsupportedReadOnlyEnvironment('dos_device_mapping_unavailable')
    return buf.value


def get_long_path(file: Path) -> Path:
    """Windows expands short names; no filesystem mutation."""
    ensure_windows()
    base.require_local_windows_path(file)
    fn = kernel32().GetLongPathNameW
    fn.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_uint32]
    fn.restype = ctypes.c_uint32
    buf = ctypes.create_unicode_buffer(MAX_PATH_BUFFER)
    count = fn(str(file), buf, len(buf))
    if not 0 < count < len(buf):
        raise UnsupportedReadOnlyEnvironment('long_name_unavailable')
    base.require_local_windows_path(buf.value)
    return Path(buf.value)


def file_identity(file: Path) -> tuple[int, int, int]:
    """Comparison-only physical file identity from an opened kernel handle.

    Assumes local NTFS Windows-2025 fixture; never logs volume serial/file ID.
    This is not a process image section or a network flow identity.
    """
    ensure_windows()
    base.require_local_windows_path(file)
    import msvcrt
    func = kernel32().GetFileInformationByHandle
    func.argtypes = [wintypes.HANDLE, ctypes.POINTER(WinFileInfo)]
    func.restype = wintypes.BOOL
    with file.open('rb') as stream:
        handle = msvcrt.get_osfhandle(stream.fileno())
        info = WinFileInfo()
        if not func(handle, ctypes.byref(info)):
            raise UnsupportedReadOnlyEnvironment('file_identity_unavailable')
    return info.volume_serial, info.file_index_high, info.file_index_low


def lexical_device_path(original: Path, device_volume: str) -> str:
    """Construct a COMPARISON string, never a new OpenProcess/File handle."""
    text = str(original)
    base.require_local_windows_path(text)
    if not device_volume.casefold().startswith('\\device\\'):
        raise UnsupportedReadOnlyEnvironment('not_native_volume_name')
    return (device_volume.rstrip('\\') + text[2:].replace('/', '\\')).casefold()


def path_components(value: str | None) -> list[str]:
    if value is None:
        return []
    return [s for s in value.casefold().replace('/', '\\').split('\\') if s]


def private_shape_diagnostic(first: str | None, second: str | None) -> dict:
    """Report counts and 8.3 hints, never the actual components."""
    if first is None or second is None:
        return {'both_decoded': False, 'exact_equal': False,
                'same_prefix_volume_shape': False, 'component_mismatch_count': None,
                'short_name_divergence': None}
    a, b = path_components(first), path_components(second)
    mismatch = sum(x != y for x, y in zip(a, b)) + abs(len(a) - len(b))
    return {
        'both_decoded': True,
        'exact_equal': first == second,
        'same_prefix_volume_shape': a[:2] == b[:2],
        'component_mismatch_count': min(100, mismatch),
        'short_name_divergence': any(
            x != y and (bool(re.search(r'~[1-9][0-9]*', x)) or
                        bool(re.search(r'~[1-9][0-9]*', y)))
            for x, y in zip(a, b)
        ),
    }


def measure_one(file: Path) -> dict:
    """Comparisons are local to the same fixture, no arbitrary EXE selected."""
    ensure_windows()
    base.require_local_windows_path(file)
    observed_bytes = base.native_app_id(file)
    handle_dos, handle_nt = r10.resolved_handle_paths(file)
    handle_blob = base.native_app_id(handle_dos)
    long_dos = get_long_path(file)
    long_blob = base.native_app_id(long_dos)
    device_volume = query_dos_device(str(file)[:2])
    lexical = lexical_device_path(file, device_volume)
    observed = r10.normalized_device_path(observed_bytes)
    resolved = r10.normalized_device_path(handle_blob)
    expanded = r10.normalized_device_path(long_blob)
    handle = handle_nt.casefold()
    short_name = any(re.search(r'~[1-9][0-9]*', s)
                     for s in re.split(r'[\\/]', str(file)))
    return {
        'supplied_matches_handle_appid': observed_bytes == handle_blob,
        'expanded_matches_handle_appid': long_blob == handle_blob,
        'supplied_matches_expanded_appid': observed_bytes == long_blob,
        'supplied_matches_lexical_device_path': observed == lexical,
        'handle_matches_handle_nt_device_path': resolved == handle,
        'expanded_matches_handle_nt_device_path': expanded == handle,
        'long_dos_path_changed': str(long_dos).casefold() != str(file).casefold(),
        'contains_8dot3_short_component': bool(short_name),
        'input_vs_handle_structure': private_shape_diagnostic(observed, handle),
        'input_vs_expanded_structure': private_shape_diagnostic(observed, expanded),
    }


def inspect_fixtures(paths: dict[str, Path], skipped: dict[str, str]) -> list[dict]:
    baseline = paths['a']
    base_identity = file_identity(baseline)
    results = []
    for label, left, right in base.pairs(paths):
        a_id, b_id = base.native_app_id(left), base.native_app_id(right)
        rec = {
            'case': label,
            'same_physical_file_by_volume_file_index': file_identity(left) == file_identity(right),
            'same_supplied_appid': a_id == b_id,
            'left': measure_one(left),
            'right': measure_one(right),
        }
        if label == 'same_file' and (not rec['same_physical_file_by_volume_file_index']
                                      or not rec['same_supplied_appid']):
            raise UnsupportedReadOnlyEnvironment('same_file_control_failed')
        if label == 'hardlink' and not rec['same_physical_file_by_volume_file_index']:
            raise UnsupportedReadOnlyEnvironment('hardlink_fileid_control_failed')
        results.append(rec)
    if not results or results[0]['case'] != 'same_file' or results[1]['case'] != 'same_name_different_directory':
        raise UnsupportedReadOnlyEnvironment('incomplete_critical_matrix')
    return results


def run_native() -> dict:
    ensure_windows()
    source = base.system_directory() / 'where.exe'
    if not source.is_file():
        raise UnsupportedReadOnlyEnvironment('original_windows_exe_missing')
    temp_text = os.environ.get('TEMP') or os.environ.get('TMP')
    if not temp_text:
        raise UnsupportedReadOnlyEnvironment('local_temp_missing')
    base.require_local_windows_path(temp_text)
    root = Path(temp_text)
    if not root.is_dir():
        raise UnsupportedReadOnlyEnvironment('local_temp_missing')
    with tempfile.TemporaryDirectory(prefix='flowbridge-appid-r14-', dir=root) as text:
        tmp = Path(text)
        base.require_local_windows_path(tmp)
        paths, skipped = base.prepare_fixtures(tmp, source)
        results = inspect_fixtures(paths, skipped)
    if tmp.exists():
        raise UnsupportedReadOnlyEnvironment('fixture_cleanup_incomplete')
    return {
        'ok': True,
        'evidence_level': 'native_readonly_namespace_and_fileid_observation',
        'native_windows_called': True,
        'cases': results,
        'skipped_optional_aliases': skipped,
        'fixture_cleanup_complete': True,
        'wfp_driver_or_filter_modified': False,
        'kernel_owner_proved': False,
        'ndisrd_packetbound_proved': False,
        'system_no_direct_proved': False,
        'release_accepted': False,
    }


def main() -> int:
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument('--consent', required=True)
    opts = args.parse_args()
    if opts.consent != CONSENT:
        print(json.dumps({'ok': False, 'error': 'read_only_consent_missing',
                          'release_accepted': False}))
        return 2
    try:
        result = run_native()
    except UnsupportedReadOnlyEnvironment as error:
        result = {'ok': False, 'error': str(error), 'release_accepted': False}
    except Exception:
        result = {'ok': False, 'error': 'native_measurement_error',
                  'release_accepted': False}
    result['source_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    print(json.dumps(result, sort_keys=True))
    return 0 if result['ok'] else 2


if __name__ == '__main__':
    sys.exit(main())
