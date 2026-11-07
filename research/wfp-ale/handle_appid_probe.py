#!/usr/bin/env python3
"""Read-only Windows AppId spelling/origin experiment; no WFP filters/drivers.

Canonical here means HANDLE-RESOLVED DOS/NT NAME, not immutable file identity.
The EXE copies are never executed. Nothing reports raw paths or AppId values.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import tempfile
import sys

import appid_native_matrix as baseline


class ProbeError(ValueError):
    pass


def normalized_device_path(blob: bytes) -> str | None:
    """Diagnostic UTF-16LE spelling, not an authenticated file/process object."""
    if not blob or len(blob) % 2 or len(blob) > 65536:
        return None
    try:
        decoded = blob.decode('utf-16-le')
    except UnicodeError:
        return None
    if decoded.endswith('\x00'):
        decoded = decoded[:-1]
    if not decoded or '\x00' in decoded:
        return None
    return decoded.replace('/', '\\').casefold()


def resolved_handle_paths(file: Path) -> tuple[Path, str]:
    """Use a real open file handle, not a guessed drive->NT mapping.

    GetFinalPathNameByHandleW VOLUME_NAME_DOS / VOLUME_NAME_NT only.
    No BFE engine, WFP filter, driver, socket, symlink or registry mutation.
    """
    if os.name != 'nt':
        raise ProbeError('no_windows_native_executor')
    baseline.require_local_windows_path(file)
    if not file.is_file():
        raise ProbeError('missing_source_file')
    import msvcrt
    kernel = ctypes.WinDLL('kernel32.dll',winmode=0x00000800)
    resolve=kernel.GetFinalPathNameByHandleW
    resolve.argtypes=[wintypes.HANDLE,wintypes.LPWSTR,wintypes.DWORD,wintypes.DWORD]
    resolve.restype=wintypes.DWORD
    with file.open('rb') as stream:
        handle=msvcrt.get_osfhandle(stream.fileno())
        def read(flags: int) -> str:
            buf=ctypes.create_unicode_buffer(32768)
            n=resolve(handle,buf,len(buf),flags)
            if n<=0 or n>=len(buf):
                raise ProbeError('handle_resolved_name_unavailable')
            return buf.value
        dos=read(0)
        native=read(2)
    if not dos.startswith('\\\\?\\') or not native.casefold().startswith('\\device\\'):
        raise ProbeError('unexpected_handle_path_namespace')
    local=dos[4:]
    baseline.require_local_windows_path(local)
    return Path(local),native


def compare_path(path: Path) -> dict:
    """Check both ways of naming the *same open file* against Windows WFP."""
    supplied_id=baseline.native_app_id(path)
    resolved_dos,resolved_nt=resolved_handle_paths(path)
    resolved_id=baseline.native_app_id(resolved_dos)
    nt_from_handle=resolved_nt.casefold()
    return {
        'supplied_vs_resolved_appid_equal':supplied_id==resolved_id,
        'supplied_appid_is_handle_device_path':normalized_device_path(supplied_id)==nt_from_handle,
        'resolved_appid_is_handle_device_path':normalized_device_path(resolved_id)==nt_from_handle,
        'supplied_appid_utf16_device_path':(normalized_device_path(supplied_id) or '').startswith('\\device\\'),
        'resolved_appid_utf16_device_path':(normalized_device_path(resolved_id) or '').startswith('\\device\\'),
    }


def combine(paths: dict[str,Path]) -> list[dict]:
    answers=[]
    for name,a,b in baseline.pairs(paths):
        aid=baseline.native_app_id(a)
        bid=baseline.native_app_id(b)
        first=compare_path(a)
        second=compare_path(b)
        if name=='same_file' and aid!=bid:
            raise ProbeError('same_file_inconsistent')
        answers.append({'case':name,'supplied_pair_appid_equal':aid==bid,
                        'first':first,'second':second})
    return answers


def run() -> dict:
    if os.name!='nt':
        raise ProbeError('no_windows_native_executor')
    if ctypes.sizeof(ctypes.c_void_p)!=8:
        raise ProbeError('x64_python_required')
    src=baseline.system_directory()/'where.exe'
    if not src.is_file():
        raise ProbeError('system_fixture_not_found')
    temp_root=os.environ.get('TEMP') or os.environ.get('TMP')
    if not temp_root:
        raise ProbeError('local_temp_missing')
    baseline.require_local_windows_path(temp_root)
    temp_base=Path(temp_root)
    if not temp_base.is_dir():
        raise ProbeError('local_temp_missing')
    with tempfile.TemporaryDirectory(dir=temp_base,prefix='flowbridge-appid-r10-') as td:
        folder=Path(td)
        baseline.require_local_windows_path(folder)
        paths,skip=baseline.prepare_fixtures(folder,src)
        values=combine(paths)
    if folder.exists():
        raise ProbeError('temporary_cleanup_incomplete')
    return {'ok':True, 'evidence_level':'native_readonly_appid_path_diagnostic',
            'cases':values,'skips':skip,'temporary_files_removed':True,
            'kernel_pid_epoch_bound':False,'ndisrd_packetbound':False,
            'system_no_direct':False,'release_accepted':False}


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--consent',required=True)
    arguments=parser.parse_args()
    if arguments.consent!='WFP_APPID_READONLY':
        print(json.dumps({'ok':False,'error':'read_only_consent_required'}))
        return 2
    try:
        result=run()
    except ProbeError as e:
        result={'ok':False,'error':str(e),'release_accepted':False}
    except Exception:
        result={'ok':False,'error':'native_probe_failed','release_accepted':False}
    result['source_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    print(json.dumps(result,sort_keys=True))
    return 0 if result['ok'] else 2


if __name__=='__main__':
    sys.exit(main())
