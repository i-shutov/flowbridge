"""Check a local Windows beta build host and prepare pinned portable NSIS."""

from __future__ import annotations

import hashlib
from io import BytesIO
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
from zipfile import BadZipFile, ZipFile, ZipInfo


NSIS_ZIP_SHA256 = 'ba63dffc4410ee89193e1cb5a41989991bd77c61068da17e3156d136b7b0b3d8'
NSIS_VERSION = 'v3.13'
NSIS_COMPILER = PurePosixPath('Bin/makensis.exe')
NSIS_ARCHIVE_SIZE_LIMIT = 10_000_000


class WindowsBuildPreflightError(ValueError):
    """A build prerequisite failed, with a safe diagnostic code."""


def _is_native_windows_x64() -> bool:
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL('kernel32.dll')
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.IsWow64Process2.argtypes = (
        wintypes.HANDLE, ctypes.POINTER(wintypes.USHORT), ctypes.POINTER(wintypes.USHORT),
    )
    kernel.IsWow64Process2.restype = wintypes.BOOL
    process = wintypes.USHORT()
    native = wintypes.USHORT()
    if not kernel.IsWow64Process2(
        kernel.GetCurrentProcess(), ctypes.byref(process), ctypes.byref(native),
    ):
        raise WindowsBuildPreflightError('windows_architecture_query_failed')
    image_file_machine_unknown = 0
    image_file_machine_amd64 = 0x8664
    return (process.value == image_file_machine_unknown
            and native.value == image_file_machine_amd64)


def detect_windows_build_host() -> dict[str, str | int]:
    if sys.platform != 'win32' or sys.maxsize <= 2**32:
        raise WindowsBuildPreflightError('build_requires_native_windows_client_x64')
    version = sys.getwindowsversion()
    if version.product_type != 1:  # VER_NT_WORKSTATION, not Server or a domain controller.
        raise WindowsBuildPreflightError('build_requires_windows_client')
    if (version.major, version.minor) != (10, 0) or not (
        version.build == 19045 or version.build >= 22000
    ):
        raise WindowsBuildPreflightError('build_requires_windows_10_22h2_or_windows_11')
    if not _is_native_windows_x64():
        raise WindowsBuildPreflightError('build_requires_native_windows_client_x64')
    return {
        'os': 'Windows 10' if version.build == 19045 else 'Windows 11',
        'build': version.build,
        'architecture': 'x64',
        'product_type': version.product_type,
    }


def _local_path(path: Path) -> Path:
    path = path.absolute()
    if os.name == 'nt':
        import ctypes
        from ctypes import wintypes

        get_drive_type = ctypes.WinDLL('kernel32.dll').GetDriveTypeW
        get_drive_type.argtypes = (wintypes.LPCWSTR,)
        get_drive_type.restype = wintypes.UINT
        if path.drive.startswith('\\\\') or get_drive_type(path.anchor) not in (2, 3, 5, 6):
            raise WindowsBuildPreflightError('nsis_paths_must_be_on_local_drives')
    return path


def _archive_members(archive: ZipFile) -> dict[PurePosixPath, ZipInfo]:
    files = {}
    seen = set()
    for entry in archive.infolist():
        name = entry.orig_filename.removesuffix('/')
        path = PurePosixPath(name)
        if (path.is_absolute() or path.as_posix() != name or not path.parts
                or '..' in path.parts or any(c in name for c in ('\\', ':', '\x00'))
                or any(part.endswith(('.', ' ')) for part in path.parts)):
            raise WindowsBuildPreflightError('nsis_archive_unsafe_path')
        if stat.S_ISLNK(entry.external_attr >> 16):
            raise WindowsBuildPreflightError('nsis_archive_symlink')
        folded = name.casefold()
        if folded in seen:
            raise WindowsBuildPreflightError('nsis_archive_duplicate_path')
        seen.add(folded)
        if not entry.is_dir():
            files[path] = entry
    return files


def _extract_pinned_nsis(archive_path: Path, directory: Path) -> tuple[Path, str]:
    if directory.exists() or directory.is_symlink():
        raise WindowsBuildPreflightError('nsis_toolchain_directory_must_be_new')
    try:
        with archive_path.open('rb') as stream:
            data = stream.read(NSIS_ARCHIVE_SIZE_LIMIT + 1)
    except OSError:
        raise WindowsBuildPreflightError('nsis_local_zip_unreadable') from None
    if (len(data) > NSIS_ARCHIVE_SIZE_LIMIT
            or hashlib.sha256(data).hexdigest() != NSIS_ZIP_SHA256):
        raise WindowsBuildPreflightError('nsis_zip_sha256_mismatch')

    try:
        with ZipFile(BytesIO(data)) as archive:
            members = _archive_members(archive)
            compilers = [path for path in members if path.parts[-2:] == NSIS_COMPILER.parts]
            if len(compilers) != 1:
                raise WindowsBuildPreflightError('nsis_archive_requires_one_bin_compiler')
            compiler = compilers[0]
            root = compiler.parent.parent
            stubs = root / 'Stubs'
            if ((root / 'Include/LogicLib.nsh') not in members
                    or (root / 'COPYING') not in members
                    or not any(stubs in path.parents for path in members)):
                raise WindowsBuildPreflightError('nsis_archive_missing_build_resources')

            directory.mkdir()
            for path, entry in members.items():
                destination = directory.joinpath(*path.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open('xb') as stream:
                    stream.write(archive.read(entry))
            compiler_hash = hashlib.sha256(archive.read(members[compiler])).hexdigest()
    except BadZipFile:
        raise WindowsBuildPreflightError('nsis_zip_invalid') from None
    except FileExistsError:
        raise WindowsBuildPreflightError('nsis_toolchain_directory_must_be_new') from None
    except OSError:
        raise WindowsBuildPreflightError('nsis_local_extraction_failed') from None
    return directory.joinpath(*root.parts), compiler_hash


def prepare_windows_build_environment(
    *, nsis_archive: Path, toolchain_dir: Path,
) -> tuple[dict[str, str], dict[str, object]]:
    """Return a child-only environment and path-redacted build provenance."""
    build_host = detect_windows_build_host()
    directory = _local_path(toolchain_dir)
    nsis_root, compiler_hash = _extract_pinned_nsis(_local_path(nsis_archive), directory)
    compiler = nsis_root.joinpath(*NSIS_COMPILER.parts)

    environment = os.environ.copy()
    environment['NSISDIR'] = str(nsis_root)
    # Python's Windows executable lookup must not prefer a current-directory
    # makensis.exe over the verified compiler at the front of the child PATH.
    environment['NoDefaultCurrentDirectoryInExePath'] = '1'
    environment['PATH'] = os.pathsep.join(
        item for item in (str(compiler.parent), environment.get('PATH')) if item
    )
    try:
        result = subprocess.run(
            [str(compiler), '/VERSION'], cwd=nsis_root, env=environment,
            check=True, capture_output=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        raise WindowsBuildPreflightError('nsis_compiler_version_check_failed') from None
    if result.stdout.strip() != NSIS_VERSION.encode('ascii'):
        raise WindowsBuildPreflightError('nsis_compiler_version_check_failed')

    return environment, {
        'build_host': build_host,
        'product_acceptance': {'target': 'Windows 10 Pro 22H2 x64', 'verified': False},
        'nsis': {
            'archive_sha256': NSIS_ZIP_SHA256,
            'compiler_sha256': compiler_hash,
            'compiler_version': NSIS_VERSION,
            'compiler_relative_path': NSIS_COMPILER.as_posix(),
            'distribution_relative_path': nsis_root.relative_to(directory).as_posix(),
        },
    }
