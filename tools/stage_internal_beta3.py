#!/usr/bin/env python3
"""Stage a PRIVATE, source-only FlowBridge 0.3.0-beta.3 checkout from pinned code.

Never pushes, uploads, tags, publishes, installs drivers or modifies the source repo.
Creates a standalone Git repository WITH NO REMOTES; optional explicit Windows-only
build makes an unsigned installer locally for authorized internal QA.
"""
from __future__ import annotations

import argparse
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tomllib
from zipfile import ZipFile, BadZipFile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import internal_windows_build_preflight as windows_build

PINNED_SOURCE = '44f1fc0eba5ac1552df94f083342e25a1a764937'
OLD = '0.3.0-beta.2'
NEW = '0.3.0-beta.3'
LOCAL_PACKAGE_NAMES = {
    'flowbridge-core', 'flowbridge-capture', 'flowbridge-net',
    'flowbridge-cli', 'flowbridge-ffi', 'flowbridge-runtime',
    'flowbridge-tunnel',
}
MODIFIED_FILES = (
    'Cargo.toml',
    'Cargo.lock',
    'packaging/explicit-beta.json',
    'packaging/windows/README-EXPLICIT-BETA.txt',
    'packaging/windows/build-explicit-beta.py',
    'tests/test_explicit_beta_candidate.py',
    'tests/test_explicit_beta_metadata.py',
    '.github/workflows/explicit-socks-beta-windows.yml',
    '.github/workflows/explicit-socks-beta-macos.yml',
)

class StagingError(ValueError):
    pass

def must(ok: bool, msg: str) -> None:
    if not ok:
        raise StagingError(msg)

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def git(root: Path, *args: str, capture: bool = True) -> str:
    result = subprocess.run(['git', '-C', str(root), *args], check=True,
                            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                            stderr=subprocess.PIPE, timeout=120)
    return result.stdout.decode('utf-8', 'strict').strip() if capture else ''

def index_exact_source(destination: Path, extracted: dict[str, tuple[bytes, int]]) -> None:
    # git add can normalize historical CRLF blobs in a fresh index and can
    # lose executable modes on Windows. Write the staged bytes and archive modes directly.
    paths = list(extracted)
    records = bytearray()
    # Batch paths to keep the Git command line short on Windows.
    for offset in range(0, len(paths), 32):
        batch = paths[offset:offset + 32]
        hashes = git(destination, 'hash-object', '-w', '--no-filters', '--', *batch)
        for path, blob in zip(batch, hashes.splitlines(), strict=True):
            mode = '100755' if extracted[path][1] & 0o100 else '100644'
            records.extend(f'{mode} {blob}\t{path}\0'.encode('utf-8'))
    subprocess.run(['git', '-C', str(destination), 'update-index', '-z', '--index-info'],
                   input=records, check=True, timeout=120)

def root_guard(root: Path) -> None:
    must((root / '.git').exists(), 'source_checkout_not_git')
    must(git(root, 'rev-parse', 'HEAD') == PINNED_SOURCE, 'source_sha_not_pinned')
    must(not git(root, 'status', '--porcelain', '--untracked-files=all'), 'source_worktree_dirty')
    must(git(root, 'config', '--get', 'user.name') != '', 'source_git_user_name_missing')
    must(git(root, 'config', '--get', 'user.email') != '', 'source_git_user_email_missing')

def change_once(source: str, old: str, new: str, label: str) -> str:
    must(source.count(old) == 1, f'{label}_expected_one_version_reference')
    return source.replace(old, new, 1)

def version_rewrites(files: dict[str, bytes]) -> dict[str, bytes]:
    """Pure audited rewrite: no runtime/source build or dependency version changes."""
    must(all(p in files for p in MODIFIED_FILES), 'required_version_sources_missing')
    out = dict(files)
    def text(rel: str) -> str:
        return files[rel].decode('utf-8', 'strict')
    def put(rel: str, value: str) -> None:
        out[rel] = value.encode('utf-8')

    cargo = text('Cargo.toml')
    must(tomllib.loads(cargo)['workspace']['package']['version'] == OLD,
         'cargo_workspace_version_changed')
    put('Cargo.toml', change_once(cargo, f'version = "{OLD}"',
                                  f'version = "{NEW}"', 'cargo'))

    lock = text('Cargo.lock')
    seen: set[str] = set()
    blocks = re.split(r'(?=^\[\[package\]\]\s*$)', lock, flags=re.M)
    for i, block in enumerate(blocks):
        if not block.startswith('[[package]]'):
            continue
        match = re.search(r'^name = "([^"]+)"\s*$', block, re.M)
        must(match is not None, 'cargo_lock_package_name_missing')
        name = match.group(1)
        if name in LOCAL_PACKAGE_NAMES:
            must(name not in seen, 'duplicate_local_cargo_package')
            seen.add(name)
            blocks[i] = change_once(block, f'version = "{OLD}"',
                                    f'version = "{NEW}"', f'lock_{name}')
    must(seen == LOCAL_PACKAGE_NAMES, 'cargo_lock_local_package_set_mismatch')
    newlock = ''.join(blocks)
    before_pkgs = {p['name']: p for p in tomllib.loads(lock)['package']}
    after_pkgs = {p['name']: p for p in tomllib.loads(newlock)['package']}
    for name, prior in before_pkgs.items():
        current = after_pkgs[name]
        expect = {**prior, 'version': NEW} if name in LOCAL_PACKAGE_NAMES else prior
        must(expect == current, 'cargo_lock_unexpected_dependency_change')
    put('Cargo.lock', newlock)

    rel = 'packaging/explicit-beta.json'
    contract = json.loads(text(rel))
    must(contract['version'] == OLD and contract['release_approved'] is False,
         'contract_release_or_version_mismatch')
    updates = {
        'version': NEW, 'windows_file_version': '0.3.0.3',
        'macos_bundle_version': '3.0.3',
        'windows_installer': f'FlowBridge-{NEW}-windows-x64-setup.exe',
        'macos_installer': f'FlowBridge-{NEW}-macOS-universal-explicit-beta.pkg',
    }
    for key, value in updates.items():
        must(key in contract, f'missing_contract_{key}')
        contract[key] = value
    must(contract['windows_namespace'] == 'FlowBridgeExplicitBeta' and
         contract['release_approved'] is False, 'contract_scope_promoted')
    out[rel] = (json.dumps(contract, ensure_ascii=False, indent=2) + '\n').encode()

    rel = 'packaging/windows/README-EXPLICIT-BETA.txt'
    put(rel, change_once(text(rel), f'Candidate version: {OLD}',
                         f'Candidate version: {NEW}', 'readme'))
    rel = 'packaging/windows/build-explicit-beta.py'
    put(rel, change_once(text(rel), f'production v{OLD} release',
                         f'production v{NEW} release', 'builder_doc'))
    rel = 'tests/test_explicit_beta_candidate.py'
    source = text(rel)
    for older, newer in ((f'VERSION = "{OLD}"', f'VERSION = "{NEW}"'),
                         (f'self.f.mac["candidate"] = "{NEW}"',
                          'self.f.mac["candidate"] = "0.0.0-beta.0"'),
                         ('"windows_file_version": "0.3.0.2"',
                          '"windows_file_version": "0.3.0.3"'),
                         ('"macos_bundle_version": "3.0.2"',
                          '"macos_bundle_version": "3.0.3"')):
        source = change_once(source, older, newer, 'candidate_test')
    put(rel, source)
    rel = 'tests/test_explicit_beta_metadata.py'
    put(rel, change_once(text(rel), f'replace(\'version = "{OLD}"\'',
                         f'replace(\'version = "{NEW}"\'', 'metadata_test'))
    for rel in ('.github/workflows/explicit-socks-beta-windows.yml',
                '.github/workflows/explicit-socks-beta-macos.yml'):
        source = text(rel)
        must(source.count(OLD) >= 1, 'workflow_version_missing')
        put(rel, source.replace(OLD, NEW))

    for rel in MODIFIED_FILES:
        must(out[rel] != files[rel], 'expected_version_file_unchanged')
    must(tomllib.loads(out['Cargo.toml'].decode())['workspace']['package']['version'] == NEW,
         'post_stage_workspace_invalid')
    must(json.loads(out['packaging/explicit-beta.json'])['release_approved'] is False,
         'post_stage_release_approved')
    return out

def safe_archive_files(blob: bytes) -> dict[str, tuple[bytes, int]]:
    files: dict[str, tuple[bytes, int]] = {}
    try:
        with ZipFile(BytesIO(blob)) as archive:
            infos = archive.infolist()
            must(0 < len(infos) <= 3000 and sum(x.file_size for x in infos) < 150_000_000,
                 'source_archive_limits')
            names = set()
            for info in infos:
                raw = info.orig_filename
                if info.is_dir():
                    continue
                pure = PurePosixPath(raw)
                must(raw == pure.as_posix() and not raw.startswith(('/', './'))
                     and '..' not in pure.parts and '\\' not in raw and ':' not in pure.parts[0],
                     'unsafe_source_archive_path')
                must(((info.external_attr >> 16) & 0o170000) != 0o120000,
                     'symlink_in_source_archive')
                must(raw.casefold() not in names, 'source_casefold_collision')
                names.add(raw.casefold())
                files[raw] = archive.read(info), (info.external_attr >> 16) & 0o777
            must(archive.testzip() is None, 'source_archive_crc')
    except (BadZipFile, OSError) as exc:
        raise StagingError('source_archive_invalid') from exc
    return files

def stage(source: Path, destination: Path, *, build: bool = False,
          nsis_archive: Path | None = None) -> dict:
    source = source.resolve(strict=True)
    destination = destination.absolute()
    must(not destination.exists() and destination != source and source not in destination.parents,
         'destination_must_be_new_outside_source')
    if build:
        try:
            windows_build.detect_windows_build_host()
        except windows_build.WindowsBuildPreflightError as exc:
            raise StagingError(str(exc)) from None
        must(nsis_archive is not None, 'build_requires_explicit_pinned_nsis_zip')
        must(shutil.which('cargo') and shutil.which('cmake') and shutil.which('python'),
             'build_prerequisites_missing')
    root_guard(source)
    archive = subprocess.check_output(['git', '-C', str(source), 'archive',
                                       '--format=zip', 'HEAD'], timeout=120)
    extracted = safe_archive_files(archive)
    needed = {k: extracted[k][0] for k in MODIFIED_FILES if k in extracted}
    changed = version_rewrites(needed)
    build_environment = None
    build_provenance = None
    if build:
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            build_environment, build_provenance = windows_build.prepare_windows_build_environment(
                nsis_archive=nsis_archive,
                toolchain_dir=destination.parent / (destination.name + '-nsis-toolchain'),
            )
        except windows_build.WindowsBuildPreflightError as exc:
            raise StagingError(str(exc)) from None
    destination.mkdir(parents=True)
    try:
        for rel, (data, mode) in extracted.items():
            target = destination / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(changed[rel] if rel in changed else data)
            if os.name != 'nt' and mode:
                target.chmod(mode)
        # No Git remote: accidental pushes cannot upload this closed product.
        subprocess.run(['git', '-C', str(destination), 'init', '-q'],
                       check=True, timeout=30)
        index_exact_source(destination, extracted)
        author = git(source, 'config', '--get', 'user.name')
        email = git(source, 'config', '--get', 'user.email')
        subprocess.run(['git', '-C', str(destination), '-c', f'user.name={author}',
                        '-c', f'user.email={email}', '-c', 'commit.gpgsign=false',
                        'commit', '-q', '-m',
                        'chore: prepare private FlowBridge 0.3.0-beta.3 source'],
                       check=True, timeout=120)
        must(not git(destination, 'remote'), 'staging_repository_has_remote')
        local_sha = git(destination, 'rev-parse', 'HEAD')
        local_tree = git(destination, 'rev-parse', 'HEAD^{tree}')
        status = 'PRIVATE_SOURCE_ONLY_READY_NOT_BUILT'
        installer = None
        if build:
            subprocess.run([sys.executable, 'tools/explicit_beta_metadata.py', 'check'],
                           cwd=destination, check=True, timeout=90)
            subprocess.run([sys.executable, 'packaging/windows/build-explicit-beta.py'],
                           cwd=destination, check=True, timeout=2400, env=build_environment)
            installer = destination / 'artifacts' / f'FlowBridge-{NEW}-windows-x64-setup.exe'
            report = json.loads(
                (destination / 'build/verification/explicit-beta-package.json').read_text())
            must(installer.is_file() and report['source_sha'] == local_sha and
                 report['installer_sha256'] == sha(installer.read_bytes()) and
                 report['explicit_socks_only'] is True and
                 report['driver_included'] is False and report['signed'] is False and
                 report['publisher_release_approved'] is False,
                 'new_installer_provenance_or_scope_failed')
            status = 'PRIVATE_LOCAL_INSTALLER_BUILT_QA_NOT_ACCEPTED'
        result = {
            'schema': 'flowbridge-internal-beta3-private-staging-v1',
            'status': status, 'original_verified_source_sha': PINNED_SOURCE,
            'original_release': OLD, 'new_version': NEW,
            'new_private_git_commit': local_sha, 'new_private_git_tree': local_tree,
            'standalone_git_repository_has_remote': False,
            'modified_source_files': list(MODIFIED_FILES),
            'installer_sha256': sha(installer.read_bytes()) if installer else None,
            'installer_built': bool(installer),
            'build_provenance': build_provenance,
            'product_acceptance_target': 'Windows 10 Pro 22H2 x64',
            'installer_installed': False, 'driver_built_or_installed': False,
            'new_win10_owner_qa_accepted': False,
            'independent_a5_a6_security_accepted': False,
            'a7_internal_deployment_approved': False,
            'public_release_or_upload_performed': False,
        }
        (destination.parent / (destination.name + '-CHECKPOINT.json')).write_text(
            json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        return result
    except BaseException:
        # Do not destroy a partially staged private source/build after failure;
        # retain for owner review and explicit, safe cleanup.
        raise

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--out-dir', type=Path, required=True)
    parser.add_argument('--build-windows', action='store_true')
    parser.add_argument('--nsis-archive', type=Path,
                        help='Local official NSIS 3.13 ZIP; mandatory for --build-windows')
    args = parser.parse_args()
    try:
        result = stage(args.source, args.out_dir, build=args.build_windows,
                       nsis_archive=args.nsis_archive)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (StagingError, subprocess.CalledProcessError, OSError, ValueError) as exc:
        print('INTERNAL_BETA3_STAGING_BLOCKED', type(exc).__name__, file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
