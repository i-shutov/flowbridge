"""Unit tests for offline Windows build-host and portable NSIS preflight."""

from __future__ import annotations

import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from zipfile import ZipFile, ZipInfo


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import internal_windows_build_preflight as preflight


class WindowsBuildHostTests(unittest.TestCase):
    def host(self, build, product_type=1, *, native_x64=True, process_size=2**63 - 1):
        version = SimpleNamespace(major=10, minor=0, build=build, product_type=product_type)
        with (patch.object(preflight.sys, 'platform', 'win32'),
              patch.object(preflight.sys, 'getwindowsversion', return_value=version, create=True),
              patch.object(preflight.sys, 'maxsize', process_size),
              patch.object(preflight, '_is_native_windows_x64', return_value=native_x64)):
            return preflight.detect_windows_build_host()

    def test_windows_client_builds_allowed(self):
        for build, name in [(19045, 'Windows 10'), (22000, 'Windows 11'), (26100, 'Windows 11')]:
            with self.subTest(build=build):
                self.assertEqual(self.host(build), {
                    'os': name, 'build': build, 'architecture': 'x64', 'product_type': 1,
                })

    def test_server_and_domain_controller_rejected_even_on_same_build(self):
        for product_type in (2, 3):
            with self.subTest(product_type=product_type):
                with self.assertRaisesRegex(preflight.WindowsBuildPreflightError,
                                            'build_requires_windows_client$'):
                    self.host(26100, product_type)

    def test_other_windows_builds_and_non_native_x64_rejected(self):
        for build in (19044, 21999):
            with self.subTest(build=build):
                with self.assertRaisesRegex(preflight.WindowsBuildPreflightError,
                                            'build_requires_windows_10_22h2_or_windows_11'):
                    self.host(build)
        for arguments in ({'native_x64': False}, {'process_size': 2**31 - 1}):
            with self.subTest(arguments=arguments):
                with self.assertRaisesRegex(preflight.WindowsBuildPreflightError,
                                            'build_requires_native_windows_client_x64'):
                    self.host(26100, **arguments)


class PortableNsisTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.root = Path(workspace.name)
        self.archive = self.root / 'nsis-3.13.zip'
        self.toolchain = self.root / 'private-toolchain'
        self.files = {
            'nsis-3.13/Bin/makensis.exe': b'real compiler fixture',
            'nsis-3.13/makensis.exe': b'root redirector fixture',
            'nsis-3.13/Include/LogicLib.nsh': b'NSIS include fixture',
            'nsis-3.13/Stubs/zlib': b'NSIS stub fixture',
            'nsis-3.13/COPYING': b'NSIS license fixture',
        }
        self.host = {'os': 'Windows 11', 'build': 26100, 'architecture': 'x64', 'product_type': 1}
        host = patch.object(preflight, 'detect_windows_build_host', return_value=self.host)
        host.start()
        self.addCleanup(host.stop)
        command = patch.object(preflight.subprocess, 'run', return_value=Mock(stdout=b'v3.13\r\n'))
        self.run = command.start()
        self.addCleanup(command.stop)

    def write_zip(self, files):
        stream = BytesIO()
        with ZipFile(stream, 'w') as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        self.archive.write_bytes(stream.getvalue())

    def prepared(self):
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        with patch.object(preflight, 'NSIS_ZIP_SHA256', digest):
            return preflight.prepare_windows_build_environment(
                nsis_archive=self.archive, toolchain_dir=self.toolchain,
            )

    def test_exact_compiler_and_child_environment_with_relative_evidence(self):
        self.write_zip(self.files)
        old_environment = os.environ.copy()
        environment, evidence = self.prepared()
        nsis = self.toolchain / 'nsis-3.13'
        self.run.assert_called_once_with(
            [str(nsis / 'Bin/makensis.exe'), '/VERSION'], cwd=nsis, env=environment,
            check=True, capture_output=True, timeout=30,
        )
        self.assertEqual(environment['PATH'].split(os.pathsep)[0], str(nsis / 'Bin'))
        self.assertEqual(environment['NSISDIR'], str(nsis))
        self.assertEqual(environment['NoDefaultCurrentDirectoryInExePath'], '1')
        self.assertEqual(os.environ.copy(), old_environment)
        self.assertEqual(evidence['build_host'], self.host)
        self.assertEqual(evidence['product_acceptance'], {
            'target': 'Windows 10 Pro 22H2 x64', 'verified': False,
        })
        self.assertEqual(evidence['nsis'], {
            'archive_sha256': hashlib.sha256(self.archive.read_bytes()).hexdigest(),
            'compiler_sha256': hashlib.sha256((nsis / 'Bin/makensis.exe').read_bytes()).hexdigest(),
            'compiler_version': 'v3.13',
            'compiler_relative_path': 'Bin/makensis.exe',
            'distribution_relative_path': 'nsis-3.13',
        })
        self.assertNotIn(str(self.root), json.dumps(evidence))

    def test_missing_archive_or_pin_mismatch_never_extracts_or_executes(self):
        for reason in ('nsis_local_zip_unreadable', 'nsis_zip_sha256_mismatch'):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(preflight.WindowsBuildPreflightError, reason):
                    preflight.prepare_windows_build_environment(
                        nsis_archive=self.archive, toolchain_dir=self.toolchain,
                    )
                self.assertFalse(self.toolchain.exists())
                self.run.assert_not_called()
                self.write_zip(self.files)

    def test_unsafe_entries_rejected_before_extraction_or_execution(self):
        symlink = ZipInfo('nsis-3.13/linked')
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        for name, reason in [
            ('../outside.txt', 'nsis_archive_unsafe_path'),
            ('/outside.txt', 'nsis_archive_unsafe_path'),
            ('C:/outside.txt', 'nsis_archive_unsafe_path'),
            ('nsis-3.13/.. /outside.txt', 'nsis_archive_unsafe_path'),
            ('nsis-3.13/bin/MAKENSIS.EXE', 'nsis_archive_duplicate_path'),
            (symlink, 'nsis_archive_symlink'),
        ]:
            with self.subTest(name=name):
                self.write_zip({**self.files, name: b'unexpected fixture'})
                with self.assertRaisesRegex(preflight.WindowsBuildPreflightError, reason):
                    self.prepared()
                self.assertFalse(self.toolchain.exists())
                self.run.assert_not_called()

        self.write_zip({**self.files, 'sub/file': b'unexpected fixture'})
        self.archive.write_bytes(self.archive.read_bytes().replace(b'sub/file', b'sub\\file'))
        with self.assertRaisesRegex(preflight.WindowsBuildPreflightError, 'nsis_archive_unsafe_path'):
            self.prepared()
        self.assertFalse(self.toolchain.exists())
        self.run.assert_not_called()

    def test_cannot_use_redirector_or_build_without_resources(self):
        required = ('Bin/makensis.exe', 'Include/LogicLib.nsh', 'Stubs/zlib', 'COPYING')
        for name in required:
            with self.subTest(name=name):
                files = self.files.copy()
                files.pop('nsis-3.13/' + name)
                self.write_zip(files)
                reason = ('nsis_archive_requires_one_bin_compiler' if name == required[0]
                          else 'nsis_archive_missing_build_resources')
                with self.assertRaisesRegex(preflight.WindowsBuildPreflightError, reason):
                    self.prepared()
                self.assertFalse(self.toolchain.exists())
                self.run.assert_not_called()

    def test_existing_toolchain_directory_is_not_reused(self):
        self.write_zip(self.files)
        self.toolchain.mkdir()
        unrelated = self.toolchain / 'unrelated.txt'
        unrelated.write_text('keep', encoding='utf-8')
        with self.assertRaisesRegex(preflight.WindowsBuildPreflightError,
                                    'nsis_toolchain_directory_must_be_new'):
            self.prepared()
        self.assertEqual(unrelated.read_text(encoding='utf-8'), 'keep')
        self.run.assert_not_called()

    def test_unexpected_version_or_nonzero_exit_fails(self):
        self.write_zip(self.files)
        self.run.return_value.stdout = b'v3.12\r\n'
        with self.assertRaisesRegex(preflight.WindowsBuildPreflightError,
                                    'nsis_compiler_version_check_failed'):
            self.prepared()
        self.toolchain = self.root / 'new-toolchain'
        self.run.side_effect = subprocess.CalledProcessError(1, ['makensis.exe', '/VERSION'])
        with self.assertRaisesRegex(preflight.WindowsBuildPreflightError,
                                    'nsis_compiler_version_check_failed'):
            self.prepared()


if __name__ == '__main__':
    unittest.main()
