"""Adversarial and end-to-end source-only beta.3 staging tests. No installer."""
from __future__ import annotations
from io import BytesIO
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch
from zipfile import ZipFile, ZipInfo

QA_ROOT = Path(__file__).resolve().parents[1]
PRODUCT_ROOT = Path(os.environ.get('FLOWBRIDGE_BETA2_FIXTURE_ROOT', QA_ROOT))
spec = importlib.util.spec_from_file_location(
    'internal_beta3', QA_ROOT / 'tools/stage_internal_beta3.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)

class OfflinePrivateStaging(unittest.TestCase):
    def fixture(self) -> dict[str,bytes]:
        # Exercise actual beta.2 version sources, not mock versions.
        return {n: (PRODUCT_ROOT / n).read_bytes() for n in s.MODIFIED_FILES}

    def test_rewrite_exact_version_only_and_local_lockfile(self):
        fixture = self.fixture()
        changed = s.version_rewrites(fixture)
        self.assertEqual(tomllib.loads(changed['Cargo.toml'].decode())
                         ['workspace']['package']['version'], s.NEW)
        contract = json.loads(changed['packaging/explicit-beta.json'])
        self.assertEqual(contract['version'], s.NEW)
        self.assertEqual(contract['windows_file_version'], '0.3.0.3')
        self.assertEqual(contract['macos_bundle_version'], '3.0.3')
        self.assertFalse(contract['release_approved'])
        self.assertEqual(set(changed), set(s.MODIFIED_FILES))
        self.assertTrue(all(changed[n] != fixture[n] for n in fixture))
        before = tomllib.loads(fixture['Cargo.lock'].decode())['package']
        after = tomllib.loads(changed['Cargo.lock'].decode())['package']
        self.assertEqual(len(before), len(after))
        self.assertEqual({p['name'] for p in after if p['version'] == s.NEW},
                         s.LOCAL_PACKAGE_NAMES)
        for first, last in zip(before, after):
            if first['name'] not in s.LOCAL_PACKAGE_NAMES:
                self.assertEqual(first, last)
            else:
                self.assertEqual({**first, 'version': s.NEW}, last)

    def test_mixed_or_approved_contract_must_fail(self):
        fixture = self.fixture()
        meta = json.loads(fixture['packaging/explicit-beta.json'])
        for field, value in [('release_approved', True),
                             ('version', '0.3.0-beta.99')]:
            with self.subTest(field=field):
                temp = fixture.copy()
                temp['packaging/explicit-beta.json'] = json.dumps(
                    {**meta, field:value}).encode()
                with self.assertRaises(s.StagingError):
                    s.version_rewrites(temp)

    def test_lockfile_unknown_local_package_must_fail(self):
        fixture = self.fixture()
        temp = fixture.copy()
        temp['Cargo.lock'] = fixture['Cargo.lock'].replace(
            b'name = "flowbridge-core"', b'name = "flowbridge-missing"')
        with self.assertRaisesRegex(s.StagingError,
                                    'cargo_lock_local_package_set_mismatch'):
            s.version_rewrites(temp)

    def test_zip_path_traversal_and_symlink_rejected(self):
        for name in ('../private-key', '/full/secret', 'C:/Windows/ssh.exe',
                     './relative', 'sub/../other'):
            with self.subTest(name=name):
                stream = BytesIO()
                with ZipFile(stream, 'w') as z:
                    z.writestr(name, b'bytes')
                with self.assertRaisesRegex(s.StagingError,
                                            'unsafe_source_archive_path'):
                    s.safe_archive_files(stream.getvalue())
        # Python zipfile normalizes backslashes on Windows; mutate both
        # archive's raw local/central name headers instead.
        stream = BytesIO()
        with ZipFile(stream, 'w') as z:
            z.writestr('dir/file', b'bytes')
        raw = stream.getvalue()
        self.assertEqual(raw.count(b'dir/file'), 2)
        with self.assertRaisesRegex(s.StagingError, 'unsafe_source_archive_path'):
            s.safe_archive_files(raw.replace(b'dir/file', b'dir\\file'))
        stream = BytesIO()
        with ZipFile(stream, 'w') as z:
            info = ZipInfo('link')
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            z.writestr(info, b'/private/key')
        with self.assertRaisesRegex(s.StagingError, 'symlink_in_source_archive'):
            s.safe_archive_files(stream.getvalue())

    @unittest.skipUnless(shutil.which('git'), 'Git not available')
    def test_standalone_stage_is_new_local_repo_no_remotes_or_binaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            src = home / 'source'
            src.mkdir()
            for rel, data in self.fixture().items():
                dest = src / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
            subprocess.run(['git', '-C', str(src), 'init', '-q'], check=True)
            subprocess.run(['git', '-C', str(src), 'config',
                            'user.name', 'Fixture Reviewer'], check=True)
            subprocess.run(['git', '-C', str(src), 'config',
                            'user.email', 'reviewer@example.invalid'], check=True)
            subprocess.run(['git', '-C', str(src), 'add', '--all'], check=True)
            subprocess.run(['git', '-C', str(src), 'commit', '-qm',
                            'known source'], check=True)
            pinned = subprocess.check_output(['git', '-C', str(src),
                                             'rev-parse', 'HEAD'], text=True).strip()
            out = home / 'private-internal-checkout'
            # A request to build on an unsupported host must be rejected
            # BEFORE the script creates a new source repo or installer.
            with patch.object(s.sys, 'platform', 'unsupported-ci-host'):
                with self.assertRaisesRegex(s.StagingError, 'build_requires_native_win10'):
                    s.stage(src, home / 'forbidden-build', build=True)
            self.assertFalse((home / 'forbidden-build').exists())
            with patch.object(s, 'PINNED_SOURCE', pinned):
                res = s.stage(src, out)
            self.assertEqual(res['status'], 'PRIVATE_SOURCE_ONLY_READY_NOT_BUILT')
            self.assertFalse(res['installer_built'])
            self.assertFalse(res['public_release_or_upload_performed'])
            self.assertFalse(res['a7_internal_deployment_approved'])
            self.assertEqual(res['original_verified_source_sha'], pinned)
            self.assertTrue((out / '.git').exists())
            self.assertEqual(
                subprocess.check_output(['git', '-C', str(out), 'remote'],
                                        text=True).strip(), '')
            self.assertEqual(json.loads(
                (out / 'packaging/explicit-beta.json').read_text())['version'], s.NEW)
            self.assertTrue((home / (out.name + '-CHECKPOINT.json')).is_file())
            self.assertEqual(json.loads(
                (src / 'packaging/explicit-beta.json').read_text())['version'], s.OLD)
            with patch.object(s, 'PINNED_SOURCE', pinned):
                with self.assertRaisesRegex(
                    s.StagingError, 'destination_must_be_new_outside_source'
                ):
                    s.stage(src, out)
            with patch.object(s, 'PINNED_SOURCE', 'f' * 40):
                with self.assertRaisesRegex(s.StagingError, 'source_sha_not_pinned'):
                    s.stage(src, home / 'never_created')

if __name__ == '__main__':
    unittest.main()
