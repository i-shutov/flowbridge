"""Exercise the exact beta.4 source cut without native builds or installer execution."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import stage_internal_beta4 as candidate
from stage_internal_beta3 import LOCAL_PACKAGE_NAMES, StagingError


class PrivateBeta4SourceCut(unittest.TestCase):
    def test_redirected_builder_uses_explicit_utf8_despite_isolated_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "candidate"
            nsis = root / "nsis.zip"
            host = {"os": "Windows 11"}
            toolchain = {"distribution_relative_path": "nsis-3.13",
                         "compiler_relative_path": "Bin/makensis.exe", "archive_sha256": "0" * 64}
            environment = {"PYTHONIOENCODING": "cp1252"}
            with (
                patch.object(candidate, "stage_source", return_value="1" * 40),
                patch.object(candidate.windows_build, "detect_windows_build_host", return_value=host),
                patch.object(candidate.windows_build, "prepare_windows_build_environment",
                             return_value=(environment, {"nsis": toolchain, "build_host": host})),
                patch.object(candidate, "verify_package", return_value={}),
                patch.object(candidate.subprocess, "run") as run,
            ):
                candidate.stage(root / "source", out, nsis_archive=nsis)
            compiler = root / "candidate-nsis-toolchain/nsis-3.13/Bin/makensis.exe"
            self.assertIn(call([sys.executable, "-I", "-X", "utf8", "packaging/windows/build-explicit-beta.py",
                                "--nsis-compiler", str(compiler)],
                               cwd=out, check=True, timeout=2400, env=environment), run.mock_calls)
            result = subprocess.run([sys.executable, "-I", "-X", "utf8", "-c",
                                     "print(chr(0xfffd))"], env={**os.environ, **environment},
                                    capture_output=True, check=True)
            self.assertEqual(result.stdout.strip(), b"\xef\xbf\xbd")

    def test_windows_10_is_excluded_before_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(candidate.windows_build, "detect_windows_build_host",
                              return_value={"os": "Windows 10", "build": 19045}):
                with self.assertRaisesRegex(StagingError, "windows_11_build_required"):
                    candidate.stage(root / "source", root / "candidate", nsis_archive=root / "nsis.zip")
            self.assertFalse((root / "candidate").exists())

    @unittest.skipIf(os.name == "nt", "Creating a Windows symlink requires a separate privilege")
    def test_symlink_parent_rejected_before_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            actual = root / "actual"
            actual.mkdir()
            fake = root / "alias"
            fake.symlink_to(actual, target_is_directory=True)
            with self.assertRaisesRegex(StagingError, "local_path_reparse_point"):
                candidate.stage(root, fake / "candidate")
            self.assertEqual(list(actual.iterdir()), [])

    @unittest.skipUnless(os.environ.get("FLOWBRIDGE_BETA4_FIXTURE_ROOT"),
                         "Set FLOWBRIDGE_BETA4_FIXTURE_ROOT to the exact product source")
    def test_exact_tree_and_software_scope(self):
        source = Path(os.environ["FLOWBRIDGE_BETA4_FIXTURE_ROOT"])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "candidate"
            result = candidate.stage(source, out)
            self.assertEqual(candidate.git(source, "rev-parse", "HEAD"), candidate.PINNED_SOURCE)
            self.assertEqual(candidate.git(out, "rev-parse", "HEAD^{tree}"), candidate.CANDIDATE_TREE)
            self.assertEqual(result["status"], "PRIVATE_SOURCE_ONLY_READY_NOT_BUILT")
            self.assertFalse(result["installer_built"])
            self.assertFalse(result["win11_product_accepted"])
            self.assertFalse(result["public_release_or_upload_performed"])
            self.assertEqual(candidate.git(out, "remote"), "")
            self.assertEqual(candidate.git(out, "status", "--porcelain"), "")
            self.assertEqual(candidate.git(source, "ls-tree", "-r", "--name-only", "HEAD"),
                             candidate.git(out, "ls-tree", "-r", "--name-only", "HEAD"))
            self.assertEqual(
                (source / "tools/explicit_beta_acceptance.py").read_bytes(),
                (out / "tools/explicit_beta_acceptance.py").read_bytes())
            old = tomllib.loads((source / "Cargo.lock").read_text())["package"]
            new = tomllib.loads((out / "Cargo.lock").read_text())["package"]
            expected = [{**pkg, "version": candidate.CANDIDATE_VERSION}
                        if pkg["name"] in LOCAL_PACKAGE_NAMES else pkg for pkg in old]
            self.assertEqual(new, expected)
            self.assertEqual(json.loads((out / "packaging/explicit-beta.json").read_bytes())["release_approved"],
                             False)
            self.assertEqual(json.loads((root / "candidate-CHECKPOINT.json").read_bytes()), result)
            with self.assertRaisesRegex(StagingError, "destination_must_be_new_outside_source"):
                candidate.stage(source, out)


if __name__ == "__main__":
    unittest.main()
