import hashlib
import json
from pathlib import Path, PureWindowsPath
import sys
import tempfile
from unittest.mock import Mock, patch
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import win11_beta4_headless_lifecycle as qa
sys.path.pop(0)


class Win11HeadlessLifecycleTest(unittest.TestCase):
    def test_cleanup_cannot_claim_foreign_install_location(self):
        install = PureWindowsPath(r"C:\FlowBridge\private-candidates\qa-test\Тест")
        settings, uninstall = qa.known_registry(install)
        self.assertTrue(qa.owned_registry(qa.UNINSTALL, (0, uninstall), install))
        self.assertTrue(qa.owned_registry(qa.SETTINGS, (0, settings), install))
        self.assertFalse(qa.owned_registry(
            qa.SETTINGS, (0, {"InstallDir": r"C:\Users\Admin\Existing"}), install))
        self.assertFalse(qa.owned_registry(qa.SETTINGS, (1, settings), install))
        self.assertFalse(qa.owned_registry(qa.SETTINGS, (0, {}), install))
        self.assertFalse(qa.owned_registry(qa.UNINSTALL, (0, {"DisplayName": "FlowBridge"}), install))
        self.assertFalse(qa.owned_registry(qa.UNINSTALL, (0, dict(uninstall, NoModify="1")), install))

    def test_existing_empty_settings_key_blocks_before_mutation(self):
        with patch.object(qa.preflight, "installed_state", return_value={"stable": {}}), \
                patch.object(qa.preflight, "isolation_status", return_value="ISOLATION_BASELINE_AVAILABLE"), \
                patch.object(qa, "registry_views", return_value=(1, 2)), \
                patch.object(qa, "registry_key", return_value=(0, {})):
            with self.assertRaisesRegex(qa.preflight.Blocked, "existing_flowbridge_registry_key"):
                qa.require_clean(Mock())

    def test_private_tree_inventory_rejects_escape(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work) / "owned"
            root.mkdir()
            (root / "regular").write_text("test", encoding="utf-8")
            self.assertEqual(qa.contents(root), {"regular"})
            try:
                (root / "outside").symlink_to(root.parent, target_is_directory=True)
            except OSError:
                self.skipTest("Symlink fixture unavailable")
            with self.assertRaisesRegex(qa.preflight.Blocked, "unsafe_tree_entry"):
                qa.contents(root)

    def test_cleanup_preserves_changed_profile_and_identity(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            profile = root / "profile"
            profile.mkdir()
            directories = {profile: qa.directory_id(profile)}
            records = {}
            changed, other = profile / "profile.json", profile / "desktop-settings.json"
            qa.write_fixture(changed, b"original", records)
            qa.write_fixture(other, b"keep", records)
            changed.write_bytes(b"modified")
            with self.assertRaisesRegex(qa.preflight.Blocked, "file_content_or_identity_changed"):
                qa.remove_owned_tree(profile, directories, records)
            self.assertEqual(changed.read_bytes(), b"modified")
            self.assertEqual(other.read_bytes(), b"keep")
            replacement = root / "replacement"
            replacement.write_bytes(b"original")
            replacement.replace(changed)
            with self.assertRaisesRegex(qa.preflight.Blocked, "file_content_or_identity_changed"):
                qa.remove_owned_tree(profile, directories, records)

    def test_missing_repair_payload_cannot_pass_reinstall_verification(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            lifecycle = qa.Lifecycle.__new__(qa.Lifecycle)
            lifecycle.install, lifecycle.shortcuts = root / "install", root / "shortcuts"
            lifecycle.install.mkdir()
            lifecycle.shortcuts.mkdir()
            lifecycle.directories, lifecycle.files = {}, {}
            lifecycle.payload = {qa.REPAIR: {"bytes": 1, "sha256": "0" * 64}}
            for directory in qa.INSTALL_SUBDIRS:
                (lifecycle.install / directory).mkdir()
            for filename in ("Uninstall.exe", qa.PRESERVE):
                (lifecycle.install / filename).write_bytes(b"x")
            for name in qa.SHORTCUTS:
                (lifecycle.shortcuts / name).write_bytes(b"x")
            settings, uninstall = qa.known_registry(lifecycle.install)
            views = {(qa.SETTINGS, 64): (0, settings), (qa.UNINSTALL, 64): (0, uninstall)}
            with patch.object(qa, "registry_views", return_value=(64,)), \
                    patch.object(qa, "registry_snapshot", return_value=views), \
                    patch.object(qa, "verified_shortcuts"):
                with self.assertRaisesRegex(qa.preflight.Blocked, "installed_payload_inventory_mismatch"):
                    lifecycle.verify_install(include_marker=True)

    def test_changed_gui_blocks_reinstall_before_installer_launch(self):
        with tempfile.TemporaryDirectory() as work:
            lifecycle = qa.Lifecycle.__new__(qa.Lifecycle)
            lifecycle.work = Path(work)
            lifecycle.install = lifecycle.work / "owned"
            lifecycle.alternate = lifecycle.work / "unused"
            lifecycle.temp = lifecycle.work / "tmp"
            lifecycle.shortcuts = lifecycle.work / "shortcuts"
            lifecycle.installer = lifecycle.work / "candidate-installer.exe"
            lifecycle.pins = {"installer": "0" * 64}
            lifecycle.kernel, lifecycle.command = Mock(), Mock()
            lifecycle.started = True
            lifecycle.payload = {name: {} for name in ("FlowBridge.exe", qa.REPAIR)}
            lifecycle.files, lifecycle.registered = {}, {}
            directories = (lifecycle.install, lifecycle.temp, lifecycle.shortcuts,
                           *(lifecycle.install / name for name in qa.INSTALL_SUBDIRS))
            for directory in directories:
                directory.mkdir()
            lifecycle.directories = {path: qa.directory_id(path) for path in (lifecycle.work, *directories)}
            gui = lifecycle.install / "FlowBridge.exe"
            repair = lifecycle.install / qa.REPAIR
            for path in (gui, repair, lifecycle.install / "Uninstall.exe",
                         *(lifecycle.shortcuts / name for name in qa.SHORTCUTS)):
                qa.write_fixture(path, b"verified", lifecycle.files)
            repair.unlink()
            gui.write_bytes(b"modified")
            with patch.object(qa.preflight, "verified_digest"), \
                    patch.object(qa.preflight, "process_count", return_value=0), \
                    patch.object(qa, "registry_snapshot", return_value={}):
                with self.assertRaisesRegex(qa.preflight.Blocked, "file_content_or_identity_changed"):
                    lifecycle.install_to(lifecycle.alternate)
                lifecycle.command.assert_not_called()
                gui.write_bytes(b"verified")
                lifecycle.recheck_install_owner(repair_removed=True)
                with self.assertRaisesRegex(qa.preflight.Blocked, "unexpected_file_type"):
                    lifecycle.recheck_install_owner()

    def test_runner_result_binds_success_and_candidate_pins(self):
        pins = {"source": "1" * 40, "tree": "2" * 40, "installer": "3" * 64,
                "manifest": "4" * 64, "harness": "5" * 64, "tool": "6" * 64}
        files = {"FlowBridge.exe": {"sha256": "a" * 64}, "flowbridge-cli.exe": {"sha256": "b" * 64},
                 "flowbridge_ffi.dll": {"sha256": "c" * 64}}
        result = {"schema": "flowbridge-private-beta4-runner-v1", "candidate": qa.preflight.VERSION,
                  "phase": "PACKAGE_EVIDENCE", "status": "PRIVATE_LOCAL_INSTALLER_BUILT_QA_NOT_ACCEPTED",
                  "installer_built": True, "installer_installed": False, "driver_included": False,
                  "staged_payload_allowlist_verified": True, "win11_product_accepted": False,
                  "new_private_git_commit": pins["source"], "new_private_git_tree": pins["tree"],
                  "installer_sha256": pins["installer"], "package_manifest_sha256": pins["manifest"],
                  "qa_harness_sha256": pins["harness"], "acceptance_tool_sha256": pins["tool"],
                  "gui_sha256": "a" * 64, "cli_sha256": "b" * 64, "ffi_sha256": "c" * 64}
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            evidence = root / "runner-result.json"
            encoded = json.dumps(result).encode()
            evidence.write_bytes(encoded)
            self.assertEqual(qa.verify_runner_result(root / "candidate", pins, files),
                             hashlib.sha256(encoded).hexdigest())
            for key, value in (("status", "BLOCKED"), ("new_private_git_tree", "0" * 40),
                               ("package_manifest_sha256", "0" * 64), ("installer_built", 1)):
                with self.subTest(key=key):
                    evidence.write_bytes(json.dumps(dict(result, **{key: value})).encode())
                    with self.assertRaisesRegex(qa.preflight.Blocked, "runner_result_binding_failed"):
                        qa.verify_runner_result(root / "candidate", pins, files)

    def test_wrong_candidate_never_reaches_lifecycle_on_windows(self):
        args = ["qa", "--candidate-root", r"C:\FlowBridge\private-candidates\run-45986630920-1\candidate"]
        for name in qa.preflight.PIN_FIELDS:
            is_source = name in ("source", "tree")
            args += ["--expected-" + name + ("" if is_source else "-sha256"),
                     "1" * (40 if is_source else 64)]
        with patch.object(qa.sys, "argv", args), patch.object(qa.sys, "platform", "win32"), \
                patch.object(qa.ctypes, "WinDLL", create=True), \
                patch.object(qa.preflight, "windows_host", return_value={"token_elevated": True}), \
                patch.object(qa.preflight, "current_session", return_value=0), \
                patch.object(qa, "require_clean"), patch.object(qa, "Lifecycle") as lifecycle, \
                patch("builtins.print") as output:
            self.assertEqual(qa.main(), 1)
            lifecycle.assert_not_called()
            self.assertIn("candidate_outside_beta4_run", output.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
