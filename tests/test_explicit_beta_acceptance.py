#!/usr/bin/env python3
"""Acceptance boundary tests; no installers, GUI, driver, or native mutation."""
import importlib.util
import json
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

TOOL = Path(__file__).resolve().parents[1] / "tools/explicit_beta_acceptance.py"
SPEC = importlib.util.spec_from_file_location("explicit_beta_acceptance", TOOL)
qa = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qa)
SOURCE = "a" * 40
SHA = "b" * 64


def windows_manifest():
    return {"schema": "flowbridge-explicit-beta-windows-qa-package-v1", "source_sha": SOURCE,
            "explicit_socks_only": True, "signed": False, "publisher_release_approved": False,
            "driver_included": False, "capture_helper_included": False,
            "system_service_included": False, "gui_protected_ui_compiled_disabled": True,
            "profile_namespace": "FlowBridgeExplicitBeta", "uninstall_registration": "FlowBridgeExplicitBeta",
            "installer_sha256": SHA, "installer_bytes": 10,
            "payload": [{"path": name, "sha256": SHA, "bytes": 10} for name in
                        ("FlowBridge.exe", "flowbridge-cli.exe", "flowbridge_ffi.dll", "LICENSE", "README.txt",
                         "BUILD-METADATA.json", "SBOM.cdx.json", "licenses/THIRD_PARTY_NOTICES.txt",
                         "licenses/nlohmann-json-LICENSE.MIT", "resources/presets.json",
                         "examples/direct.json", "examples/ssh-socks.json", "examples/chain.json")],
            "qa_harness": {"path": "FlowBridgeNativeSmoke.exe", "sha256": SHA, "bytes": 20}}


def macos_manifest():
    return {"schema": "flowbridge-explicit-beta-macos-qa-package-v1", "source_sha": SOURCE,
            "explicit_socks_only": True, "signed": False, "publisher_release_approved": False,
            "driver_included": False, "system_extension_included": False,
            "bundle_id": "org.flowbridge.FlowBridgeExplicitBeta", "pkg_sha256": SHA, "pkg_bytes": 10}


class AcceptanceBoundaryTests(unittest.TestCase):
    def test_source_and_package_pins_are_independent(self):
        self.assertEqual(qa.validate_manifest(windows_manifest(), SOURCE, SHA), "windows")
        self.assertEqual(qa.validate_manifest(macos_manifest(), SOURCE, SHA), "macos")
        for source, package, message in (("c" * 40, SHA, "source_sha_mismatch"),
                                        (SOURCE, "d" * 64, "package_sha_mismatch")):
            with self.subTest(message=message), self.assertRaisesRegex(qa.Rejected, message):
                qa.validate_manifest(windows_manifest(), source, package)

    def test_scope_flags_require_literal_booleans(self):
        for flag, value in (("explicit_socks_only", "true"), ("signed", 0),
                            ("driver_included", None), ("publisher_release_approved", True),
                            ("capture_helper_included", True), ("system_service_included", True),
                            ("gui_protected_ui_compiled_disabled", False)):
            m = windows_manifest()
            m[flag] = value
            with self.subTest(flag=flag), self.assertRaises(qa.Rejected):
                qa.validate_manifest(m, SOURCE, SHA)

    def test_payload_escape_and_protected_components_rejected(self):
        bad = ("../evil.exe", "/FlowBridge.exe", "C:/FlowBridge.exe", "foo\\bar.exe",
               "licenses/../evil.exe", "./FlowBridge.exe", "a//b", "a/",
               "FlowBridgeCapture.exe", "driver.sys", "a.inf", "WFP/helper.exe")
        for name in bad:
            m = windows_manifest()
            m["payload"][0]["path"] = name
            with self.subTest(name=name), self.assertRaises(qa.Rejected):
                qa.validate_manifest(m, SOURCE, SHA)

    def test_case_insensitive_payload_collision_rejected(self):
        m = windows_manifest()
        m["payload"].append({"path": "FLOWBRIDGE.EXE", "sha256": SHA, "bytes": 10})
        with self.assertRaisesRegex(qa.Rejected, "duplicate_payload_path"):
            qa.validate_manifest(m, SOURCE, SHA)

    def test_missing_harness_or_product_binary_cannot_pass(self):
        m = windows_manifest()
        del m["qa_harness"]
        with self.assertRaisesRegex(qa.Rejected, "missing_pinned_qa_harness"):
            qa.validate_manifest(m, SOURCE, SHA)
        m = windows_manifest()
        m["payload"] = m["payload"][1:]
        with self.assertRaisesRegex(qa.Rejected, "payload_allowlist_mismatch"):
            qa.validate_manifest(m, SOURCE, SHA)

    def test_arbitrary_additional_executable_is_rejected(self):
        m = windows_manifest()
        m["payload"].append({"path": "ordinary-name.exe", "sha256": SHA, "bytes": 10})
        with self.assertRaisesRegex(qa.Rejected, "payload_allowlist_mismatch"):
            qa.validate_manifest(m, SOURCE, SHA)

    def test_parent_link_cannot_redirect_installed_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            installed = root / "installed"
            installed.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (outside / "license.txt").write_text("unexpected outside file")
            try:
                (installed / "licenses").symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError):
                return
            with self.assertRaisesRegex(qa.Rejected, "linked_payload_component"):
                qa.contained_payload_file(installed, "licenses/license.txt")

    def test_byte_pin_catches_tampering_and_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "payload"
            path.write_bytes(b"original")
            sha = qa.digest(path)
            self.assertEqual(qa.verified_file(path, sha, 8), path.resolve())
            path.write_bytes(b"modified")
            with self.assertRaisesRegex(qa.Rejected, "file_sha_mismatch"):
                qa.verified_file(path, sha, 8)
            link = Path(tmp) / "link"
            try:
                link.symlink_to(path)
            except (OSError, NotImplementedError):
                return
            with self.assertRaisesRegex(qa.Rejected, "missing_or_linked_file"):
                qa.verified_file(link, qa.digest(path), 8)

    def test_macos_listing_is_exactly_isolated_app(self):
        qa.validate_macos_listing(".\n./Applications\n./Applications/FlowBridgeExplicitBeta.app\n"
                                  "./Applications/FlowBridgeExplicitBeta.app/Contents/Info.plist\n")
        for name in ("Applications/FlowBridge.app", "Applications/Unrelated.app/file",
                     "Library/LaunchDaemons/start.plist", "../etc/file",
                     "Applications/FlowBridgeExplicitBeta.app/Contents/Library/SystemExtensions"):
            with self.subTest(name=name), self.assertRaises(qa.Rejected):
                qa.validate_macos_listing(name)

    def test_entitlement_inspection_does_not_confuse_failure_with_absence(self):
        qa.validate_macos_entitlements(0, "", "Executable=/temporary/beta.app\n")
        qa.validate_macos_entitlements(0, plistlib.dumps({}).decode(), "")
        with self.assertRaisesRegex(qa.Rejected, "cannot_inspect_beta_entitlements"):
            qa.validate_macos_entitlements(1, "", "unrecognized failure")
        with self.assertRaisesRegex(qa.Rejected, "malformed_beta_entitlements"):
            qa.validate_macos_entitlements(0, "", "binary contains an invalid entitlements blob; OS will ignore these entitlements")
        with self.assertRaisesRegex(qa.Rejected, "invalid_entitlements_output"):
            qa.validate_macos_entitlements(0, "garbled output", "")
        with self.assertRaisesRegex(qa.Rejected, "forbidden_beta_entitlement"):
            qa.validate_macos_entitlements(0, plistlib.dumps({"com.apple.developer.system-extension.install": False}).decode(), "")

    def test_hosted_and_non_native_context_never_become_owner_pass(self):
        with mock.patch.object(qa.sys, "platform", "win32"), mock.patch.object(qa.platform, "node", return_value="VM-910136"):
            hosted = qa.execution_context("windows", "VM-910136", {
                "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"})
            self.assertFalse(hosted["owner_native"])
            self.assertTrue(hosted["github_hosted"])
            self.assertFalse(qa.execution_context("windows", "VM-910136", {"CI": "true"})["owner_native"])
            self.assertTrue(qa.execution_context("windows", "vm-910136", {})["owner_native"])
            with self.assertRaisesRegex(qa.Rejected, "wrong_execution_host"):
                qa.execution_context("windows", "another-host", {})
            with self.assertRaisesRegex(qa.Rejected, "wrong_execution_platform"):
                qa.execution_context("macos", "VM-910136", {})

    def test_fingerprint_detects_profile_changes_without_exposing_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = root / "profile.json"
            profile.write_text('{"private":"SECRET1"}')
            before = qa.fingerprint(root)
            self.assertRegex(before, r"^[0-9a-f]{64}$")
            self.assertNotIn("SECRET", before)
            profile.write_text('{"private":"SECRET2"}')
            self.assertNotEqual(qa.fingerprint(root), before)

    def test_new_report_does_not_infer_acceptance_from_pins(self):
        report = qa.new_report(SOURCE)
        self.assertFalse(report["a3_a4_full_acceptance"])
        self.assertFalse(report["release_accepted"])
        self.assertEqual(set(report["checks"].values()), {"NOT_RUN"})

    def test_read_only_cli_produces_not_run_report_without_any_os_installation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / "beta.pkg"
            package.write_bytes(b"test-only fixture, not an installer")
            m = macos_manifest()
            m["pkg_sha256"] = qa.digest(package)
            m["pkg_bytes"] = package.stat().st_size
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(m))
            result = subprocess.run([sys.executable, str(TOOL), "--manifest", str(manifest),
                                     "--package", str(package), "--expected-source", SOURCE,
                                     "--expected-package-sha256", qa.digest(package),
                                     "--expected-manifest-sha256", qa.digest(manifest),
                                     "--expected-tool-sha256", qa.digest(TOOL), "--output", str(root / "out")],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads((root / "out/native-acceptance.json").read_text())
            self.assertEqual(report["status"], "VERIFIED_BYTES_NATIVE_NOT_RUN")
            self.assertFalse(report["release_accepted"])
            self.assertEqual(set(report["checks"].values()), {"NOT_RUN"})

    def test_failure_report_does_not_dump_private_paths_or_package_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "SECRET_PRIVATE_PATH.json"
            manifest.write_text("SECRET_PRIVATE_CONTENT")
            result = subprocess.run([sys.executable, str(TOOL), "--manifest", str(manifest),
                                     "--package", str(root / "unused"), "--expected-source", SOURCE,
                                     "--expected-package-sha256", SHA,
                                     "--expected-manifest-sha256", SHA,
                                     "--expected-tool-sha256", qa.digest(TOOL), "--output", str(root / "out")],
                                    capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("SECRET_PRIVATE", result.stdout)
            report = json.loads((root / "out/native-acceptance.json").read_text())
            self.assertEqual(report["error_code"], "file_sha_mismatch")
            self.assertFalse(report["release_accepted"])


if __name__ == "__main__":
    unittest.main()
