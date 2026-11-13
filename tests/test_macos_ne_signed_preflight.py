#!/usr/bin/env python3
"""Cross-platform synthetic negatives for macOS NE signed-app admission.

No native activation, install, driver, code-signing changes or claims of
real Mac execution. All successful fixtures are explicitly simulated.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "tools/macos_ne_signed_preflight.py"
SPEC = importlib.util.spec_from_file_location("macos_ne_signed_preflight", SCRIPT)
qa = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qa)

TEAM = "ABCDEFGHIJ"
BUNDLE = "org.flowbridge.FlowBridge"
APP_ROLES = [
    "app-proxy-provider-systemextension",
    "dns-proxy-systemextension",
]


def entitlements(extension: bool) -> dict:
    result = {"com.apple.developer.networking.networkextension": list(APP_ROLES)}
    if not extension:
        result["com.apple.developer.system-extension.install"] = True
    return result


class Fixture:
    def __init__(self, root: Path):
        self.root = root
        self.app = root / "FlowBridge.app"
        self.extension = (self.app / "Contents/Library/SystemExtensions" /
                          (BUNDLE + ".extension.systemextension"))
        self.identity_override = None
        self.team_override = None
        self.entitlement_override = None
        self.verify_failure = False
        for path, bundle_id, exe in ((self.app, BUNDLE, "FlowBridge"),
                                     (self.extension, BUNDLE + ".extension", "FlowBridgeExtension")):
            contents = path / "Contents"
            contents.mkdir(parents=True, exist_ok=True)
            (contents / "MacOS").mkdir(exist_ok=True)
            (contents / "MacOS" / exe).write_bytes(b"fixture, not executable")
            info = {"CFBundleIdentifier": bundle_id, "CFBundleExecutable": exe}
            if path == self.app:
                info["NSSystemExtensionUsageDescription"] = "Route selected app connections"
            else:
                info["NetworkExtension"] = {"NEProviderClasses": dict(qa.NE_PROVIDER_CLASSES)}
            (contents / "Info.plist").write_bytes(plistlib.dumps(info))

    def runner(self, args: list[str]) -> subprocess.CompletedProcess[bytes]:
        extension = str(args[-1]).endswith(".systemextension")
        signed_id = self.identity_override or BUNDLE + (".extension" if extension else "")
        team = self.team_override or TEAM
        if "--verify" in args:
            return subprocess.CompletedProcess(args, 1 if self.verify_failure else 0, b"", b"")
        if "--verbose=4" in args:
            return subprocess.CompletedProcess(
                args, 0, b"", ("Identifier=" + signed_id + "\nTeamIdentifier=" + team + "\n").encode())
        ent = self.entitlement_override if self.entitlement_override is not None else entitlements(extension)
        return subprocess.CompletedProcess(args, 0, plistlib.dumps(ent), b"")

    def run(self, *, host="darwin", team=TEAM, app=None):
        return qa.preflight(app or self.app, BUNDLE, team, runner=self.runner,
                            host_os=host, allowed_roots=(self.root,))


class NativePreflightTests(unittest.TestCase):
    def test_positive_is_only_readiness_not_activation_or_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Fixture(Path(tmp))
            result = f.run()
            self.assertEqual(result["status"], "PREREQUISITES_PASS_NATIVE_NOT_RUN")
            self.assertTrue(result["required_entitlements_verified"])
            for key in ("activation_accepted", "native_packet_evidence_accepted",
                        "dns_containment_proved", "publisher_release_approved", "release_accepted"):
                self.assertIs(result[key], False, key)

    def test_wrong_host_or_missing_expected_team_cannot_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Fixture(Path(tmp))
            for host, team, code in (("win32", TEAM, "macos_host_required"),
                                     ("darwin", "short", "invalid_expected_team_id"),
                                     ("darwin", "ZZZZZZZZZZ", "codesign_team_mismatch")):
                with self.subTest(code=code), self.assertRaisesRegex(qa.GateFailure, code):
                    f.run(host=host, team=team)

    def test_wrong_signing_id_and_team_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Fixture(Path(tmp))
            for attribute, value, code in (("identity_override", "org.attacker.copy", "codesign_identifier_mismatch"),
                                           ("team_override", "ZZZZZZZZZZ", "codesign_team_mismatch"),
                                           ("verify_failure", True, "codesign_verify_failed")):
                setattr(f, attribute, value)
                with self.subTest(code=code), self.assertRaisesRegex(qa.GateFailure, code):
                    f.run()
                setattr(f, attribute, None if attribute != "verify_failure" else False)

    def test_missing_additional_or_forged_entitlements_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Fixture(Path(tmp))
            cases = [
                ({}, "app_network_extension_entitlements_mismatch"),
                ({"com.apple.developer.networking.networkextension": APP_ROLES},
                 "app_install_entitlement_missing"),
                ({**entitlements(False), "com.apple.developer.networking.networkextension":
                  APP_ROLES + ["packet-tunnel-provider-systemextension"]},
                 "app_network_extension_entitlements_mismatch"),
                ({**entitlements(False), "com.apple.developer.system-extension.install": False},
                 "app_install_entitlement_missing"),
            ]
            for value, code in cases:
                f.entitlement_override = value
                with self.subTest(code=code), self.assertRaisesRegex(qa.GateFailure, code):
                    f.run()

    def test_missing_extension_entitlements_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Fixture(Path(tmp))
            original_runner = f.runner

            def poisoned(args):
                if str(args[-1]).endswith(".systemextension") and "--entitlements" in args:
                    return subprocess.CompletedProcess(args, 0, plistlib.dumps({}), b"")
                return original_runner(args)
            f.runner = poisoned
            with self.assertRaisesRegex(qa.GateFailure, "extension_network_extension_entitlements_mismatch"):
                f.run()

    def test_extra_extension_cannot_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Fixture(Path(tmp))
            (f.extension.parent / "another.systemextension").mkdir()
            with self.assertRaisesRegex(qa.GateFailure, "system_extension_count_mismatch"):
                f.run()

    def test_provider_classes_must_be_concrete_and_exact(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Fixture(Path(tmp))
            path = f.extension / "Contents/Info.plist"
            data = plistlib.loads(path.read_bytes())
            data["NetworkExtension"]["NEProviderClasses"]["com.apple.networkextension.app-proxy"] = "Wrong.Provider"
            path.write_bytes(plistlib.dumps(data))
            with self.assertRaisesRegex(qa.GateFailure, "provider_class_registration_mismatch"):
                f.run()

    def test_bundle_id_or_missing_executable_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Fixture(Path(tmp))
            path = f.app / "Contents/Info.plist"
            data = plistlib.loads(path.read_bytes())
            data["CFBundleIdentifier"] = "org.attacker.Copy"
            path.write_bytes(plistlib.dumps(data))
            with self.assertRaisesRegex(qa.GateFailure, "app_bundle_id_mismatch"):
                f.run()
            data["CFBundleIdentifier"] = BUNDLE
            path.write_bytes(plistlib.dumps(data))
            (f.app / "Contents/MacOS/FlowBridge").unlink()
            with self.assertRaisesRegex(qa.GateFailure, "app_executable_missing"):
                f.run()

    def test_symlinked_extension_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Fixture(Path(tmp))
            original = f.extension.with_suffix(".not-extension")
            f.extension.rename(original)
            try:
                f.extension.symlink_to(original, target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("symlinks unavailable")
            with self.assertRaisesRegex(qa.GateFailure, "system_extension_linked"):
                f.run()

    def test_cli_always_records_false_acceptance_and_redacts_private_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            private = Path(tmp) / "PRIVATE_SECRET_PATH.app"
            out = Path(tmp) / "report.json"
            result = subprocess.run([
                sys.executable, str(SCRIPT), "--app", str(private),
                "--expected-bundle-id", BUNDLE, "--expected-team-id", TEAM,
                "--output", str(out)], capture_output=True, text=True, check=False)
            self.assertNotEqual(result.returncode, 0)
            content = out.read_text()
            self.assertNotIn("PRIVATE_SECRET_PATH", content)
            self.assertFalse(json.loads(content)["release_accepted"])
            self.assertFalse(json.loads(content)["activation_accepted"])
            self.assertFalse(json.loads(content)["native_packet_evidence_accepted"])

    def test_invalid_plist_rejected_without_raw_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Fixture(Path(tmp))
            (f.app / "Contents/Info.plist").write_text("SECRET_INVALID_XML")
            with self.assertRaisesRegex(qa.GateFailure, "app_plist_invalid"):
                f.run()

    def test_malformed_codesign_entitlements_are_not_absence_or_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Fixture(Path(tmp))
            def corrupted(args):
                if "--entitlements" in args:
                    return subprocess.CompletedProcess(args, 0, b"not plist", b"")
                return Fixture.runner(f, args)
            f.runner = corrupted
            with self.assertRaisesRegex(qa.GateFailure, "entitlements_absent_or_malformed"):
                f.run()


if __name__ == "__main__":
    unittest.main()
