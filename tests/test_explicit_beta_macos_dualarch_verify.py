#!/usr/bin/env python3
"""Negative/positive synthetic controls for the immutable dual-arch A4 verifier.

Fixtures are NOT a macOS package, installation, signing or physical acceptance.
"""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("a4_dualarch", ROOT / "tools/explicit_beta_macos_dualarch_verify.py")
assert spec is not None and spec.loader is not None
a4 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a4)


def native(arch: str, *, preflight: bool = False) -> dict:
    d = {
        "schema": "flowbridge-explicit-beta-native-acceptance-v1",
        "source_sha": a4.SOURCE, "target": "macos",
        "package_sha256": a4.PKG_SHA, "manifest_sha256": a4.MANIFEST_SHA,
        "tool_sha256": a4.TOOL_SHA, "pins_verified": True,
        "release_accepted": False, "a3_a4_full_acceptance": False,
        "checks": {p: "NOT_RUN" if preflight else "PASS" for p in a4.PHASES},
        "status": "VERIFIED_BYTES_NATIVE_NOT_RUN" if preflight else "CI_AUTOMATED_CHECKS_PASS",
    }
    if not preflight:
        d.update({
            "host": {"platform": "macos", "architecture": arch,
                     "github_hosted": True, "ci_environment_detected": True,
                     "owner_native": False, "os_version": "synthetic"},
            "macos_launch_scope": "process survived 4 seconds; visual/routing checks not performed",
            "driver_or_extension_activation_requested": False,
            "network_configuration_requested": False,
            "publisher_signature_acceptance": "NOT_RUN",
            "native_transparent_routing": "NOT_RUN",
            "dns_leak_acceptance": "NOT_RUN",
            "manual_visual_keyboard_review": "NOT_RUN",
            "owner_managed_ssh": "NOT_RUN",
            "cleanup_required": False, "test_profile_retained": True,
        })
    return d


def write(path: Path, item: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(item), encoding="utf-8")


class FrozenMacChecks(unittest.TestCase):
    def test_positive_synthetic_never_promotes_owner_or_release(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            for arch in a4.ARCHES:
                write(directory / f"bytes-{arch}.json", native(arch, preflight=True))
                write(directory / f"native-{arch}.json", native(arch))
                d = a4.verify_native(directory, arch)
                self.assertEqual(d["status"], "HOSTED_NATIVE_6_6_OWNER_OPEN")
                self.assertFalse(d["owner_native_accepted"])
                write(directory / arch / f"check-{arch}.json", d)
            d = a4.compare(directory)
            self.assertEqual(d["total_hosted_phases_passed"], 12)
            self.assertEqual(d["architectures_with_real_pkg_lifecycle"], 2)
            for key in ("owner_native_accepted", "native_ne_activated",
                        "physical_dns_no_leak_proved", "release_accepted"):
                self.assertIs(d[key], False)

    def test_missing_one_architecture_never_passes(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            write(Path(root) / "check-arm64.json", a4.verify_native_fixture_not_used() if False else {
                "schema": a4.SCHEMA, "arch": "arm64",
                "status": "HOSTED_NATIVE_6_6_OWNER_OPEN"})
            with self.assertRaisesRegex(a4.Fail, "missing_or_duplicate_arch_report"):
                a4.compare(Path(root))

    def test_wrong_arch_or_emulated_claim_does_not_pass(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            write(directory / "bytes-x86_64.json", native("x86_64", preflight=True))
            w = native("arm64")
            write(directory / "native-x86_64.json", w)
            with self.assertRaisesRegex(a4.Fail, "host_native_arch_or_identity_mismatch"):
                a4.verify_native(directory, "x86_64")

    def test_ci_cannot_claim_owner_native(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            d = Path(root)
            write(d / "bytes-arm64.json", native("arm64", preflight=True))
            w = native("arm64")
            w["host"]["owner_native"] = True
            write(d / "native-arm64.json", w)
            with self.assertRaisesRegex(a4.Fail, "host_native_arch_or_identity_mismatch"):
                a4.verify_native(d, "arm64")

    def test_release_go_and_wrong_package_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            d = Path(root)
            write(d / "bytes-arm64.json", native("arm64", preflight=True))
            w = native("arm64")
            w["release_accepted"] = True
            write(d / "native-arm64.json", w)
            with self.assertRaisesRegex(a4.Fail, "qa_source_or_approval_mismatch"):
                a4.verify_native(d, "arm64")
            w["release_accepted"] = False
            w["package_sha256"] = "0" * 64
            write(d / "native-arm64.json", w)
            with self.assertRaisesRegex(a4.Fail, "qa_source_or_approval_mismatch"):
                a4.verify_native(d, "arm64")

    def test_partial_six_step_lifecycle_never_passes(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            d = Path(root)
            write(d / "bytes-arm64.json", native("arm64", preflight=True))
            w = native("arm64")
            w["checks"]["uninstall"] = "NOT_RUN"
            write(d / "native-arm64.json", w)
            with self.assertRaisesRegex(a4.Fail, "hosted_lifecycle_not_all_pass"):
                a4.verify_native(d, "arm64")

    def test_scope_escalation_and_cleanup_failure_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            d = Path(root)
            write(d / "bytes-arm64.json", native("arm64", preflight=True))
            w = native("arm64")
            w["native_transparent_routing"] = "PASS"
            write(d / "native-arm64.json", w)
            with self.assertRaisesRegex(a4.Fail, "unsupported_native_or_cleanup_claim"):
                a4.verify_native(d, "arm64")
            w["native_transparent_routing"] = "NOT_RUN"
            w["cleanup_required"] = True
            write(d / "native-arm64.json", w)
            with self.assertRaisesRegex(a4.Fail, "unsupported_native_or_cleanup_claim"):
                a4.verify_native(d, "arm64")

    def test_duplicate_report_cannot_satisfy_intel(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            d = Path(root)
            target = d / "a" / "check-x86_64.json"
            write(target, {"schema": a4.SCHEMA})
            write(d / "b" / "check-x86_64.json", {"schema": a4.SCHEMA})
            with self.assertRaisesRegex(a4.Fail, "missing_or_duplicate_arch_report"):
                a4.compare(d)

    def test_incomplete_preflight_rejected_even_if_native_claims_pass(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            d = Path(root)
            pre = native("arm64", preflight=True)
            pre["checks"]["install"] = "PASS"
            write(d / "bytes-arm64.json", pre)
            write(d / "native-arm64.json", native("arm64"))
            with self.assertRaisesRegex(a4.Fail, "preflight_not_read_only"):
                a4.verify_native(d, "arm64")


if __name__ == "__main__":
    unittest.main()
