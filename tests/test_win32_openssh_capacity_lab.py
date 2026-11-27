"""Source drift and evidence-boundary regressions for the hosted experiment."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools/qa"))
import win32_openssh_capacity_lab as lab


class LabTests(unittest.TestCase):
    def git(self, path, *args):
        return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()

    def make_commit(self, path):
        self.git(path, "init", "--quiet")
        self.git(path, "config", "core.autocrlf", "false")
        self.git(path, "add", "--all")
        self.git(path, "-c", "user.name=QA", "-c", "user.email=qa@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Fixture")
        return self.git(path, "rev-parse", "HEAD")

    def test_only_the_single_pinned_header_change_survives_source_check(self):
        original = b"#define MAX_FDS 256  /* a 2^n number */\n"
        expanded = original.replace(b"256", b"1024", 1)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, dependencies = root / "source", root / "dependencies"
            header = source / lab.HEADER
            header.parent.mkdir(parents=True)
            header.write_bytes(original)
            (source / "another-file").write_text("unchanged")
            dependencies.mkdir()
            (dependencies / "vcpkg.json").write_text("{}")
            with (patch.object(lab, "OPENSSH_SOURCE", self.make_commit(source)),
                  patch.object(lab, "VCPKG_SOURCE", self.make_commit(dependencies)),
                  patch.object(lab, "HEADER_ORIGINAL", lab.digest(original)),
                  patch.object(lab, "HEADER_EXPERIMENTAL", lab.digest(expanded)),
                  patch.object(lab, "verify_registry")):
                lab.prepare(source, dependencies)
                self.assertEqual(header.read_bytes(), expanded)
                lab.verify_source_change(source, dependencies)
                (source / "another-file").write_text("unexpected")
                with self.assertRaisesRegex(lab.LabFailure, "modify_only_select_header"):
                    lab.verify_source_change(source, dependencies)
                with self.assertRaisesRegex(lab.LabFailure, "select_header_mismatch"):
                    lab.expanded_header(original + b"unexpected")

    def test_pinned_registry_must_contain_manifest_overrides(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, dependencies = root / "source", root / "dependencies"
            dependencies.mkdir()
            (dependencies / "baseline").write_text("registry fixture")
            baseline = self.make_commit(dependencies)
            manifest = source / lab.VCPKG_MANIFEST
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({
                "builtin-baseline": baseline,
                "overrides": [{"name": name, "version": version}
                              for name, version in lab.REGISTRY_OVERRIDES.items()],
            }), encoding="utf-8")
            for name, version in lab.REGISTRY_OVERRIDES.items():
                history = dependencies / "versions" / f"{name[0]}-" / f"{name}.json"
                history.parent.mkdir(parents=True)
                history.write_text(json.dumps({
                    "versions": [{"version": version, "port-version": 0}],
                }), encoding="utf-8")
            with patch.object(lab, "VCPKG_BASELINE", baseline):
                lab.verify_registry(source, dependencies)
                history.write_text('{"versions": []}', encoding="utf-8")
                with self.assertRaisesRegex(lab.LabFailure, "missing_override"):
                    lab.verify_registry(source, dependencies)

    def test_compiled_runtime_requires_every_x64_fixture_binary(self):
        pe = b"MZ" + bytes(58) + (64).to_bytes(4, "little") + b"PE\0\0\x64\x86"
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary)
            for name in lab.REQUIRED_BINARIES:
                (runtime / name).write_bytes(pe)
            self.assertEqual(set(lab.runtime_hashes(runtime)), lab.REQUIRED_BINARIES)
            (runtime / "sshd-session.exe").unlink()
            with self.assertRaisesRegex(lab.LabFailure, "incomplete_lab_runtime"):
                lab.runtime_hashes(runtime)
            (runtime / "sshd-session.exe").write_bytes(pe[:-2] + b"\x4c\x01")
            with self.assertRaisesRegex(lab.LabFailure, "expected_windows_x64_pe"):
                lab.runtime_hashes(runtime)

    def test_experimental_pass_still_requires_full_live_gate_and_exact_binary_pair(self):
        binary_hashes = {"ssh.exe": "1" * 64, "sshd.exe": "2" * 64}
        wrapper = {
            "scenario": "raw", "hosted_windows_runner": True, "passed": True,
            "network_test_destinations_loopback_only": True, "managed_acceptance_proved": False,
            "ffi_sha256": None, "cli_sha256": None, "raw_backend_512_stability_proved": True,
            "ssh_sha256": binary_hashes["ssh.exe"], "sshd_sha256": binary_hashes["sshd.exe"],
        }
        raw = {
            "windows_openssh_tested": True, "passed": True, "external_network": False,
            "actual_ssh_executable_sha256": binary_hashes["ssh.exe"],
            "minimum_required_held": 512, "selected_held_ceiling": 512, "peak_held": 512,
            "attempts": [{"requested_tier": 512, "target_held": 512, "accepted_held": 512,
                          "test_ceiling_applied": False}],
            "capacity_baseline_verified": True, "resource_recovery_verified": True,
            "recovery_successes": 16, "actual_connection_attempts": 528,
        }
        result = lab.summary(raw, wrapper, binary_hashes, 0)
        self.assertEqual(result["status"], "LAB_STRICT_512_PASS")
        self.assertFalse(result["production_raw512_accepted"])
        self.assertFalse(result["production_adoption_approved"])
        self.assertFalse(result["frozen_beta3_changed"])
        failure_cases = (
            ({"peak_held": 246}, {}, 0),
            ({"recovery_successes": 15}, {}, 0),
            ({"resource_recovery_verified": False}, {}, 0),
            ({"actual_ssh_executable_sha256": "3" * 64}, {}, 0),
            ({}, {"sshd_sha256": "4" * 64}, 0),
            ({}, {"managed_acceptance_proved": True}, 0),
            ({}, {"cli_sha256": "5" * 64}, 0),
            ({}, {"hosted_windows_runner": False}, 0),
            ({}, {}, 1),
        )
        for evidence_update, wrapper_update, exit_code in failure_cases:
            with self.subTest(evidence_update=evidence_update, wrapper_update=wrapper_update, exit_code=exit_code):
                result = lab.summary(raw | evidence_update, wrapper | wrapper_update, binary_hashes, exit_code)
                self.assertEqual(result["status"], "LAB_STRICT_512_NOT_MET")

    def test_failed_gate_does_not_export_unclassified_input(self):
        evidence = {
            "peak_held": 246, "actual_connection_attempts": 248, "recovery_successes": 0,
            "private_reason": "DO_NOT_LOG",
            "resource_error_counts": {"DO_NOT_LOG": 1, "no_buffer_space": "DO_NOT_LOG"},
        }
        wrapper = {"fixture_server_resource_error_counts": {"postauth_notify_pipe_file_limit": 1}}
        result = lab.summary(evidence, wrapper, {"ssh.exe": "1" * 64, "sshd.exe": "2" * 64}, 1)
        self.assertEqual(result["recovery_status"], "NOT_REACHED")
        self.assertEqual(result["actual_connection_attempts"], 248)
        self.assertEqual(result["fixture_server_resource_error_counts"], {"postauth_notify_pipe_file_limit": 1})
        self.assertNotIn("DO_NOT_LOG", str(result))


if __name__ == "__main__":
    unittest.main()
