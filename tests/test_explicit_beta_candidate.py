"""Contract tests for candidate evidence validation; fixtures are not native QA.

The positive fixture models a complete hosted run, including original byte
digests. Negative cases substitute evidence from other builds, platforms or
scopes and must fail before a distributable candidate is written.
"""
from __future__ import annotations

import contextlib
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
import explicit_beta_candidate as candidate


SOURCE = "a" * 40
TREE = "b" * 40
OTHER = "c" * 40
RUN = "123456789"
VERSION = "0.3.0-beta.1"


def encoded(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class EvidenceFixture:
    """Synthetic report/byte inputs, with a Git provenance stub for assembly."""

    def __init__(self, directory: Path):
        self.root = directory / "source"
        self.inputs = directory / "inputs"
        self.stage = self.inputs / "windows" / "payload"
        self.output = directory / "candidate"
        self.root.mkdir()
        self.stage.mkdir(parents=True)
        self.installer = b"synthetic Windows installer bytes, not executable\n"
        self.pkg = b"synthetic macOS package bytes, not executable\n"
        self.harness = b"synthetic QA harness bytes, not executable\n"
        self.lock = b"version = 4\n# Synthetic lockfile for provenance validation\n"
        self.contract = encoded({"schema": "flowbridge-explicit-beta-version-v1",
                                 "version": VERSION, "release_approved": False,
                                 "windows_file_version": "0.3.0.1", "macos_short_version": "0.3.0",
                                 "macos_bundle_version": "3.0.1",
                                 "windows_installer": f"FlowBridge-{VERSION}-windows-x64-setup.exe",
                                 "macos_installer": f"FlowBridge-{VERSION}-macOS-universal-explicit-beta.pkg",
                                 "windows_namespace": "FlowBridgeExplicitBeta",
                                 "macos_bundle_id": "org.flowbridge.FlowBridgeExplicitBeta"})
        self.sbom = {
            "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "name": "FlowBridge Explicit Beta",
                                       "version": VERSION},
                         "properties": [{"name": "flowbridge:source_sha", "value": SOURCE},
                                        {"name": "flowbridge:inventory_scope",
                                         "value": "resolved production and build inputs; binary linkage not inspected"}]},
            "components": [{"type": "library", "name": "flowbridge-cli", "version": VERSION,
                            "bom-ref": "pkg:cargo/flowbridge-cli@" + VERSION,
                            "purl": "pkg:cargo/flowbridge-cli@" + VERSION}],
            "dependencies": [{"ref": "pkg:cargo/flowbridge-cli@" + VERSION, "dependsOn": []}],
        }
        self.notices = b"Synthetic dependency notices for validation tests only\n"
        self.metadata = {
            "schema": "flowbridge-explicit-beta-build-metadata-v1", "version": VERSION,
            "source_sha": SOURCE, "platform": "windows", "targets": ["x86_64-pc-windows-msvc"],
            "shipped_cargo_roots": ["flowbridge-cli", "flowbridge-ffi"],
            "cargo_lock_sha256": sha(self.lock), "version_contract_sha256": sha(self.contract),
            "sbom_sha256": sha(encoded(self.sbom)), "notices_sha256": sha(self.notices),
            "component_count": 1, "license_inventory": [],
            "binary_linkage_reviewed": False, "independent_license_review_passed": False,
            "vulnerability_audit_performed": False, "publisher_release_approved": False,
            "explicit_socks_only": True, "driver_included": False, "system_extension_included": False,
        }
        self.payload = {
            "FlowBridge.exe": b"synthetic GUI\n",
            "flowbridge-cli.exe": b"synthetic CLI\n",
            "flowbridge_ffi.dll": b"synthetic FFI\n",
            "LICENSE": b"synthetic project license\n",
            "README.txt": b"Explicit SOCKS engineering candidate\n",
            "licenses/nlohmann-json-LICENSE.MIT": b"synthetic nlohmann notice\n",
            "licenses/THIRD_PARTY_NOTICES.txt": self.notices,
            "SBOM.cdx.json": encoded(self.sbom),
            "BUILD-METADATA.json": encoded(self.metadata),
            "resources/presets.json": b"{}\n",
            "examples/direct.json": b"{}\n",
            "examples/ssh-socks.json": b"{}\n",
            "examples/chain.json": b"{}\n",
        }
        provenance = {"source_sha": SOURCE, "source_tree_sha": TREE, "workflow_run_id": RUN}
        self.windows = {
            **provenance, "schema": "flowbridge-explicit-beta-windows-qa-package-v1",
            "candidate": VERSION, "explicit_socks_only": True, "signed": False,
            "driver_included": False, "publisher_release_approved": False,
            "capture_helper_included": False, "system_service_included": False,
            "gui_protected_ui_compiled_disabled": True, "app_specific_interception": False,
            "wfp_native_gate": "NO_GO", "profile_namespace": "FlowBridgeExplicitBeta",
            "uninstall_registration": "FlowBridgeExplicitBeta",
            "system_dns_or_proxy_mutated": False, "udp_or_quic_proxied": False,
            "independent_reviewer_passed": False,
            "installer_sha256": sha(self.installer), "installer_bytes": len(self.installer),
            "qa_harness": {"sha256": sha(self.harness), "bytes": len(self.harness)},
            "sbom_sha256": sha(self.payload["SBOM.cdx.json"]),
            "build_metadata_sha256": sha(self.payload["BUILD-METADATA.json"]),
            "payload": [{"path": name, "sha256": sha(data), "bytes": len(data)}
                        for name, data in self.payload.items()],
        }
        self.installed = {
            **provenance, "passed": True, "on_owner_win10": False, "release_accepted": False,
            "installer_sha256": sha(self.installer),
            "installed_gui_sha256": sha(self.payload["FlowBridge.exe"]),
        }
        self.mac = {
            **provenance, "schema": "flowbridge-explicit-beta-macos-qa-package-v1",
            "candidate": VERSION, "explicit_socks_only": True, "signed": False,
            "driver_included": False, "publisher_release_approved": False,
            "system_extension_included": False, "bundle_id": "org.flowbridge.FlowBridgeExplicitBeta",
            "pkg_sha256": sha(self.pkg), "pkg_bytes": len(self.pkg),
        }
        self.mac_resources = self.inputs / "macos" / "Resources"
        self.mac_bom = deepcopy(self.sbom)
        self.mac_bom["components"][0].update(name="flowbridge-ffi",
                                              **{"bom-ref": "pkg:cargo/flowbridge-ffi@" + VERSION,
                                                 "purl": "pkg:cargo/flowbridge-ffi@" + VERSION})
        self.mac_bom["dependencies"][0]["ref"] = "pkg:cargo/flowbridge-ffi@" + VERSION
        self.mac_notices = b"Synthetic macOS dependency notices for validation tests only\n"
        self.mac_metadata = {**deepcopy(self.metadata), "platform": "macos",
                             "targets": ["aarch64-apple-darwin", "x86_64-apple-darwin"],
                             "shipped_cargo_roots": ["flowbridge-ffi"],
                             "sbom_sha256": sha(encoded(self.mac_bom)),
                             "notices_sha256": sha(self.mac_notices)}
        self.mac.update(sbom_sha256=sha(encoded(self.mac_bom)),
                        build_metadata_sha256=sha(encoded(self.mac_metadata)))
        self.scope = {
            **provenance, "source_gate": True, "native_package_gate": True,
            "extension_present": False, "release_accepted": False,
            "pkg_sha256": sha(self.pkg), "binary_arches": ["arm64", "x86_64"],
        }
        self.ssh = {
            **provenance, "source_commit": SOURCE, "passed": True,
            "managed_acceptance_proved": True, "scenario": "managed",
            "ffi_sha256": sha(self.payload["flowbridge_ffi.dll"]),
            "cli_sha256": sha(self.payload["flowbridge-cli.exe"]),
            "hosted_windows_runner": True, "windows_10_11_user_machine_tested": False,
            "wfp_driver_loaded": False, "native_dns_leaks_verified": False,
            "raw_backend_512_stability_proved": False,
            "managed_capacity": {"passed": True, "held": 128, "churn": 10000, "rejected": 1152},
            "owned_pool": {"passed": True, "independent_children": 4},
            "banner_first_real_ssh": {"cli_sha256": sha(self.payload["flowbridge-cli.exe"])},
            "supervised_banner_first_real_ssh": {"cli_sha256": sha(self.payload["flowbridge-cli.exe"])},
            "rust_owned_ssh_control": {"banner_helper_sha256": sha(self.payload["flowbridge-cli.exe"])},
        }
        self.core = [{**provenance, "runner_os": name, "passed": True, "format": True,
                      "clippy": True, "workspace_tests": True, "dns_loopback": True}
                     for name in ("Linux", "Windows", "macOS")]
        self.report_files = {
            "explicit-beta-package.json": self.windows,
            "explicit-beta-installer-result.json": self.installed,
            "explicit-macos-package.json": self.mac,
            "native-package.json": self.scope,
            "summary.json": self.ssh,
            **{f"core-{r['runner_os']}.json": r for r in self.core},
        }

    def validate(self) -> dict:
        return candidate.validate_reports(SOURCE, self.windows, self.installed,
                                          self.mac, self.scope, self.ssh, self.core)

    def write(self) -> None:
        for name, data in self.payload.items():
            path = self.stage / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.mac_resources.mkdir(parents=True, exist_ok=True)
        for name, data in (("SBOM.cdx.json", encoded(self.mac_bom)),
                           ("BUILD-METADATA.json", encoded(self.mac_metadata)),
                           ("THIRD_PARTY_NOTICES.txt", self.mac_notices)):
            (self.mac_resources / name).write_bytes(data)
        for name, report in self.report_files.items():
            (self.inputs / name).write_bytes(encoded(report))
        (self.inputs / f"FlowBridge-{VERSION}-windows-x64-setup.exe").write_bytes(self.installer)
        (self.inputs / f"FlowBridge-{VERSION}-macOS-universal-explicit-beta.pkg").write_bytes(self.pkg)
        (self.inputs / "FlowBridgeNativeSmoke.exe").write_bytes(self.harness)
        (self.root / "tools").mkdir(exist_ok=True)
        (self.root / "docs/qa").mkdir(parents=True, exist_ok=True)
        (self.root / "packaging").mkdir(exist_ok=True)
        (self.root / "tools/explicit_beta_acceptance.py").write_text("# synthetic QA tool\n")
        (self.root / "docs/qa/EXPLICIT_BETA_NATIVE_ACCEPTANCE.md").write_text("Native QA remains open.\n")
        (self.root / "Cargo.lock").write_bytes(self.lock)
        (self.root / "packaging/explicit-beta.json").write_bytes(self.contract)
        qa_tool = (self.root / "tools/explicit_beta_acceptance.py").read_bytes()
        for os_name, target, package, manifest in (
            ("Windows", "windows", self.installer, self.windows),
            ("macOS", "macos", self.pkg, self.mac),
        ):
            report = {
                "schema": "flowbridge-explicit-beta-native-acceptance-v1",
                "status": "CI_AUTOMATED_CHECKS_PASS", "source_sha": SOURCE,
                "workflow_run_id": RUN, "target": target,
                "package_sha256": sha(package), "manifest_sha256": sha(encoded(manifest)),
                "tool_sha256": sha(qa_tool),
                "host": {"github_hosted": True, "ci_environment_detected": True, "owner_native": False},
                "release_accepted": False, "a3_a4_full_acceptance": False,
                "checks": {name: "PASS" for name in
                           ("install", "payload", "launch", "upgrade", "uninstall", "stable_preserved")},
            }
            (self.inputs / f"native-qa-{os_name}.json").write_bytes(encoded(report))

    @staticmethod
    def git_read(args, **kwargs):
        if args == ["git", "rev-parse", "HEAD"]:
            return SOURCE + "\n"
        if args == ["git", "rev-parse", "HEAD^{tree}"]:
            return TREE + "\n"
        if args[:3] == ["git", "status", "--porcelain"]:
            return "" if kwargs.get("text") else b""
        raise AssertionError(f"Unexpected external operation in fixture: {args!r}")

    def assemble(self, run_id: str = RUN) -> Path:
        with mock.patch.object(candidate, "ROOT", self.root), \
                mock.patch.object(candidate.subprocess, "check_output", side_effect=self.git_read), \
                contextlib.redirect_stdout(io.StringIO()):
            return candidate.assemble(self.inputs, self.output, SOURCE, run_id)

    def replace_payload(self, name: str, data: bytes) -> None:
        self.payload[name] = data
        for entry in self.windows["payload"]:
            if entry["path"] == name:
                entry.update(sha256=sha(data), bytes=len(data))
                break


class CandidateReportContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.f = EvidenceFixture(Path(self.temp.name))

    def test_complete_hosted_report_never_grants_native_or_release_acceptance(self):
        report = self.f.validate()
        self.assertTrue(report["hosted_candidate_valid"])
        self.assertFalse(report["release_accepted"])
        self.assertFalse(report["publisher_release_approved"])
        self.assertEqual(report["native_release_1_0"], "NO_GO")
        self.assertEqual(report["gates"]["native_G2_packet_ownership"], "NO_GO")
        self.assertEqual(report["gates"]["A3_owner_windows"], "NOT_RUN")
        self.assertEqual(report["gates"]["A4_owner_mac"], "NOT_RUN")
        self.assertEqual(report["gates"]["A6_independent_release_review"], "OPEN")

    def test_each_report_is_bound_to_one_source(self):
        for name, field in (("windows", "source_sha"), ("installed", "source_sha"),
                            ("mac", "source_sha"), ("scope", "source_sha"),
                            ("ssh", "source_commit")):
            with self.subTest(report=name):
                report = getattr(self.f, name)
                before = report[field]
                report[field] = OTHER
                with self.assertRaises(ValueError):
                    self.f.validate()
                report[field] = before
        self.f.core[0]["source_sha"] = OTHER
        with self.assertRaises(ValueError):
            self.f.validate()

    def test_reports_from_different_workflow_runs_cannot_be_combined(self):
        self.f.ssh["workflow_run_id"] = "999999999"
        with self.assertRaises(ValueError):
            self.f.validate()

    def test_manifest_tree_must_equal_core_tree(self):
        self.f.mac["source_tree_sha"] = OTHER
        with self.assertRaises(ValueError):
            self.f.validate()

    def test_missing_duplicate_and_failed_core_platforms_are_rejected(self):
        valid = deepcopy(self.f.core)
        alternatives = [valid[:2], [valid[0], valid[1], valid[1]],
                        [dict(valid[0], workspace_tests=False), *valid[1:]],
                        [dict(valid[0], source_tree_sha=OTHER), *valid[1:]]]
        for reports in alternatives:
            with self.subTest(reports=reports):
                self.f.core = reports
                with self.assertRaises(ValueError):
                    self.f.validate()

    def test_changed_packaged_ffi_and_cli_are_rejected(self):
        for report, key in ((self.f.ssh, "ffi_sha256"), (self.f.ssh, "cli_sha256"),
                            (self.f.ssh["banner_first_real_ssh"], "cli_sha256"),
                            (self.f.ssh["supervised_banner_first_real_ssh"], "cli_sha256"),
                            (self.f.ssh["rust_owned_ssh_control"], "banner_helper_sha256")):
            with self.subTest(report=report, field=key):
                previous = report[key]
                report[key] = "d" * 64
                with self.assertRaises(ValueError):
                    self.f.validate()
                report[key] = previous

    def test_native_claims_cannot_be_promoted_from_hosted_ssh(self):
        for name in ("windows_10_11_user_machine_tested", "wfp_driver_loaded", "native_dns_leaks_verified"):
            with self.subTest(claim=name):
                self.f.ssh[name] = True
                with self.assertRaises(ValueError):
                    self.f.validate()
                self.f.ssh[name] = False

    def test_unsigned_distribution_scope_cannot_be_relabeled(self):
        for report in (self.f.windows, self.f.mac):
            for field, invalid in (("signed", True), ("publisher_release_approved", True),
                                   ("driver_included", True), ("explicit_socks_only", False)):
                with self.subTest(platform=report["schema"], field=field):
                    previous = report[field]
                    report[field] = invalid
                    with self.assertRaises(ValueError):
                        self.f.validate()
                    report[field] = previous

    def test_beta_version_and_package_identity_must_agree(self):
        self.f.mac["candidate"] = "0.3.0-beta.2"
        with self.assertRaises(ValueError):
            self.f.validate()
        self.f.mac["candidate"] = VERSION
        self.f.mac["bundle_id"] = "org.flowbridge.FlowBridge"
        with self.assertRaises(ValueError):
            self.f.validate()

    def test_128_1152_10000_4_capacity_contract_is_not_weakened(self):
        for name, invalid in (("held", 127), ("churn", 9999), ("rejected", 1)):
            with self.subTest(counter=name):
                old = self.f.ssh["managed_capacity"][name]
                self.f.ssh["managed_capacity"][name] = invalid
                with self.assertRaises(ValueError):
                    self.f.validate()
                self.f.ssh["managed_capacity"][name] = old
        self.f.ssh["owned_pool"]["independent_children"] = 3
        with self.assertRaises(ValueError):
            self.f.validate()

    def test_payload_requires_exact_allowlist_not_unknown_executable(self):
        self.f.windows["payload"].append({"path": "other-helper.exe", "sha256": "d" * 64, "bytes": 5})
        with self.assertRaises(ValueError):
            candidate.payload_map(self.f.windows)

    def test_unsafe_and_case_duplicate_payload_paths_are_rejected(self):
        original = deepcopy(self.f.windows["payload"])
        paths = ("../escaped.txt", "/absolute.txt", "licenses/../../escape.txt", "C:escape.txt",
                 "C:/escape.txt", "licenses\\escape.txt", "licenses//notice.txt", "LICENSES/third_party_notices.TXT",
                 "FlowBridgeCapture.exe", "driver.sys")
        for path in paths:
            with self.subTest(path=path):
                self.f.windows["payload"] = [*original, {"path": path, "sha256": "d" * 64, "bytes": 5}]
                with self.assertRaises(ValueError):
                    candidate.payload_map(self.f.windows)

    def test_missing_product_and_invalid_hash_are_rejected(self):
        self.f.windows["payload"] = [x for x in self.f.windows["payload"] if x["path"] != "flowbridge_ffi.dll"]
        with self.assertRaises(ValueError):
            self.f.validate()
        self.f.windows["payload"].append({"path": "flowbridge_ffi.dll", "sha256": "not-a-hash", "bytes": 14})
        with self.assertRaises(ValueError):
            self.f.validate()

    def test_package_reports_must_refer_to_installed_audited_bytes(self):
        for report, field in ((self.f.installed, "installer_sha256"),
                              (self.f.installed, "installed_gui_sha256"),
                              (self.f.scope, "pkg_sha256")):
            with self.subTest(field=field):
                old = report[field]
                report[field] = "e" * 64
                with self.assertRaises(ValueError):
                    self.f.validate()
                report[field] = old


class CandidateAssemblyContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.f = EvidenceFixture(Path(self.temp.name))

    def test_verified_originals_and_open_native_gates_survive_assembly(self):
        self.f.write()
        archive = self.f.assemble()
        with zipfile.ZipFile(archive) as bundle:
            self.assertIsNone(bundle.testzip())
            names = bundle.namelist()
            self.assertEqual(len(names), len(set(n.casefold() for n in names)))
            index = json.loads(bundle.read("candidate-index.json"))
            self.assertFalse(index["release_accepted"])
            self.assertEqual(index["workflow_run_id"], RUN)
            self.assertEqual(index["source_sha"], SOURCE)
            self.assertEqual(index["gates"]["A6_independent_release_review"], "OPEN")
            self.assertEqual(index["gates"]["operator_qa_runner_hosted_windows_and_macOS"], "PASS")
            self.assertEqual(index["gates"]["A3_owner_windows"], "NOT_RUN")
            self.assertEqual(index["gates"]["A4_owner_mac"], "NOT_RUN")
            for os_name in ("Windows", "macOS"):
                qa_report = json.loads(bundle.read(f"evidence/native-qa-{os_name}.json"))
                self.assertFalse(qa_report["host"]["owner_native"])
                self.assertFalse(qa_report["a3_a4_full_acceptance"])
            for entry in index["files"]:
                data = bundle.read(entry["path"])
                self.assertEqual(sha(data), entry["sha256"])
                self.assertEqual(len(data), entry["bytes"])
            sums = bundle.read("SHA256SUMS.txt").decode("ascii").splitlines()
            for line in sums:
                expected, path = line.split("  ", 1)
                self.assertEqual(sha(bundle.read(path)), expected)
            self.assertEqual(bundle.read("windows/FlowBridge-" + VERSION + "-windows-x64-setup.exe"), self.f.installer)
            self.assertEqual(bundle.read("macos/FlowBridge-" + VERSION + "-macOS-universal-explicit-beta.pkg"), self.f.pkg)

    def test_qa_runner_must_use_delivered_tool_package_and_manifest(self):
        self.f.write()
        for os_name in ("Windows", "macOS"):
            path = self.f.inputs / f"native-qa-{os_name}.json"
            valid = json.loads(path.read_bytes())
            for field, value in (("tool_sha256", "d" * 64), ("package_sha256", "d" * 64),
                                 ("manifest_sha256", "d" * 64), ("source_sha", OTHER),
                                 ("workflow_run_id", "987654321")):
                with self.subTest(platform=os_name, field=field):
                    path.write_bytes(encoded({**valid, field: value}))
                    with self.assertRaises(ValueError):
                        self.f.assemble()
                    self.assertFalse(self.f.output.exists())
                    path.write_bytes(encoded(valid))

    def test_hosted_qa_cannot_claim_owner_approval_or_skip_lifecycle(self):
        self.f.write()
        for os_name in ("Windows", "macOS"):
            path = self.f.inputs / f"native-qa-{os_name}.json"
            valid = json.loads(path.read_bytes())
            invalid = [
                {**valid, "release_accepted": True},
                {**valid, "a3_a4_full_acceptance": True},
                {**valid, "host": {**valid["host"], "owner_native": True}},
                {**valid, "host": {**valid["host"], "github_hosted": False}},
                {**valid, "host": {**valid["host"], "ci_environment_detected": False}},
                {**valid, "checks": {**valid["checks"], "upgrade": "NOT_RUN"}},
                {**valid, "status": "VERIFIED_BYTES_NATIVE_NOT_RUN"},
            ]
            for report in invalid:
                with self.subTest(platform=os_name, report=report):
                    path.write_bytes(encoded(report))
                    with self.assertRaises(ValueError):
                        self.f.assemble()
                    self.assertFalse(self.f.output.exists())
                    path.write_bytes(encoded(valid))

    def test_outer_run_cannot_relabel_reports_from_another_run(self):
        self.f.write()
        with self.assertRaises(ValueError):
            self.f.assemble(run_id="999999999")
        self.assertFalse(self.f.output.exists())

    def test_changed_installer_bytes_fail_before_candidate_is_written(self):
        self.f.write()
        path = self.f.inputs / f"FlowBridge-{VERSION}-windows-x64-setup.exe"
        path.write_bytes(self.f.installer + b"altered")
        with self.assertRaises(ValueError):
            self.f.assemble()
        self.assertFalse(self.f.output.exists())

    def test_changed_staged_ffi_fails_even_when_reports_claim_pass(self):
        self.f.write()
        (self.f.stage / "flowbridge_ffi.dll").write_bytes(b"different binary")
        with self.assertRaises(ValueError):
            self.f.assemble()
        self.assertFalse(self.f.output.exists())

    def test_changed_mac_package_and_harness_are_rejected(self):
        self.f.write()
        for name in (f"FlowBridge-{VERSION}-macOS-universal-explicit-beta.pkg", "FlowBridgeNativeSmoke.exe"):
            with self.subTest(file=name):
                path = self.f.inputs / name
                original = path.read_bytes()
                path.write_bytes(original + b"changed")
                with self.assertRaises(ValueError):
                    self.f.assemble()
                path.write_bytes(original)
                self.assertFalse(self.f.output.exists())

    def test_duplicate_input_report_cannot_shadow_valid_evidence(self):
        self.f.write()
        extra = self.f.inputs / "other-run"
        extra.mkdir()
        (extra / "summary.json").write_bytes(encoded(self.f.ssh))
        with self.assertRaises(ValueError):
            self.f.assemble()

    def test_self_consistent_metadata_from_other_source_is_rejected(self):
        self.f.metadata["source_sha"] = OTHER
        self.f.replace_payload("BUILD-METADATA.json", encoded(self.f.metadata))
        self.f.windows["build_metadata_sha256"] = sha(self.f.payload["BUILD-METADATA.json"])
        self.f.write()
        with self.assertRaises(ValueError):
            self.f.assemble()

    def test_self_consistent_metadata_cannot_claim_release_approval(self):
        self.f.metadata["publisher_release_approved"] = True
        self.f.replace_payload("BUILD-METADATA.json", encoded(self.f.metadata))
        self.f.windows["build_metadata_sha256"] = sha(self.f.payload["BUILD-METADATA.json"])
        self.f.write()
        with self.assertRaises(ValueError):
            self.f.assemble()

    def test_sbom_cannot_be_replaced_by_empty_json_with_fresh_payload_hash(self):
        self.f.replace_payload("SBOM.cdx.json", b"{}\n")
        self.f.windows["sbom_sha256"] = sha(self.f.payload["SBOM.cdx.json"])
        self.f.metadata["sbom_sha256"] = self.f.windows["sbom_sha256"]
        self.f.replace_payload("BUILD-METADATA.json", encoded(self.f.metadata))
        self.f.windows["build_metadata_sha256"] = sha(self.f.payload["BUILD-METADATA.json"])
        self.f.write()
        with self.assertRaises(ValueError):
            self.f.assemble()

    def test_metadata_lockfile_digest_must_match_checkout(self):
        self.f.metadata["cargo_lock_sha256"] = "d" * 64
        self.f.replace_payload("BUILD-METADATA.json", encoded(self.f.metadata))
        self.f.windows["build_metadata_sha256"] = sha(self.f.payload["BUILD-METADATA.json"])
        self.f.write()
        with self.assertRaises(ValueError):
            self.f.assemble()

    def test_mac_metadata_and_notices_are_verified_independently(self):
        self.f.write()
        path = self.f.mac_resources / "THIRD_PARTY_NOTICES.txt"
        path.write_bytes(b"unrelated macOS notices")
        with self.assertRaises(ValueError):
            self.f.assemble()

    def test_manifest_inventory_digests_must_equal_embedded_files(self):
        for platform, field in (("windows", "sbom_sha256"), ("windows", "build_metadata_sha256"),
                                ("mac", "sbom_sha256")):
            with self.subTest(platform=platform, field=field), tempfile.TemporaryDirectory() as directory:
                fixture = EvidenceFixture(Path(directory))
                getattr(fixture, platform)[field] = "d" * 64
                fixture.write()
                with self.assertRaises(ValueError):
                    fixture.assemble()
                self.assertFalse(fixture.output.exists())

    def test_candidate_version_must_match_frozen_version_contract(self):
        contract = json.loads(self.f.contract)
        contract["version"] = "0.4.0-beta.1"
        self.f.contract = encoded(contract)
        self.f.metadata["version_contract_sha256"] = sha(self.f.contract)
        self.f.mac_metadata["version_contract_sha256"] = sha(self.f.contract)
        self.f.replace_payload("BUILD-METADATA.json", encoded(self.f.metadata))
        self.f.windows["build_metadata_sha256"] = sha(self.f.payload["BUILD-METADATA.json"])
        self.f.mac["build_metadata_sha256"] = sha(encoded(self.f.mac_metadata))
        self.f.write()
        with self.assertRaises(ValueError):
            self.f.assemble()

    @unittest.skipIf(sys.platform == "win32", "Symlink creation on Windows requires platform-specific setup")
    def test_symlinked_payload_parent_cannot_escape_stage(self):
        self.f.write()
        outside = Path(self.temp.name) / "outside-licenses"
        (self.f.stage / "licenses").rename(outside)
        (self.f.stage / "licenses").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.f.assemble()


if __name__ == "__main__":
    unittest.main()
