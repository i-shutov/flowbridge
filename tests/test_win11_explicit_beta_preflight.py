import importlib.util
from pathlib import Path, PureWindowsPath
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "preflight", Path(__file__).resolve().parents[1] / "tools/win11_explicit_beta_preflight.py",
)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class Win11PreflightTest(unittest.TestCase):
    def setUp(self):
        self.pins = {"source": "1" * 40, "tree": "2" * 40,
                     "installer": "3" * 64, "manifest": "4" * 64,
                     "harness": "5" * 64, "tool": "6" * 64}
        self.manifest = {
            "schema": "flowbridge-explicit-beta-windows-qa-package-v1",
            "candidate": "0.3.0-beta.4", "source_sha": self.pins["source"],
            "source_tree_sha": self.pins["tree"], "installer_sha256": self.pins["installer"],
            "installer_bytes": 20, "qa_harness": {"sha256": self.pins["harness"], "bytes": 30},
            "explicit_socks_only": True, "gui_protected_ui_compiled_disabled": True,
            "driver_included": False, "capture_helper_included": False,
            "system_service_included": False, "signed": False, "publisher_release_approved": False,
            "profile_namespace": "FlowBridgeExplicitBeta", "uninstall_registration": "FlowBridgeExplicitBeta",
            "payload": [{"path": path, "sha256": "f" * 64, "bytes": 99}
                        for path in sorted(preflight.PAYLOAD)],
        }

    def test_run_directory_excludes_frozen_candidate(self):
        accepted = preflight.PRIVATE / "run-beta4-12345-1/candidate"
        self.assertEqual(preflight.candidate_root(accepted), accepted)
        for tail in ("run-45986630920-1/candidate", "run-beta4-12345-01/candidate",
                     "run-beta4-12345-1/candidate/..", "../run-beta4-12345-1/candidate"):
            with self.subTest(tail=tail), self.assertRaisesRegex(preflight.Blocked, "outside_beta4"):
                preflight.candidate_root(preflight.PRIVATE / PureWindowsPath(tail))

    def test_manifest_pins_and_allowlist(self):
        preflight.check_pins(self.pins)
        installer, harness, payload = preflight.validate_manifest(self.manifest, self.pins)
        self.assertEqual((installer, harness), (20, 30))
        self.assertEqual(payload.keys(), preflight.PAYLOAD)
        for key, value in (("source_tree_sha", "0" * 40), ("candidate", "0.3.0-beta.3"),
                           ("capture_helper_included", 0), ("system_service_included", True)):
            with self.subTest(key=key), self.assertRaisesRegex(preflight.Blocked, "manifest_contract"):
                preflight.validate_manifest(dict(self.manifest, **{key: value}), self.pins)
        self.manifest["payload"][0]["path"] = "../FlowBridge.exe"
        with self.assertRaisesRegex(preflight.Blocked, "payload_allowlist"):
            preflight.validate_manifest(self.manifest, self.pins)

    def test_session_zero_never_serves_as_active_input_desktop(self):
        sessions = [{"id": 2, "target_account": True}, {"id": 3, "target_account": False}]
        self.assertEqual(preflight.desktop_status(0, sessions, True), "BLOCKED_SESSION_0")
        self.assertEqual(preflight.desktop_status(2, sessions, False), "BLOCKED_INPUT_DESKTOP_UNAVAILABLE")
        self.assertEqual(preflight.desktop_status(3, sessions, True), "BLOCKED_SESSION_NOT_ACTIVE_FOR_ACCOUNT")
        self.assertEqual(preflight.desktop_status(2, sessions, True), "INTERACTIVE_DESKTOP_OBSERVED")

    def test_path_metadata_stops_before_symlink(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            target = root / "private"
            target.mkdir()
            link = root / "link"
            try:
                link.symlink_to(target, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"Symlink fixture unavailable: {error.__class__.__name__}")
            self.assertEqual(preflight.path_status(root / "missing/file"), "absent")
            self.assertEqual(preflight.path_status(link / "profile.json"), "reparse")

    def test_no_prior_beta_registration_or_metadata_is_required(self):
        beta = {key: "absent" for key in ("profile_directory", "profile_file",
                                        "desktop_settings_file", "default_install_directory",
                                        "shortcuts_directory")}
        beta["registry"] = {"64": {"install_dir_value": False, "uninstall_key": False,
                                  "installer_language_value": True}}
        state = {"beta": beta, "flowbridge_process_count": 0}
        self.assertEqual(preflight.isolation_status(state), "ISOLATION_BASELINE_AVAILABLE")
        beta["registry"]["64"]["uninstall_key"] = True
        self.assertEqual(preflight.isolation_status(state), "BLOCKED_EXISTING_BETA_REGISTRATION")
        state["flowbridge_process_count"] = 1
        self.assertEqual(preflight.isolation_status(state), "BLOCKED_RUNNING_FLOWBRIDGE")


if __name__ == "__main__":
    unittest.main()
