"""Focused checks for the beta.4 notice and native-input evidence chain."""
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import test_beta3_frozen_static_audit as old_tests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import beta4_frozen_static_audit as audit


class Beta4StaticInventory(unittest.TestCase):
    def test_beta4_requires_exact_attributions_in_new_notice_format(self):
        notices, inventory, rustc = old_tests.notice_fixture()
        old = ("\n=== nlohmann/json 3.11.3 — vendored Windows GUI header ===\n").encode()
        attributions = "Copyright © attribution owners".encode()
        notices = notices.replace(b"0.3.0-beta.3", b"0.3.0-beta.4", 1)
        notices = notices.replace(old + b"nlohmann MIT", old + b"\n--- LICENSE.MIT ---\n"
                                  b"nlohmann MIT\n\n--- ATTRIBUTIONS.txt ---\n" + attributions)
        inventory[1]["files"].append({"name": "ATTRIBUTIONS.txt", "sha256": audit.sha(attributions)})
        parsed = audit.license_notice_bytes(notices, inventory, rustc, version=audit.VERSION,
                                            nlohmann_attributions=True)
        self.assertEqual(parsed[audit.NLOHMANN_REF, "ATTRIBUTIONS.txt"], attributions)
        with self.assertRaisesRegex(audit.Rejected, "notice_text_hash"):
            audit.license_notice_bytes(notices.replace(attributions, b"changed"), inventory, rustc,
                                       version=audit.VERSION, nlohmann_attributions=True)
        with self.assertRaisesRegex(audit.Rejected, "notice_nlohmann_license"):
            audit.license_notice_bytes(notices, inventory, rustc, version=audit.VERSION)

    def test_exact_nsis_compiler_and_resources_are_rehashed(self):
        relative_paths = ("Bin/makensis.exe", "COPYING", *audit.NSIS_ENTRIES.values())
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, "w") as bundle:
                for rel in relative_paths:
                    entry = "nsis-3.13/" + rel
                    data = rel.encode()
                    bundle.writestr(entry, data)
                    path = root / entry
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
            payload = archive.getvalue()
            with patch.object(audit, "NSIS_ARCHIVE_SHA", audit.sha(payload)):
                expected = {rel: audit.sha(rel.encode()) for rel in relative_paths}
                self.assertEqual(audit.distribution_inputs(payload, root), expected)
                (root / "nsis-3.13/Bin/makensis.exe").write_bytes(b"replacement")
                with self.assertRaisesRegex(audit.Rejected, "nsis_extracted_input_bytes"):
                    audit.distribution_inputs(payload, root)

    def test_native_build_cache_pins_cmake_and_exact_target_records(self):
        cache = (b"FLOWBRIDGE_EXPLICIT_BETA_ONLY:BOOL=ON\r\n"
                 b"CMAKE_GENERATOR:INTERNAL=Visual Studio 17 2022\r\n"
                 b"CMAKE_GENERATOR_PLATFORM:INTERNAL=x64\r\n")
        observed = {"cmake": "4.1.1", "msvc_cxx_compiler_version": "19.44.35230.0",
                    "cmake_cxx_compiler_sha256": "1" * 64,
                    "targets": {"FlowBridge": {"runtime_library": "MultiThreaded", "platform_toolset": "v143",
                                "windows_target_platform_version": "10.0.26100.0", "project_sha256": "2" * 64}},
                    "static_linker_members_verified": False}
        expected = {"cmake": "4.1.1", "generator": "Visual Studio 17 2022", "generator_platform": "x64",
                    "cmake_cache_sha256": audit.sha(cache), "cmake_compiler_config_sha256": "1" * 64,
                    "msvc_cxx_compiler_version": "19.44.35230.0",
                    "generated_targets": {"FlowBridge": {"msvc_runtime_library": "MultiThreaded",
                        "platform_toolset": "v143", "windows_target_platform_version": "10.0.26100.0",
                        "vcxproj_sha256": "2" * 64}},
                    "rust_crt_static_configured_targets": ["flowbridge-cli", "flowbridge-ffi"],
                    "static_linker_members_verified": False}
        with (patch.object(audit, "generated_msvc_settings", return_value=observed),
              patch.object(audit, "local_bytes", return_value=cache)):
            self.assertEqual(audit.native_provenance(Path("unused"), expected), observed)
            with self.assertRaisesRegex(audit.Rejected, "cmake_sbom_input_chain"):
                audit.native_provenance(Path("unused"), {**expected, "cmake_cache_sha256": "0" * 64})

    def test_wrong_manifest_fails_before_payload_traversal(self):
        with (patch.object(audit, "local_bytes", return_value=b"wrong beta artifact"),
              patch.object(audit, "payload_paths") as walk):
            with self.assertRaisesRegex(audit.Rejected, "manifest_sha256"):
                audit.audit(Path("unused"))
            walk.assert_not_called()


if __name__ == "__main__":
    unittest.main()
