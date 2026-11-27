"""Negative coverage for version identity and production dependency selection."""
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("beta_metadata", ROOT / "tools/explicit_beta_metadata.py")
META = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(META)


class MetadataTests(unittest.TestCase):
    def fixture(self, target: Path) -> None:
        for relative in ("packaging/explicit-beta.json", "Cargo.toml", "Cargo.lock"):
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        for manifest in (ROOT / "crates").glob("*/Cargo.toml"):
            destination = target / manifest.relative_to(ROOT)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(manifest, destination)

    def test_workspace_lock_version_drift_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            META.check_versions(root)
            lock = root / "Cargo.lock"
            lock.write_text(lock.read_text().replace('version = "0.3.0-beta.2"', 'version = "0.3.0"', 1))
            with self.assertRaisesRegex(ValueError, "Cargo.lock version mismatch"):
                META.check_versions(root)

    def test_installer_namespace_and_version_cannot_diverge(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            path = root / "packaging/explicit-beta.json"
            config = json.loads(path.read_text())
            config["macos_bundle_id"] = "org.flowbridge.FlowBridge"
            path.write_text(json.dumps(config))
            with self.assertRaisesRegex(ValueError, "macos_bundle_id"):
                META.read_contract(root)

    def test_dirty_input_does_not_acquire_clean_commit_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            def run(args, *_):
                if args == ["git", "rev-parse", "HEAD"]:
                    return "1" * 40
                if args[:2] == ["git", "status"]:
                    return " M Cargo.toml"
                self.fail("No dependency inventory may run after dirty-source failure")
            with patch.object(META, "command", side_effect=run):
                with self.assertRaisesRegex(ValueError, "Uncommitted source"):
                    META.generate("macos", root / "output", root=root)
            self.assertFalse((root / "output").exists())

    def test_dev_unrelated_and_proc_macro_inputs_are_not_runtime_claims(self):
        kinds = {"root": ["lib"], "normal": ["lib"], "derive": ["proc-macro"],
                 "macro-helper": ["lib"], "build": ["lib"], "dev": ["lib"], "unrelated": ["lib"]}
        packages = [{"id": name, "name": name, "targets": [{"kind": kind}]} for name, kind in kinds.items()]
        def dep(name, kind=None):
            return {"pkg": name, "dep_kinds": [{"kind": kind, "target": None}]}
        nodes = [{"id": name, "deps": []} for name in kinds]
        nodes[0]["deps"] = [dep("normal"), dep("derive"), dep("build", "build"), dep("dev", "dev")]
        nodes[2]["deps"] = [dep("macro-helper")]
        metadata = {"packages": packages, "workspace_members": ["root", "unrelated"],
                    "resolve": {"nodes": nodes}}
        runtime, build, graph = META.input_graph(metadata, ("root",))
        self.assertEqual(runtime, {"root", "normal"})
        self.assertEqual(build, {"derive", "macro-helper", "build"})
        self.assertNotIn("dev", graph["root"])
        self.assertNotIn("unrelated", graph)

    def test_license_path_cannot_escape_selected_crate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            crate = root / "crate"
            crate.mkdir()
            (root / "external-license").write_text("This is not crate-owned license material")
            package = {"manifest_path": str(crate / "Cargo.toml"), "name": "example", "version": "1",
                       "license_file": "../external-license"}
            with self.assertRaisesRegex(ValueError, "escapes crate source"):
                META.licenses(package, root)

    def test_windows_generator_includes_native_input_provenance_and_attributions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            for relative in (".cargo/config.toml", "third_party/nlohmann/LICENSE.MIT",
                             "third_party/nlohmann/ATTRIBUTIONS.txt", "third_party/nlohmann/json.hpp"):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)

            build = root / "build/windows-explicit-beta"
            compiler = build / "CMakeFiles/4.1.3/CMakeCXXCompiler.cmake"
            compiler.parent.mkdir(parents=True)
            compiler.write_text('set(CMAKE_CXX_COMPILER_ID "MSVC")\n'
                                'set(CMAKE_CXX_COMPILER_VERSION "19.44.35207.0")\n')
            (build / "CMakeCache.txt").write_text("CMAKE_CACHE_MAJOR_VERSION:INTERNAL=4\n"
                "CMAKE_CACHE_MINOR_VERSION:INTERNAL=1\nCMAKE_CACHE_PATCH_VERSION:INTERNAL=3\n")
            project = """<?xml version="1.0" encoding="utf-8"?>
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
    <PropertyGroup><WindowsTargetPlatformVersion>10.0.26100.0</WindowsTargetPlatformVersion></PropertyGroup>
    <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
        <PlatformToolset>v143</PlatformToolset>
    </PropertyGroup>
    <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
        <ClCompile><RuntimeLibrary>MultiThreaded</RuntimeLibrary></ClCompile>
    </ItemDefinitionGroup>
</Project>"""
            for name in ("FlowBridge", "FlowBridgeNativeSmoke"):
                (build / (name + ".vcxproj")).write_text(project)

            nsis = root / "nsis"
            runtime_inputs = ("Stubs/lzma_solid-x86-unicode", "Plugins/x86-unicode/System.dll",
                              "Plugins/x86-unicode/LangDLL.dll", "Plugins/x86-unicode/nsDialogs.dll")
            for relative in runtime_inputs:
                target = nsis / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                header = bytearray(70)
                header[:2] = b"MZ"
                struct.pack_into("<I", header, 0x3c, 64)
                header[64:] = b"PE\0\0\x4c\x01"
                target.write_bytes(header + relative.encode())
            (nsis / "COPYING").write_text("NSIS license text")

            sysroot = root / "rust"
            for relative in ("licenses/Apache-2.0.txt", "licenses/MIT.txt", "COPYRIGHT-library.html"):
                target = sysroot / "share/doc/rust" / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("Rust license text")
            version = META.read_contract(root)["version"]
            roots = META.ROOTS["windows"]
            cargo = {"packages": [{"id": name, "name": name, "version": version, "targets": [{"kind": ["lib"]}]}
                                  for name in roots],
                     "workspace_members": roots,
                     "resolve": {"nodes": [{"id": name, "deps": []} for name in roots]}}
            commands = {("git", "rev-parse", "HEAD"): "1" * 40,
                        ("git", "status", "--porcelain", "--untracked-files=normal"): "",
                        ("cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform",
                         "x86_64-pc-windows-msvc"): json.dumps(cargo),
                        (str(nsis / "makensis.exe"), "/VERSION"): "v3.13",
                        ("rustc", "--print", "sysroot"): str(sysroot),
                        ("rustc", "--version"): "rustc 1.100.0 (ab0123456 2026-11-27)",
                        ("cargo", "--version"): "cargo 1.100.0 (ab0123456 2026-11-27)"}
            output = root / "metadata"
            with patch.object(META, "command", side_effect=lambda args, _: commands[tuple(args)]):
                result = META.generate("windows", output, root=root, nsis_root=nsis)
            notices = (output / "THIRD_PARTY_NOTICES.txt").read_bytes()
            self.assertIn("Björn Hoehrmann".encode(), notices)
            self.assertIn(b"Florian Loitsch", notices)
            attribution = next(entry for entry in result["license_inventory"] if "nlohmann" in entry["component"])
            self.assertEqual([entry["name"] for entry in attribution["files"]], ["LICENSE.MIT", "ATTRIBUTIONS.txt"])
            self.assertEqual(result["notices_sha256"], META.digest(notices))
            bom = json.loads((output / "SBOM.cdx.json").read_bytes())
            components = {item["purl"]: item for item in bom["components"]}
            edges = {item["ref"]: item["dependsOn"] for item in bom["dependencies"]}
            self.assertEqual({components[ref]["name"] for ref in edges["pkg:generic/nsis@3.13"]}, set(runtime_inputs))
            for ref in edges["pkg:generic/nsis@3.13"]:
                nsis_input = components[ref]
                self.assertEqual(nsis_input["hashes"][0]["content"],
                                 META.digest((nsis / nsis_input["name"]).read_bytes()))
                self.assertIn({"name": "flowbridge:binary_linkage", "value": "distribution-file-hash-only"},
                              nsis_input["properties"])
            self.assertEqual(result["windows_nsis_distribution_members"], {
                "compiler_input_selection_verified": False, "installer_embedded_members_verified": False,
            })
            for name in roots:
                self.assertIn("pkg:generic/msvc-static-runtime", edges[f"pkg:cargo/{name}@{version}"])
            native = result["windows_native_build_inputs"]
            self.assertEqual(native["msvc_cxx_compiler_version"], "19.44.35207.0")
            self.assertFalse(native["static_linker_members_verified"])
            self.assertIn("Windows PowerShell", result["windows_managed_ssh_external_runtimes"][1])
            self.assertFalse(result["independent_license_review_passed"])

            (build / "FlowBridge.vcxproj").write_text(project.replace("MultiThreaded", "MultiThreadedDLL"))
            with self.assertRaisesRegex(ValueError, "non-static Windows Release settings"):
                META.windows_build_inputs(root, build)

            wrong_machine = bytearray((nsis / runtime_inputs[0]).read_bytes())
            struct.pack_into("<H", wrong_machine, 68, 0x8664)
            (nsis / runtime_inputs[0]).write_bytes(wrong_machine)
            with self.assertRaisesRegex(ValueError, "Invalid x86 PE header"):
                META.nsis_runtime_inputs(nsis, "3.13")


if __name__ == "__main__":
    unittest.main()
