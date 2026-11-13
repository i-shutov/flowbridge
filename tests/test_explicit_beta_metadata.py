"""Negative coverage for version identity and production dependency selection."""
import importlib.util
import json
from pathlib import Path
import shutil
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
            lock.write_text(lock.read_text().replace('version = "0.3.0-beta.1"', 'version = "0.3.0"', 1))
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


if __name__ == "__main__":
    unittest.main()
