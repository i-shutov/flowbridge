#!/usr/bin/env python3
"""Version contract and locked dependency inventory for explicit beta packages.

The CycloneDX SBOM describes resolved Cargo production/build inputs for the
shipped roots and targets. It does not claim that every crate survives linking,
nor replace binary composition, vulnerability or independent license review.
No host paths, build timestamps, credentials or environment values are emitted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "packaging/explicit-beta.json"
TARGETS = {
    "windows": ("x86_64-pc-windows-msvc",),
    "macos": ("aarch64-apple-darwin", "x86_64-apple-darwin"),
}
ROOTS = {"windows": ("flowbridge-cli", "flowbridge-ffi"), "macos": ("flowbridge-ffi",)}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encoded(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def command(args: list[str], root: Path = ROOT) -> str:
    return subprocess.check_output(args, cwd=root, text=True, encoding="utf-8", timeout=240).strip()


def read_contract(root: Path = ROOT) -> dict:
    config = json.loads((root / "packaging/explicit-beta.json").read_text(encoding="utf-8"))
    if config.get("schema") != "flowbridge-explicit-beta-version-v1":
        raise ValueError("Unknown explicit beta version schema")
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)-beta\.([1-9]\d*)", config.get("version", ""))
    if not match:
        raise ValueError("Explicit beta version must be major.minor.patch-beta.N")
    major, minor, patch, beta = match.groups()
    expected = {
        "windows_file_version": f"{major}.{minor}.{patch}.{beta}",
        "macos_short_version": f"{major}.{minor}.{patch}",
        "windows_installer": f"FlowBridge-{config['version']}-windows-x64-setup.exe",
        "macos_installer": f"FlowBridge-{config['version']}-macOS-universal-explicit-beta.pkg",
        "windows_namespace": "FlowBridgeExplicitBeta",
        "macos_bundle_id": "org.flowbridge.FlowBridgeExplicitBeta",
        "release_approved": False,
    }
    for key, value in expected.items():
        if config.get(key) != value:
            raise ValueError(f"Explicit beta contract mismatch: {key}")
    if not re.fullmatch(r"\d+\.\d+\.\d+", config.get("macos_bundle_version", "")):
        raise ValueError("macOS bundle version requires three numeric components")
    if any(int(n) > 65535 for n in (major, minor, patch, beta)):
        raise ValueError("Windows version component exceeds PE version range")
    return config


def check_versions(root: Path = ROOT) -> dict:
    contract = read_contract(root)
    workspace = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    if workspace["workspace"]["package"]["version"] != contract["version"]:
        raise ValueError("Cargo workspace and explicit beta version differ")
    lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
    local = {p["name"]: p for p in lock["package"] if p["name"].startswith("flowbridge-")}
    for member in workspace["workspace"]["members"]:
        package = tomllib.loads((root / member / "Cargo.toml").read_text(encoding="utf-8"))["package"]
        if package.get("version") != {"workspace": True}:
            raise ValueError(f"Workspace version not inherited by {package['name']}")
        if local.get(package["name"], {}).get("version") != contract["version"]:
            raise ValueError(f"Cargo.lock version mismatch: {package['name']}")
    return contract


def input_graph(metadata: dict, roots: tuple[str, ...]) -> tuple[set[str], set[str], dict[str, set[str]]]:
    """Select reachable non-dev dependencies; distinguish runtime and build inputs.

    A proc macro and its dependencies are build inputs even when its incoming
    Cargo dependency is normal. Build script packages can contribute generated
    linked code; the SBOM includes them, without claiming binary presence.
    """
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    start = {p["id"] for p in packages.values() if p["name"] in roots and p["id"] in metadata["workspace_members"]}
    if len(start) != len(roots):
        raise ValueError("Shipped Cargo roots missing from metadata")
    runtime, build, graph = set(), set(), {}
    pending = [(p, False) for p in sorted(start)]
    visited: set[tuple[str, bool]] = set()
    while pending:
        current, build_only = pending.pop()
        if (current, build_only) in visited:
            continue
        visited.add((current, build_only))
        (build if build_only else runtime).add(current)
        graph.setdefault(current, set())
        for dep in nodes[current].get("deps", []):
            kinds = dep.get("dep_kinds", [])
            usable = [k for k in kinds if k["kind"] != "dev"]
            if not usable:
                continue
            child = dep["pkg"]
            proc_macro = any("proc-macro" in t.get("kind", []) for t in packages[child]["targets"])
            for kind in usable:
                next_build = build_only or kind["kind"] == "build" or proc_macro
                graph[current].add(child)
                pending.append((child, next_build))
    return runtime, build, graph


def licenses(package: dict, root: Path) -> list[tuple[str, bytes]]:
    directory = Path(package["manifest_path"]).parent.resolve()
    candidates = {p for p in directory.iterdir() if p.is_file() and not p.is_symlink()
                  and p.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE"))}
    if package.get("license_file"):
        path = (directory / package["license_file"]).resolve(strict=True)
        if not path.is_relative_to(directory):
            raise ValueError(f"License file escapes crate source: {package['name']}")
        candidates.add(path)
    if not candidates and (package["name"], package["version"]) == ("valuable", "0.1.1"):
        candidates.add(root / "third_party/valuable/LICENSE.MIT")
    if not candidates:
        raise ValueError(f"No actual license files: {package['name']} {package['version']}")
    return [(p.name, p.read_bytes()) for p in sorted(candidates)]


def generate(platform: str, output: Path, *, root: Path = ROOT, offline: bool = False,
             nsis_root: Path | None = None) -> dict:
    contract = check_versions(root)
    source = command(["git", "rev-parse", "HEAD"], root)
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("Cannot establish source commit")
    # Builders must use a clean checkout; a real commit ID cannot identify dirty input.
    if command(["git", "status", "--porcelain", "--untracked-files=normal"], root):
        raise ValueError("Uncommitted source files: build metadata requires a clean checkout")
    lock_bytes = (root / "Cargo.lock").read_bytes()
    lock = tomllib.loads(lock_bytes.decode("utf-8"))
    locked = {(p["name"], p["version"], p.get("source")): p for p in lock["package"]}
    merged: dict[str, dict] = {}
    edges: dict[str, set[str]] = {}
    license_blobs: dict[str, list[tuple[str, bytes]]] = {}
    for target in TARGETS[platform]:
        args = ["cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", target]
        if offline:
            args.append("--offline")
        metadata = json.loads(command(args, root))
        runtime, build, graph = input_graph(metadata, ROOTS[platform])
        packages = {p["id"]: p for p in metadata["packages"]}
        refs = {p: f"pkg:cargo/{packages[p]['name']}@{packages[p]['version']}" for p in runtime | build}
        for package_id in sorted(runtime | build):
            package = packages[package_id]
            name, version = package["name"], package["version"]
            ref = refs[package_id]
            source_key = package.get("source")
            pin = locked.get((name, version, source_key))
            if pin is None:
                raise ValueError(f"Metadata package absent from exact lockfile: {name} {version}")
            entry = merged.setdefault(ref, {"type": "library", "bom-ref": ref, "name": name,
                                           "version": version, "purl": ref, "properties": []})
            values = {p["name"]: p["value"] for p in entry["properties"]}
            targets = set(filter(None, values.get("flowbridge:targets", "").split(","))) | {target}
            roles = set(filter(None, values.get("flowbridge:input_roles", "").split(",")))
            if package_id in runtime:
                roles.add("production-dependency")
            if package_id in build:
                roles.add("build-input")
            values.update({"flowbridge:targets": ",".join(sorted(targets)),
                           "flowbridge:input_roles": ",".join(sorted(roles)),
                           "flowbridge:binary_linkage": "not-inspected"})
            entry["properties"] = [{"name": k, "value": v} for k, v in sorted(values.items())]
            if pin.get("checksum"):
                entry["hashes"] = [{"alg": "SHA-256", "content": pin["checksum"]}]
            if package_id not in metadata["workspace_members"]:
                if package.get("license"):
                    entry["licenses"] = [{"expression": package["license"]}]
                license_blobs.setdefault(ref, licenses(package, root))
            else:
                entry["licenses"] = [{"license": {"name": "FlowBridge repository LICENSE"}}]
            edges.setdefault(ref, set()).update(refs[p] for p in graph[package_id])
    lines = [f"FlowBridge {contract['version']} explicit beta — resolved component notices\n",
             "Targets: " + ", ".join(TARGETS[platform]) + "\n",
             "Includes production and build inputs of the shipped Cargo roots; exact binary retention is not asserted.\n",
             "Externally installed OpenSSH and OS frameworks are not redistributed by this package.\n"]
    inventory = []
    for ref, files in sorted(license_blobs.items()):
        lines.append(f"\n{'=' * 72}\n{ref}\n")
        record = {"component": ref, "files": []}
        for name, data in files:
            text = data.decode("utf-8")
            lines.extend([f"\n--- {name} ---\n", text, "\n"])
            record["files"].append({"name": name, "sha256": digest(data)})
        inventory.append(record)
    if platform == "windows":
        data = (root / "third_party/nlohmann/LICENSE.MIT").read_bytes()
        lines.extend(["\n=== nlohmann/json 3.11.3 — vendored Windows GUI header ===\n", data.decode("utf-8"), "\n"])
        ref = "pkg:github/nlohmann/json@v3.11.3"
        merged[ref] = {"type": "library", "bom-ref": ref, "name": "nlohmann/json", "version": "3.11.3",
                       "purl": ref, "licenses": [{"license": {"id": "MIT"}}],
                       "hashes": [{"alg": "SHA-256", "content": digest((root / "third_party/nlohmann/json.hpp").read_bytes())}]}
        inventory.append({"component": ref, "files": [{"name": "LICENSE.MIT", "sha256": digest(data)}]})
        if nsis_root is None or not (nsis_root / "COPYING").is_file():
            raise ValueError("Windows packaging requires actual NSIS distribution COPYING")
        data = (nsis_root / "COPYING").read_bytes()
        lines.extend(["\n=== NSIS installer runtime distribution COPYING ===\n", data.decode("utf-8"), "\n"])
        inventory.append({"component": "NSIS installer runtime", "files": [{"name": "COPYING", "sha256": digest(data)}]})
        compiler = nsis_root / "Bin/makensis.exe"
        if not compiler.is_file():
            compiler = nsis_root / "makensis.exe"
        nsis_version = command([str(compiler), "/VERSION"], root).removeprefix("v")
        ref = "pkg:generic/nsis@" + nsis_version
        merged[ref] = {"type": "application", "bom-ref": ref, "name": "NSIS installer runtime",
                       "version": nsis_version, "purl": ref,
                       "licenses": [{"license": {"name": "NSIS distribution COPYING"}}],
                       "properties": [{"name": "flowbridge:input_roles", "value": "installer-bootstrapper"}]}
    sysroot = Path(command(["rustc", "--print", "sysroot"], root))
    runtime_files = []
    for relative in ("licenses/Apache-2.0.txt", "licenses/MIT.txt", "COPYRIGHT-library.html"):
        path = sysroot / "share/doc/rust" / relative
        if not path.is_file():
            raise ValueError(f"Rust runtime license missing: {relative}; install rust-docs")
        data = path.read_bytes()
        lines.extend([f"\n=== Rust runtime / {relative} ===\n", data.decode("utf-8"), "\n"])
        runtime_files.append({"name": relative, "sha256": digest(data)})
    rustc = command(["rustc", "--version"], root)
    inventory.append({"component": rustc, "files": runtime_files})
    rust_version = rustc.split()[1]
    ref = "pkg:generic/rust-standard-library@" + rust_version
    merged[ref] = {"type": "library", "bom-ref": ref, "name": "Rust standard library",
                   "version": rust_version, "purl": ref,
                   "licenses": [{"expression": "MIT OR Apache-2.0"}],
                   "properties": [{"name": "flowbridge:license_attribution", "value": "See bundled COPYRIGHT-library.html text for third-party components"}]}
    notices = "".join(lines).encode("utf-8")
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "name": "FlowBridge Explicit Beta",
                                      "version": contract["version"]},
                         "properties": [{"name": "flowbridge:source_sha", "value": source},
                                        {"name": "flowbridge:inventory_scope", "value": "resolved production and build inputs; binary linkage not inspected"}]},
            "components": [merged[k] for k in sorted(merged)],
            "dependencies": [{"ref": k, "dependsOn": sorted(v)} for k, v in sorted(edges.items())]}
    sbom_bytes = encoded(sbom)
    metadata = {"schema": "flowbridge-explicit-beta-build-metadata-v1", "version": contract["version"],
                "source_sha": source, "platform": platform, "targets": list(TARGETS[platform]),
                "shipped_cargo_roots": list(ROOTS[platform]), "cargo_lock_sha256": digest(lock_bytes),
                "version_contract_sha256": digest((root / "packaging/explicit-beta.json").read_bytes()),
                "rustc": rustc, "cargo": command(["cargo", "--version"], root),
                "sbom_sha256": digest(sbom_bytes), "notices_sha256": digest(notices),
                "component_count": len(merged), "license_inventory": inventory,
                "inventory_scope": "locked resolved production/build inputs; not exact binary composition",
                "native_sdk_and_runtime_distribution_review": "required; not performed by this Cargo inventory",
                "binary_linkage_reviewed": False, "independent_license_review_passed": False,
                "vulnerability_audit_performed": False, "publisher_release_approved": False,
                "explicit_socks_only": True, "driver_included": False, "system_extension_included": False}
    output.mkdir(parents=True, exist_ok=True)
    for name, data in (("SBOM.cdx.json", sbom_bytes), ("THIRD_PARTY_NOTICES.txt", notices),
                       ("BUILD-METADATA.json", encoded(metadata))):
        (output / name).write_bytes(data)
    return metadata


def macos_manifest(pkg: Path, output: Path, *, root: Path = ROOT) -> dict:
    config = check_versions(root)
    metadata_path = pkg.parent.parent / "Build/Products/Release/FlowBridgeExplicitBeta.app/Contents/Resources/BUILD-METADATA.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if metadata["source_sha"] != command(["git", "rev-parse", "HEAD"], root):
        raise ValueError("macOS package metadata is from another source")
    result = {"schema": "flowbridge-explicit-beta-macos-qa-package-v1", "candidate": config["version"],
              "source_sha": metadata["source_sha"], "source_tree_sha": command(["git", "rev-parse", "HEAD^{tree}"], root),
              "workflow_run_id": os.environ.get("GITHUB_RUN_ID"), "pkg": str(pkg.resolve()), "pkg_sha256": digest(pkg.read_bytes()),
              "pkg_bytes": pkg.stat().st_size, "bundle_id": config["macos_bundle_id"],
              "explicit_socks_only": True, "driver_included": False, "system_extension_included": False,
              "publisher_release_approved": False, "signed": False, "app_signature": "ad-hoc",
              "sbom_sha256": metadata["sbom_sha256"],
              "build_metadata_sha256": digest(metadata_path.read_bytes())}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(encoded(result))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("check", help="Offline version/lockfile consistency check; does not run Cargo")
    field = sub.add_parser("field", help="Read one version contract field")
    field.add_argument("name")
    build = sub.add_parser("generate")
    build.add_argument("--platform", choices=sorted(TARGETS), required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--offline", action="store_true")
    build.add_argument("--nsis-root", type=Path)
    manifest = sub.add_parser("macos-manifest")
    manifest.add_argument("--pkg", type=Path, required=True)
    manifest.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "field":
        print(read_contract()[args.name])
    elif args.action == "check":
        print(json.dumps({"version": check_versions()["version"], "version_consistency": "PASS"}))
    elif args.action == "generate":
        result = generate(args.platform, args.output, offline=args.offline, nsis_root=args.nsis_root)
        print(json.dumps({"version": result["version"], "components": result["component_count"],
                          "platform": result["platform"], "source_sha": result["source_sha"]}))
    else:
        print(json.dumps(macos_manifest(args.pkg, args.output)))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"Explicit beta metadata failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
