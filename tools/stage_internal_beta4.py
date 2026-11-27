#!/usr/bin/env python3
"""Cut a private, explicit-SOCKS-only beta.4 candidate from one audited source tree."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import internal_windows_build_preflight as windows_build
from stage_internal_beta3 import git, index_exact_source, must, safe_archive_files, sha

PINNED_SOURCE = "1261201d8561ee4e70faccc8699f60606a71c93b"
PINNED_SOURCE_TREE = "b42325734201827e6b4d7566b4b3418205d78889"
CANDIDATE_TREE = "ce336e83bb724a65bf512e79e286c97fb0cb3190"
CANDIDATE_VERSION = "0.3.0-beta.4"
INSTALLER = f"FlowBridge-{CANDIDATE_VERSION}-windows-x64-setup.exe"
SOURCE_PATCH = Path(__file__).with_name("internal_beta4_source.patch")
NATIVE_BUILD = Path("build/windows-explicit-beta")
NSIS_RESOURCES = {
    "Stubs/lzma_solid-x86-unicode",
    "Plugins/x86-unicode/System.dll",
    "Plugins/x86-unicode/LangDLL.dll",
    "Plugins/x86-unicode/nsDialogs.dll",
}


def reject_links(path: Path) -> None:
    for part in (*reversed(path.parents), path):
        if os.path.lexists(part):
            info = part.lstat()
            must(not stat.S_ISLNK(info.st_mode) and not (
                getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
            ), "local_path_reparse_point")


def stage_source(source: Path, destination: Path) -> str:
    must(git(source, "rev-parse", "HEAD") == PINNED_SOURCE, "source_sha_not_pinned")
    must(git(source, "rev-parse", "HEAD^{tree}") == PINNED_SOURCE_TREE, "source_tree_not_pinned")
    must(not git(source, "status", "--porcelain", "--untracked-files=all"), "source_worktree_dirty")
    archive = subprocess.check_output(
        ["git", "-C", str(source), "archive", "--format=zip", PINNED_SOURCE], timeout=120)
    extracted = safe_archive_files(archive)

    destination.mkdir()
    for relative, (data, mode) in extracted.items():
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)
        if os.name != "nt" and mode:
            target.chmod(mode)
    git(destination, "init", "-q")
    index_exact_source(destination, extracted)
    must(git(destination, "write-tree") == PINNED_SOURCE_TREE, "source_archive_changed_tree")
    git(destination, "update-index", "--refresh")
    git(destination, "apply", "--index", "--unidiff-zero", str(SOURCE_PATCH))
    must(git(destination, "write-tree") == CANDIDATE_TREE, "candidate_tree_not_pinned")
    # Create the one-root commit without config-driven hooks or signing.
    commit = git(destination, "-c", "user.name=FlowBridge Private Build",
                 "-c", "user.email=qa@example.invalid", "commit-tree", CANDIDATE_TREE,
                 "-m", f"Prepare private FlowBridge {CANDIDATE_VERSION} source",
                 "-m", f"Source: {PINNED_SOURCE}")
    git(destination, "update-ref", "HEAD", commit)
    must(not git(destination, "remote"), "candidate_unexpected_remote")
    must(not git(destination, "status", "--porcelain", "--untracked-files=all"),
         "candidate_source_worktree_dirty")
    return commit


def verify_package(destination: Path, commit: str, nsis_root: Path, toolchain: dict) -> dict:
    manifest_file = destination / "build/verification/explicit-beta-package.json"
    installer = destination / "artifacts" / INSTALLER
    harness = destination / NATIVE_BUILD / "Release/FlowBridgeNativeSmoke.exe"
    nsis_log = destination / NATIVE_BUILD / "nsis-compile.log"
    acceptance_tool = destination / "tools/explicit_beta_acceptance.py"
    stage = destination / "build/explicit-beta-payload"
    for path in (manifest_file, installer, harness, nsis_log, acceptance_tool, stage):
        reject_links(path)
    original_manifest = manifest_file.read_bytes()
    manifest = json.loads(original_manifest)
    acceptance_tool_sha = sha(acceptance_tool.read_bytes())
    must(acceptance_tool_sha == "faf62aabeea95ef316f5c0935177a65820ea4679ac94afe8b5461138dd17a33c",
         "acceptance_tool_source_bytes_mismatch")
    checks = runpy.run_path(str(acceptance_tool))
    verify_file = checks["verified_file"]
    installer_sha = sha(installer.read_bytes())
    must(checks["validate_manifest"](manifest, commit, installer_sha) == "windows"
         and manifest["candidate"] == CANDIDATE_VERSION
         and manifest["source_tree_sha"] == CANDIDATE_TREE
         and manifest["wfp_native_gate"] == "NO_GO"
         and all(manifest[key] is False for key in (
             "system_dns_or_proxy_mutated", "app_specific_interception", "udp_or_quic_proxied",
             "independent_reviewer_passed")),
         "package_version_scope_or_source_tree_mismatch")
    verify_file(installer, installer_sha, manifest["installer_bytes"])
    verify_file(harness, manifest["qa_harness"]["sha256"], manifest["qa_harness"]["bytes"])
    verify_file(nsis_log, manifest["nsis_compile_log_sha256"])
    payload = {item["path"]: item for item in manifest["payload"]}
    for path in stage.rglob("*"):
        reject_links(path)
    must({path.relative_to(stage).as_posix() for path in stage.rglob("*") if path.is_file()}
         == payload.keys(), "package_staged_payload_mismatch")
    for name, item in payload.items():
        member = checks["contained_payload_file"](stage, name)
        verify_file(member, item["sha256"], item["bytes"])
    verify_file(stage / "BUILD-METADATA.json", manifest["build_metadata_sha256"])
    verify_file(stage / "SBOM.cdx.json", manifest["sbom_sha256"])
    metadata = json.loads((stage / "BUILD-METADATA.json").read_bytes())
    verify_file(stage / "licenses/THIRD_PARTY_NOTICES.txt", metadata["notices_sha256"])
    nsis = metadata["windows_nsis_distribution_members"]
    must(nsis["compiler_passed_explicitly"] is True
         and nsis["compiler_relative_path"] == toolchain["compiler_relative_path"]
         and nsis["compiler_sha256"] == toolchain["compiler_sha256"]
         and "v" + nsis["compiler_version"] == toolchain["compiler_version"]
         and nsis["resource_sha256"].keys() == NSIS_RESOURCES
         and nsis["installer_embedded_members_verified"] is False,
         "nsis_compiler_or_resource_provenance_mismatch")
    for name, digest in {**nsis["resource_sha256"], "COPYING": nsis["copying_sha256"],
                         nsis["compiler_relative_path"]: nsis["compiler_sha256"]}.items():
        member = nsis_root / name
        reject_links(member)
        verify_file(member, digest)
    native = metadata["windows_native_build_inputs"]
    must(metadata["source_sha"] == commit and native["generator_platform"] == "x64",
         "native_configuration_source_mismatch")
    build = destination / NATIVE_BUILD
    verify_file(build / "CMakeCache.txt", native["cmake_cache_sha256"])
    verify_file(build / "CMakeFiles" / native["cmake"] / "CMakeCXXCompiler.cmake",
                native["cmake_compiler_config_sha256"])
    for target in ("FlowBridge", "FlowBridgeNativeSmoke"):
        verify_file(build / f"{target}.vcxproj", native["generated_targets"][target]["vcxproj_sha256"])
    return {
        "installer_sha256": installer_sha,
        "package_manifest_sha256": sha(original_manifest),
        "gui_sha256": payload["FlowBridge.exe"]["sha256"],
        "cli_sha256": payload["flowbridge-cli.exe"]["sha256"],
        "ffi_sha256": payload["flowbridge_ffi.dll"]["sha256"],
        "qa_harness_sha256": manifest["qa_harness"]["sha256"],
        "acceptance_tool_sha256": acceptance_tool_sha,
        "build_metadata_sha256": manifest["build_metadata_sha256"],
        "sbom_sha256": manifest["sbom_sha256"],
        "nsis_compile_log_sha256": manifest["nsis_compile_log_sha256"],
        "nsis_distribution_inputs": nsis,
        "native_build_inputs": native,
        "staged_payload_allowlist_verified": True,
    }


def stage(source: Path, destination: Path, *, nsis_archive: Path | None = None) -> dict:
    source = source.absolute()
    destination = destination.absolute()
    checkpoint = destination.with_name(destination.name + "-CHECKPOINT.json")
    for path in (source, destination, checkpoint):
        reject_links(path)
    must(not os.path.lexists(destination) and not os.path.lexists(checkpoint)
         and destination != source and source not in destination.parents,
         "destination_must_be_new_outside_source")
    build = nsis_archive is not None
    if build:
        must(windows_build.detect_windows_build_host()["os"] == "Windows 11", "windows_11_build_required")
        reject_links(nsis_archive.absolute())

    commit = stage_source(source, destination)
    result = {
        "schema": "flowbridge-internal-beta4-private-staging-v1",
        "status": "PRIVATE_SOURCE_ONLY_READY_NOT_BUILT",
        "original_verified_source_sha": PINNED_SOURCE,
        "original_verified_source_tree": PINNED_SOURCE_TREE,
        "new_version": CANDIDATE_VERSION,
        "new_private_git_commit": commit,
        "new_private_git_tree": CANDIDATE_TREE,
        "standalone_git_repository_has_remote": False,
        "installer_built": False,
        "installer_installed": False,
        "driver_built_or_installed": False,
        "win11_product_accepted": False,
        "internal_pilot_approved": False,
        "public_release_or_upload_performed": False,
    }
    subprocess.run([sys.executable, "-I", "tools/explicit_beta_metadata.py", "check"],
                   cwd=destination, check=True, timeout=90)
    if build:
        directory = destination.with_name(destination.name + "-nsis-toolchain")
        reject_links(directory)
        env, provenance = windows_build.prepare_windows_build_environment(
            nsis_archive=nsis_archive, toolchain_dir=directory)
        toolchain = provenance["nsis"]
        nsis_root = directory / toolchain["distribution_relative_path"]
        compiler = nsis_root / toolchain["compiler_relative_path"]
        reject_links(compiler)
        subprocess.run([sys.executable, "-I", "packaging/windows/build-explicit-beta.py",
                        "--nsis-compiler", str(compiler)],
                       cwd=destination, check=True, timeout=2400, env=env)
        result.update(verify_package(destination, commit, nsis_root, toolchain))
        result.update(status="PRIVATE_LOCAL_INSTALLER_BUILT_QA_NOT_ACCEPTED", installer_built=True,
                      build_host=provenance["build_host"], nsis_archive_sha256=toolchain["archive_sha256"])
    with checkpoint.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--nsis-archive", type=Path,
                        help="Build the unsigned installer with the official local NSIS 3.13 archive")
    args = parser.parse_args()
    print(json.dumps(stage(args.source, args.out_dir, nsis_archive=args.nsis_archive), sort_keys=True))


if __name__ == "__main__":
    main()
