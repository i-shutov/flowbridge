#!/usr/bin/env python3
"""Pinned, explicit-only beta checks on an operator-selected Windows/macOS host.

Default: validate the supplied bytes and write a NOT_RUN report. --execute adds
install/launch/upgrade/uninstall of the isolated beta only. This is not a WFP/NE,
SSH stress, visual review, signing, or release-approval test. No third-party Python
modules are required; the runner is intended to accompany the immutable QA kit.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

SCHEMA = "flowbridge-explicit-beta-native-acceptance-v1"
PRODUCT = "FlowBridgeExplicitBeta"
BUNDLE = "org.flowbridge.FlowBridgeExplicitBeta"
RECEIPT = BUNDLE + ".installer"
FORBIDDEN = ("capture", "wfp", "ndisrd", ".sys", ".inf", "systemextension",
             "networkextension", "launchdaemon", "privilegedhelper")
AUTOMATED = ("install", "payload", "launch", "upgrade", "uninstall", "stable_preserved")
WINDOWS_PAYLOAD = {
    "FlowBridge.exe", "flowbridge-cli.exe", "flowbridge_ffi.dll", "LICENSE", "README.txt",
    "SBOM.cdx.json", "BUILD-METADATA.json", "licenses/THIRD_PARTY_NOTICES.txt",
    "licenses/nlohmann-json-LICENSE.MIT", "resources/presets.json",
    "examples/direct.json", "examples/ssh-socks.json", "examples/chain.json",
}


class Rejected(RuntimeError):
    """A stable error code; never contains a profile, key, or command output."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise Rejected(code)


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def check_hash(value: object, length: int = 64) -> str:
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None,
            "invalid_sha_pin")
    return value


def verified_file(path: Path, sha: str, size: int | None = None) -> Path:
    check_hash(sha)
    require(path.is_file() and not path.is_symlink(), "missing_or_linked_file")
    require(size is None or (type(size) is int and size >= 0 and path.stat().st_size == size),
            "file_size_mismatch")
    require(digest(path) == sha, "file_sha_mismatch")
    return path.resolve()


def contained_payload_file(root: Path, relative: str) -> Path:
    """Reject symlinks and Windows junction/reparse substitutions inside install."""
    safe_relative(relative)
    current = root
    for part in (None, *PurePosixPath(relative).parts):
        if part is not None:
            current = current / part
        details = current.lstat()
        require(not stat.S_ISLNK(details.st_mode)
                and not (getattr(details, "st_file_attributes", 0) & 0x400),
                "linked_payload_component")
    require(current.resolve().is_relative_to(root.resolve()), "payload_outside_installation")
    return current


def safe_relative(value: object) -> str:
    require(isinstance(value, str) and bool(value) and "\\" not in value and ":" not in value,
            "unsafe_payload_path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and str(path) == value
            and all(x not in (".", "..", "") for x in value.split("/")), "unsafe_payload_path")
    require(not any(x in value.lower() for x in FORBIDDEN), "forbidden_payload")
    return value


def validate_manifest(m: dict, source: str, package_sha: str) -> str:
    require(isinstance(m, dict), "invalid_manifest")
    require(m.get("source_sha") == check_hash(source, 40), "source_sha_mismatch")
    require(m.get("explicit_socks_only") is True and m.get("signed") is False
            and m.get("publisher_release_approved") is False
            and m.get("driver_included") is False, "invalid_beta_scope")
    if m.get("schema") == "flowbridge-explicit-beta-windows-qa-package-v1":
        require(m.get("capture_helper_included") is False
                and m.get("system_service_included") is False
                and m.get("gui_protected_ui_compiled_disabled") is True
                and m.get("profile_namespace") == PRODUCT
                and m.get("uninstall_registration") == PRODUCT, "invalid_windows_scope")
        require(m.get("installer_sha256") == check_hash(package_sha), "package_sha_mismatch")
        require(isinstance(m.get("payload"), list) and bool(m["payload"]), "missing_payload")
        names = set()
        exact_names = set()
        for item in m["payload"]:
            require(isinstance(item, dict), "invalid_payload_entry")
            name = safe_relative(item.get("path"))
            require(name.casefold() not in names, "duplicate_payload_path")
            names.add(name.casefold())
            exact_names.add(name)
            check_hash(item.get("sha256"))
            require(type(item.get("bytes")) is int and item["bytes"] >= 0, "invalid_payload_size")
        require(exact_names == WINDOWS_PAYLOAD, "payload_allowlist_mismatch")
        harness = m.get("qa_harness")
        require(isinstance(harness, dict), "missing_pinned_qa_harness")
        check_hash(harness.get("sha256"))
        require(type(harness.get("bytes")) is int and harness["bytes"] > 0, "invalid_harness_size")
        return "windows"
    require(m.get("schema") == "flowbridge-explicit-beta-macos-qa-package-v1",
            "unsupported_manifest_schema")
    require(m.get("bundle_id") == BUNDLE and m.get("system_extension_included") is False,
            "invalid_macos_scope")
    require(m.get("pkg_sha256") == check_hash(package_sha), "package_sha_mismatch")
    return "macos"


def execution_context(target: str, expected_host: str, env: dict | None = None) -> dict:
    env = os.environ if env is None else env
    actual = {"win32": "windows", "darwin": "macos"}.get(sys.platform, "unsupported")
    require(actual == target, "wrong_execution_platform")
    require(bool(expected_host) and platform.node().casefold() == expected_host.casefold(),
            "wrong_execution_host")
    hosted = env.get("GITHUB_ACTIONS", "").lower() == "true"
    ci = hosted or bool(env.get("CI")) or bool(env.get("RUNNER_ENVIRONMENT"))
    return {"platform": target, "os_release": platform.release(), "os_version": platform.version(),
            "architecture": platform.machine(), "host_sha256": hashlib.sha256(platform.node().encode()).hexdigest(),
            "github_hosted": hosted and env.get("RUNNER_ENVIRONMENT") == "github-hosted",
            "ci_environment_detected": ci, "owner_native": not ci,
            "host_identity_basis": "operator-supplied hostname; not hardware attestation"}


def fingerprint(path: Path) -> str:
    """Content-only digest, without publishing user filenames or file contents."""
    if not path.exists() and not path.is_symlink():
        return "ABSENT"
    entries = []
    paths = [path] if not path.is_dir() or path.is_symlink() else sorted(path.rglob("*"))
    require(len(paths) <= 20000, "snapshot_too_large")
    for item in paths:
        relative = "." if item == path else item.relative_to(path).as_posix()
        if item.is_symlink():
            entries.append([relative, "link", os.readlink(item)])
        elif item.is_file():
            entries.append([relative, "file", digest(item)])
        elif item.is_dir():
            entries.append([relative, "directory"])
    return hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest()


def command(args: list[str] | str, *, timeout: int = 180, executable: str | None = None) -> str:
    result = subprocess.run(args, executable=executable, capture_output=True, timeout=timeout,
                            check=False, text=True, encoding="utf-8", errors="replace")
    require(result.returncode == 0, "native_command_failed")
    return result.stdout


def until(test, timeout: int = 90) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if test():
            return
        time.sleep(0.2)
    raise Rejected("native_step_timeout")


def windows_registry(key: str, field: str) -> object:
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as handle:
            return winreg.QueryValueEx(handle, field)[0]
    except FileNotFoundError:
        return None


def windows_run(package: Path, harness: Path, manifest: dict, out: Path, report: dict) -> None:
    settings = r"Software\FlowBridgeExplicitBeta"
    uninstall = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\FlowBridgeExplicitBeta"
    stable_settings = r"Software\FlowBridge"
    stable_uninstall = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\FlowBridge"
    local = Path(os.environ["LOCALAPPDATA"])
    profile = local / PRODUCT
    shortcuts = Path(os.environ["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs/FlowBridge Explicit Beta"
    require(not profile.exists() and not profile.is_symlink()
            and not shortcuts.exists() and not shortcuts.is_symlink()
            and windows_registry(settings, "InstallDir") is None
            and windows_registry(uninstall, "DisplayName") is None, "existing_beta_refused")
    import ctypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenMutexW.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_wchar_p]
    kernel.OpenMutexW.restype = ctypes.c_void_p
    ctypes.set_last_error(0)
    handle = kernel.OpenMutexW(0x100000, False, "Local\\FlowBridge.NativeUI.v02")
    if handle:
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle(handle)
        raise Rejected("running_flowbridge_refused")
    require(ctypes.get_last_error() == 2, "cannot_exclude_running_flowbridge")
    stable_keys = [(stable_settings, "InstallDir"), (stable_uninstall, "InstallLocation"),
                   (stable_uninstall, "DisplayVersion"), (stable_uninstall, "UninstallString")]
    before_registry = [windows_registry(*x) for x in stable_keys]
    stable_paths = [local / "FlowBridge"]
    if isinstance(before_registry[0], str) and before_registry[0]:
        stable_paths += [Path(before_registry[0]) / name for name in
                         ("FlowBridge.exe", "flowbridge-cli.exe", "flowbridge_ffi.dll", "Uninstall.exe")]
    before_stable = [fingerprint(p) for p in stable_paths]
    base = Path(tempfile.mkdtemp(prefix="flowbridge-explicit-native-"))
    installed = base / "Beta QA With Spaces"
    other = base / "Must Not Relocate"
    steps = report["checks"]
    report["owned_cleanup_paths"] = {
        "test_work_directory": str(base), "installed_beta": str(installed),
        "beta_uninstaller": str(installed / "Uninstall.exe"),
    }
    report["test_work_directory_retained"] = True
    report["cleanup_required"] = True

    def install(destination: Path) -> None:
        command(f'"{package}" /S /D={destination}', executable=str(package))
        until(lambda: (installed / "Uninstall.exe").is_file())

    def payload() -> None:
        for entry in manifest["payload"]:
            path = contained_payload_file(installed, entry["path"])
            verified_file(path, entry["sha256"], entry["bytes"])

    install(installed)
    require(windows_registry(settings, "InstallDir") == str(installed)
            and windows_registry(uninstall, "InstallLocation") == str(installed), "wrong_beta_registration")
    steps["install"] = "PASS"
    payload()
    caps = json.loads(command([str(installed / "flowbridge-cli.exe"), "capabilities"], timeout=20))
    require(caps.get("mode") == "explicit_loopback_socks5"
            and all(caps.get(k) is False for k in
                    ("transparent_interception", "system_kill_switch", "udp")), "false_capability_claim")
    steps["payload"] = "PASS"
    # The native harness imports the FFI DLL. Keep the verified test executable
    # beside a byte-identical copy of the installed DLL, not an arbitrary PATH DLL.
    qa = base / "qa-harness"
    qa.mkdir()
    qa_harness = qa / "FlowBridgeNativeSmoke.exe"
    shutil.copyfile(harness, qa_harness)
    shutil.copyfile(installed / "flowbridge_ffi.dll", qa / "flowbridge_ffi.dll")
    verified_file(qa_harness, manifest["qa_harness"]["sha256"], manifest["qa_harness"]["bytes"])
    ffi = next(x for x in manifest["payload"] if x["path"] == "flowbridge_ffi.dll")
    verified_file(qa / "flowbridge_ffi.dll", ffi["sha256"], ffi["bytes"])
    output = command([str(qa_harness), str(installed / "FlowBridge.exe"), str(out / "installed-beta-ui.bmp")])
    require(all(marker in output for marker in
                ("PASS Windows DLL", "PASS Win32 GUI", "PASS compact Windows GUI")), "gui_smoke_incomplete")
    screens = [out / ("installed-beta-ui-compact-" + page + ".bmp")
               for page in ("dashboard", "ssh", "proxy", "apps", "advanced")]
    require(all(p.is_file() and p.stat().st_size > 1500 for p in screens)
            and len({digest(p) for p in screens}) == 5, "gui_screens_incomplete")
    require((profile / "profile.json").is_file(), "missing_beta_profile")
    report["screenshots"] = [{"file": p.name, "sha256": digest(p)} for p in screens]
    steps["launch"] = "PASS"
    beta_before = fingerprint(profile)
    marker = installed / "native-qa-preserve-user-file.txt"
    marker.write_text("Preserve this user-owned test file.\n", encoding="utf-8")
    marker_hash = digest(marker)
    install(other)
    payload()
    require(not other.exists() and fingerprint(profile) == beta_before
            and digest(marker) == marker_hash, "upgrade_did_not_preserve_beta")
    steps["upgrade"] = "PASS"
    command([str(installed / "Uninstall.exe"), "/S"])
    until(lambda: not (installed / "Uninstall.exe").exists()
          and windows_registry(settings, "InstallDir") is None
          and windows_registry(uninstall, "DisplayName") is None)
    require(all(not (installed / item["path"]).exists() for item in manifest["payload"])
            and not list(shortcuts.glob("*.lnk")) and fingerprint(profile) == beta_before
            and digest(marker) == marker_hash, "uninstall_did_not_preserve_owner_files")
    steps["uninstall"] = "PASS"
    require([windows_registry(*x) for x in stable_keys] == before_registry
            and [fingerprint(p) for p in stable_paths] == before_stable, "stable_state_changed")
    steps["stable_preserved"] = "PASS"
    report["cleanup_required"] = False
    report["test_profile_retained"] = True


def validate_macos_listing(listing: str) -> None:
    paths = listing.splitlines()
    require(bool(paths), "empty_pkg_payload")
    app = "Applications/" + PRODUCT + ".app"
    found = False
    for raw in paths:
        value = raw[2:] if raw.startswith("./") else raw
        if value in (".", "", "Applications"):
            continue
        safe_relative(value)
        require(value == app or value.startswith(app + "/"), "pkg_non_beta_payload")
        found = True
    require(found, "missing_beta_app")


def validate_macos_entitlements(returncode: int, stdout: str, stderr: str) -> None:
    """Empty success is valid; unknown failures and malformed-data warnings are not."""
    combined = stdout + stderr
    require(not any(key in combined for key in
                    ("com.apple.developer.networking.networkextension",
                     "com.apple.developer.system-extension.install")), "forbidden_beta_entitlement")
    require(not any(message in combined.lower() for message in
                    ("invalid entitlements", "malformed entitlement", "will ignore these entitlements")),
            "malformed_beta_entitlements")
    require(returncode == 0, "cannot_inspect_beta_entitlements")
    if stdout.strip():
        try:
            entitlements = plistlib.loads(stdout.strip().encode("utf-8"))
        except Exception as exc:
            raise Rejected("invalid_entitlements_output") from exc
        require(isinstance(entitlements, dict), "invalid_entitlements_output")


def macos_run(package: Path, out: Path, report: dict) -> None:
    require(os.geteuid() != 0, "run_as_normal_macos_user")
    app = Path("/Applications") / (PRODUCT + ".app")
    data = Path.home() / "Library/Application Support"
    beta_data = data / PRODUCT
    require(not app.exists() and not app.is_symlink()
            and not beta_data.exists() and not beta_data.is_symlink(), "existing_beta_refused")
    receipt = subprocess.run(["/usr/sbin/pkgutil", "--pkg-info", RECEIPT], capture_output=True, timeout=20)
    require(receipt.returncode == 1, "existing_beta_receipt_or_query_failed")
    validate_macos_listing(command(["/usr/sbin/pkgutil", "--payload-files", str(package)]))
    # Do not infer safety from a filename: inspect expanded package scripts and app.
    base = Path(tempfile.mkdtemp(prefix="flowbridge-explicit-native-"))
    report["owned_cleanup_paths"] = {
        "test_work_directory": str(base), "installed_beta": str(app),
        "beta_package_receipt": RECEIPT,
    }
    report["test_work_directory_retained"] = True
    expanded = base / "expanded"
    command(["/usr/sbin/pkgutil", "--expand-full", str(package), str(expanded)])
    infos = list(expanded.rglob("PackageInfo"))
    require(len(infos) == 1, "unexpected_component_count")
    info = ET.parse(infos[0]).getroot()
    require(info.get("identifier") == RECEIPT and info.get("install-location") == "/"
            and info.find("scripts") is None, "pkg_component_or_scripts_rejected")
    require(not any(p.is_file() for directory in expanded.rglob("Scripts")
                    for p in directory.rglob("*")), "pkg_scripts_rejected")
    for distribution in expanded.rglob("Distribution"):
        dist = ET.parse(distribution).getroot()
        require(all(dist.find(".//" + name) is None for name in
                    ("script", "installation-check", "volume-check")), "pkg_distribution_script_rejected")
    apps = list(expanded.rglob(PRODUCT + ".app"))
    require(len(apps) == 1 and not apps[0].is_symlink(), "ambiguous_beta_app")
    expected_app = fingerprint(apps[0])
    plist = plistlib.loads((apps[0] / "Contents/Info.plist").read_bytes())
    require(plist.get("CFBundleIdentifier") == BUNDLE
            and plist.get("CFBundleExecutable") == PRODUCT, "wrong_beta_bundle")
    command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(apps[0])])
    entitlements = subprocess.run(["/usr/bin/codesign", "-d", "--entitlements", ":-", str(apps[0])],
                                 capture_output=True, text=True, timeout=45, check=False)
    report["codesign_entitlements_query"] = {
        "returncode": entitlements.returncode, "stdout_bytes": len(entitlements.stdout.encode()),
        "stderr_bytes": len(entitlements.stderr.encode()),
        "no_entitlements_notice": "no entitlements" in entitlements.stderr.lower(),
    }
    validate_macos_entitlements(entitlements.returncode, entitlements.stdout, entitlements.stderr)
    command(["/usr/bin/xcrun", "lipo", str(apps[0] / "Contents/MacOS" / PRODUCT),
             "-verify_arch", "arm64", "x86_64"])
    command(["/usr/bin/sudo", "-n", "/usr/bin/true"], timeout=10)
    stable_paths = [Path("/Applications/FlowBridge.app"), data / "FlowBridge"]
    stable_before = [fingerprint(p) for p in stable_paths]
    steps = report["checks"]
    report["cleanup_required"] = True

    def install() -> None:
        command(["/usr/bin/sudo", "-n", "/usr/sbin/installer", "-pkg", str(package), "-target", "/"])
        require(not app.is_symlink() and fingerprint(app) == expected_app, "installed_app_differs")

    install()
    steps["install"] = steps["payload"] = "PASS"
    process = subprocess.Popen([str(app / "Contents/MacOS" / PRODUCT)], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    try:
        time.sleep(4)
        require(process.poll() is None, "gui_exited_during_launch")
        steps["launch"] = "PASS"
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
    beta_data.mkdir(parents=True, exist_ok=True)
    (beta_data / "native-qa-preserve-user-file.txt").write_text("Preserve beta settings.\n", encoding="utf-8")
    beta_before = fingerprint(beta_data)
    install()
    require(fingerprint(beta_data) == beta_before, "upgrade_did_not_preserve_beta")
    steps["upgrade"] = "PASS"
    require(not app.is_symlink() and fingerprint(app) == expected_app, "uninstall_ownership_lost")
    # Only the app absent at entry and installed above may be removed. Profiles,
    # stable app, network settings, extensions and unrelated receipts are untouched.
    command(["/usr/bin/sudo", "-n", "/bin/rm", "-R", str(app)])
    command(["/usr/bin/sudo", "-n", "/usr/sbin/pkgutil", "--forget", RECEIPT])
    require(not app.exists() and fingerprint(beta_data) == beta_before, "uninstall_did_not_preserve_beta")
    steps["uninstall"] = "PASS"
    require([fingerprint(p) for p in stable_paths] == stable_before, "stable_state_changed")
    steps["stable_preserved"] = "PASS"
    report["cleanup_required"] = False
    report["test_profile_retained"] = True
    report["macos_launch_scope"] = "process survived 4 seconds; visual/routing checks not performed"


def new_report(source: str) -> dict:
    return {"schema": SCHEMA, "source_sha": source,
            "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
            "started_utc": datetime.now(timezone.utc).isoformat(),
            "status": "NOT_RUN", "checks": {x: "NOT_RUN" for x in AUTOMATED},
            "manual_visual_keyboard_review": "NOT_RUN", "owner_managed_ssh": "NOT_RUN",
            "native_transparent_routing": "NOT_RUN", "dns_leak_acceptance": "NOT_RUN",
            "publisher_signature_acceptance": "NOT_RUN", "release_accepted": False,
            "a3_a4_full_acceptance": False, "network_configuration_requested": False,
            "driver_or_extension_activation_requested": False, "cleanup_required": False}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--package", type=Path, required=True)
    ap.add_argument("--expected-source", required=True)
    ap.add_argument("--expected-package-sha256", required=True)
    ap.add_argument("--expected-manifest-sha256", required=True)
    ap.add_argument("--expected-tool-sha256", required=True)
    ap.add_argument("--harness", type=Path)
    ap.add_argument("--expected-computer")
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    report = new_report(args.expected_source)
    code = 1
    try:
        verified_file(Path(__file__), args.expected_tool_sha256)
        verified_file(args.manifest, args.expected_manifest_sha256)
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        target = validate_manifest(manifest, args.expected_source, args.expected_package_sha256)
        size = manifest.get("installer_bytes" if target == "windows" else "pkg_bytes")
        require(type(size) is int and size > 0, "invalid_package_size")
        package = verified_file(args.package, args.expected_package_sha256, size)
        harness = None
        if target == "windows":
            require(args.harness is not None, "windows_harness_required")
            h = manifest["qa_harness"]
            harness = verified_file(args.harness, h["sha256"], h["bytes"])
            report["harness_sha256"] = h["sha256"]
        report.update({"target": target, "package_sha256": args.expected_package_sha256,
                       "manifest_sha256": args.expected_manifest_sha256,
                       "tool_sha256": args.expected_tool_sha256, "pins_verified": True,
                       "candidate_version": manifest.get("candidate"),
                       "status": "VERIFIED_BYTES_NATIVE_NOT_RUN"})
        if args.execute:
            report["host"] = execution_context(target, args.expected_computer or "")
            if target == "windows":
                windows_run(package, harness, manifest, args.output, report)
            else:
                macos_run(package, args.output, report)
            require(all(report["checks"][x] == "PASS" for x in AUTOMATED), "incomplete_native_checks")
            report["status"] = ("OWNER_NATIVE_AUTOMATED_CHECKS_PASS" if report["host"]["owner_native"]
                                else "CI_AUTOMATED_CHECKS_PASS")
        code = 0
    except Exception as error:
        report["status"] = "FAIL"
        report["error_code"] = str(error) if isinstance(error, Rejected) else type(error).__name__
    finally:
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        text = json.dumps(report, sort_keys=True, indent=2) + "\n"
        (args.output / "native-acceptance.json").write_text(text, encoding="utf-8")
        print(text, end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
