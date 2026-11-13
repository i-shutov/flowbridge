#!/usr/bin/env python3
"""Read-only gate for a genuinely signed FlowBridge macOS Network Extension.

No installation, activation, security setting, network, or system-extension
mutation. A PASS only admits *subsequent* owner native testing; it does not
mean the Network Extension has been activated or that any traffic was routed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import platform
import plistlib
import re
import subprocess
import sys
from typing import Callable

SCHEMA = "flowbridge-macos-ne-prerequisites-v1"
NE_ROLES = frozenset(("app-proxy-provider-systemextension", "dns-proxy-systemextension"))
NE_PROVIDER_CLASSES = {
    "com.apple.networkextension.app-proxy": "FlowBridgeExtension.TransparentProxyProvider",
    "com.apple.networkextension.dns-proxy": "FlowBridgeExtension.DNSProxyProvider",
}


class GateFailure(Exception):
    """Stable, path-free refusal code; never wrap raw codesign diagnostics."""


def command(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=False, timeout=20)


def require(condition: bool, code: str) -> None:
    if not condition:
        raise GateFailure(code)


def read_plist(path: Path, label: str) -> dict:
    require(path.is_file() and not path.is_symlink(), label + "_plist_missing")
    try:
        data = path.read_bytes()
        require(len(data) <= 131072, label + "_plist_oversized")
        result = plistlib.loads(data)
    except (OSError, ValueError, TypeError, plistlib.InvalidFileException) as exc:
        raise GateFailure(label + "_plist_invalid") from exc
    require(type(result) is dict, label + "_plist_invalid")
    return result


def codesign(path: Path, expected_id: str, expected_team: str,
             runner: Callable[[list[str]], subprocess.CompletedProcess[bytes]]) -> dict:
    target = str(path)
    try:
        verified = runner(["codesign", "--verify", "--deep", "--strict", "--verbose=2", target])
        displayed = runner(["codesign", "--display", "--verbose=4", target])
        entitlements = runner(["codesign", "--display", "--entitlements", ":-", target])
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GateFailure("codesign_unavailable") from exc

    require(verified.returncode == 0, "codesign_verify_failed")
    require(displayed.returncode == 0, "codesign_metadata_unavailable")
    require(entitlements.returncode == 0, "codesign_entitlements_unavailable")

    # codesign writes metadata to stderr; only parse exact unambiguous lines.
    metadata = (displayed.stdout + b"\n" + displayed.stderr).decode("utf-8", "replace")
    ids = re.findall(r"(?m)^Identifier=([^\r\n]+)\s*$", metadata)
    teams = re.findall(r"(?m)^TeamIdentifier=([^\r\n]+)\s*$", metadata)
    require(ids == [expected_id], "codesign_identifier_mismatch")
    require(teams == [expected_team], "codesign_team_mismatch")
    require(len(entitlements.stdout) <= 131072, "entitlements_oversized")
    try:
        ent = plistlib.loads(entitlements.stdout)
    except (ValueError, TypeError, plistlib.InvalidFileException) as exc:
        raise GateFailure("entitlements_absent_or_malformed") from exc
    require(type(ent) is dict, "entitlements_absent_or_malformed")
    return ent


def allowed_app_path(app: Path, allowed_roots: tuple[Path, ...]) -> None:
    require(app.suffix == ".app" and app.is_dir() and not app.is_symlink(),
            "not_an_installed_app")
    # Reject symlinks that relocate the installed bundle outside Applications.
    require(app.parent in allowed_roots and
            app.resolve(strict=True) == app.parent.resolve(strict=True) / app.name,
            "app_not_in_applications")


def preflight(app: Path, bundle_id: str, team_id: str, *,
              runner: Callable[[list[str]], subprocess.CompletedProcess[bytes]] = command,
              host_os: str | None = None,
              allowed_roots: tuple[Path, ...] | None = None) -> dict:
    require((host_os if host_os is not None else sys.platform) == "darwin",
            "macos_host_required")
    require(re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", bundle_id) is not None,
            "invalid_expected_bundle_id")
    require(re.fullmatch(r"[A-Z0-9]{10}", team_id) is not None,
            "invalid_expected_team_id")
    if allowed_roots is None:
        allowed_roots = (Path("/Applications"), Path.home() / "Applications")
    allowed_app_path(app, allowed_roots)
    app_info = read_plist(app / "Contents/Info.plist", "app")
    require(app_info.get("CFBundleIdentifier") == bundle_id, "app_bundle_id_mismatch")
    require(isinstance(app_info.get("NSSystemExtensionUsageDescription"), str) and
            bool(app_info["NSSystemExtensionUsageDescription"].strip()),
            "app_system_extension_purpose_missing")
    app_bin = app / "Contents/MacOS" / str(app_info.get("CFBundleExecutable", ""))
    require(app_bin.is_file() and not app_bin.is_symlink(), "app_executable_missing")

    extensions_dir = app / "Contents/Library/SystemExtensions"
    require(extensions_dir.is_dir() and not extensions_dir.is_symlink(),
            "system_extensions_directory_missing")
    extensions = sorted(p for p in extensions_dir.iterdir() if p.suffix == ".systemextension")
    require(len(extensions) == 1, "system_extension_count_mismatch")
    extension = extensions[0]
    require(extension.is_dir() and not extension.is_symlink(), "system_extension_linked")
    extension_id = bundle_id + ".extension"
    require(extension.name == extension_id + ".systemextension",
            "system_extension_directory_mismatch")
    ext_info = read_plist(extension / "Contents/Info.plist", "extension")
    require(ext_info.get("CFBundleIdentifier") == extension_id,
            "extension_bundle_id_mismatch")
    registration = ext_info.get("NetworkExtension")
    require(type(registration) is dict, "provider_class_registration_mismatch")
    provider_classes = registration.get("NEProviderClasses")
    require(type(provider_classes) is dict and provider_classes == NE_PROVIDER_CLASSES,
            "provider_class_registration_mismatch")
    ext_bin = extension / "Contents/MacOS" / str(ext_info.get("CFBundleExecutable", ""))
    require(ext_bin.is_file() and not ext_bin.is_symlink(), "extension_executable_missing")

    app_ent = codesign(app, bundle_id, team_id, runner)
    ext_ent = codesign(extension, extension_id, team_id, runner)
    for label, ent in (("app", app_ent), ("extension", ext_ent)):
        roles = ent.get("com.apple.developer.networking.networkextension")
        require(type(roles) is list and len(roles) == len(NE_ROLES) and
                all(type(x) is str for x in roles) and set(roles) == NE_ROLES,
                label + "_network_extension_entitlements_mismatch")
    require(app_ent.get("com.apple.developer.system-extension.install") is True,
            "app_install_entitlement_missing")
    require("com.apple.developer.system-extension.install" not in ext_ent,
            "extension_must_not_request_install_entitlement")

    return {
        "schema": SCHEMA,
        "status": "PREREQUISITES_PASS_NATIVE_NOT_RUN",
        "signed_app_and_extension": True,
        "app_and_extension_team_agree": True,
        "required_entitlements_verified": True,
        "extension_bundle_and_provider_classes_verified": True,
        "installed_application_location_verified": True,
        "activation_accepted": False,
        "native_packet_evidence_accepted": False,
        "dns_containment_proved": False,
        "publisher_release_approved": False,
        "release_accepted": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--expected-bundle-id", required=True)
    parser.add_argument("--expected-team-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    result = {
        "schema": SCHEMA,
        "status": "BLOCKED",
        "error_code": None,
        "host_os": sys.platform,
        "host_arch": platform.machine(),
        "activation_accepted": False,
        "native_packet_evidence_accepted": False,
        "dns_containment_proved": False,
        "publisher_release_approved": False,
        "release_accepted": False,
    }
    code = 1
    try:
        result.update(preflight(args.app, args.expected_bundle_id, args.expected_team_id))
        code = 0
    except GateFailure as exc:
        result["error_code"] = str(exc)
    except (OSError, ValueError, TypeError) as exc:
        # Never leak full codesign output or local paths into evidence.
        result["error_code"] = "read_only_preflight_io_error"
    # JSON is intentionally path-, hostname-, team-, cert- and profile-free.
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    except OSError:
        print("cannot_write_preflight_report", file=sys.stderr)
        return 2
    print(result["status"] if code == 0 else "BLOCKED:" + str(result["error_code"]))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
