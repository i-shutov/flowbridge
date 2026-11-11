#!/usr/bin/env python3
"""Native disposable Windows QA of separately namespaced explicit SOCKS candidate.

No WFP/NDISRD driver, privileged capture helper, DNS or firewall changes.
Verify real GUI, disabled capture controls, payload SHA, installed GUI TCP,
upgrade preservation, and complete removal of ONLY candidate-owned entries.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def must(ok: bool, msg: str) -> None:
    if not ok:
        raise RuntimeError(msg)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, *, executable: str | None = None, timeout: int = 180) -> str:
    completed = subprocess.run(command, executable=executable, check=True,
                               capture_output=True, timeout=timeout)
    out = completed.stdout.decode("utf-8", errors="replace")
    if completed.stderr:
        out += completed.stderr.decode("utf-8", errors="replace")
    print("STEP", out[-3000:], flush=True)
    return out


def until(what, message: str, seconds: int = 90) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if what():
            return
        time.sleep(0.15)
    raise RuntimeError(message)


def registry(key: str, field: str) -> str | None:
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as handle:
            return winreg.QueryValueEx(handle, field)[0]
    except FileNotFoundError:
        return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--harness", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    must(sys.platform == "win32" and os.environ.get("GITHUB_ACTIONS") == "true"
         and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
         and os.environ.get("RUNNER_OS") == "Windows",
         "Refuse running installer QA outside disposable hosted Windows")
    report = {
        "kind": "native_windows_hosted_explicit_socks_beta_installer",
        "passed": False, "on_owner_win10": False,
        "driver_installed": False, "helper_included": False,
        "system_proxy_or_firewall_modified": False,
        "app_process_ownership_proved": False,
        "protected_mode_supported": False,
        "test_steps": [], "source_sha": None,
    }

    def passed(name: str) -> None:
        report["test_steps"].append(name)
        print("PASS", name, flush=True)

    a.output.mkdir(parents=True, exist_ok=True)
    try:
        m = json.loads(a.manifest.read_text(encoding="utf-8"))
        must(m["schema"] == "flowbridge-explicit-beta-windows-qa-package-v1"
             and m["signed"] is False
             and m["explicit_socks_only"] is True
             and m["gui_protected_ui_compiled_disabled"] is True
             and m["capture_helper_included"] is False
             and m["driver_included"] is False
             and m["system_service_included"] is False
             and m["publisher_release_approved"] is False,
             "Beta package scope manifest is invalid")
        report["source_sha"] = m["source_sha"]
        installer = Path(m["installer"]).resolve(strict=True)
        harness = a.harness.resolve(strict=True)
        must(digest(installer) == m["installer_sha256"]
             and installer.stat().st_size == m["installer_bytes"],
             "Installer SHA or size does not match manifest")
        beta_settings = r"Software\FlowBridgeExplicitBeta"
        beta_uninstall = (r"Software\Microsoft\Windows\CurrentVersion"
                          r"\Uninstall\FlowBridgeExplicitBeta")
        stable_settings = r"Software\FlowBridge"
        stable_uninstall = (r"Software\Microsoft\Windows\CurrentVersion"
                            r"\Uninstall\FlowBridge")
        userprofile = Path(os.environ["LOCALAPPDATA"]) / "FlowBridgeExplicitBeta"
        stableprofile = Path(os.environ["LOCALAPPDATA"]) / "FlowBridge"
        beta_shortcuts = (Path(os.environ["APPDATA"]) / "Microsoft" / "Windows"
                          / "Start Menu" / "Programs" / "FlowBridge Explicit Beta")
        must(registry(beta_settings, "InstallDir") is None
             and registry(beta_uninstall, "DisplayName") is None
             and not beta_shortcuts.exists() and not userprofile.exists(),
             "Existing beta registration/user profile: do not overwrite")
        must(registry(stable_settings, "InstallDir") is None
             and registry(stable_uninstall, "DisplayName") is None,
             "Refuse existing stable install on this isolated test account")

        # Evidence that this beta build never modifies a stable version's profile.
        stableprofile.mkdir(parents=True, exist_ok=True)
        sentinel = stableprofile / "profile-keep-from-stable.txt"
        sentinel.write_text("KEEP STABLE USER PROFILE\n", encoding="utf-8")
        sentinel_sha = digest(sentinel)

        base = Path(tempfile.mkdtemp(prefix="flowbridge-explicit-beta-",
                                     dir=os.environ["RUNNER_TEMP"]))
        destination = base / "Beta QA With Spaces"
        alternate = base / "Should Not Relocate"
        def install(where: Path) -> None:
            cmd = f'"{installer}" /S /D={where}'
            run(cmd, executable=str(installer), timeout=180)
            until(lambda: (destination / "Uninstall.exe").is_file(),
                  "Beta installer did not finish")
        install(destination)
        for item in m["payload"]:
            rel = item["path"]
            must(not any(term in rel.lower() for term in
                         ("capture", "wfp", "ndisrd", ".sys", ".inf")),
                 "Forbidden protected-mode component in beta installer")
            path = destination / rel
            must(path.is_file() and path.stat().st_size == item["bytes"]
                 and digest(path) == item["sha256"], "Installed file differs: " + rel)
        must(not (destination / "FlowBridgeCapture.exe").exists(),
             "Protected capture helper included in explicit package")
        must(registry(beta_settings, "InstallDir") == str(destination)
             and registry(beta_uninstall, "InstallLocation") == str(destination),
             "Wrong beta registration")
        must(registry(stable_settings, "InstallDir") is None,
             "Beta installer touched stable registration")
        passed("Separate HKCU install, exact payload hashes, no capture helper")

        cli = destination / "flowbridge-cli.exe"
        caps = json.loads(run([str(cli), "capabilities"], timeout=15))
        must(caps["mode"] == "explicit_loopback_socks5"
             and not caps["transparent_interception"]
             and not caps["system_kill_switch"] and not caps["udp"],
             "CLI falsely advertises protected capabilities")
        passed("Actual installed CLI reports exact explicit SOCKS-only limits")

        # The real Win32 smoke exercise starts the installed GUI and verifies
        # its WFP/App-selector buttons cannot be enabled in the beta build.
        screenshot = a.output / "installed-beta-ui.bmp"
        gui = destination / "FlowBridge.exe"
        stdout = run([str(harness), str(gui), str(screenshot)], timeout=180)
        must("PASS Windows DLL" in stdout and "PASS Win32 GUI" in stdout
             and "PASS compact Windows GUI" in stdout,
             "Installed native GUI smoke incomplete")
        image_hashes = set()
        for page in ("dashboard", "ssh", "proxy", "apps", "advanced"):
            path = a.output / ("installed-beta-ui-compact-" + page + ".bmp")
            must(path.exists() and path.stat().st_size > 1500,
                 "Missing real Win32 page " + page)
            sha = digest(path)
            must(sha not in image_hashes, "Duplicate GUI page " + page)
            image_hashes.add(sha)
        passed("Installed GUI: actual Win32 controls, disabled capture, five screens, TCP, Start/Stop")

        profile = userprofile / "profile.json"
        must(profile.is_file() and digest(sentinel) == sentinel_sha,
             "Beta user profile missing or stable profile modified")
        beta_profile_hash = digest(profile)
        keep = destination / "user-owned-keep.txt"
        keep.write_text("DO NOT DELETE USER FILE\n", encoding="utf-8")
        install(alternate)
        must(not alternate.exists()
             and registry(beta_settings, "InstallDir") == str(destination)
             and keep.exists() and digest(profile) == beta_profile_hash,
             "Upgrade moved the installation or removed user settings")
        passed("In-place upgrade retains exact beta install path and private files")

        run([str(destination / "Uninstall.exe"), "/S"], timeout=180)
        until(lambda: not (destination / "FlowBridge.exe").exists()
              and not (destination / "Uninstall.exe").exists()
              and registry(beta_settings, "InstallDir") is None
              and registry(beta_uninstall, "DisplayName") is None
              and not list(beta_shortcuts.glob("*.lnk")),
              "Uninstall left candidate files, registration or shortcuts", 90)
        must(all(not (destination / item["path"]).exists()
                 for item in m["payload"]), "Package-owned payload retained")
        must(digest(profile) == beta_profile_hash
             and keep.read_text(encoding="utf-8") == "DO NOT DELETE USER FILE\n"
             and digest(sentinel) == sentinel_sha,
             "Uninstaller destroyed beta/stable owner files")
        passed("Uninstaller removes only beta binaries/registration, preserves both profiles")

        report["passed"] = True
        report["installed_gui_sha256"] = next(
            x["sha256"] for x in m["payload"] if x["path"] == "FlowBridge.exe")
        report["installer_sha256"] = m["installer_sha256"]
    except Exception as exc:
        report["error"] = str(exc)
        raise
    finally:
        (a.output / "explicit-beta-installer-result.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
