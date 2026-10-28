#!/usr/bin/env python3
"""Collect exact dependency license files from the locked Cargo registry.

Run after cargo fetch/build. Debian MinGW cross-build notices are included when
available; --mingw requires them for a Windows cross-built release. No component
license is substituted by this script. The output is a distributable notice file.
"""
import argparse
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mingw", action="store_true")
    args = parser.parse_args()
    meta = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--offline", "--format-version", "1"],
        cwd=ROOT, text=True))
    pieces = ["FlowBridge 0.2.0 — third-party component notices\n"
              "Generated from Cargo.lock and the local distribution's license files.\n"
              "This includes target-specific dependencies, some of which are not linked\n"
              "into every artifact. Copyright and license text follows unchanged.\n"]
    missing = []
    for package in sorted(meta["packages"], key=lambda p: (p["name"], p["version"])):
        if package["id"] in meta["workspace_members"]:
            continue
        directory = pathlib.Path(package["manifest_path"]).parent
        candidates = sorted({p for p in directory.iterdir()
                             if p.is_file() and p.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE"))})
        if package.get("license_file"):
            candidates = sorted(set(candidates + [directory / package["license_file"]]))
        if not candidates and package["name"] == "valuable" and package["version"] == "0.1.1":
            # The crate archive omits its workspace-root license; retained from
            # the exact official repository commit in .cargo_vcs_info.json.
            candidates = [ROOT / "third_party/valuable/LICENSE.MIT"]
        pieces.append(f"\n{'=' * 72}\n{package['name']} {package['version']}\n"
                      f"Declared license: {package.get('license') or 'see license file'}\n"
                      f"Upstream: {package.get('repository') or package.get('homepage') or 'https://crates.io/crates/' + package['name']}\n")
        if not candidates:
            missing.append(package["name"])
        for path in candidates:
            pieces.append(f"\n--- {path.name} ---\n{path.read_text(encoding='utf-8')}\n")
    if missing:
        raise SystemExit("License files unavailable for: " + ", ".join(missing))
    pieces.append("\n" + "=" * 72 + "\nnlohmann/json 3.11.3\nhttps://github.com/nlohmann/json\n")
    pieces.append((ROOT / "third_party/nlohmann/LICENSE.MIT").read_text())
    sysroot = pathlib.Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip())
    rust_notices = sysroot / "share/doc/rust/COPYRIGHT-library.html"
    for name in ("Apache-2.0.txt", "MIT.txt"):
        path = sysroot / "share/doc/rust/licenses" / name
        if not path.is_file():
            raise SystemExit(f"Rust runtime license missing: {path}")
        pieces.append(f"\n{'=' * 72}\nRust standard library / {name}\n{path.read_text()}\n")
    if rust_notices.is_file():
        pieces.append("\nRust standard library bundled third-party attribution (HTML source):\n" + rust_notices.read_text())
    if args.mingw:
        for name in ("mingw-w64-common", "gcc-mingw-w64-base", "nsis"):
            path = pathlib.Path("/usr/share/doc") / name / "copyright"
            if not path.is_file():
                raise SystemExit(f"Required MinGW notice missing: {path}")
            pieces.append(f"\n{'=' * 72}\nMinGW cross-toolchain / {name}\n{path.read_text()}\n")
        for name in ("GPL-3", "LGPL-2.1", "LGPL-3"):
            path = pathlib.Path("/usr/share/common-licenses") / name
            if path.is_file():
                pieces.append(f"\n--- Referenced license text: {name} ---\n{path.read_text()}\n")
    output = ROOT / "third_party/THIRD_PARTY_NOTICES.txt"
    output.write_text("".join(pieces), encoding="utf-8")
    print(f"Saved {output.name}: {output.stat().st_size} bytes")


if __name__ == "__main__":
    main()
