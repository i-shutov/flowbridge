#!/usr/bin/env python3
"""Package source, docs, examples and verification evidence; exclude build trees.

Run from any directory. The output is ../artifacts/flowbridge-VERSION-source.zip.
No proprietary reference archive, credentials, toolchain or binaries are included.
"""
import hashlib
import json
import pathlib
import zipfile
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
VERSION = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
EXCLUDED = {"target", "build", "dist", ".git", "__pycache__", ".DS_Store"}


def files():
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in EXCLUDED or part.endswith(".xcodeproj") for part in relative.parts):
            continue
        if relative.parts[:3] == ("native", "macos", "lib"):
            continue
        if relative.parts[:2] == ("docs", "verification") and path.suffix.lower() == ".bmp":
            continue  # Keep the inspected PNG in docs, not duplicate uncompressed captures.
        if path.suffix.lower() in {".pfx", ".p12", ".key"} or path.name == ".env":
            continue
        yield path


def main():
    manifest = ROOT / "docs" / "SOURCE_MANIFEST.json"
    entries = [{"path": str(p.relative_to(ROOT)), "size": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in files() if p != manifest]
    manifest.write_text(json.dumps({"format": 1, "version": VERSION, "excludes_self": True, "files": entries}, indent=2) + "\n", encoding="utf-8")
    output = ROOT.parent / "artifacts"
    output.mkdir(exist_ok=True)
    archive = output / f"flowbridge-{VERSION}-source.zip"
    packaged = list(files())
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p in packaged:
            entry = zipfile.ZipInfo("flowbridge/" + p.relative_to(ROOT).as_posix(), (2026, 10, 28, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = (0o100755 if p.suffix == ".sh" else 0o100644) << 16
            z.writestr(entry, p.read_bytes())
    # Verify packaged bytes against the retained manifest and CRC once.
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        for entry in entries:
            assert hashlib.sha256(z.read("flowbridge/" + entry["path"])).hexdigest() == entry["sha256"]
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / f"flowbridge-{VERSION}-source.zip.sha256").write_text(f"{digest}  {archive.name}\n")
    print(json.dumps({"path": str(archive), "bytes": archive.stat().st_size, "files": len(packaged), "sha256": digest}, indent=2))


if __name__ == "__main__":
    main()
