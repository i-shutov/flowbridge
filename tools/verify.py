#!/usr/bin/env python3
"""Run reproducible project gates and retain actual output/exit statuses.

Usage: python3 tools/verify.py [--offline] [--cross] [--c-abi]
Requires Rust in PATH; network tests use only localhost. Existing logs are replaced.
Cross checks require preinstalled Rust target standard libraries; they do not
link or run native applications. --c-abi currently requires GCC on Linux.
"""
import argparse
import datetime
import json
import os
import pathlib
import platform
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--cross", action="store_true")
    parser.add_argument("--c-abi", action="store_true")
    args = parser.parse_args()
    output = ROOT / "docs" / "verification"
    output.mkdir(parents=True, exist_ok=True)
    lock = ["--locked"] + (["--offline"] if args.offline else [])
    commands = [
        ("rust-version", ["rustc", "--version"]),
        ("cargo-version", ["cargo", "--version"]),
        ("format", ["cargo", "fmt", "--all", "--", "--check"]),
        ("clippy", ["cargo", "clippy", *lock, "--workspace", "--all-targets", "--", "-D", "warnings"]),
        ("rust-tests", ["cargo", "test", *lock, "--workspace"]),
        ("build", ["cargo", "build", *lock, "--workspace"]),
        ("cli-smoke", [sys.executable, "tests/smoke.py"]),
    ]
    if args.c_abi:
        if sys.platform != "linux":
            parser.error("--c-abi currently supports Linux/GCC; use target-platform build instructions elsewhere")
        commands.extend([
            ("c-abi-build", ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", "native/include", "tests/ffi_smoke.c", "-L", "target/debug", "-lflowbridge_ffi", f"-Wl,-rpath,{ROOT / 'target/debug'}", "-o", "target/ffi-smoke"]),
            ("c-abi-run", [str(ROOT / "target/ffi-smoke")]),
        ])
    if args.cross:
        for target in ["x86_64-pc-windows-msvc", "aarch64-apple-darwin", "x86_64-apple-darwin"]:
            commands.append((f"check-{target}", ["cargo", "check", *lock, "--workspace", "--target", target]))
    results = []
    for name, command in commands:
        print(f"[{name}]", flush=True)
        start = datetime.datetime.now(datetime.timezone.utc)
        try:
            result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
            text, code = result.stdout, result.returncode
        except (OSError, subprocess.TimeoutExpired) as error:
            text, code = str(error), 1
        elapsed = (datetime.datetime.now(datetime.timezone.utc) - start).total_seconds()
        (output / f"{name}.txt").write_text(text, encoding="utf-8")
        results.append({"name": name, "command": command, "exit_code": code, "elapsed_seconds": elapsed, "output": f"{name}.txt"})
        print(text[-2000:] if code else f"PASS ({elapsed:.2f}s)", flush=True)
        if code:
            break
    report = {
        "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": platform.system(), "architecture": platform.machine(),
        "all_passed": len(results) == len(commands) and all(x["exit_code"] == 0 for x in results),
        "native_ui_built_by_this_runner": False, "native_interception_tested": False,
        "gates": results,
    }
    (output / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
