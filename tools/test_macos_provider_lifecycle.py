#!/usr/bin/env python3
"""Compile the actual Swift provider with OS/FFI test shims; no NE activation.

Only the two Apple platform import lines are removed from the tested provider.
Its lifecycle and flow-admission method bodies are unchanged. The separate
normal macOS CI job compiles the production file against Apple's real SDK.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PROVIDER = "native/macos/Extension/TransparentProxyProvider.swift"
BASELINE_SHA = "5b5afc2feeda2195f302380e615ba003d4906e09"
BASELINE_BLOB = "86e195e4e25d47b664f5cb1773ff8deea2985dcd"
REGRESSIONS = {
    "duplicate_start": "duplicate start did not reject",
    "cancel_pending_start": "native handle destroyed more than once",
    "restart_during_clear": "restart during clear did not reject",
    "stale_direct_after_stop": "stale decision released flow DIRECT after stop",
}


def run(args: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=ROOT, text=True, capture_output=True, timeout=timeout, check=False)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def compile_provider(source: bytes, folder: Path, swift: str) -> Path:
    folder.mkdir(parents=True, exist_ok=False)
    text = source.decode("utf-8")
    for line in ("import NetworkExtension\n", "import Darwin\n"):
        require(text.count(line) == 1, "Unexpected production import layout")
        text = text.replace(line, "")
    transformed = folder / "ProviderUnderTest.swift"
    transformed.write_text(text, encoding="utf-8")
    binary = folder / "provider-tests"
    result = run([swift, "-swift-version", "5", "-warnings-as-errors", "-O",
                  str(ROOT / "tests/macos_provider_test_shims.swift"),
                  str(ROOT / "native/macos/Extension/SharedNativeSession.swift"),
                  str(ROOT / "native/macos/Extension/ProviderLifecycleQueue.swift"),
                  str(transformed), str(ROOT / "tests/macos_provider_lifecycle.swift"),
                  "-o", str(binary)])
    require(result.returncode == 0, "Swift compile failed:\n" + result.stdout + result.stderr)
    return binary


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--baseline-file", type=Path)
    p.add_argument("--negative-controls", action="store_true")
    args = p.parse_args()
    output = args.output.resolve()
    require(not output.exists(), "Evidence directory already exists")
    output.mkdir(parents=True)
    report = {"schema": "flowbridge-macos-provider-lifecycle-v1", "status": "FAIL",
              "tests_passed": 0, "baseline_regressions_reproduced": 0,
              "mutants_rejected": 0, "actual_provider_body_tested": True,
              "apple_networkextension_stubbed": True, "rust_ffi_stubbed": True,
              "native_ne_activated": False, "physical_no_direct_proved": False,
              "release_accepted": False}
    code = 1
    try:
        swift = shutil.which("swiftc")
        require(swift is not None, "Swift compiler unavailable")
        report["swift_version"] = run([swift, "--version"]).stdout.strip()
        source = (ROOT / PROVIDER).read_bytes()
        report["production_provider_sha256"] = hashlib.sha256(source).hexdigest()
        tracked = [PROVIDER, "native/macos/Extension/ProviderLifecycleQueue.swift",
                   "native/macos/Extension/SharedNativeSession.swift",
                   "tests/macos_provider_test_shims.swift", "tests/macos_provider_lifecycle.swift",
                   "tools/test_macos_provider_lifecycle.py"]
        report["file_sha256"] = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in tracked}
        head = run(["git", "rev-parse", "HEAD"])
        report["checkout_sha"] = head.stdout.strip() if head.returncode == 0 else "LOCAL_WORKTREE"
        with tempfile.TemporaryDirectory(prefix="flowbridge-provider-") as tmp:
            work = Path(tmp)
            current = compile_provider(source, work / "current", swift)
            result = run([str(current)], timeout=120)
            (output / "current-tests.log").write_text(result.stdout + result.stderr, encoding="utf-8")
            require(result.returncode == 0, "Provider regressions failed:\n" + result.stdout + result.stderr)
            match = re.search(r"TESTS=(\d+) FAILED=(\d+) NATIVE_NE_ACTIVATION=false", result.stdout)
            require(match is not None and int(match[1]) == 23 and int(match[2]) == 0,
                    "Unexpected suite count / failed tests")
            report["tests_passed"] = int(match[1])
            if args.negative_controls:
                if args.baseline_file:
                    baseline = args.baseline_file.read_bytes()
                else:
                    old = run(["git", "show", BASELINE_SHA + ":" + PROVIDER])
                    require(old.returncode == 0, "Pinned baseline unavailable; fetch full Git history")
                    baseline = old.stdout.encode("utf-8")
                blob = hashlib.sha1(b"blob " + str(len(baseline)).encode() + b"\0" + baseline).hexdigest()
                require(blob == BASELINE_BLOB, "Baseline source drift; cannot claim reproduction")
                old_binary = compile_provider(baseline, work / "baseline", swift)
                baseline_log = []
                for name, diagnostic in REGRESSIONS.items():
                    failed = run([str(old_binary), name], timeout=15)
                    baseline_log.append(f"=== {name} rc={failed.returncode} ===\n" + failed.stdout + failed.stderr)
                    require(failed.returncode == 1 and diagnostic in failed.stdout and
                            "TESTS=1 FAILED=1" in failed.stdout, "Baseline did not reproduce: " + name)
                (output / "baseline-regressions.log").write_text("\n".join(baseline_log), encoding="utf-8")
                report["baseline_regressions_reproduced"] = len(REGRESSIONS)
                report["baseline_commit_sha"] = BASELINE_SHA
                report["baseline_git_blob"] = blob
                # Remove one fix at a time. The real provider body must fail its
                # corresponding regression rather than merely compile successfully.
                text = source.decode("utf-8")
                anchor1 = 'guard matchesFlowSnapshot(source: source, native: native, revision: revision, policy: policy) else {'
                anchor2 = '                    finished()\n                }\n            } catch {'
                mutations = [
                    ("stale_direct", text.replace(anchor1, 'guard true else {'), "stale_direct_after_stop",
                     "stale decision released flow DIRECT after stop"),
                    ("double_destroy", text.replace(anchor2,
                     '                    if !current { fb_native_destroy(id.uint64Value) }\n' + anchor2),
                     "cancel_pending_start", "native handle destroyed more than once"),
                ]
                require(text.count(anchor1) == 2 and text.count(anchor2) == 1, "Mutation anchors drifted")
                # 'guard true else' is deliberately unreachable and may be rejected
                # by -warnings-as-errors. Use a runtime true value instead.
                mutations[0] = (mutations[0][0], mutations[0][1].replace('guard true else {',
                                'guard native != 0 else {'), mutations[0][2], mutations[0][3])
                for name, altered, test, diagnostic in mutations:
                    mutated = compile_provider(altered.encode(), work / name, swift)
                    failed = run([str(mutated), test], timeout=15)
                    (output / ("mutation-" + name + ".log")).write_text(failed.stdout + failed.stderr, encoding="utf-8")
                    require(failed.returncode == 1 and diagnostic in failed.stdout,
                            "Mutant was not rejected for the intended cause: " + name)
                    report["mutants_rejected"] += 1
        report["status"] = "PASS_CODE_REGRESSION_ONLY"
        code = 0
    except (RuntimeError, OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
        report["error"] = str(exc)
    (output / "lifecycle-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
