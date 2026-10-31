# Native owned SSH pool lifecycle — 2026-10-30

## Production defects corrected

1. Win32 Start installed a default single-worker gate (128 flows), then tried to replace it with a two-worker pool (64 per worker). The shared per-endpoint budget correctly rejected the incompatible limits. A green transport-only test had not exercised this GUI startup sequence.
2. Win32 disabled the capture button whenever the user-owned engine was running, although managed capture requires that engine to be running. The shared availability predicate now distinguishes managed and external modes and blocks pending/stopping sessions.
3. macOS applied a pool against the old profile before a stopped engine was reloaded, ignored a pool configuration error, and did not reapply policy on existing-engine Start. Routing configuration is now deferred while stopped, installed after reload and before start, and any live owned-handle refresh failure stops routing rather than preserving cached readiness.

## Implementation

The optional strict boolean `enabled` in `fb_engine_sync_owned_ssh_pool_json` defaults to true. False masks all members unavailable without changing their budgets; true still requires the real registered supervisor's ready state and nonzero PID. The caller cannot forge readiness or use destroyed/duplicate handles. No new default single-worker gate is installed while pausing a pool. Established streams remain on their original workers.

## Executable regressions

- `tests/windows_native_smoke.cpp`: actual Rust ABI plus the SAME `ssh_pool_policy.hpp` used by Win32; pause/resume, 2->1->2, stale handles, and capture availability. It does not launch SSH or load WFP by itself.
- `tests/macos_engine_pool_lifecycle.swift`: compiles the ACTUAL `EngineController` against the Rust static library, uses an isolated temporary profile, exercises 1->2->4->3->2->1, changed-primary restart, invalid start, and failed live refresh. No Apple extension activation or actual SSH authentication is claimed by this controller test.
- `tests/real_owned_pool_lifecycle.py`: launched from the existing isolated Linux sshd suite, starts FOUR independent real OpenSSH processes, uses owned-supervisor API, tests 2->4->3->2 transitions, admission pause with retained bytes, all-paused failure without DIRECT, and zero leaked permits.
- Full Rust/native and DNS matrix remains mandatory on the exact PR head. A syntax check alone is not acceptance.

## Unchanged release boundary

These changes fix actual startup/control-path bugs. They do not establish a signed and installed Windows WFP driver, reproduce the user's Windows 251/252 internal FD limit, approve a macOS Network Extension, or close the system DNS/DPI/long-soak release gates. Version remains 0.2.0 internal beta until those separate criteria are demonstrated.
