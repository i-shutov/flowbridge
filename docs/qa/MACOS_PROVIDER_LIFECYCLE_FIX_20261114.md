# R02/R08 — actual macOS provider lifecycle correction

Date: 2026-11-14. **Product source correction, not another disconnected model.**
Base: `5b5afc2feeda2195f302380e615ba003d4906e09`.
Original provider Git blob: `86e195e4e25d47b664f5cb1773ff8deea2985dcd`.

## Reproduced source defects

The original `TransparentProxyProvider.swift` was copied byte-for-byte and
its Git blob hash verified before tests. Its full method bodies were compiled
with deterministic test-only NetworkExtension and Rust FFI substitutes.
No driver, extension activation, OS packet path or real SSH was exercised.

Four pinned-baseline regressions fail for their specified causes:

| Case | Original behaviour | Correction |
|---|---|---|
| Duplicate Start | Replaces the live generation and submits another settings apply | Refuse starting/active/stopping/incomplete-cleanup states without touching the live session |
| Stop while settings apply is pending | Stop destroys the core handle; the delayed startup callback destroys it again | Transfer ownership once under the provider lock; stale callback owns no handle |
| Restart before asynchronous clear completes | New startup can race removal of the old settings | Serialize entire asynchronous apply/clear operations; do not admit restart before clear completion |
| DIRECT evaluation interrupted by Stop | Old policy result can return `false` after Stop, delegating that delivered flow DIRECT | Revalidate captured session, generation and profile immediately before returning DIRECT |

These are reproducible **code-level** errors under controlled interleavings,
not claims of live leaks or crashes observed on a signed Mac installation.

## Implemented changes

`ProviderLifecycleQueue.swift` is a production helper, called by the actual
provider. It keeps one apply/clear operation active until its completion,
unlike a serial DispatchQueue that only serializes submission. Completion
identities prevent an old completion from finishing the next operation.

Startup uses a UUID generation, refuses overlapping starts and zero handles,
and publishes readiness/DNS state only when it still owns the current core.
Failures before settings publication release the startup state for retry.
A failed settings apply schedules cleanup before completing startup failure.

Shutdown immediately closes admission, consumes the core handle once,
revokes the DNS lease, cancels relays, and coalesces simultaneous Stop
callbacks behind one clear. A clear error keeps restart blocked until a
subsequent explicit Stop successfully clears settings. No settings error is
silently treated as evidence of successful cleanup.

The last TCP admission check now also verifies session/generation/profile.
This rejects stale Proxy results across a full restart and stale DIRECT
results across a rule reload. The transport exclusion path also rechecks
its captured snapshot. The `TCPRelay` byte I/O implementation is unchanged.
This is validation of an observed snapshot, not a new kernel-level atomic
no-DIRECT guarantee: Stop can still race after any user-mode validation,
and OS-level containment requires separate native evidence.

## Executed local tests and reproduction

Local compiler: Swift 6.2.1 on Linux x86_64, language mode 5,
`-warnings-as-errors -O`. Exit status 0 on the final complete invocation.

- 20/20 current-provider cases pass, including 50 start/stop cycles,
  cancellation during FFI creation, DNS lease revocation, zero handles,
  failed apply/clear, retry, duplicate Stop, synchronous callbacks,
  stale policy and stale session decisions, and the positive DIRECT path.
- 4/4 exact historical-provider regressions reproduce their expected FAIL.
- 2/2 deliberately restored defects are rejected by their matching tests.
- Source hashes are written to `lifecycle-report.json`; byte-for-byte
  equality with the exact hosted checkout must be checked separately.

Command from a full checkout (the pinned baseline must be in Git history):

```sh
python tools/test_macos_provider_lifecycle.py --negative-controls \
  --output build/verification/provider-lifecycle
```

The harness removes **only** `import NetworkExtension` and `import Darwin`
from its temporary provider copy. The production method bodies are not
rewritten. Test shims provide controlled callbacks and record FFI ownership;
they are never packaged into FlowBridge.

The dedicated macOS CI workflow runs the same regressions, baseline and
mutation controls. The existing general workflow separately compiles the
real app/system-extension target with the Apple SDK and signing disabled.
Passing either workflow does not imply native extension activation.

## Acceptance boundary / next native test

The actual signed/macOS R02 gate remains OPEN: signing/entitlements,
install/approve/activate on Apple Silicon and Intel, real selected and
unselected IPv4/IPv6 traffic, DNS/UDP/QUIC containment, SSH outage,
sleep/wake, uninstall and independently observed egress still need tests.

Native follow-up must force Start/Stop cancellation, rule reload during
connection admission, settings failure/recovery, and repeated restart while
checking actual OS configuration, Rust handle lifetime and packet traces.
Keep `release_accepted=false`, `native_ne_activated=false` and
`physical_no_direct_proved=false` in these code-regression reports.

This patch does not change Windows G2, NDISRD/WFP authorization, frozen
explicit-beta packages, signatures, user machines, firewall or routing.

Primary Apple contracts:
- https://developer.apple.com/documentation/networkextension/netunnelprovider/settunnelnetworksettings(_:completionhandler:)
- https://developer.apple.com/documentation/networkextension/neappproxyprovider/stopproxy(with:completionhandler:)


## R06 P0 follow-up — transactional boundary for Apply rules (2026-11-14)

The R02 lifecycle repair alone did **not** close the user-mode Apply race.
The provider previously committed new Rust rules using `fb_native_reload_json`
and only later updated its Swift `profile`. A flow evaluated from the old
Swift profile could return DIRECT/Proxy during that split state. This is a
deterministic source-level mismatch, **not** a proven physical traffic leak.

**Actual product fix:**

1. Verify the current session and install `applyingRules` admission barrier
   under the provider lock **before** Rust reload starts.
2. Increment `policyRevision` to invalidate evaluations captured before Apply,
   even if Rust rejects the update.
3. Reject new flows and stale DIRECT/Proxy evaluations while Apply is running.
   Final Proxy admission also validates generation, revision, profile and handle.
4. On a rejected Rust reload, keep the prior Swift profile and unblock it.
   On Stop, invalidate the barrier; late FFI completion cannot revive state.
5. Rust `fb_native_reload_json` itself already validates schema/transports
   before committing; the Swift fence covers the cross-language admission
   window, not an atomic WFP or NetworkExtension security barrier.

**Exact-source hosted evidence:**

- [Focused macOS run #43635270498](https://github.com/i-shutov/flowbridge/actions/runs/43635270498):
  **23/23** actual-provider-method-body tests PASS on Apple Silicon;
  **4/4** historical baseline failures reproduced, **3/3** deliberate
  mutants rejected, including one removing the new Apply admission barrier.
- New deterministic tests: old DIRECT evaluation during reload, arriving
  DIRECT flow during reload, rejection and retry after invalid Rust update,
  Stop while Rust reload is still executing.
- Functional code commit `5a3f14e32ffa72daf84fd9d72c06b8f9b7dfdd18`
  followed by focused tests and mutation source through `748e625a86a1`.
- Separate general Rust/native and DNS workflows must be independently
  inspected after completion before receiving PASS on the tested tree.

**Still OPEN:** real signed Apple Silicon/Intel NetworkExtension activation,
selected/unselected TCP IPv4/v6 over actual SSH, physical no-DIRECT/DNS/UDP/
QUIC observations, rule Apply/Stop during outages and user-machine rollback.
The tests use Apple NE and Rust FFI substitutes, not live kernel redirection.
`native_ne_activated=false`, `physical_no_direct_proved=false`,
`release_accepted=false`. Frozen explicit SOCKS beta remains unchanged.
