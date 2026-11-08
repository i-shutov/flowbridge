# R39 pre-admission engineering — broker lifecycle regression fix

Date: 2026-11-08. Scope: `research/windows-wfp-ale-attribution-20261107` ONLY.
This is user-mode source hardening, not a native end-to-end R39 acceptance,
and does not modify main or the SOCKS-only beta PR #56.

## Defects and patch

1. The experimental broker previously issued a **global kernel STOP** whenever
   `receive()` failed for a local accepted socket. An unrelated process could
   connect to an ephemeral loopback broker port without WFP redirect context,
   fail the WFP query, and thereby kill an already authenticated SSH relay.
   Missing/untrusted receipt must instead be **per-socket reject and close**.
   Kernel heartbeat loss, post-receipt CLAIM/SSH failures, worker panic and
   policy failure still result in fail-closed global revocation.

2. The broker's 32-worker guard used `Vec::len()` without reaping finished
   threads. After 32 successful connections over time, the 33rd connection
   was rejected with global STOP even when there were zero active relays.
   A `WorkerPool` reaps completed handles before admission and counts only
   in-flight threads. Its active limit is still 32. At saturation, the new
   accepted socket is dropped; **there is never DIRECT fallback**.

3. For auditability, final broker output now reports successful joined
   relays, rejected unproven ingress and drops at active capacity separately.
   Counters are not evidence of an actual WFP redirect.

## Tests included in exact production helper

`kernel-r19/broker_lifecycle.rs` has deterministic tests for:
- A rejected unproven local ingress while an authenticated worker remains live;
- Exactly two live workers, a third drop, then successful reuse of the cap;
- Post-receipt fatal error and panic preserved as fatal;
- 100 completed workers without leaking the active capacity.

The hosted Windows no-load workflow compiles and executes these through
`cargo test --locked --release`, and builds the real broker. **Only a
completed green run counts as compiler-backed evidence.** No driver load or
BFE activation is part of that workflow.

## Still required for R39

Gate 1: actual Microsoft-returned signed `.sys/.cat` for the exact source,
verified on target Windows (no test-signing/disabled protections). R38C's CAB
is unsigned; its PDB match and InfVerif PASS do not satisfy signing.

Gate 2: current *independently operated* VNC, SYSTEM rescue and rollback,
plus independent physical egress observation before any kernel load/filter.

Gate 3: one unprepared selected EXE, continuous kernel origin/AppId/epoch and
ALE_CONNECT_REDIRECT + AUTH ticket, owned accepted-socket records and terminal
CLAIM, SET of those records on the **real SSH socket before connect**, pinned
host key/user authentication, direct-tcpip and exact target bytes.

Gate 4: negative peer, twin EXE, PID/epoch, replay/tombstone, SSH/PING loss,
BFE crash/cleanup, family, DNS/UDP/QUIC and physical DIRECT tests. No
system-wide kill-switch claim from user-mode cancellation.

`g2_pass=false`, `native_r39_e2e_observed=false`,
`release_accepted=false` until independently evidenced.
