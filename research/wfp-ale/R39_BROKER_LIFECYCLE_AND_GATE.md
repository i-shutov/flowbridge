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

## Executed exact-source CI and independent artifact readback (2026-11-08)

- Commit: `2086cbaa860671cb3fa13524751fddf3f301e926`.
- [GitHub Actions run 42463556304](https://github.com/i-shutov/flowbridge/actions/runs/42463556304): **3/3 jobs SUCCESS** (Windows no-load kernel/broker, Windows local socket, Linux real isolated SSH).
- Windows actual broker unit tests **44/44 PASS**, including all five new lifecycle tests; kernel ledger 11/11, AUTH 7/7, handoff 19/19. Driver never loaded.
- Original Actions ZIP artifact ID **13610587594**; independently downloaded, ZIP CRC checked; SHA256 `ab18b9b4bc5fe889ecefaf063cfec9cafed394a81aefc250fab7092d7a3397db` (matches Actions artifact digest).
- `sources-r24.zip`: **30/30** exact SHA256/size and normalized Git blob checks; changed broker source blobs also matched the GitHub repository.
- PE CodeView RSDS and PDB MSF7 GUID/age independently matched. Current unsigned driver SHA256 `e4814cc069e424a246bb187e8540c3bbff3ec6f38d99f49dd9b17c65b91eb8d4`; PDB SHA256 `a1ed616daba270cba289f8f4ef233ff1dccbbbc8f09fbe49b5e7abfb55802c59`; broker SHA256 `8f6708635cf1e55328065c5535cd646a56bdac8835254b5fd6d6e976cde766ca`.
- Current unsigned CAB SHA256 `27e014f259ba9b8a16ae8a2887682a4557e2d84067122120f3d598ec58936147`. Independently decoded **41 MSZIP blocks** and matched all three internal SYS, INF and PDB bytes against staged sources by SHA256. INF SHA256 `29b62d0272436d62098d2514a6586db171261faaa58c9ac31a271518f3c5fbdd` is unchanged from the previously WDK-InfVerif-PASS artifact; **no fresh InfVerif was run for this commit**.
- Machine-readable independent receipt: `R39_VERIFIED_BROKER_CI_RECEIPT.json`.

**Do not use old R38C SYS/PDB/CAB hashes for this new source commit.** The unsigned build, reproducible tests and matched symbols do not satisfy the Microsoft signing/Windows-host safety gate. `g2_pass=false`, `native_r39_e2e_observed=false`.
