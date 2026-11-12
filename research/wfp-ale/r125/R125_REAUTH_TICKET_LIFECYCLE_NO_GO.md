# R125 — ALE reauthorization vs one-use redirect ticket: three independent denial gates

2026-11-12. Strict scope: `i-shutov/flowbridge`, research branch `research/windows-wfp-ale-attribution-20261107`, parent `51452107b8c311d194def2a130bb30f65967c9fa`; `main` read-only `5b5afc2feeda2195f302380e615ba003d4906e09`. Not beta, PR #56, release, historical G1, PacketBound/G2 or an actual kernel test.

## Material source-derived hypothesis

Microsoft documents reauthorization of an **already approved** ALE flow when ALE policy changes, an interface changes in applicable configurations, or a pended authorization completes. It occurs at the original `ALE_AUTH_CONNECT_V4/V6` layer for outgoing flows and has `FWP_CONDITION_FLAG_IS_REAUTHORIZE`. The flow's packets may then be incoming *or* outgoing; deriving its original authorization layer from current packet direction is invalid.

In the exact frozen R19 source, a selected original-AppId TCP callout that receives a **genuine reauthorization indication** is not equipped to reauthorize its previously admitted flow. It has THREE separate state barriers:

1. `kernel-r19/kernel/src/redirect.rs` blob `9a07e026134d46ef646d39862bd982cc48bbc5f6`: `auth_check()` explicitly rejects `0x0000_0004` (`IS_REAUTHORIZE`) and `0x0200_0000` (`HONORING_POLICY_AUTHORIZE`), then calls `route.book.attest(identity,original_destination,now())` only if those bits are absent.
2. `kernel-r19/kernel/src/handoff.rs` blob `e1d17217db50362ba9c4efc83af820b6beb094cf`: `Book::attest` rejects a live ticket with `auth_seen=true`. A first successful authorization sets `auth_seen=true`.
3. `Book::take` (the broker CLAIM) sets `slot.live=false` **before** checking the supplied context, including terminal failed claims. Thus after a successful initial AUTH+CLAIM, the ticket is absent; lifting the flag check and resetting `auth_seen` alone cannot reauthorize it.

Conditional consequence: if WFP routes an existing selected flow to this same R19 AUTH callback during reauthorization and the callout retains action-write authority, it returns BLOCK, even for an otherwise unchanged previously accepted connection. The precise runtime selection, fields and OS effect have **not been observed**. This is **liveness/availability NO-GO** for continued admitted-flow semantics, **not a proven DIRECT leak**. Fail-closed denial is still preferable to an unproven allow.

## Independent deterministic negatives

`r125_reauth_lifecycle_negative.py`: 7 stdlib unit tests PASS; `r125_reauth_lifecycle_independent.mjs`: independent Node.js transition oracle PASS. Both exhaust **4096** deterministic hypothetical combinations: 4 lifecycle phases (issued/authed/claimed/retired) × IPv4/IPv6 × TCP/UDP × 256 flag/metadata/identity/destination/SSH/TTL masks.

- R19-like initial-admission boolean: **2/4096** positive SYNTHETIC states (one per TCP family; no live WFP evidence).
- Hypothetically removing ONLY the reauthorization flag gate: **4/4096**; this does not restore an established flow, because authed and claimed phases still reject.
- Removing the flag gate AND allowing `auth_seen` reset: **8/4096**, including some pre-CLAIM authed states; claimed/retired remain denied because no live slot exists.
- Reauthorization after initial AUTH but before CLAIM: denied by flag + `auth_seen`. Reauthorization after successful CLAIM: denied by flag + missing live slot. Process/PID epoch mismatch, reused endpoint/5-tuple, lost SSH, absent original destination or metadata, IPv6/UDP out-of-scope remain negative or unproven, not inferred successful.

Both oracles: SHA-256 of identical line-oriented 4096-result matrix **`b4033b51b83ae96cc7f680b3aeacfa32e913f550aad22626866123b339d0d60d`**. Source Git blobs and four decisive source anchors independently checked via GitHub. No Rust compiler or native Windows channel: physical WFP behavior and Rust ABI not tested.

## Required architecture before claiming continued-flow support

Separate the ephemeral one-time **initial CLAIM ticket** from an authenticated, kernel-origin, revocable **established-flow reauthorization state**, bound at first actual ALE classify to selected exact WFP AppId, referenced PID + creation epoch + start key + canonical EXE, endpoint and compartment, original v4/v6 destination and redirect state; consume tickets exactly once without resurrecting them. Preserve security checks on each future WFP reauthorization including flow identity, policy epoch, process death/PID reuse, re-used 5-tuple, sibling DIRECT, DNS/UDP/QUIC, WFP/BFE/SSH loss. If any authoritative field is unavailable, block. A user-mode or BFE inventory correlation cannot supply missing kernel proof.

This is a **proposed contract**, not an implemented driver/callout or an authorization to change R19. Need independently gated Windows physical classify tests to establish whether and how such a record can safely survive initial CLAIM, multiple reauthorizations and policy changes. A read-only BFE inventory or Windows Rust compile remains useful but does not prove this behavior.

## Next decisive permitted experiment

Native Windows x64 R124 harness with metadata-only compilation, then separately opted-in Rust synthetic tests; capture source and executable SHA-256, rustc -vV, Windows build, JSONL and exit codes. Also execute the R125 Python/Node negatives on matching research checkout. Kernel/driver/filter/packet or VNC work remains explicitly forbidden absent separate owner decision and driver/VNC/SYSTEM rescue/rollback gates.

Official Microsoft references reviewed 2026-11-12:
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-stateful-filtering
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_incoming_metadata_values0_

No changes to main/release, beta branch, PR #56, runners/CI, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, network, other repositories, automation schedules/state, controller, driver/callout/NDISRD, ProxiFyre AGPL, closed PR40, vendor binaries, C++ WFP payload or paid resources. Only expected-SHA non-forced research ref mutation is permissible.
