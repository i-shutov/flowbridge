# R74 — WFP receipt-error observability cut; terminal CLAIM fault matrix

Date: 2026-11-09. **ONLY** research/windows-wfp-ale-attribution-20261107. Baseline research HEAD `02f98c108a5b47475ae57d71181ff72662eedc01`; main `5b5afc2feeda2195f302380e615ba003d4906e09`. Independent architecture R&D, not beta, PR #56, PacketBound/G2, G1 at `dd1ab3c`, leak-free or native Windows proof.

## New actionable NO-GO (not an observed leak)

There is **no authenticated owner/redirect evidence in the broker when obtaining the WFP receipt itself fails**. The broker cannot distinguish:

(A) an unrelated TCP client reaching the local listener without valid WFP redirect records/context, from
(B) a genuine selected process's redirected connection whose `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS)` or `...CONTEXT` failed, or returned an invalid custom context.

Both induce the same `broker_windows::receive(client) -> Err`. The current `broker.rs` (lines 88–90) maps either to `Ok(WorkerOutcome::IngressRejected)`, i.e. **per-socket refusal, no global STOP**. This is intentional DoS resistance against unrelated bogus ingress. It prevents simultaneously guaranteeing (1) no global STOP on an unauthenticated local client and (2) immediate global STOP on every failed selected-app receipt **without an independent authenticated kernel signal**. Scenario (B) is conditional: no native occurrence or packet leakage was observed.

The actual accepted socket is dropped on failed receipt; there is **no application-payload forwarding and no direct fallback in that broker path**. But this is not a system-wide no-DIRECT guarantee, and WFP failure or another selected app socket is outside the broker's proof.

Once a validated `Received` exists, the worker treats failed CLAIM, `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS`, TCP socket setup, SSH pinned-host-key, SSH user authentication, channel-open or relay as **fatal and sticky-revoking** (`broker.rs` lines 92–108). `Book::take` consumes a successful CLAIM terminally before downstream SSH operations; failed post-CLAIM SSH cannot obtain a second successful CLAIM. This is source-level behavior; physical egress suppression remains unproven.

## Exact source / API trust boundary

Pinned blob SHAs independently read and matched on 2026-11-09:

- `kernel-r19/broker_windows.rs`: `16ec8853d322b40f0e00e14d49ae3410741b9395`. `receive` invokes two socket-specific `WSAIoctl` queries; `query` has a fixed 65536-byte records buffer and 128-byte custom-context buffer. A failed query returns `Err` without identifying selected origin. For the *verified SSH method specifically*, CLAIM occurs before outbound SET_RECORDS.
- `kernel-r19/broker.rs`: `ce6c549a9ae488cc7c0ca9a7e7be68871b9d7f2c`. Pre-receipt errors are per socket, post-receipt failures invoke `revoke`.
- `kernel-r19/kernel/src/handoff.rs`: `e1d17217db50362ba9c4efc83af820b6beb094cf`. Terminal `Book::take`; no replay after successful CLAIM.
- `kernel-r19/kernel/src/redirect.rs`: `9a07e026134d46ef646d39862bd982cc48bbc5f6`. Broker process loss kills Book; origin death after CLAIM does not itself revoke the already admitted SSH worker.
- `kernel-r19/trusted-ssh-r37/src/lib.rs`: `c6d8c8746fac45073c11557de893164e49d830eb`. Host key, user auth and direct-tcpip channel before copy, watch-based revocation.

Microsoft documents an opaque, variable-sized redirect record obtained on the *accepted socket*. Insufficient output buffer and other `WSAIoctl` errors are possible; the current fixed-capacity `query()` does not retry or provide an independent origin witness. Two official error-code descriptions for an undersized query buffer are inconsistent, so this research does not assume a particular native error number.

Primary APIs:
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-context
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0

## Executable deterministic independent oracles

`r74/r74_negative.py` — Python stdlib, **20 unit tests**; `r74/r74_independent.mjs` — Node stdlib independent bitmask model. The 2 programs enumerate **16,384** abstract worlds = both IP families × 13 binary flags and agree on the per-world ordered SHA256:

`ba9534ef412fda18d6ddf37cddd414ab0b97cbcaff4875a8f4aab797be71855f`.

Synthetic overlapping scenario counts: selected/pre-receipt-error **4096** vs unrelated/pre-receipt-error **4096** (same broker decision); post-receipt STOP **8160**, with consumed-CLAIM/no-copy **4064**; source-level relay candidate **32**, including owner death after CLAIM **8**, endpoint reuse after CLAIM **16** and WFP-loss flagged **16**. **0** physical no-DIRECT certificates: these booleans are injected *assumptions*, not observed OS facts. An owner-exit or WFP-loss flag is not a current broker admission input. No kernel calls or actual flows were exercised.

Independent source audit: 11/11 invariants after scoping one search to the trusted SSH method (the initial global search incorrectly caught the earlier legacy branch). The full extended local checkpoint also includes a pure Rust `#![forbid(unsafe_code)]` model and 18 Rust tests **not run** (no local rustc/cargo); only the two language oracles are published by this commit. No Rust PASS is claimed.

## Trust chain and explicit boundaries

`FwpmGetAppIdFromFileName0` → exact opaque `FWPM_CONDITION_ALE_APP_ID` → kernel `ALE_CONNECT_REDIRECT_V4/V6` and `ALE_AUTH_CONNECT_V4/V6` with original AppId and trusted WFP metadata → referenced original process identity and creation epoch/start key (not a retrospective PID/5-tuple join) → socket-specific redirect records/context → one-use CLAIM → outbound SET_RECORDS → pinned SSH host/user authentication → channel → copy. The gap at **receipt failure** precedes any broker-recognized original identity. R72/R73's lack of kernel independent CLAIM-to-socket binding and R69–R71's metadata/state conditions remain open.

**NO-GO:** genuine kernel-origin accepted-socket proof, owner-death liveness, reused 5-tuple attribution, physical IPv4/v6 egress, selected sibling DIRECT, DNS/UDP/QUIC, SSH/WFP-loss leak-free, PacketBound/G2, historical G1 promotion.

**Next decisive R75:** design authenticated, per-flow, bounded kernel-origin *receipt-failure* evidence (and tests for replay, process death/PID reuse and loss) that does not let arbitrary local clients trigger global STOP; inspect official `WSAIoctl` read-only error semantics with an owned ordinary socket only, **without** treating that as a native redirected-flow experiment. Until a later separately authorized kernel/VNC/SYSTEM gate, no driver/callout/filter or system changes.

No changes to main/release, beta integration/windows-rust-capture-agent-20261031, PR #56, runner, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, network, other repos, automations or paid operations.
