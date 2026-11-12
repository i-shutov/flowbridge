# R139 — accepted-socket source contract, verified R138 evidence, and release blockers

Date 2026-11-12. Scope **only** `i-shutov/flowbridge` branch
`research/windows-wfp-ale-attribution-20261107`.
Base research HEAD `9d013262a08a7f7f887a28fa54b4a5b961bed385`.
Read-only `main` `5b5afc2feeda2195f302380e615ba003d4906e09`.
No modification of R19 implementation, beta, release, PR56, runners, service,
firewall/security policies, network, drivers or WFP callouts/filters.

## R138 owner archive accepted without over-claim

Received `evidence-only(4).zip` SHA-256
`f0cbe6a8acefec374eb7ecb3c273b3707efd9dd92cc64dfa1e008a0d`.
All 18 members checked for CRC, lists of 20 unique Rust tests matched 20 successful
runs, no stderr bytes; full 480-line decision matrix exactly matches independently
re-run Python and Node oracles:
`8185ca0c6b8a1dbd968ab3be9a3b0fa105bbc16f9ca0b4b8271f8a1de3d16695`.

Held owner-derived process handles reported two concurrently live different PIDs,
matching file-derived WFP AppIds, A then self-exiting with code 23 while B remained
alive then exited with code 29. Exact process-identity gate mask 1;
AppId-only gate mask 15. The result *demonstrates the insufficiency of AppId alone
for a process-instance ticket*. It does **not** mean a per-EXE WFP filter should
exclude another copy of the selected EXE. `R138_RECEIVED_ACCEPTANCE.json` retains
sanitized member hashes/results, not raw image names or local PIDs.

No EXE bytes were supplied, so the user-reported compiled binary digests were
not independently rehashed. Host time is not attested. Nothing was injected or
intercepted and no PID reuse was forced.

## Decisive transition: inspect R19 native accepted-socket witness *source*

The exact existing R19 source has an important partial positive **design**:

- `broker_windows.rs::receive(accepted: TcpStream)` owns the socket it receives,
  performs both `SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS` and
  `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` against `&accepted`, parses the
  context, and constructs `Received` with private fields.
- `Received::claim_and_connect_trusted_ssh` calls the kernel `CLAIM` before creating
  its own outbound physical SSH socket, sets opaque redirect records on that socket
  through `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` **before** `connect`, and rejects
  every error. The separate SOCKS branch similarly sets records before connect.
- `redirect.rs` sets `localRedirectTargetPID`, `localRedirectHandle` and the
  `localRedirectContext` on the writable request. The context is a proposed kernel
  Book ticket, not itself OS-verified authority.
- `QUERY_RECORDS=0x980000DC`, `QUERY_CONTEXT=0x980000DD`,
  `SET_RECORDS=0x980000DE` agree with SDK `mstcpip.h` expressions
  `_WSAIOW(IOC_VENDOR, 220/221/222)`; this header match is checked separately.
- R19 rejects ordinary non-WFP TCP ingress in its negative test; this test is
  not proof of a real redirected connection.

This is **source-contract evidence only**. Neither the accepted socket nor the
kernel context has yet been observed in a *native activated WFP redirect*; no
process was bound to an ALE classify in R139. An arbitrary client-provided
byte buffer is not an accepted-socket WFP record, nor is an AppId a process owner.

Pinned Git blobs checked from repository source (no C++ payload reused):

| File | Git blob |
| --- | --- |
| `kernel-r19/broker_windows.rs` | `16ec8853d322b40f0e00e14d49ae3410741b9395` |
| `kernel-r19/kernel/src/lib.rs` | `0af6d4539673d2894cbaa91af0ea8f3524862a26` |
| `kernel-r19/kernel/src/redirect.rs` | `9a07e026134d46ef646d39862bd982cc48bbc5f6` |
| `kernel-r19/policy_windows.rs` | `acf60334320d970f58af3349ee75fbaa59826602` |

## Two independent RELEASE NO-GO gates still open

**A. ACTION_WRITE / veto semantics.** Microsoft documents that a callout may
change `FWPS_CLASSIFY_OUT0.actionType` with `FWPS_RIGHT_ACTION_WRITE`, or without
that right only to veto a higher-weight `FWP_ACTION_PERMIT` by writing BLOCK.
R19 `redirect.rs::block` unconditionally writes BLOCK, and `lib.rs` STOP/rundown
branches also write BLOCK without confirming the right or an incoming PERMIT.
This produces a **conditional source-level contract violation** for a classify
that arrives without action-write and without a prior permit. R135 established
this; R139 now makes the exact-source signature an explicit release gate.
The scenario has not been observed on the user's Windows host.

**B. Dynamic BFE session lifetime.** `policy_windows.rs` opens a BFE session with
`FWPM_SESSION_FLAG_DYNAMIC`. Microsoft documents that objects added in the session
are removed when it ends. That is a useful cleanup behavior but **not a persistent
selected-app no-DIRECT barrier on crash or teardown**. R129 showed all four
FlowBridge filters absent on the host; R131 characterized the gap. No new policy
is activated for this experiment. A persistent/independent fail-closed enforcement
design requires separate threat review and explicit lab authorization.

These are **separate** from a full kernel-origin attribution proof; addressing
one does not eliminate the other. Do not "repair" source by merely allowing
unrestricted BLOCK writes when ACTION_WRITE is absent, or by converting dynamic
WFP policies into persistent filters without recovery design and operator consent.

## Reproducible source-only experiment

`FlowBridge-R139-SourceGate.ps1` uses PowerShell 5.1 and:

1. Downloads four pinned exact Git blobs, verifies their Git SHA-1 over byte-accurate
   `blob <size>\0` bodies, records SHA-256 and preserves the bytes in an isolated
   temporary directory. No checkout or newline normalization.
2. Checks the two accepted-socket query calls, private Received, exact CLAIM ->
   SET_RECORDS -> connect order on *both* outbound branches, fail-closed output,
   kernel redirect request context, conditional action-rights blockers and dynamic
   session lifetime signatures. These are bounded source checks, **not an AST or a
   comprehensive proof that no other code path can bypass the gate**.
3. Optionally reads a locally installed `mstcpip.h` for the SDK macro formulas.
   Missing headers are `HEADER_UNAVAILABLE`, not automatic system installation.
4. Writes `R139_EVIDENCE.json`. **Exit 3 deliberately means RELEASE NO-GO** and
   a successful *source* audit; exit 2 indicates source/SDK mismatch or unavailable.
   Neither exit is a WFP or G2 PASS.

This script does not compile code, call WFP, create sockets, manipulate filters,
query foreign processes or change system settings. It makes only HTTPS GitHub
blob downloads and local filesystem reads/writes in its own temp directory.

The pure Python/Node test oracles exercise 2,048 synthetic stage combinations for
accepted-socket provenance *assumptions*, record/context lookup, parse, CLAIM,
outbound creation, SET_RECORDS, connect, pinned host key, SSH channel and revocation.
Exactly **one** full-gated combination is conditionally admissible; no claim is
made this state occurred in real Windows. SHA-256:
`b96761c1db4c04d8e3485730b6c2c385cf6968af17eedc4edad4a39f7da9eb96`.
26/26 Python negative and source-surface tests pass; independent Node oracle matches
all 2,048 outcome rows. A failed CLAIM has only a modeled **attempt**, not a
provably consumed kernel ticket in that hypothetical state.

## Next implementation tasks (separate from native GO)

1. **A: classify contract repair design:** define an action-write/veto helper for
   all R19 callback exits. Enumerate incoming action and rights, including
   STOP/rundown. Preserve incoming result when no write/veto right and report
   UNPROTECTED/NO-GO rather than writing an unauthorized action.
2. **B: crash-safe policy architecture:** choose an independently administered
   enforcement model and recovery/rollback plan, with explicit selected-app scope.
   No automatic persistent WFP mutation is authorized here.
3. **C: accepted-socket integration proof:** only after driver-lab authorization,
   demonstrate actual native ALE classify -> accepted socket WSAIoctl records/context
   -> one-use kernel CLAIM -> SET_RECORDS on physical SSH socket. Test v4/v6,
   PID reuse, same-name sibling, 5-tuple reuse, failure/recovery, DNS/UDP/QUIC.

Assignments are scoped as proposed junior-model tasks in `LOCAL_REVIEW_TASKS.md`.
No callable subagent executor or model selector is present; none was run.

## Primary Microsoft contracts

- https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_classify_out0
- https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-context
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection

No G1 `dd1ab3c` promotion, PacketBound/G2 PASS, leak-free/no-DIRECT or
release GO. Only the research branch may be updated with exact expected SHA
and `force=false`; stop on conflict.
