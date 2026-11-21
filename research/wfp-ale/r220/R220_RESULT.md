# R220 — ALE AUTH_CONNECT flag-separation negative model

Date: 2026-11-21. Scope: **only** `research/windows-wfp-ale-attribution-20261107` in `i-shutov/flowbridge`. Base research commit `50201c01387659573fadedc88050d5c1088b0dd0`; base main `5b5afc2feeda2195f302380e615ba003d4906e09`. This is not beta, PR #56, PacketBound/G2 PASS, or a native kernel demonstration.

## Documented semantics and testable hypothesis

Official Microsoft [Filtering condition flags](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-flags) identifies separate AUTH_CONNECT bits:

- `FWP_CONDITION_FLAG_IS_CONNECTION_REDIRECTED = 0x00100000`: an ALE_CONNECT_REDIRECT callout redirected **this connection**.
- `FWP_CONDITION_FLAG_IS_PROXY_CONNECTION = 0x00200000`: **previous redirect records** exist on this proxied connection.
- `FWP_CONDITION_FLAG_IS_REAUTHORIZE = 0x00000004` and `FWP_CONDITION_FLAG_IS_HONORING_POLICY_AUTHORIZE = 0x02000000` have distinct meanings.

At pinned R19 `research/wfp-ale/kernel-r19/kernel/src/redirect.rs`, exact blob `a093f049d162987981a957aac90db1014bc6ff09`, `auth_check` requires REDIRECTED, rejects REAUTHORIZE/HONORING, and does not use PROXY_CONNECTION as evidence of REDIRECTED. The [redirection API documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection) and [proxied connections tracking](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking) describe redirect records, but these are **not** final authority for the actual AUTH flags on FlowBridge's physical SSH socket.

Consequently R218/R219's single `redirected` boolean must not conflate the two flags. Neither does this imply that both flags cannot co-occur. The R218 physical SSH self-blocking hypothesis remains *conditional*: it requires native evidence of actual ORIGINAL_APP_ID, flags, filter arbitration, and socket destination.

## Executable user-mode experiment

- `r220_auth_flags_model.rs`: dependency-free Rust, `#![forbid(unsafe_code)]`, seven unit tests, no OS/network/driver APIs.
- `r220_flags_oracle.mjs`: independent JavaScript boolean-matrix oracle, source-contract assertions if the R19 kernel source is present in the checkout, five sensitivity mutants.
- Linux executor: Node 22.16.0, `node --check` PASS; `node research/wfp-ale/r220/r220_flags_oracle.mjs` PASS; **2048/2048** synthetic vectors (1536 out of scope, 508 block, 4 permit-*candidates*); all five mutants detected (2/4/4/4/4 mismatches). Vector digest SHA-256 `c437d2d05cc25436d22251919f2577a055346dbbecb68fc024bb5febd4726391`.
- Original artifact Git blob SHAs: Rust `3caf8fb521d7dc77f3c829151ced1364f54e6923`; JS `72efb9e37694323adb8fdd1d27c9f9fb5b0c6460`. Runtime source-contract assertions were skipped locally because no R19 checkout was available; official contract and pinned R19 blob were reviewed separately.
- **Not executed:** Rust compilation/7 tests (no `rustc`/`cargo`), Windows native classify, BFE inventory, WFP filters, kernel driver or network/proxy interactions.

## Trust boundary / outstanding NO-GO

Kernel-origin process create events `PsSetCreateProcessNotifyRoutineEx`, referenced `EPROCESS/FileObject`, `PsGetProcessCreateTimeQuadPart` and `PsGetProcessStartKey`; pinned WFP AppId via `FwpmGetAppIdFromFileName0`; real `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6` to `ALE_AUTH_CONNECT_V4/V6` including `FWPS_CONNECT_REQUEST0.previousVersion`, process metadata, redirect handle, v4/v6; accepted-socket `SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT`, terminal kernel CLAIM; outbound `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS`, final arbitration of physical SSH: **not end-to-end proven**. Read-only BFE `FwpmEngineOpen0/FwpmFilterGetByKey0` proves a policy snapshot, not that classify succeeded or DIRECT cannot occur. PID reuse, 5-tuple reuse, sibling DIRECT, DNS/UDP/QUIC, and WFP/BFE/SSH failure remain unresolved.

Next **permitted** decisive step: compile and run all pure-Rust R201/R202/R218/R219/R220 unit tests with independently checked oracle results in an admitted user-mode environment; then separately authorized passive Windows BFE readback. **No** kernel classify without explicit driver/VNC/SYSTEM rescue/rollback/cost gates. No release/no-DIRECT/leak-free claim.
