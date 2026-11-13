# R170 — correct R166's compartment **metadata vs incoming field** ambiguity

Research only: `research/windows-wfp-ale-attribution-20261107`; 2026-11-13.
**Correction / partial API feasibility finding, NOT a native WFP GO, kernel proof, DIRECT/leak-free or PacketBound/G2 PASS.**

## Precise official API route

R166 correctly found that `FWPS_METADATA_FIELD_COMPARTMENT_ID` is **not** listed at
`ALE_CONNECT_REDIRECT_V4/V6` in Microsoft's metadata table. This does **not**
mean that compartment cannot be read on that layer: it is a different category,
a layer-specific `FWPS_INCOMING_VALUES0.incomingValue[index]` field.

| Layer | Exact documented incoming field |
| --- | --- |
| `ALE_CONNECT_REDIRECT_V4` | `FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_COMPARTMENT_ID` |
| `ALE_CONNECT_REDIRECT_V6` | `FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_COMPARTMENT_ID` |
| `ALE_AUTH_CONNECT_V4` | `FWPS_FIELD_ALE_AUTH_CONNECT_V4_COMPARTMENT_ID` |
| `ALE_AUTH_CONNECT_V6` | `FWPS_FIELD_ALE_AUTH_CONNECT_V6_COMPARTMENT_ID` |

All four enumerated indexes are documented from Windows 10 version 1703.
At actual classify, require matching `layerId`, `index < valueCount` and correct
`FWPS_INCOMING_VALUE0.value.type`; do not mistake an incoming field for a
`currentMetadataValues` bit or assume equal compartments after proxying.
No native classify values were observed.

Authoritative Microsoft sources:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_connect_redirect_v4_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_connect_redirect_v6_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v4_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v6_
- https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_incoming_values0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer

## Source-level scope of proof

Pinned R19 blobs at research parent `ec417c4ca0d8e56ea5241b3993e341a291b2f55d`:
`redirect.rs` `a093f049d162987981a957aac90db1014bc6ff09`,
`policy_windows.rs` `acf60334320d970f58af3349ee75fbaa59826602`,
`lib.rs` `53f5ce6faa0f9f591974287f38ea890cafeb0dd2`,
`handoff.rs` `e1d17217db50362ba9c4efc83af820b6beb094cf`.
The existing R19 redirect and AUTH functions index AppId/protocol/flags/destination,
but neither V4/V6 compartment field. FBR3's 128-byte context does not encode
compartment. The source-pinned Python and independent Node scripts generate
48 hypothetical IPv4/IPv6×PID×endpoint×compartment pairs: 48/48 same R19 wire
projection, whereas an *illustrative only* appended 32-bit compartment differs
in 36/48. This revalidates the R166 projection gap while supplying the **previously
missing documented data-source path**, not an actual endpoint-collision exploit.

Executed locally: Python normal/`-O`/`-OO` 48/48 each; Node 48/48; all matrices
byte-identical, SHA-256 `2b42f9e3cdb49493d3d87630af7124c6fa6d76584a01cd47249bf6f6cb440a35`.
Three source blob hashes passed; deliberate source mutation and independent
Node-model mutation both failed closed. No Rust compilation or Windows native
callout performed.

## Trust chain and remaining NO-GO

`PsSetCreateProcessNotifyRoutineEx` + referenced `PEPROCESS`/`FileObject` +
`PsGetProcessCreateTimeQuadPart`/`PsGetProcessStartKey` + canonical AppId
→ native ALE REDIRECT/AUTH with checked indexed compartment, process/endpoint/
parent/scope/flags/action-rights → immutable ticket → actual accepted socket
`SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS` → one-shot kernel CLAIM →
`SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on actual SSH socket → pinned SSH.

**None of this end-to-end chain is accepted.** R164 ledger exhaustion,
R165 no runtime witness producer, R168 60s global STOP, endpoint/PID reuse,
5-tuple ABA, sibling DIRECT, DNS/UDP/QUIC, reauthorization and BFE/SSH loss
remain NO-GO. No historical G1 transfer. A next **permitted** experiment is
a clean-room Rust user-mode WDK-enum/layout test, without driver/network.
Only owner-authorized driver+VNC/SYSTEM rescue/rollback gates could permit
a later real paired REDIRECT/AUTH classification. Do not run such tests here.

Diff limited to R170 evidence in this research branch; never main/beta/PR56.
