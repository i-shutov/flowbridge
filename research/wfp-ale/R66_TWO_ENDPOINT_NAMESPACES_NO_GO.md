# R66 — Endpoint handle namespace join is not a documented origin proof
Date: 2026-11-09. **Only** research/windows-wfp-ale-attribution-20261107. Independent R&D, not beta/PR #56/main/release.
Baseline research HEAD `2d9239fa8bc20192911cd3a9753b615ed7052701`; main `5b5afc2feeda2195f302380e615ba003d4906e09`.

## Decisive contract gap
Microsoft's Winsock IOCTL reference describes `SIO_QUERY_WFP_ALE_ENDPOINT_HANDLE` as returning a **transport-layer endpoint handle** of a socket (a UINT64 used in transport injection). `FwpsAleEndpointGetById0` takes an **ALE endpoint ID**; `FWPS_ALE_ENDPOINT_PROPERTIES0` contains an endpoint-local `appId`, but no original AUTH_CONNECT ticket or process creation epoch. The WFP classify metadata `transportEndpointHandle` is also documented for transport injection. The inspected official references contain **no promise of interchangeability** between a Winsock transport endpoint handle and the `endpointId` accepted by `FwpsAleEndpointGetById0`. This is **absence of a proven mapping**, not evidence that values must differ on Windows. Even verified numeric equality is not a kernel-bound original owner witness.

Additionally `FwpsAleEndpointGetById0` does not specify a memory release function; `FwpmFreeMemory0` documents `Fwpm*` outputs and undefined behavior for invalid pointers. Keep the R65 unsafe diagnostic quarantined. Do **not** pass raw socket-returned UINT64 to `FwpsAleEndpointGetById0` as a claimed attestation, or use it to authorize CLAIM. No Windows live code is enabled in R66.

## Executable independent negative check
- `r66/r66_independent.mjs`: deterministic, offline Node bitmask oracle; no OS or network calls.
- A separate Python boolean-tuple oracle and pure Rust no-FFI source are in the local R66 checkpoint. Python: 13/13 PASS; Node matches SHA-256 of the entire decision stream `e7a8df77504da8573004691e7f9d5d9ab694751dda95259a34675ae661151e20`.
- 131072 synthetic states, IPv4 + IPv6; a weak numeric-join model issues 64 conditional permits, of which 62 lack at least one **hypothetical hidden** witness. Only 2 satisfy all model-only witnesses; **these are NOT Windows permits or observed kernel proofs**.
- Witnesses include original kernel-bound ticket, physical owner life, sibling DIRECT exclusion, DNS/UDP scope and reauthorization. Missing WFP callback = UNOBSERVED, not BLOCK. SSH/WFP loss cannot be declared leak-free via callback observations.

**GO:** keep R65 quarantined and retain the no-driver read-only diagnosis. **NO-GO:** original PID+creation epoch+canonical EXE, replay-safe CLAIM, process death/PID reuse, re-used 5-tuple, sibling DIRECT, DNS/UDP/QUIC, AUTH_CONNECT reauthorization, physical egress and PacketBound/G2/leak-free.

## Official sources
- https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls
- https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/nf-fwpsu-fwpsaleendpointgetbyid0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_ale_endpoint_properties0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/ns-fwpsu-fwps_incoming_metadata_values0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfreememory0

## Next decisive experiment R67
Seek a documented kernel-origin **single-operation** AUTH_CONNECT → CONNECT_REDIRECT identity bridge, and independently negative-test PID/creation-epoch reuse, 5-tuple reuse, redirect record replay, death-vs-callback race, absent BFE dispatch, IPv4/IPv6, sibling DIRECT, DNS/UDP and SSH/WFP loss. Do not replace a missing proof with a numeric correlation. No driver/callout/filter/VNC/network/system mutation authorized.
