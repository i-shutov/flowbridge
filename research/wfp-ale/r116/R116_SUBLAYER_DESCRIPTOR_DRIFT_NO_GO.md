# R116 — independently query owned WFP sublayer descriptor (NO-GO)

Date: 2026-11-11. Repository `i-shutov/flowbridge`; ONLY branch `research/windows-wfp-ale-attribution-20261107`.
Intake research HEAD `e0bd96ee0ed4627ce268508fbf7b6279e6097010`, read-only `main` `5b5afc2feeda2195f302380e615ba003d4906e09`.

## Material gap: filter shape does not attest sublayer priority

R19's owned `FWPM_SUBLAYER0` is created with key `1649f024-25b3-4e01-9ca1-5ca803010019`, weight `0x7000`, flags `0`, providerKey NULL. R103's read-only BFE filter inventory validates the four baseline filter keys/layers/conditions/callout actions and compares only **same-sublayer** foreign filter weights, but never queries `FWPM_SUBLAYER0` itself. Thus a fixture with four identical baseline filters plus a mutated owned sublayer weight (e.g., `0x7000 → 0`) leaves R103's `UNKNOWN_NO_VISIBLE_CANDIDATE` diagnostic unchanged. This is a management-plane descriptor coverage gap, not evidence that a real system reconfigured the sublayer or leaked traffic. R103 exit 4 already says UNKNOWN, never PASS.

Microsoft documents arbitration as (1) priority between sublayers, (2) per-filter weight within each sublayer, with action rights, override policy and veto semantics. Therefore sublayer weight must not be inferred from filter effectiveWeight, nor compared directly to filter weights. [Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration); [FWPM_SUBLAYER0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_sublayer0).

## Functional independent Rust user-mode, read-only candidate

`r116_readonly_sublayer_probe.rs` queries the sublayer using **only** `FwpmEngineOpen0`, `FwpmSubLayerGetByKey0`, `FwpmFreeMemory0`, `FwpmEngineClose0`, with explicit x64 C layout and a pinned R19 expected descriptor. No driver or network/socket access, no writes or filter enumeration. Unknown API/ACL failure or mismatch => exit 2; exact descriptor => exit 4 (`SUBLAYER_DESCRIPTOR_MATCH_ONLY`), explicitly NOT GO/PASS. It does not falsely join a GetByKey response with R103's independent enumerator snapshot; no atomic temporal relation can be certified by these separate calls. No proof that the kernel callout registered, classified, or denied any selected flow.

The x64 ABI expected offsets (from Microsoft SDK `FWPM_SUBLAYER0`): flags 32, provider 40, providerData 48, weight 64, sizeof 72. `ctypes` independent layout calculation matches these sizes. The Rust source has embedded unit/ABI tests; **native Rust compile/execute has not been performed**.

## Deterministic negative checks

`python3 research/wfp-ale/r116/r116_sublayer_negative.py` and `node research/wfp-ale/r116/r116_sublayer_independent.mjs` each independently enumerate 160 descriptor/API cases: 1 structurally consistent (still exit 4 / UNKNOWN), 159 reject or unavailable (exit 2). Both compute the same ordered-matrix SHA-256:

`2fce70b1b300bd2250f0aac11dbb36eba7c6532a11bcc87d8995d7607d5e22ee`

The tests reject changed weight, nonzero flags, populated providerKey, wrong key, missing/ACL-hidden object or API failure. They prove the model's fail-closed predicate, not that the actual BFE API returns these fixtures.

## Chain of trust remains entirely unproved

1. **Selected executable:** `FwpmGetAppIdFromFileName0`, `FWPM_CONDITION_ALE_APP_ID`/`ALE_ORIGINAL_APP_ID`, process image-section identity. File-name equality is not canonical EXE attestation.
2. **Kernel-origin identity:** `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6` and `FWPS_METADATA_FIELD_PROCESS_ID` if valid, referenced `EPROCESS` via `PsLookupProcessByProcessId`, `PsGetProcessCreateTimeQuadPart`, valid IRQL/lifetime. PID reuse, process death, start-key and 5-tuple re-use unresolved.
3. **Redirect lifecycle:** `FwpsQueryConnectionRedirectState0`, `FwpsAcquireWritableLayerDataPointer0`, `FWPS_CONNECT_REQUEST0`, `FwpsApplyModifiedLayerData0`; real v4/v6 original destination and one-shot ticket before proxy claim not authenticated.
4. **Socket handoff:** `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT)` on actual accepted socket; `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on outbound socket. No timestamp/tuple join as surrogate.
5. **Independent enforcement:** `FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6` must gate sibling DIRECT and fail-closed upon process exit/reuse, WFP/BFE/SSH loss. No such proof, including DNS, UDP/QUIC or alternate IPv6 paths.
6. **This probe:** BFE user-mode management descriptor via `FwpmSubLayerGetByKey0`; ACL-limited and momentary. It is **not** kernel-authenticated per-flow evidence and cannot change any GO state.

## Next decisive allowed experiment

First obtain native R115 PowerShell 5.1 evidence on the authorized Windows x64 host (exact checkout, Rust ABI compilation and synthetic tests), which was previously blocked by checkout CRLF conversion. Then, separately compile and run R116 in **read-only** mode with pinned-source verification, checking exact Windows build, Rust toolchain, ABI tests, SHA-256 of binary, stdout JSON, exit code, and signed logs if available. Combine observations only as non-atomic diagnostic events; mismatch/ACL error remains UNKNOWN. Actual kernel-origin and sibling DIRECT require owner-approved driver/VNC/SYSTEM gates and remain prohibited in this research cycle.

Out of scope and untouched: main, release, beta branch, PR #56, runners/CI, network, firewall, Defender, services, SecureBoot, MemoryIntegrity, automations, other repositories, ProxiFyre, PR40, vendor/C++ payloads, installed drivers/callouts/filters and paid work. No PacketBound/G2, leak-free, no-DIRECT or G1 dd1ab3c promotion.

## Primary sources

- https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_sublayer0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmsublayergetbykey0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfreememory0
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
