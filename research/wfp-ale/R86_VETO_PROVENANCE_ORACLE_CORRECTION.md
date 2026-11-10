# R86 — ACTION_WRITE veto provenance: R85 model soundness correction

Date: 2026-11-10. Repository `i-shutov/flowbridge`, **only** branch `research/windows-wfp-ale-attribution-20261107`. Independent architectural R&D, not beta, PR #56, PacketBound/G2 PASS, leak-free, or G1 transfer.

## Exact baseline and source pins

At start: research HEAD `11ea6f66f33e95e35d1f03444e28048c63b51f61`; `main` `5b5afc2feeda2195f302380e615ba003d4906e09`. Read-only blobs:
- R85 report: `94141766e228d507fc6993168b8baec6a1ad45e0`.
- R85 Python oracle: `2cd0dfc8ec1eff135ccfb0a0935f5c16d99a87f5`.
- R19 `kernel/src/redirect.rs`: `9a07e026134d46ef646d39862bd982cc48bbc5f6`.
- R19 `kernel/src/lib.rs`: `0af6d4539673d2894cbaa91af0ea8f3524862a26`.
- R19 `policy_windows.rs`: `acf60334320d970f58af3349ee75fbaa59826602`.

R85's 64-case oracle calls **all** no-`FWPS_RIGHT_ACTION_WRITE` + prior `PERMIT` cases `DOCUMENTED`. This is broader than the official `FWPS_CLASSIFY_OUT0` exception: without an action-write right, `BLOCK` is allowed to veto a **higher-weight filter's previously returned PERMIT**. The prior action value alone does **not** establish its origin. `FWPS_CLASSIFY_OUT0.filterId` is reserved for system use, not an authenticated provenance channel.

This is a confirmed soundness defect in the R85 **test oracle**, **not** proof that R19 ever receives a forbidden WFP callback state; actual callback reachability is unproved. No driver or WFP experiment has run.

## Reproducible deterministic correction

The revised finite model explicitly distinguishes `HIGHER_WEIGHT_PERMIT`, `OTHER_OR_ABSENT`, and `UNKNOWN` predecessor provenance. Axes: 4 source paths × 2 IP families × 2 rights states × 4 prior actions × 3 origins = **192** synthetic cases.

- `DOCUMENTED`: write right exists, or no right with a **proven** higher-weight prior PERMIT; **104** cases.
- `CONTRACT_GAP`: no right and non-PERMIT, or no right and PERMIT without the qualifying provenance; **80** counterfactual cases.
- `UNPROVEN`: no right, PERMIT, but unknown provenance; **8** cases, no positive claim.

Executed on Linux user mode: `python3 research/wfp-ale/r86/r86_veto_provenance_negative.py` — **6/6 PASS**; `node research/wfp-ale/r86/r86_veto_provenance_independent.mjs` — **192/192 independent ordered matrix matches**. SHA-256: `562cfc32271142b04603243d9b8ca830a2dc22efaf81a39fa28310d9f5bdadde`.

The independent Python and Node models contain **no** WFP API calls, kernel payloads, packet interception, WinSock tests, BFE changes, or network operations; neither can establish Windows reachability. R85's conditional source-level NO-GO is unchanged.

## Trust chain, evidence boundary, and unresolved gates

1. **Selection** — `FwpmGetAppIdFromFileName0`, `FWPM_CONDITION_ALE_APP_ID`: exact opaque AppId does not alone prove a canonical binary identity or publisher; same basename is not evidence.
2. **Original owner** — `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6`, `FWPS_METADATA_FIELD_PROCESS_ID`; a referenced process from process-create with `PsGetProcessCreateTimeQuadPart`, start key and epoch. A later PID join is not kernel-origin proof.
3. **Redirect** — `FWPS_CONNECT_REQUEST0`, `FwpsAcquireWritableLayerDataPointer0`, `FwpsApplyModifiedLayerData0`, `FwpsQueryConnectionRedirectState0`; all classify decisions require permitted action rights, and an unknown predecessor is not a verified veto.
4. **AUTH_CONNECT and accept** — `FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6` original app/destination; `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT)` on the **actual accepted socket**; one-shot `DeviceIoControl(CLAIM)` must not be conflated with attested socket identity.
5. **Outbound and containment** — `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on an outbound proxy TCP socket, authenticated SSH, and independently enforced selected-app sibling DIRECT denial. No validated chain connects these into PacketBound; PID reuse, 5-tuple reuse, process death, IPv4/IPv6 edge cases, TCP-only DNS/UDP/QUIC, SSH/BFE loss, leak-free/no-DIRECT remain **NO-GO**. Historical G1 at `dd1ab3c` is not imported.

## Next decisive experiment and strict isolation

Compile and execute the *exact published R83 Rust blob* on separately permitted Windows x86_64 as user-mode read-only negative WinSock ABI/overlapped-I/O baseline **only**. For R85/R86 rights provenance, first resolve the documented predecessor-state guarantee for ALE CONNECT_REDIRECT and AUTH_CONNECT. A true WFP classify trace would require separately granted driver/VNC/SYSTEM rescue/rollback gates; they are **not granted**, so do not initiate.

Official documentation checked 2026-11-10:
- https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_classify_out0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nc-fwpsk-fwps_callout_classify_fn0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_action0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsacquirewritablelayerdatapointer0

No modifications to main/release, integration/windows-rust-capture-agent-20261031, PR #56, runner, services, firewall/UFW, Defender/SecureBoot/MemoryIntegrity, networks, other repos, automations. No drivers/callouts/filters, NDISRD, VNC, vendor binaries, ProxiFyre AGPL, closed PR40, C++ WFP payload, signed-driver work or payment.
