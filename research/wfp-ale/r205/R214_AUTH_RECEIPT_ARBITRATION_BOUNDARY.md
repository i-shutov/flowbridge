# R214 — AUTH receipt vs final WFP arbitration (conditional evidence NO-GO)

2026-11-18. Sole scope: research/windows-wfp-ale-attribution-20261107. This is independent architectural research, NOT beta, PR #56, PacketBound/G2 PASS, no-DIRECT/leak-free, or transferred G1.

Pinned read-only source: research HEAD 1a30a752d9eb870ca5345855ac623aa48934585b; main HEAD 5b5afc2feeda2195f302380e615ba003d4906e09.
Exact independently read Git blob SHA-1s:
- kernel-r19/kernel/src/redirect.rs: a093f049d162987981a957aac90db1014bc6ff09
- kernel-r19/kernel/src/handoff.rs: e1d17217db50362ba9c4efc83af820b6beb094cf
- kernel-r19/policy_windows.rs: acf60334320d970f58af3349ee75fbaa59826602

## Narrow result

The R19 AUTH classify path runs auth_check -> Book::attest -> sets slot.auth_seen=true BEFORE returning FWP_ACTION_PERMIT and clearing FWPS_RIGHT_ACTION_WRITE. Book::take consumes an auth_seen ticket within the existing identity/TTL gates, with no WFP final-disposition input. BFE uses FWP_ACTION_CALLOUT_TERMINATING.

Microsoft Filter Arbitration states that even a hard permit can be overridden by another callout Veto, and different WFP layers have independent filtering. Therefore an R19 local AUTH attestation is not by itself a proof of final WFP PERMIT. This boundary is distinct from R207 (later reauthorization), R212 (ISSUE-to-APPLY race), and R85/R86 (legality/provenance of action-rights veto). It does NOT establish an exploitable bypass.

In particular, a final WFP block may prevent the redirected connection from reaching the broker's accepted socket. No actual accepted-socket receipt coexisting with such a block was demonstrated. Thus synthetic terminal CLAIM *given a separate hypothetical socket receipt* is NOT evidence of real Windows reachability, packet egress or physical SSH success.

## Executed independent negatives

- Python: r214_arbitration_negative.py — 6/6 unittest methods PASS, v4/v6, normal permit, veto, other-layer block, invalid auth, mutation check.
- Node: r214_arbitration_oracle.mjs — 12/12 independent states PASS; 4 conditional evidence-vs-final-decision mismatches (synthetic, native reachability UNKNOWN).
- Python py_compile and Node --check PASS.
- Independent GitHub readback: 3/3 exact source blob pins and 7/7 structural source guards PASS. Full-checkout --source command is included but was NOT executed locally. rustc, Windows BFE/classify, SSH and physical traffic were NOT run.

Reproduce in a full checkout:
    python3 research/wfp-ale/r205/r214_arbitration_negative.py --source
    node research/wfp-ale/r205/r214_arbitration_oracle.mjs

## Proof boundary and next decisive step

Required kernel-origin chain: process-create referenced EPROCESS/FileObject -> PID/epoch/start key/canonical EXE/AppId (FwpmGetAppIdFromFileName0) -> ALE_CONNECT_REDIRECT V4/V6 (FwpsAcquireWritableLayerDataPointer0, FwpsApplyModifiedLayerData0) -> ALE_AUTH_CONNECT V4/V6, final arbitration and lifecycle -> actual accepted socket WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS) -> one-shot kernel CLAIM -> SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS on physical SSH and trusted SSH health. A PID/5-tuple/time correlation is not that proof.

Next permitted preflight: pinned standalone R201/R202 read-only Rust tests, optional passive R199 BFE inventory on an admitted Win10 Pro x64, with independently checked hashes. Inventory is NOT final classify proof. A decisive veto-vs-accept-vs-CLAIM native trace requires a NEW explicit owner decision and full driver/VNC/SYSTEM rescue and rollback gates; no such authorization exists. Other open NO-GO: process death/PID reuse, 5-tuple reuse, endpoint closure, reauthorization, sibling DIRECT, DNS/UDP/QUIC, IPv4/IPv6 compartments, WFP/SSH loss, and the R198/R209/R213 physical SSH ORIGINAL_APP_ID self-block.

Official docs checked 2026-11-18:
- https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
- https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_classify_out0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records

Status remains architectural NO-GO. No driver, callout, WFP filter, NDISRD, vendor binary, ProxiFyre, network, runner, firewall, services, OS security, other repo, PR #56, or automation mutation.
