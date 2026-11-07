# R29 — conditional AUTH_CONNECT liveness blocker: dual AppId overconstraint

Date: 2026-11-08. Independent offline R&D. Exclusively research/windows-wfp-ale-attribution-20261107.
Parent source: e4074ac63bc710c27958e515fbf199b87ced5640.
main at start: 5b5afc2feeda2195f302380e615ba003d4906e09.

## Reproduced source fact
Exact Rust file research/wfp-ale/kernel-r19/kernel/src/redirect.rs, Git blob 6330935a8366d8ac573cbb2b474626f5883881f9.
The R26 AUTH callback reads both ALE_ORIGINAL_APP_ID and ALE_APP_ID for IPv4/IPv6 and requires:
    if orig!=&route.name[..route.len] || current_app!=&route.name[..route.len]
Its adjacent comment says that APP_ID can be broker or original and that ORIGINAL_APP_ID is the selected key. The code enforces an additional, undocumented equality of both paths.

Microsoft's Using Proxied Connections Tracking states that ORIGINAL_APP_ID identifies the original application for proxy connections; it is equal to APP_ID when the connection has *not* been proxied. This differentiates the two fields for the proxied case. It does NOT prove what APP_ID Windows presents for the selected application's specific inbound AUTH_CONNECT indication in this implementation.

Conditional counterexample: genuine selected-executable TCP redirect with ORIGINAL_APP_ID=selected.exe and APP_ID=broker.exe (all other metadata and health valid). Source AUTH rejects. This is an **availability/liveness concern**, not an observed Windows result, leak or reason to remove any guard. The processId at AUTH might also name a different stage/process; that requires a separate kernel-origin proof.

## Executed negative tests and independent check
- r29_auth_appid_negative.py: Python 3.13, five unittest methods PASS; IPv4/IPv6 conditional proxy mismatch, wrong origin, missing proof, UDP and dangerous current-only mutant controls.
- r29_independent_truth_table.py: 32/32 independent static AppId combinations (2 IP families x 4 original x 4 current); 2/2 conditional proxy mismatches. Does not import main model.
- Earlier local R28 checkpoint tests rerun: 6/6 methods PASS, 48/48 independent observation pairs. The optional R28 --source command was NOT run because local exact checkout is unavailable.
- GitHub exact source API pinned redirect blob 6330935a... and handoff blob f6200cac997f3c7e2fbd6a60443286727a8c2297; direct field/condition checks passed 11/11.
- No Rust compiler, native WFP invocation, Windows trace or driver loading/compilation in this cycle. No GitHub Actions or runner.

## Trust chain / NO-GO
Process: PsSetCreateProcessNotifyRoutineEx, PsGetProcessCreateTimeQuadPart, PsGetProcessStartKey and referenced process/image objects only establish process generation.
Redirect: FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6, FWPS_METADATA_FIELD_PROCESS_ID and TRANSPORT_ENDPOINT_HANDLE, FwpsQueryConnectionRedirectState0, FWPS_CONNECT_REQUEST0.localRedirectHandle/localRedirectContext/localRedirectTargetPID.
AUTH: FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6, redirected flag, original/current AppId, original destination, broker PID, process generation, endpoint handle; code has conditional overconstraint and still lacks an issuance-bound AUTH nonce (R27/R28).
Broker: accepted socket WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS, SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT), terminal claim, outbound SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS. Not run.
System: sibling DIRECT, process death/PID reuse, reused 5-tuple, DNS/UDP/QUIC, IPv4/IPv6 physical egress and WFP/BFE/SSH loss all remain NO-GO. No PacketBound/G2 or no-DIRECT/leak-free PASS. No historical G1 transfer.

## Next decisive permitted experiment
Distinguish inbound selected-application AUTH_CONNECT from broker outbound AUTH_CONNECT in read-only API/source analysis. Do not remove the second AppId check until a native, separately gated positive-path test identifies the correct connection stage and binds kernel-origin ownership. Native kernel load/filter changes, VNC/SYSTEM rescue and driver-signing remain outside authorization.

Official sources:
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v4_
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ale-endpoint-lifetime-management
