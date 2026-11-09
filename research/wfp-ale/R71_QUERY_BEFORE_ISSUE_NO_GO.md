# R71 — Query-before-issue NO-GO (2026-11-09)

Scope: ONLY i-shutov/flowbridge, research/windows-wfp-ale-attribution-20261107. Independent architecture R&D; no beta, PR #56, PacketBound/G2, leak-free or historical G1 promotion.

Baseline HEAD: research `d20c4973524573ec764a983103ef896569d995b4`, main `5b5afc2feeda2195f302380e615ba003d4906e09`. Actual pinned source blobs: `kernel-r19/kernel/src/redirect.rs` `9a07e026134d46ef646d39862bd982cc48bbc5f6`, `kernel-r19/kernel/src/handoff.rs` `e1d17217db50362ba9c4efc83af820b6beb094cf`, `kernel-r19/policy_windows.rs` `acf60334320d970f58af3349ee75fbaa59826602`.

## Source-level counterexample

In `redirect::classify` the code checks `FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE` and calls `FwpsQueryConnectionRedirectState0(m.redirectRecords,HANDLE,NULL)` **only if the bit is set**. If it is absent, later code may reach `Book::issue`. If present but `redirectRecords == NULL`, the code does not reject NULL before calling the query. Microsoft's documented query parameter is a redirect-records handle indicated by ALE_CONNECT_REDIRECT metadata; **no NULL-as-NOT_REDIRECTED meaning is documented**. Absence of metadata or a NULL handle is therefore UNVERIFIED, never clean. This is source-level, not a verified native Windows path: missing/NULL may or may not occur in real callbacks, and no kernel callout was run.

Windows 8+ documentation requires querying before redirection. A confirmed `FWPS_CONNECTION_NOT_REDIRECTED` allows a fresh candidate redirect; `REDIRECTED_BY_SELF` and `PREVIOUSLY_REDIRECTED_BY_SELF` forbid a second redirect. `REDIRECTED_BY_OTHER` may permit another inspector to redirect if its result is not trusted, but FlowBridge currently conservatively requests BLOCK. BLOCK_REQUESTED is not a physical packet-drop or no-DIRECT proof. All callbacks outside current-AppId-selected/TCP scope are UNOBSERVED, not blocked by this callout.

## Additional distinct gap: PING is not SSH/WFP health proof

`redirect::ready()` checks configured/armed book, broker PING age (`LEASE`) and referenced broker process identity. It does **not** establish that the physical SSH link, WFP filtering, IPv4/IPv6 egress or sibling DIRECT paths are suppressed. An intact lease can coexist, in a synthetic counter-world, with physical SSH/WFP loss. SELF/PREVIOUSLY_SELF early no-redirect returns also precede this readiness check; they are not proof of egress fate.

## Executed offline proof and limits

The R71 local checkpoint (sha256-verified archive) includes a Python source-derived reference (**28/28 tests PASS**), independently implemented Node oracle (full counters and ordered decision-stream hashes match on **524,288** synthetic states = 16 binary dimensions × 8 record observations), and pure user-mode/read-only/no-driver Rust model (**27 tests authored, NOT run**; no rustc/cargo here). Of the model cases: 64 unqueried ticket candidates in pinned R19, 64 hypothetical null-as-clean candidates (NOT a claimed Windows result), 0 strict candidates lacking verified query, 64 strict conditional candidates; 32 of those lack selected original AppId, 32 have hidden sibling DIRECT, 32 a reused 5-tuple, and 48 hidden SSH/WFP loss despite broker lease. 393,216 cases outside callback scope are UNOBSERVED. Legacy ordered SHA256: `52332c47a9d89a817bd30c791126a3b1c32eab99c3b4c2e54156b8d6aad822d9`; strict: `67bcd2baf35733cc91d4bea1679a033630e436ac0324b1ee28be3e95a0366e21`.

Adjacent small JS/Rust files are independently reviewable offline guard sketches. They are not kernel code or native WFP evidence; the larger executed test matrices are retained in the R71 checkpoint.

## Unclosed provenance chain / decision

`FwpmGetAppIdFromFileName0` yields AppId path blobs, not original `EPROCESS` with PID+creation epoch+canonical EXE. Prospective kernel-only mechanisms `PsSetCreateProcessNotifyRoutineEx`, `PsGetProcessCreateTimeQuadPart`, `PsGetProcessStartKey` and `PS_CREATE_NOTIFY_INFO.FileObject` were NOT executed. WFP `FWPS_INCOMING_METADATA_VALUES0.processId` refers to the current endpoint owner; `transportEndpointHandle` does not prove an ALE endpoint ID. `FwpsAcquireClassifyHandle0`, `FwpsAcquireWritableLayerDataPointer0`, `FwpsApplyModifiedLayerData0` and a redirect context do not alone tie the original operation to accepted SOCKET. AUTH_CONNECT's conditional `LOCAL_REDIRECT_TARGET_PID` and `ORIGINAL_DESTINATION`, and broker `WSAIoctl` query/set redirect-context/records, do not by themselves authenticate `Book::take` on that accepted socket.

Narrow GO: only a non-NULL records handle and genuine `FwpsQueryConnectionRedirectState0 == NOT_REDIRECTED` may satisfy **this one prerequisite** for issuing a new ticket; all other origin/lease checks remain independent. NO-GO: R19 missing-record path, historic original owner, socket-to-CLAIM causal proof, process death/PID reuse, repeated tuple, sibling DIRECT, DNS/UDP/QUIC, physical WFP/SSH loss, PacketBound/G2, IPv4/IPv6 egress, leak-free.

Next decisive R72: read-only Rust user-mode Windows process-identity diagnostic if supported access/toolchain exists (`OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`, `GetProcessTimes`, `QueryFullProcessImageNameW`, optionally read-only `FwpmGetAppIdFromFileName0`); demonstrate inability of polling to prove historical kernel origin; independently audit `Book::attest -> Book::take` accepted-socket witness. No driver, filter, network test, VNC, signed-driver or system mutation authorized.

Sources reviewed 2026-11-09:
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_connection_redirect_state_
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-field-identifiers
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking

No main/release, beta branch, PR #56, runner, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, networks, other repositories, automations or controller changed.
