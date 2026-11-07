# R26 — kernel-origin AUTH_CONNECT receipt required for broker admission

Scope: **research/windows-wfp-ale-attribution-20261107 only**. Work starts from R25 (SHA `b3ac167a6e548b427328cd8cf1112713c3e142ba`). Main and beta PR #56 unchanged.

## Concrete R25 defect addressed in source

R24 used four static ALE_AUTH_CONNECT rules checking only (selected AppId, TCP, loopback, port). Those rules were unable to distinguish a genuine redirected connection from an ordinary selected-EXE direct connection to the same address/port. This was a real architectural missing guard, not a previously observed network leak.

R26 replaces the static destination-only AUTH rules with **native terminating ALE_AUTH_CONNECT V4/V6 callouts** and a kernel-issued ticket that cannot be consumed until it has received a same-origin authorization witness.

The callback requires all these data to agree **in the same AUTH classification**:

* WFP `FWP_CONDITION_FLAG_IS_CONNECTION_REDIRECTED`, and no reauthorization / `HONORING_POLICY_AUTHORIZE` shortcuts;
* `FWPS_METADATA_FIELD_PROCESS_ID` and `TRANSPORT_ENDPOINT_HANDLE`;
* `FWPS_METADATA_FIELD_LOCAL_REDIRECT_TARGET_PID` matching the pinned broker process;
* `FWPS_METADATA_FIELD_ORIGINAL_DESTINATION` matching the outstanding kernel ticket's original IP/port;
* `ALE_ORIGINAL_APP_ID` matching the selected creation-time image path;
* effective remote address and port matching precisely the configured local IPv4/IPv6 broker endpoint;
* original owner's kernel ledger PID, process creation epoch, PsGetProcessStartKey and generation bound to the issued ticket.

R26 changes the private Book slot to carry `auth_seen`. Kernel `Book::attest` rejects unknown/mismatched endpoints, wrong origin/epoch, wrong destination, expiry, replay and ambiguous duplicate tickets. `Book::take` is terminal but will never succeed without an earlier matching AUTH receipt. Ordinary socket context presence, a forged byte blob, direct loopback and the user-mode process PID do not mint that witness.

At BFE level, only four rules exist: V4/V6 redirect `FWP_ACTION_CALLOUT_UNKNOWN` and V4/V6 AUTH `FWP_ACTION_CALLOUT_TERMINATING`. Each AUTH rule requires exact selected `FWPM_CONDITION_ALE_ORIGINAL_APP_ID` plus TCP. The kernel callback makes the connection-specific decision; there is no static same-address/port-only PERMIT path.

## Research limitations, including potentially blocking behavior

The AUTH callback is deliberately deny-by-default. It denies missing metadata, unusual call sequences, reauthorization and unsupported network address types instead of granting traffic. Whether Windows presents the expected metadata and original AppId at the AUTH layer on a real redirected connection has **not yet been measured**. Even a successful kernel compile and unit test cannot establish that it will accept a real flow.

This source change is NOT a physical no-DIRECT proof. The BFE policy is in a dynamic session and is removed if that session dies; it is not a crash-persistent kill switch. The current `FWPS_CONNECT_REQUEST0` rewrite and broker use an experimental 3-second lease, selected process history limit and private one-use tickets; unexpected IRQL/ABI, callback lifetime, process exit and unloading races still need a separate kernel safety review.

The original driver is **unsigned**; this CI compiles and tests it without loading, signing, installing, adding BFE filters, changing Windows protections or modifying any runner/service. A real kernel load still requires accepted signature, current VNC proof, independent SYSTEM rescue, rollback and independent physical network observation. User permission to develop/install does not invent those prerequisites.

## Native test sequence

1. Hosted Windows CI: build exact x64 kernel and broker source, run 14+ exact ledger/handoff tests plus broker policy tests, verify PE/imports; **this is NO-LOAD evidence**.
2. On a separately admitted signed-driver host, register the four callbacks, start a fresh selected EXE after driver attachment, install only scoped dynamic BFE filters and observe first real redirect.
3. Verify original EXE → ALE_CONNECT_REDIRECT ticket → ALE_AUTH_CONNECT attestation → accepted socket WSAIoctl context and redirect records → kernel CLAIM → WFP SET records on outbound broker socket → OpenSSH SOCKS exact response; test IPv4 and IPv6 independently.
4. Independently reject direct to broker port, sibling EXE, replayed tickets, wrong original destination, bad target PID, stale endpoint, reused PID, expired leases, missing SSH and missing WFP; inspect physical DIRECT traffic and crashes before any PASS.

R26 `g2_pass=false` and `release_accepted=false` until full verified native chain. No G1/NDISRD PacketBound transfer.

Official references: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection ; https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-flags ; https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization .
