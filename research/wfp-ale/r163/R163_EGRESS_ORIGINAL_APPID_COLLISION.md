# R163 — Conditional self-collision: WFP ORIGINAL_APP_ID and physical SSH egress

## Scope and status

Independent architecture R&D; **conditional NO-GO, not native validation**.
Branch only: research/windows-wfp-ale-attribution-20261107.
Baseline research HEAD ca72eee3d5dc422ad6894219f9b68e63cf731034 (R162);
main HEAD 5b5afc2feeda2195f302380e615ba003d4906e09.
No driver, filters, services, network, firewall, policies, security settings, PRs or runners were touched.

## Exact source chain (immutable Git blob identifiers)

1. research/wfp-ale/kernel-r19/broker.rs
   blob 6163e84aea08ddde7e51a7fb94ccb6d68ae951fb:
   admitted policy mode requires VerifiedSsh, creates BFE plan from selected WFP AppId
   and calls claim_and_connect_trusted_ssh on an accepted socket carrying WFP evidence.
2. research/wfp-ale/kernel-r19/broker_windows.rs
   blob 329ef14b63e70226bfad7372b0014559213abd04:
   after terminal kernel CLAIM, creates a **real IPv4 physical SSH TCP socket**,
   sets SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS via WSAIoctl **before connect** to
   the SSH server. The TCP socket does not connect to the original destination.
3. research/wfp-ale/kernel-r19/policy_windows.rs
   blob acf60334320d970f58af3349ee75fbaa59826602:
   selected-original-AppId TCP/6 ALE_AUTH_CONNECT_V4/V6 filter, terminating callout,
   FWPM_CONDITION_ALE_ORIGINAL_APP_ID, no exception for the broker's SSH upstream.
4. research/wfp-ale/kernel-r19/kernel/src/redirect.rs
   blob a093f049d162987981a957aac90db1014bc6ff09:
   auth_check accepts only a redirected, WFP-metadata-verified initial connection
   with remote loopback address and the broker listener port, live process/endpoint,
   exact original destination and one-use ticket. With action-write, rejection
   returns FWP_ACTION_BLOCK; non-loopback physical SSH peer cannot pass auth_check.

Two kernel/policy files are byte-for-byte source-gated by the executable Python
test on a real repository checkout or on the checkpoint's immutable source copies.
The two broker files were read and blob-pinned from GitHub, but their full bytes
are not bundled in the source-gate fixture.

## Novel cross-leg conditional failure

Microsoft documents ALE_ORIGINAL_APP_ID as original application path for proxied
connections; Windows redirect records are transferred to the outbound proxy socket.
The *exact runtime* ALE_ORIGINAL_APP_ID and redirect flags on an SSH tunnel socket
after transfer are **not established by this offline experiment**.

Let A be the selected EXE, B the broker, S an external SSH server.

- If WFP reports ORIGINAL_APP_ID=A on the records-tagged B->S socket, the
  selected-AppId AUTH rule also matches that leg. It asks for remote loopback +
  broker port, which S cannot satisfy. With action-write the result is BLOCK:
  this would prevent the very physical SSH transport used by FlowBridge.
- If WFP reports ORIGINAL_APP_ID=B (or another nonmatching identity), the four
  A-scoped rules do not classify the B->S leg. This alone is **neither proof of
  an untrusted DIRECT connection nor proof of an unbroken kernel origin chain**.
- Without action-write, a prior CONTINUE may be preserved; do not invent a veto.
- With the dynamic BFE session gone, no filter invocation is shown by this model.

These are conditional predictions, not evidence that native Windows has executed
the first branch. The actual broker SSH socket is IPv4-only; IPv6 SSH scenarios in
the matrix cover a hypothetical future path rather than present socket behavior.

## Tests and independent oracle

Execute on a full checkout:

    python3 research/wfp-ale/r163/r163_egress_collision.py
    python3 research/wfp-ale/r163/r163_egress_collision.py --matrix > /tmp/r163-matrix.json
    node research/wfp-ale/r163/r163_independent.mjs /tmp/r163-matrix.json

The source gate checks exact Git blob SHA and relevant filter/AUTH predicates.
The test enumerates 1,152 explicit inputs across IPv4/IPv6, selected/broker/
sibling AppId, loopback/SSH/other remote target, BFE presence, attached records,
redirect/reauthorize flags, action-write right and ticket truth.
Crucially, **attached records never imply a specific ORIGINAL_APP_ID** in either
independent model. Expected: 960 NOT_INVOKED, 96 PRESERVE_CONTINUE,
92 BLOCK and 4 synthetic PERMIT controls.
Python normal, -O, -OO: 10/10 each. Node: 1,152/1,152, zero divergences.
Corrupting a matrix result and changing a source-pinned byte were both rejected.
The 4 PERMIT controls are synthetic, **not** native permission proof.

## Trust chain and unresolved gates

GetFinalPathNameByHandleW -> FwpmGetAppIdFromFileName0 ->
FwpmFilterAdd0 / FwpmFilterGetByKey0 ->
PsSetCreateProcessNotifyRoutineEx / referenced PEPROCESS / FileObject /
PsGetProcessCreateTimeQuadPart / PsGetProcessStartKey ->
FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6 /
FwpsAcquireWritableLayerDataPointer0 / FwpsQueryConnectionRedirectState0 ->
FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6 / kernel endpoint / original destination ->
accepted socket SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS / CONTEXT ->
same-requestor CLAIM -> records-tagged physical SSH TCP socket ->
**the second AUTH event has not been independently accepted** ->
pinned SSH server and SSH channel.

Unresolved: actual ORIGINAL_APP_ID on that second leg, PID/creation-epoch +
canonical EXE, endpoint ABA, re-used 5-tuple, IPv4/IPv6 compartments, process
death/PID reuse, sibling DIRECT, DNS/UDP/QUIC, ALE reauthorization, BFE/SSH loss.
No PacketBound/G2 PASS, no-DIRECT/leak-free or historical G1 inheritance.

## Decisive future experiment (requires separate driver/VNC/SYSTEM gates)

Capture kernel classify data for **both** initial A->loopback and records-tagged
B->physical-SSH native AUTH_CONNECT events on an independently admitted host.
Log typed ALE_APP_ID, ALE_ORIGINAL_APP_ID, IP_REMOTE_ADDRESS/PORT, flags,
PROCESS_ID, TRANSPORT_ENDPOINT_HANDLE, LOCAL_REDIRECT_TARGET_PID, original
destination, compartment ID, FWPS_RIGHT_ACTION_WRITE and final action.
Correlate by trusted WFP-generated origin records, not time/PID/5-tuple.
No test driver, WFP filter or VNC experiment is authorized by this document.

If confirmed, design a physically distinguishable AUTH policy for the two legs.
Do **not** simply PERMIT all selected-AppId traffic or exempt broad ports:
this would reopen the unrelated DIRECT bypass.

## Official Microsoft documentation

- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0
