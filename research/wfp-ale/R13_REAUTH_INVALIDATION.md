# R13 — ALE reauthorization invalidates stale AUTH model evidence

Date: 2026-11-07. Research branch ONLY: research/windows-wfp-ale-attribution-20261107.
Parent HEAD: 191ea0cbe5c47bd648e703a35ecc0519b89d71d8.
Main observed: 5b5afc2feeda2195f302380e615ba003d4906e09.
No beta, PR #56, release, other branch, runner, workflow, driver, WFP filter,
service, firewall, network, VNC, safety control or automation changes.

## Genuine model counterexample (NOT a real kernel bypass)

In the R7 ResearchGate event model:
1. Register a synthetic referenced owner (PID, generation, epoch, opaque AppId).
2. Record synthetic ALE CONNECT_REDIRECT ticket and endpoint.
3. Record matching initial ALE AUTH_CONNECT; it becomes supporting evidence.
4. Receive ALE reauthorization on that endpoint. Old code returned
   REAUTHORIZE_NOT_NEW_PROOF without invalidating the prior AUTH.
5. A matching synthetic accepted-socket receipt could still get
   CONDITIONAL_MODEL_ONLY despite the intervening reauthorization.

The same false-admission was possible when an intervening AUTH was malformed:
missing path identity or invalid family returned INVALID_AUTH but kept the
earlier AUTH and pending ticket. R13 independently reproduced the pre-fix
failure (a pending ticket was not retired).

Microsoft states that ALE reauthorization can occur after policy/interface
change or a pending operation, that FWP_CONDITION_FLAG_IS_REAUTHORIZE
distinguishes it, and that some fields can be FWP_EMPTY on reauthorization.
It does not imply a new connection or retained positive ownership proof.

## Functional correction

ResearchGate.observe_auth now invalidates a *pending endpoint's* old AUTH
and retires its ticket on any reauthorization, even with missing fields.
Malformed initial AUTH and unknown/nonboolean reauthorization flags also
invalidate that endpoint. A different endpoint remains independent.
Revoked endpoint handles cannot be revived within this model session.
This deliberately conservative behavior may deny legitimate flows;
it is a synthetic evidence discipline, NOT proof of a production WFP policy
or a Microsoft requirement to terminate every reauthorized flow.

Changes:
- endpoint_witness_model.py: source correction in observe_auth.
- reauthorization_invalidation_audit.py: separate invariant/oracle with
  IPv4/v6, reordered AUTH, malformed and unknown evidence, endpoint isolation,
  process death, same-name sibling AppId and SSH loss.
- reauthorization_invalidation_mutants.py: five executable unsafe mutants.

## Actual QA / reproducibility

Python 3.13.5 in isolated Linux: 38/38 deterministic negative/positive
model cases PASS; 5/5 deliberate unsafe mutants detected; py_compile PASS.
The original failing behavior was verified before the correction.
The independent audit Git blob is 075874370ebdafc072ca2aff34b9ab5cb417fc75,
matching the exact locally executed 6155-byte file.
Mutation verifier Git blob is 58c2daa1d759d2449c59b4e73413f4746c4a628e,
matching the exact locally executed 2876-byte file.
The local execution used a method-identical mirror of the model's main
state-machine methods because the full GitHub checkout is not available
in this isolated executor. The pushed model modifies only the verified
observe_auth anchor in the exact original file; no other method was changed.
Full repository R5/R7 regression suite and native Windows/Rust tests
were not executed in this cycle.

Commands from a repo checkout:
    python3 research/wfp-ale/reauthorization_invalidation_audit.py
    python3 research/wfp-ale/reauthorization_invalidation_mutants.py

## Kernel-origin trust chain: still NO-GO

- FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6 + exact ALE_APP_ID and valid
  FWPS_METADATA_FIELD_PROCESS_ID must be from one kernel classify.
  Referenced EPROCESS creation epoch and canonical executable provenance
  must be obtained safely; PsLookupProcessByProcessId requires IRQL <= APC_LEVEL.
- FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6 has initial/reauthorization semantics;
  FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4/V6 governs endpoint lifetime.
  A numeric endpoint handle is not authenticated accepted-socket ownership.
- FwpsQueryConnectionRedirectState0 + FWPS_CONNECT_REQUEST0 + owned
  redirect context and handle have not been executed.
- WSAIoctl SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT must run on
  the actually accepted socket and SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS
  on the outbound TCP socket before connect; not executed.
- IPv4/v6 sibling DIRECT, DNS/system resolver, UDP/QUIC, process exit/PID
  reuse and WFP/SSH loss require independent native enforcement evidence.
  Local ingress denial is not a system kill switch.

NO kernel-origin identity, native ALE receipt linkage, PacketBound/G2,
system no-DIRECT, leak-free dual-stack or release acceptance.
Historical G1 on dd1ab3c is not transferred. R12 AppId read-only findings
remain bounded to tested Windows-2025 path aliases.

Primary Microsoft API references:
https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts-asynchronously
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ale-endpoint-lifetime-management
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records

Next decisive safe experiment: read-only AppId DOS/NT namespace comparison
on authorized Windows 10/11 x64 with strict redaction. It cannot prove
kernel connection identity. Actual redirect/EPROCESS/sibling DIRECT requires
a separately approved signed backend and all VNC/SYSTEM rescue/rollback gates.
