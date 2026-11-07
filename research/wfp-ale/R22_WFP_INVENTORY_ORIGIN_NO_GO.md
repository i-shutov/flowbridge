# R22 — WFP inventory is not a kernel-origin or policy-owner witness

2026-11-07. Research-only branch research/windows-wfp-ale-attribution-20261107.
Starting branch SHA: f144d3bdb36ae94ed64c3930364487bce9077286.
Read-only main SHA: 5b5afc2feeda2195f302380e615ba003d4906e09.
Read-only beta SHA: c339df2e4d20edf1d11d45786581a68451a71929.
Scope: no WFP modification, no driver loading/building, no runner, no VNC, no
network or protection changes, no main/beta/PR56/automation changes.

## New design-critical distinction: BFE management objects versus runtime authority

The proposed R21 read-only inventory cannot by itself answer the question
"which dynamic session created this filter, and will this filter survive
the proxy process dying?" FWPM_SESSION0 reports sessionKey, flags and a
processId of the BFE *management client*. FWPM_FILTER0 reports filterKey,
filterId, providerKey, flags and an action, but does not expose a creator
sessionKey. The providerKey identifies the *policy provider*, not the
session owner. Neither a shared providerKey nor a matching numeric PID gives
the origin process of a particular ALE connection.

Microsoft explicitly documents that FwpmSessionEnum0 and FwpmFilterEnum0
iterate snapshots captured when their respective enumeration handles were
created. FwpmSessionCreateEnumHandle0 cannot be invoked within a transaction;
FwpmFilterCreateEnumHandle0 describes using an explicit transaction for a
current consistent filter view. Thus the two enumeration handles do not
establish a documented single atomic cross-inventory snapshot. Access control
also limits which filters a client can enumerate. A missing or visible entry
is not evidence of global OS enforcement.

The stronger ambiguity survives even if two tables were captured
simultaneously: two dynamic management sessions A and B can be visible with
the same single filter (filterKey/filterId/providerKey/action/flags all equal)
in hypothetical worlds where the hidden filter creator is respectively A
or B. When A exits, the dynamic filter is deleted in the first world but not
in the second. The published management view is identical. This is a
non-identifiability counterexample, NOT measured Windows packet behavior.
The synthetic worlds use ordinary dynamic filters; flags PERSISTENT/BOOTTIME
are deliberately excluded from their ambiguous-owner construction.

## Additional high-impact failure-mode flag

FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED has documented semantics:
for a CALLOUT_TERMINATING or CALLOUT_UNKNOWN action, if the corresponding
callout is unregistered, THIS FILTER is treated as a permit filter.
This is an explicit fail-open *filter-level* configuration choice. Do not
confuse it with the default absent-callout behavior (which Microsoft
documents as block for these callout actions). The observed flag alone
does not establish that a callout is currently registered or unregistered,
and a single filter treated as permit does NOT prove system-wide DIRECT;
other filters or policy may still block.

FWPM_FILTER_FLAG_DISABLED similarly means that a returned filter is disabled;
counting it as an active block is wrong. PERSISTENT only establishes the
documented object lifetime, not protection during missing driver, BFE failure
or the time until every affected ALE flow is reauthorized. BOOTTIME is
distinct and is removed once BFE finishes initialization.

A management FWPM_CALLOUT0 record added with FwpmCalloutAdd0 is distinct
from a runtime callback registered with FwpsCalloutRegister1. Microsoft
explicitly permits the former to preexist the latter. Therefore adding
FwpmCalloutEnum0 to the read-only inventory would still not authenticate a
live origin-bound classify callback.

## Executed deterministic tests — exact source, not miniature method copies

- r22_visibility_ambiguity.py: 16 indistinguishable pairs =
  2 IP families x 4 transport labels (TCP, UDP, DNS_UDP, QUIC_UDP)
  x 2 ordinary dynamic-filter flag configurations.
- test_r22_visibility_ambiguity.py: 14/14 unittest methods PASS against
  that exact module, including 256 parameterized negative admission
  decisions and 16 opposite-survival counterexamples.
- r22_independent_audit.py: independently constructed plain-dictionary
  observation oracle; 32/32 worlds checked; 16/16 ambiguous pairs.
  Eight intentionally wrong inference strategies each have one or more
  counterexamples (R22_OFFLINE_RESULT.json records counts).
- Source and tests were executed on Python 3.13 locally. Published blob
  SHA values are compared against tested source files. No WFP-native data,
  Rust compiler, kernel driver or packet trace used in this cycle.

A proof of logical insufficiency is NOT a proof that FlowBridge leaks or
that any exact Windows configuration is insecure. It only rejects an
unsupported trust promotion from management metadata to packet enforcement.

Reproduction from repo root:
  cd research/wfp-ale
  python3 -m unittest -v test_r22_visibility_ambiguity.py
  python3 r22_independent_audit.py

## Actual trust chain and outstanding NO-GO

1. Selection: FwpmGetAppIdFromFileName0 and FWPM_CONDITION_ALE_APP_ID
   versus native FWPS_FIELD_ALE_CONNECT_REDIRECT_{V4,V6}_ALE_APP_ID.
   Canonical EXE file identity, aliases, and sibling path distinctions
   need a same-origin validated binding. Still NO-GO.
2. Origin: process creation via PsSetCreateProcessNotifyRoutineEx and
   referenced EPROCESS + PsGetProcessCreateTimeQuadPart / PsGetProcessStartKey,
   legally and safely associated with that SAME classify. Not proved live.
3. Redirect: FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6 and
   FWPS_METADATA_FIELD_PROCESS_ID only if metadata bit valid;
   FwpsAcquireWritableLayerDataPointer0 / FwpsApplyModifiedLayerData0,
   FwpsRedirectHandleCreate0 and FwpsQueryConnectionRedirectState0;
   no registered runtime proof, and the R19 observer never redirected.
4. AUTH: FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6, incoming reauthorization flag,
   FWP_EMPTY fields and per-flow verdict. FwpmTransactionCommit0 is not
   a proof that every old flow has completed reauthorization.
5. Socket handoff: SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS / _CONTEXT on
   the actual accepted socket, then SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS
   on the outbound socket before connect. Provenance and one-use scope
   not established by any management inventory or user-model ticket.
6. IPv4/IPv6, process exit/reused PID, reused 5-tuple, selected and sibling
   DIRECT, DNS/UDP/QUIC, independent physical traffic during WFP/SSH loss:
   no direct packet evidence. G2/PacketBound/no-DIRECT/OS fail-closed NO-GO.
   Historic G1 dd1ab3c evidence cannot be imported into this proof.

## Next decisive experiment within current permissions

A standalone clean-room Rust *user-mode*, *read-only*, *no-driver* WFP
inventory on an authorized Windows 10/11 x64 host, WITHOUT CI runner,
filter changes or transactions. FwpmEngineOpen0; FwpmSessionCreateEnumHandle0
+ FwpmSessionEnum0; FwpmFilterCreateEnumHandle0 + FwpmFilterEnum0;
optionally FwpmCalloutCreateEnumHandle0 + FwpmCalloutEnum0.
Free returned arrays with FwpmFreeMemory0; destroy both enumeration handles
and close the engine. Capture exact per-page Win32 status, pagination and
possible ACL incompleteness; classify PERSISTENT, BOOTTIME, DISABLED,
PERMIT_IF_CALLOUT_UNREGISTERED and action together; do not join filter
to session or attest driver liveness from management snapshots.
No code was executed on a Windows host in R22.

This experiment can identify dangerous candidate policy flags and inventory
blind spots. It CANNOT prove per-packet/no-DIRECT enforcement.
The decisive native original-process + redirect + physical DIRECT test remains
separately gated and is expressly prohibited in the current task.

Official Microsoft sources (checked 2026-11-07):
https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0
https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmsessioncreateenumhandle0
https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmsessionenum0
https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltercreateenumhandle0
https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilterenum0
https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscalloutregister1
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpmk/nf-fwpmk-fwpmcalloutadd0
https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
