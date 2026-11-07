# R3 — parallel mechanisms, independent trust boundaries (2026-11-07)

Only research/windows-wfp-ale-attribution-20261107. Explicit SOCKS-only beta and PR #56 remain independent and unchanged.

## Corrected kernel metadata

Microsoft's metadata-by-layer table lists FWPS_METADATA_FIELD_PROCESS_ID, but not FWPS_METADATA_FIELD_PROCESS_PATH, at ALE_CONNECT_REDIRECT_V4/V6. ALE_APP_ID is a fixed classify field. PID alone does not authenticate the image or creation epoch. This correction invalidates the previous R2 synthetic missing-path-metadata assumption; the fixture now asserts missing fixed AppId and separately rejects invented PROCESS_PATH metadata.

## Parallel architecture appraisal

| Criterion | WFP/ALE connection-aware candidate | NDISRD frame interception |
|---|---|---|
| Kernel interception unit | Classification of a TCP connection at ALE_CONNECT_REDIRECT | Individual packet buffer |
| App owner | Conditional ALE_APP_ID + PROCESS_ID, generation and canonical image still unproved | Not in INTERMEDIATE_BUFFER; IP Helper/ETW 5-tuple is only a candidate |
| Correlation witness | Own callout context, actual accepted-socket WFP redirect records, outbound records set before connect | No documented shared per-frame kernel owner token |
| DNS/UDP/QUIC | Separate explicit coverage tests and enforcement | Per-frame handling without authenticated process owner |
| SSH/WFP loss | Separate system-level fail-closed proof needed | Service rejection is not a system DIRECT block |
| State | NO-GO for accepted kernel proof | NO-GO for PacketBound |

At a minimum, an authorized signed WFP callout would need: trusted ALE fixed AppId; PROCESS_ID metadata validity; referenced EPROCESS generation and creation epoch from that same classified endpoint; canonical image provenance; owned unique redirect context; WSAIoctl SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT against exactly the accepted socket; and SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS before any outbound connect. No step is currently native-proven.

FwpsPendClassify0 may defer an ALE classification when allowed, but does not authenticate delayed PsLookupProcessByProcessId against PID reuse. FwpsPendOperation0 is not valid for CONNECT_REDIRECT. Process notification callbacks cannot guarantee completeness for already running processes merely by registering after boot.

Sources: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer ; https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection ; https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpspendclassify0 ; https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pcreate_process_notify_routine_ex .

R3 no-driver synthetic exploration is in dual_mechanism_audit.py. It is NOT a kernel witness nor a beta release gate. No driver/filter, network, runner, automated task or PR mutation. G2 OPEN/NO-GO.
