# R4: two WFP layers and lifetime-sensitive endpoint evidence — 2026-11-07

Branch: research/windows-wfp-ale-attribution-20261107. This is independent R&D, not beta or PR #56. No kernel code, driver, BFE filter or network operation was executed.

## A concrete candidate beyond the PID snapshot

Microsoft's **metadata fields by layer** lists FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE at BOTH ALE_CONNECT_REDIRECT_V4/V6 and ALE_AUTH_CONNECT_V4/V6. PROCESS_ID is listed at both; PROCESS_PATH is listed at ALE_AUTH_CONNECT, but is NOT available at ALE_CONNECT_REDIRECT. The redirect fixed classify field ALE_APP_ID is available. This suggests a *hypothesis* of a cross-layer corroboration path for a particular endpoint without matching IP Helper tuples. It is NOT documented as an immutable per-TCP-connection token common to a redirect record and a process epoch, and the exact WFP layer order and effect of redirection on process identity must be independently tested.

Endpoint handle is a handle to an endpoint, not an authenticated independent per-NDISRD-frame witness. The handle must not be used to mint PacketBound. A shared endpoint handle must not be used as a proxy for EPROCESS: a duplicate endpoint/lifetime, process exit, PID reuse, ambiguous callback or changed process image leaves the flow unverified.

## Executable conservative offline implementation

`endpoint_witness_model.py` implements a pure Python fail-closed research gate with per-session tickets, owner generation + epoch + AppId, a supplemental AUTH_CONNECT endpoint observation, accepted-socket redirect context conditions and explicit SSH/WFP loss states. It cannot authenticate the `Owner`, `Redirect` or `Authorization` data: all positive observations are *synthetic assumptions*. Duplicate/ambiguous PID generation poisons that PID and revokes pending tickets within the research session. Replayed tickets, stale exits, mismatched same-name app identity, IPv4/IPv6 substitution and foreign socket receipts are rejected; NDISRD tuple attribution always remains NO_PER_FRAME_OWNER_PROOF.

Local Python 3.13 run of the corrected exact model: **82/82 assertions PASS**, syntax compilation PASS. Source SHA256 (locally): `d3a27e66e9ee8ad94c37e0cc4f61c33552583bc0563f4a9a185d986bdd760204`. Independent adversarial test found an initial false acceptance after colliding AUTH_CONNECT endpoint observations: conflict -> dropped observation -> later reinsert -> conditional acceptance. Fixed with a persistent endpoint-poison set that revokes queued tickets and prevents restored authorization within the same research session. No native Windows evidence. No `rustc` or Windows runtime is installed in the available isolated executor; Rust native compile and Win32 read-only AppId probe are not accepted. No GitHub Actions run was dispatched.

## Current architectural gate: NO-GO

An actual GO requires a reviewed and authorized **kernel-origin** chain within the very same connection: ALE_CONNECT_REDIRECT AppId + metadata PID + referenced correct EPROCESS generation/creation-time + canonical image verification -> owned redirect context and ticket -> redirect record queried on the accepted proxy socket -> record set on new proxy socket before connect, with an independently verified system-level enforcement policy. `FwpsPendClassify0` is documented for asynchronous redirect, but a deferred numeric PID lookup after process exit can resolve a reused PID. Endpoint handle correlation alone cannot repair this race.

Parallel NDISRD investigation remains restricted to packet I/O and remains NO-GO for per-frame packet-to-owner attestation absent a documented kernel-origin shared token. SOCKS-only beta is an independently accepted scope and is not altered.

## Next decisive experiment requiring separate native authorization

Verify empirically whether endpoint handles and original AppId/owner metadata remain stable across one redirect, original AUTH_CONNECT and proxy AUTH_CONNECT on real Windows 10/11, including same-name siblings, process death/PID reuse, simultaneous IPv4/IPv6, SSH loss and endpoint closure. A true WFP classify/callout/driver trial is separately gated by owner authorization, signed-driver exact SHA, recent VNC and SYSTEM rescue, Defender/firewall/rollback checks. Do not run it on hosted/no-driver environments or treat the model as native proof.

Official Microsoft primary sources:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ale-endpoint-lifetime-management
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_connect_redirect_v4_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpspendclassify0
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records

Research outcome: `release_accepted=false`; `native_kernel_identity_proved=false`; `NDISRD_PacketBound=false`; `system_no_direct_proved=false`. Historical G1 remains limited to dd1ab3c.
