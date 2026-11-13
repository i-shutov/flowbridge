# R01 / G2 — Windows protected transparent routing: architecture decision checkpoint

Date: 2026-11-13. **Status: P0 BLOCKED / NO-GO.** This is a decision
package, not new product authorization or native acceptance. The owner
authorization for separately installed signed NDISRD + independent Rust
user-mode, **no custom kernel driver**, remains binding (Issue #41).

## 1. Exact missing trust boundary

A protected selected-app flow must have an unforgeable link:

> Intercepted packet or accepted redirected connection
> → kernel-origin OS app identity + process creation epoch
> → original endpoint, address family and compartment
> → selected policy generation → supervised SSH route or fail-closed block.

NDISRD ReadPacket/INTERMEDIATE_BUFFER yields a frame, adapter and direction
flags, **not** a per-packet process epoch or kernel connection identity.
GetExtendedTcpTable gives a separate endpoint-to-PID snapshot. TCP/IP ETW
is also a separate stream; linking any of these via tuple, ISN, timing or
packet hash is not the authenticated common kernel token required for G2.
The last G2 job #43407099791 failed with kernel_connection_id_missing.
Hosted 11/11 SOCKS-only CI #43407093536 does not waive that failure.

Primary APIs:
- [NDISRD ReadPacket](https://www.ntkernel.com/docs/windows-packet-filter-documentation/c-api/readpacket/)
- [NDISRD intermediate buffer](https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_intermediate_buffer/)
- [Microsoft WFP Bind or Connect Redirection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection)
- [Microsoft query redirect records](https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records)
- [Microsoft set redirect records](https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records)

**Conclusion:** no accepted per-frame kernel-origin PacketBound producer exists
in this implementation of the currently authorized NDISRD-only interface.
This is an API/proof NO-GO for this acceptance contract, not a claim that
no Windows transparent proxy architecture is possible.

## 2. Owner architecture decision required

| Option | Compatible with existing approval? | Release consequence |
| --- | --- | --- |
| A. NDISRD-only, original strict per-frame PID/epoch criterion | **Yes** | G2 cannot be accepted until a verifiable trusted kernel common token/API is demonstrated. Limited explicit SOCKS beta remains separate. |
| B. Signed WFP ALE connection-redirect backend providing identity/context with accepted socket and redirect records | **No — explicit new permission and signing feasibility needed** | Candidate path to real 1.0, after independent signed lab and lifecycle fixes. |
| C. Licensed third-party signed connection-aware backend supplying equivalent kernel-origin identity/redirect receipt | **No — separate vendor/API/license authorization** | Feasibility must establish a real vendor and documented exact API before integration; cannot be presumed. |

Recommendation for immediate execution: keep A as **the only currently
authorized product path** and do not weaken G2. Run a bounded **read-only
API/license feasibility review** of B/C so the owner can decide on
a production architecture. Research alone cannot authorize integration.
No option has been selected in this document on the owner's behalf.

## 3. If option B becomes authorized, known source blockers remain

Research is isolated to
research/windows-wfp-ale-attribution-20261107 and must not be merged
into main, PR #56 or PR #59 without product authorization:

- R158: AppId readback used in BFE filters may differ from ARM/broker AppId;
  require exact canonical bytes tied to OS process lifetime.
- R160: dynamic BFE policy can vanish while kernel PING remains healthy;
  health is not proof of fail-closed coverage.
- R161: terminal lease/session cannot be safely rearmed in the loaded
  instance; generation-tagged recovery must be implemented.
- R162: ALE reauthorization is rejected by current one-shot AUTH guard,
  so a valid previously accepted flow may be blocked during policy changes.
  An ACTION_WRITE/veto-correct idempotent model is still required.
- Accepted socket must carry genuine redirect context and records; opaque
  records must be attached to the new outbound proxy socket **before**
  connect. App origin, endpoint, generation and loop avoidance remain bound.

These are source-level findings, **not** observed native traffic failures.
Additional synthetic models alone do not count as native G2 progress.

## 4. Objective exit for first real native G2 experiment

**Prerequisites:** dedicated disposable Windows 10/11 x64 driver-capable lab,
approved exact signed driver/backend, rollback snapshot, real out-of-band
VNC/SYSTEM rescue, independent observer and security state inventory.
Do not attempt on the user's working Win10 or production VPS. Hosted signing
rehearsal does not authorize kernel driver installation.

- **G2.1** Kernel-proven source process/AppId/creation epoch, original
  endpoint, family, compartment and policy generation tied to the selected
  connection. No snapshot-to-packet heuristic substitution.
- **G2.2** Original redirect → accepted socket → verified one-use records
  and context → outbound socket before connect. IPv4/IPv6, tuple/PID reuse,
  unrelated sibling flows and loop handling have negative tests.
- **G2.3** Selected unmodified EXE reaches remote echo **only via real
  supervised SSH**; unselected EXE takes only configured permitted DIRECT.
- **G2.4** Selected protected route never silently escapes DIRECT on SSH
  failure, BFE filter/session loss, reauthorization, crash, upgrade/restart,
  network change or stop. Verify using **physical independent egress pcap**.
- **G2.5** Selected hostname DNS, IPv6, application DoH/DoT and UDP/QUIC
  limitations separately measured on both ends; unsupported protected
  traffic must be blocked or protected mode refused, not mislabelled safe.
- **G2.6** Original JSON + pcap + driver/code signature + source SHA +
  binary hashes + OS/build + commands + exact result and independent review.
  Keep protected-mode activation sealed until all required gates PASS.

**STOP:** any unknown packet owner, missing redirect record, stale
AppId/generation, selected-flow DIRECT, missing rescue, failed policy
re-AUTH or unsafe cleanup invalidates the experiment. Never suppress
failed source/native evidence.

## 5. Keep the release train moving separately

1. Complete beta A3 (new Windows bytes) + A4 (ARM64/Intel Mac) + A5/A6
   license/security/independent release review. No tag before owner A7 GO.
2. R02 macOS signed-app prerequisite preflight in separate Draft PR #60
   narrows the signing/entitlement gap without activating NE.
3. Freeze one explicit Windows architecture decision A/B/C; no more
   iterative ETW/tuple heuristics as a substitute for G2.
4. After the approved lab, run bounded G2.1–G2.6 and fix real failures,
   then integrate DNS R03/R04, security R08 and frozen RC R09/R10.

**Current decision:** beta publication not approved, G2 NO-GO,
physical no-DIRECT unproved, FlowBridge 1.0 NO-GO.
