# R92 — WFP filter deletion invisible to R19 readiness

Date: 2026-11-10. Research branch ONLY: research/windows-wfp-ale-attribution-20261107.
Not beta, PR #56, PacketBound/G2 PASS, or physical no-DIRECT/leak-free evidence.

Research parent: 992a84b87c328483e08744d98ac5051183914066.
Read-only main: 5b5afc2feeda2195f302380e615ba003d4906e09.

## Exact source-level observation

- kernel-r19/kernel/src/lib.rs, Git blob 0af6d4539673d2894cbaa91af0ea8f3524862a26:
  R19 registers notify for all four runtime callouts; the notify function ignores its arguments and always returns SUCCESS.
- kernel-r19/kernel/src/redirect.rs, Git blob 9a07e026134d46ef646d39862bd982cc48bbc5f6:
  ready() checks the broker process, heartbeat lease and ticket book but never reads active WFP filter state.
- kernel-r19/policy_windows.rs, Git blob acf60334320d970f58af3349ee75fbaa59826602:
  management objects are installed under FWPM_SESSION_FLAG_DYNAMIC.
- kernel-r19/policy_plan.rs, Git blob c8ab344551f1adfc20fd0019c4606cf3ca3c81c4:
  four scoped AUTH_CONNECT/CONNECT_REDIRECT v4/v6 rules.

Microsoft documents FWPS_CALLOUT_NOTIFY_DELETE_FILTER notifications for deleted filters referring to a callout, including filters added before the runtime callback was registered. A delete notification cannot veto deletion. FWPM_SESSION_FLAG_DYNAMIC deletes session-owned objects on session end. R19 ignores that signal; therefore a broker may remain logically ready even though part of its four-filter protection is no longer present. This is a conditional source/contract inconsistency, NOT an observed Windows loss, physical DIRECT packet, leak or exploit. Independent system filters could still block traffic.

A notify-only repair is insufficient for continuous enforcement proof: additions predating callback registration are not replayed, notification absence cannot certify object existence, callbacks and management snapshots are not an atomic full-system barrier, and BFE/SSH loss remains unresolved. No permissive fallback is authorized.

## Reproducible deterministic negative test

- r92/r92_filter_liveness_negative.py: 5/5 Python tests PASS.
- r92/r92_filter_liveness_independent.mjs: independently enumerated all 512 rows; 512/512 match.
- SHA256 for canonical ordered CSV rows: 9a424012465b30258c6ba00a543358af2d19401825915bbb234f34d67f221757.
- 60/512 states represent broker readiness with one or more absent scoped filters. In 30/512 states there is not even a hypothetical independent barrier.
- Seven exact-GitHub-source structural checks all passed.
- Synthetic counts are NOT physical Windows states, frequency estimates, no-DIRECT success/failure, or kernel-origin proof. No native Windows WFP or Rust compiler experiment was run.

Reproduce from repository root:

    python3 research/wfp-ale/r92/r92_filter_liveness_negative.py
    node research/wfp-ale/r92/r92_filter_liveness_independent.mjs

## Trust boundary and next decisive experiment

Full kernel-to-SSH evidence remains NO-GO: precise original process PID + creation epoch + pinned file/AppId and endpoint at FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6; FwpsQueryConnectionRedirectState0 and FwpsAcquireWritableLayerDataPointer0/FwpsApplyModifiedLayerData0; authentic original AppId at AUTH_CONNECT_V4/V6; actual accepted socket and WSAIoctl SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT; nonreplayable CLAIM; WSAIoctl SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS on the physical authenticated SSH socket; independently enforced sibling DIRECT and loss containment. Not proven for process death/PID reuse, reused five-tuple, bound source, IPv4/IPv6, DNS/UDP/QUIC, SSH/BFE/WFP failure or PacketBound/G2.

Next within allowed permissions: a clean-room Rust user-mode read-only WFP management snapshot of the four own filter/callout GUIDs using FwpmEngineOpen0, FwpmFilterGetByKey0, FwpmCalloutGetByKey0 and FwpmEngineClose0. A snapshot is diagnostic only, not per-flow, physical or continuous authority. Any kernel instrumentation needs separately authorized owner driver/VNC/SYSTEM rescue/rollback gates.

Official Microsoft contracts:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nc-fwpsk-fwps_callout_notify_fn1
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-notify-callouts
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0

No mutation to main/release/beta/PR #56, runner, services, firewalls, Defender, SecureBoot, MemoryIntegrity, network, other repositories, automations or controllers. No driver, filter, NDISRD, signing, VNC, vendor binary, AGPL ProxiFyre, closed PR40, C++ WFP payload or paid operation.
