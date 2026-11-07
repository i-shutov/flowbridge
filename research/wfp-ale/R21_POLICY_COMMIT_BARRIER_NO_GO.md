# R21 — WFP policy commit and dynamic-session teardown: security-barrier NO-GO

Date 2026-11-07. Scope ONLY research/windows-wfp-ale-attribution-20261107.
Starting HEAD f7eefc1098f4b140e66da6ae0cfeb340d69fc389.
Read-only main 5b5afc2feeda2195f302380e615ba003d4906e09; beta c339df2e4d20edf1d11d45786581a68451a71929.

## Documented boundary A — commit does not acknowledge every existing ALE flow

FwpmTransactionCommit0 reports a completed BFE management transaction, not a documented synchronous all-flows reauthorization fence. Microsoft ALE Reauthorization states that, after a policy change is detected, the first subsequent packet through an affected existing ALE flow is submitted for reauthorization. An existing permitted flow can have packets in either direction; reauthorization may arrive in the reverse direction and unknown fields may be FWP_EMPTY. Therefore commit success, subsequent filter enumeration and currently healthy WFP/SSH polling are insufficient to conclude that every earlier flow has already been blocked. This is an INSUFFICIENT-EVIDENCE result, NOT a measured DIRECT leak and NOT an assertion that WFP forwards any packet before required reauthorization.

## Documented boundary B — owner failure deletes dynamic session objects

Microsoft WFP Object Management: a session created with FWPM_SESSION_FLAG_DYNAMIC owns objects that BFE automatically deletes when that session terminates, including when its client process exits or an RPC rundown occurs. Thus a dynamic-only filter owned by the proxy cannot itself furnish a fail-closed invariant across proxy crash. Whether traffic becomes DIRECT still depends on other independent active policies. Static/persistent filters have different lifetimes but cannot automatically prove BFE restart behavior, service safety, packet enforcement or no-DIRECT.

## Executed exact-source offline proof

- policy_barrier_r21.py defines 144 pairs of synthetic worlds with identical management observations but different hidden per-flow reauthorization history. Cartesian axes: IPv4/IPv6, TCP/UDP, selected/sibling/system DNS, unchanged/reused PID epoch, fresh/reused 5-tuple, no loss / hidden SSH / hidden WFP failure. The proof is observational equivalence: management visibility alone cannot distinguish those worlds.
- event_bound_observation is a CONDITIONAL MODEL predicate, not a kernel authority. It requires a same-event token, session, PID plus creation epoch, complete opaque AppId, original tuple, family, protocol, matching policy epoch, reauthorization flag, BLOCK, and known fields. The claimed from_kernel_event input is synthetic, never authenticated by this code.
- test_policy_barrier_r21.py executes 9 actual-source unittest methods, all PASS.
- r21_independent_audit.py implements a separate dictionary-based predicate and compares 4096 seeded cases against the implementation (3650 negative, 446 positive MODEL-ONLY). It detects eight intentionally invalid alternatives, including tuple-only/PID-only joins, policy-commit promotion and dynamic-session crash retention.
- No compiler, Windows driver, callout, NDISRD, WFP filters, BFE session, VNC, network configuration, GitHub runner, firewalls or OS security settings were accessed or changed.

Offline reproduction from repository root:

    cd research/wfp-ale
    python3 -m unittest -v test_policy_barrier_r21.py
    python3 r21_independent_audit.py

## Trust chain required, all currently NO-GO

1. Selected EXE: FwpmGetAppIdFromFileName0, FWPM_CONDITION_ALE_APP_ID, native ALE_APP_ID field, exact canonical file identity rather than basename/path alias.
2. Original process: PsSetCreateProcessNotifyRoutineEx, referenced EPROCESS, PsGetProcessCreateTimeQuadPart, PsGetProcessStartKey from the SAME process instance and legal IRQL; neither later PID nor 5-tuple proves origin.
3. Capture/redirect: FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6, validity of FWPS_METADATA_FIELD_PROCESS_ID, FwpsQueryConnectionRedirectState0, FWPS_CONNECT_REQUEST0, original destination, independent kernel origin.
4. AUTH/reauthorization: FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6 and ALE_AUTH_RECV_ACCEPT_V4/V6; FWP_CONDITION_FLAG_IS_REAUTHORIZE, FWP_EMPTY, per-flow post-change event and verdict. FwpmTransactionCommit0 is NOT a flow barrier.
5. Accepted socket: SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS / _CONTEXT on the actual accepted socket and validated connection-specific driver context; no caller-authored flags.
6. Outbound: SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS before connect, no replay across exit/PID reuse or reused 5-tuple; UDP requires WSARecvMsg/WSASendMsg ancillary records.
7. System coverage: native independent sibling DIRECT, IPv4/IPv6, DNS/UDP/QUIC, filter/session loss and SSH loss. A proxy rejecting ingress is not an OS kill switch.
8. NDISRD packet ownership/PacketBound: still absent; cannot be inferred from a WFP AppId or tuple/timestamp.

Decision: kernel-origin ownership, G2/PacketBound, no-DIRECT/leak-free and OS fail-closed remain NO-GO. Do not arm a safety claim on commit or dynamic-filter presence.

Next permitted experiment: read-only inventory of existing WFP sessions and filter lifetime (FwpmEngineOpen0, FwpmSessionEnum0, FwpmFilterEnum0) on an already authorized Windows x64 local environment; separately execute unchanged R16-R20 Rust tests on a non-runner toolchain. Neither demonstrates packet-level fail-closed. A decisive native classify + packet test across policy changes and process failure requires separately gated driver/VNC/SYSTEM rescue/rollback approval and is PROHIBITED here.

Microsoft sources:
https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactioncommit0
https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
