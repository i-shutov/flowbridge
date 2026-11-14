# R194 — Selected ORIGINAL_APP_ID AUTH scope collides with tagged broker egress

2026-11-15; branch research/windows-wfp-ale-attribution-20261107 only. Independent R&D; NOT beta, PR #56, PacketBound/G2 PASS, no-DIRECT, leak-free or native proof.

## Pinned Git and source

Input research HEAD: e89cd540457ba987aa9064f1fa61e41f6cf4442c.
Input main (read-only): 5b5afc2feeda2195f302380e615ba003d4906e09.

- policy_windows.rs blob acf60334320d970f58af3349ee75fbaa59826602: AUTH_CONNECT V4/V6 BFE filters match FWPM_CONDITION_ALE_ORIGINAL_APP_ID == selected plus IP_PROTOCOL == TCP. FWP_ACTION_CALLOUT_TERMINATING; no current broker AppId/record exemption.
- kernel/src/redirect.rs blob a093f049d162987981a957aac90db1014bc6ff09: auth_classify blocks when auth_check fails. That predicate needs selected process PID/epoch/start-key, matching endpoint/ticket, WFP redirect flag, effective remote LOOPBACK + configured broker port and localRedirectTargetPID. A broker's separate outbound socket does not fulfill this conjunction.
- kernel/src/lib.rs blob 53f5ce6faa0f9f591974287f38ea890cafeb0dd2: guarded block is subject to action rights/arbitration; never presume unconditional block.
- policy_plan.rs blob 0c3d0e88eb9d06f4030131d9533da2d629dbdab0: readback of conditions is not callback execution proof.

## Conditional source-level functional NO-GO

Microsoft documents that ALE_ORIGINAL_APP_ID on a proxied connection denotes the original application, distinct from the broker's current ALE_APP_ID. Its required WFP redirect-record forwarding uses WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS) on a NEW outbound proxy TCP socket.

If a selected-origin connection is redirected, the broker correctly transfers its records to a new outbound socket, that socket reaches the R19 AUTH filter, and the R19 terminating callout has sufficient rights, then the filter matches the selected ORIGINAL_APP_ID on the broker egress. But auth_check rejects this non-client, non-local-broker-target connection. R19 therefore attempts BLOCK of its own required forwarding leg. This is not merely a PID/5-tuple correlation: it follows from the documented filter key and the code's positive authorization predicate.

This is a **conditional** functional incompatibility, NOT an observed Windows block. Actual filter arbitration, original-AppId propagation on the tested host, WFP classification stage, rights and final socket state are unmeasured. Removing WFP records to bypass the match cannot be deemed a solution: it breaks the documented record lineage. Do not introduce an unconditional broker exemption by EXE basename, tuple, port or proxy flag. A future design must distinguish authenticated selected-client DIRECT from record-bearing broker outbound without widening bypass.

## Tests and limits

Two separate pure user-mode, no-driver or network scripts:
- proxy_egress_negative.py: 10 unittest cases pass under normal, -O and -OO.
- independent_oracle.mjs: independent Node.js matrix output.

768/768 byte-identical rows; matrix SHA-256 3fb8c124db5b0cdac265e802b2f44b74ebdadd4e98ba04d2ce48ba6392b226f0.
576 UNMATCHED_OUTSIDE_FILTER; 184 BLOCK_IF_R19_CALLBACK_RUNS; eight PERMIT_CANDIDATE_NOT_NATIVE_PROOF. All 16 synthetic selected-original TCP, broker-current, records-set egress cases are conditional BLOCK. Those are MODEL results, not live flows. The model deliberately assumes valid metadata on the client leg; additional Windows provenance constraints are not simulated. A mutated broker-always-permit rule is detected. No Rust compiler or Windows WFP runtime was executed.

## Decisive next experiment and complete trust obligation

First: compile and run existing R190 READ-ONLY Rust BFE probe on a separately admitted Windows 10 Pro x64 host, record OS build, compiler/binary SHA, BFE API results/ACL gaps. BFE inventory cannot verify this callback chronology.

Before any driver experiments, prove a pure Rust policy model for two authenticated legs: selected client + selected DIRECT gate versus tagged broker outbound. No permit is valid solely because appId, PID, 5-tuple or redirect flag resembles a prior connection.

Any actual test of ALE_AUTH_CONNECT on both accepted and outbound sockets, FWPS_CLASSIFY_OUT0 rights, flags, ALE_APP_ID/ALE_ORIGINAL_APP_ID, record transfer, IPv4/IPv6, process death/PID reuse, sibling DIRECT, DNS/UDP/QUIC, WFP/SSH loss requires a separate owner decision and all driver/VNC/SYSTEM rescue/rollback gates. NOT performed.

Full unproved chain: referenced EPROCESS + process-create PID/creation epoch/canonical EXE -> kernel ALE REDIRECT v4/v6 exact AppId / original endpoint / owned redirect handle+context -> AUTH with live endpoint ticket -> actual accepted socket WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT) -> same-requestor CLAIM -> broker outbound SIO_SET redirect records -> SSH. NO-GO for end-to-end, leak-free and PacketBound/G2.

Official Microsoft sources:
https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-flags

Only this research branch may advance via expected_sha and force=false. No driver/callout/NDISRD/filter, firewall/service/OS/security/network/runner/automation changes, paid calls, AGPL, PR40, vendor binaries, or C++ WFP payload.
