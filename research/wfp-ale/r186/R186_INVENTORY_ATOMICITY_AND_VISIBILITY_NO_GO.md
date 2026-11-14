# R186 — Read-only BFE inventory: atomicity, ACL visibility, and runtime registration

Track: independent WFP/ALE architecture R&D only; research branch research/windows-wfp-ale-attribution-20261107. Baseline research HEAD 621113199bb5d50f478d0c20302aa90cf3637af6; read-only main HEAD 5b5afc2feeda2195f302380e615ba003d4906e09. Not beta, PR #56, or driver work.

## Material source/API finding

R19 policy_windows.rs (blob acf60334320d970f58af3349ee75fbaa59826602) opens FWPM_SESSION_FLAG_DYNAMIC; policy_plan.rs (blob 0c3d0e88eb9d06f4030131d9533da2d629dbdab0) commits the four selected TCP ALE AUTH_CONNECT/CONNECT_REDIRECT v4/v6 objects and performs post-commit per-key readback. R184 established that these dynamic objects disappear when the owning session dies. Their fixed GUIDs can be reused by a later owning session.

Consecutive FwpmFilterGetByKey0/FwpmCalloutGetByKey0 reads are not a continuous-ownership certificate. In an abstract teardown/reinstallation schedule, a read can succeed against owner A, a policy gap can occur, and later reads can succeed against owner B. No claim of an actual Windows packet leak follows. Conversely FWPM_CALLOUT_FLAG_REGISTERED in FWPM_CALLOUT0.flags genuinely reports whether a callout is currently registered in the kernel, but a snapshot is not a runtime classification or permanent guarantee. Do not misstate this flag as unavailable.

FwpmFilterCreateEnumHandle0 uses a non-live snapshot; only filters readable under the caller's token are enumerated. Even complete enumeration can omit ACL-hidden objects. A read-only FwpmTransactionBegin0(..., FWPM_TXN_READ_ONLY) offers transactional consistency for the BFE management objects, not an end-to-end packet or callout-execution witness. This model optimistically pins the queried registration flag to one phase; real asynchronous kernel registration/classification must not be inferred as transaction-frozen.

## Executed negative tests

Independent clean-room Python and Node.js models produce byte-identical 540-line JSONL matrices (SHA-256 d67572b0143c6ded43b394270280117e6764524904ce8630a9700313e18db157). Scenarios: 3 abstract owner/registration histories; 45 ordered eight-query schedules over three phases; hidden foreign-filter true/false; non-transactional vs best-case transaction snapshot. Seven mixed-epoch read schedules produce 14 false-green rows across ACL variants even though owner death occurs between reads. Python unittest 7/7 in normal, -O and -OO; independent Node oracle 540/540. Mutation ignoring query-time registered flag detected. These are controlled symbolic outcomes, not Windows measurements.

## Next allowable experiment

Build a clean-room read-only Rust Windows inventory, opening an ordinary non-dynamic management session, beginning FWPM_TXN_READ_ONLY, verifying the exact four R19 filter GUIDs and four callout GUIDs via FwpmFilterGetByKey0 and FwpmCalloutGetByKey0 (including filterId, layer, sublayer, action, conditions, flags and REGISTERED), checking FwpmSubLayerGetByKey0, enumerating sessions with FwpmSessionCreateEnumHandle0/FwpmSessionEnum0, and inspecting all readable foreign filters via FwpmFilterCreateEnumHandle0/FwpmFilterEnum0. Explicitly handle FWP_E/RPC/access failures, cleanup FwpmFreeMemory0, and report OBJECTS_OBSERVED_AT_SNAPSHOT only. This is a proposal, not a compiled/native test; rustc is absent in the current environment.

The kernel-origin trust chain remains NO-GO: referenced image/process and PID/creation epoch/canonical EXE; ALE redirect/AUTH v4/v6 original/current AppId, compartment, reauthorization; accepted socket redirect record/context query; durable kernel Witness ACK; one-shot CLAIM; physical SSH redirect-record handoff; fail-closed BFE/SSH loss; sibling DIRECT, DNS/UDP/QUIC, IPv6 and 5-tuple/PID reuse. No PacketBound/G2 PASS, leak-free or no-DIRECT promise. No changes to protected refs, beta/PR #56, drivers, filters, hosts, network, firewall, services, runner, security controls, or automations.

Microsoft primary references:
- https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactionbegin0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltercreateenumhandle0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_callout0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmsessionenum0
- https://learn.microsoft.com/en-us/windows/win32/fwp/access-control
