# R95 — registered BFE callout is not sufficient when filter action/count has changed

Date: 2026-11-10. Repo: i-shutov/flowbridge. ONLY branch: research/windows-wfp-ale-attribution-20261107. R&D, not beta, PR #56, release, PacketBound/G2 PASS or leak-free.

Research parent HEAD: 1b7c944c4dca3c0e9763a45aa85dc8e44c70c922. Main read-only: 5b5afc2feeda2195f302380e615ba003d4906e09. Pre-change R93 source blob: e24cb662e15f84047e254b50b95c735b2e460170. Inspected R19 producer: kernel-r19/policy_windows.rs blob acf60334320d970f58af3349ee75fbaa59826602; rule order kernel-r19/policy_plan.rs blob c8ab344551f1adfc20fd0019c4606cf3ca3c81c4.

## Source-level counterexample

R94 checks eight named BFE objects, matching filter/callout GUID, matching layer between objects, sublayer, zero flags and callout REGISTERED bit. Its original FilterPrefix stopped before FWPM_FILTER0.action and numFilterConditions. With all prior fields unchanged, a same-GUID filter changed to FWP_ACTION_PERMIT, CALLOUT_INSPECTION, a different action.calloutKey or zero conditions would still return R94 snapshot_gate_complete=true. This is a *diagnostic* false positive, not a measured Windows policy mutation or physical traffic leak. The real R19 installer uses CALLOUT_TERMINATING for both AUTH filters and CALLOUT_UNKNOWN for both REDIRECT filters, with two scoped conditions and exact action callout keys.

## Functional clean-room Rust correction

The standalone R93 read-only Windows x86_64 tool now includes the documented prefix of FWPM_FILTER0 through FWPM_ACTION0: a 16-byte x64 FWP_VALUE0 placeholder (opaque union never read), count, condition pointer and action. Every rule now requires num_filter_conditions==2, non-null pointer, expected action 0x5003 for AUTH v4/v6 or 0x4005 for REDIRECT v4/v6, and exact action.callout_key. Existing R94 checks are preserved. JSON adds per-rule action_and_count_matches, summary action_and_count_complete, and zero exit requires all three gates. Rust tests add action constants and x64 offset assertions (weight 96, count 112, pointer 120, action 128).

No new imported Windows API: FwpmEngineOpen0, FwpmFilterGetByKey0, FwpmCalloutGetByKey0, FwpmFreeMemory0, FwpmEngineClose0 ONLY. No driver, filter, callout, socket, network experiment, mutation or installation.

LIMIT: this checks the two-condition count/pointer, NOT the condition contents, selected AppId, protocol, exact four WFP layer GUIDs, classifyFn authenticity, origin, owner, atomicity, continuous enforcement or lack of DIRECT. The added FFI layout has not been compiled or checked at runtime on Windows. Exit 0 remains only a non-atomic management snapshot, NOT protection proof.

## Deterministic independent negative tests

Assuming the old R94 GUID/shape checks pass, enumerate four 4-bit masks: registered, correct action type, correct action key, correct condition count/pointer, total 65536. R94 accepts 4096; the fixed model accepts 1; 4095 old false positives rejected. Python 3/3 tests and independent Node 65536-row enumeration PASSED in local scratch. Independently matching canonical CSV SHA-256: 7d04d62a8237e7437ef7c9fc2a603e5e38292f79213dec86b30974a2b9ba94e5. No native Windows proof; exact changed Rust text was statically checked against fetched Git source. Native Rust compilation and published-file execution still pending.

Reproduce:
python3 research/wfp-ale/r95/r95_action_negative.py
node research/wfp-ale/r95/r95_action_independent.mjs

## Trust boundary and decisive next experiment

Still NO-GO for same-event referenced kernel PID/creation epoch/canonical EXE + AppId at ALE_CONNECT_REDIRECT V4/V6; original endpoint and scope; AUTH_CONNECT rights/metadata; accepted SOCKET with WSAIoctl SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/_CONTEXT; one-shot CLAIM; outbound SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS before authenticated SSH; PID death/reuse; reused 5-tuple; sibling DIRECT; IPv4/IPv6; DNS/UDP/QUIC; BFE/WFP/SSH loss. PacketBound/G2/no-DIRECT/leak-free not claimed.

Next permitted decisive test: compile exact updated R93 Rust and its layout tests on already authorized Windows x86_64 with existing tools; query BFE read-only, collect OS build, caller ACL, executable SHA-256, JSON and exit code. Condition-value checks need separately verified Rust ABI. Kernel/WFP driver experiment remains prohibited absent owner approval and all driver/VNC/SYSTEM rescue/rollback gates.

Official Microsoft:
https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_action0
https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_callout0
https://learn.microsoft.com/en-us/windows/win32/api/fwptypes/ns-fwptypes-fwp_value0

No main/release/beta, PR56, runner, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, network config, other repositories, automation/controller, drivers, WFP filters, NDISRD, VNC, signed drivers, ProxiFyre, closed PR40, vendor binaries, C++ WFP payload or paid operations touched.
