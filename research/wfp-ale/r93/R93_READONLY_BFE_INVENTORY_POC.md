# R93 — read-only Rust BFE filter/callout inventory (NOT a WFP proof)

Date: 2026-11-10. Scope exclusively research/windows-wfp-ale-attribution-20261107, i-shutov/flowbridge. Independent architecture R&D, not beta, PR #56, release, PacketBound/G2 PASS or leak-free.

## Baseline and exact R19 keys

- Research parent: 1a9b21d6dbbad895c7e9071cecd21155aac3ad15; main (read-only): 5b5afc2feeda2195f302380e615ba003d4906e09.
- Original policy_windows.rs blob acf60334320d970f58af3349ee75fbaa59826602; policy_plan.rs blob c8ab344551f1adfc20fd0019c4606cf3ca3c81c4.
- RULES in install order: AUTH_CONNECT v4, AUTH_CONNECT v6, CONNECT_REDIRECT v4, CONNECT_REDIRECT v6. Filter data1 fields 0x1649f030..33; callout data1 fields in corresponding order 0x1649f018, 0x1649f019, 0x1649f014, 0x1649f016. All GUIDs share the exact suffix in the Rust probe.
- R92 observed the source-level mismatch: notify() ignores deletion; redirect::ready() checks broker heartbeat/book but not live WFP policy. Actual removed-filter traffic was never observed.

## Functional R93 artifact and safety

- r93_readonly_policy_inventory.rs: standalone, dependency-free Windows x86_64 user-mode diagnostic. FFI calls ONLY FwpmEngineOpen0, FwpmFilterGetByKey0, FwpmCalloutGetByKey0, FwpmFreeMemory0 and FwpmEngineClose0. Local NULL server, NULL session, no installing filters, driver, service, firewall, socket, kernel callout or network access.
- Queries exactly four R19 filter and four R19 callout GUIDs; each returned native allocation is freed, and the BFE session is closed by Drop.
- One JSON line per rule includes GetByKey status, callout flags and conservative shape_present. Checks expected filter/callout GUID, R19 sublayer, zero filter flags, filter.layerKey == callout.applicableLayer. NULL or errored reads never count as present.
- Exit 0 means only 'the eight named management objects looked coherent across a non-atomic set of reads'; exit 2 means engine unavailable; exit 3 means incomplete or wrong shape. JSON explicitly reports kernel_origin_proof:false and continuous_enforcement_proof:false.
- Does NOT inspect WFP filter conditions, action types, true layer identity, AppId, owner, actual kernel callout registration/function, live enforcement, per-flow origin or packet/SSH behaviour. Even exit 0 is NO-GO for protection. BFE read ACLs can deny the query.
- ABI and runtime are NOT validated: rustc / cargo and Windows x86_64 were unavailable to this executor. No Windows/WFP experiment was run. The code is published uncompiled and must be independently reviewed.

## Deterministic negative tests

- Python r93_inventory_negative.py: 5/5 PASS in a local scratch tree using manually reconstructed source-verified R19 snippets; complete Git blobs were separately read by GitHub connector. Full-checkout source guard is still required.
- Independent Node r93_inventory_independent.mjs: separately enumerates 256 combinations of eight object presence bits and 16 combinations of four shape checks (4096 rows). Python/Node canonical CSV SHA-256 match: c9a9d54b31d8f307dd9a53f1b7393b616d62f1846725ae3e914a13de8bcda04c. Exactly 1/4096 synthetic combinations reports complete; 4095 fail closed. No native execution or observed Windows outcomes follow.
- Reproduce from full repo root: python3 research/wfp-ale/r93/r93_inventory_negative.py ; node research/wfp-ale/r93/r93_inventory_independent.mjs
- Later, only on an already-authorized Windows x86_64 with existing Rust toolchain: rustc --edition=2021 --test research/wfp-ale/r93/r93_readonly_policy_inventory.rs; run tests; compile the non-test file and read its JSON output. No tooling or driver installation is authorized by R93.

## Trust chain and next deciding experiment

Full NO-GO chain: verified kernel image/canonical EXE, PID + creation epoch and AppId -> WFP ALE_CONNECT_REDIRECT v4/v6 original endpoint and redirect records -> ALE_AUTH_CONNECT v4/v6 original AppId and kernel metadata -> accepted SOCKET with SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS and CONTEXT -> one-shot CLAIM -> SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS on physical authenticated SSH -> sibling DIRECT exclusion, death/PID reuse, five-tuple reuse, IPv4/v6, DNS/UDP/QUIC and BFE/SSH loss containment. R93 observes only a non-atomic management-plane object snapshot, not any of those per-flow trust edges.

Next deciding experiment: independently compile and exercise the exact R93 Rust source on an authorized Windows x86_64 user-mode host, capturing binary SHA-256, caller privileges, OS build and JSON; result can only validate management-query ABI and object observability. Positive kernel-origin/flow behaviour would require new, separately authorized driver/VNC/SYSTEM rescue/rollback gates, explicitly outside this work.

## Official API documentation

- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltergetbykey0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_callout0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfreememory0

No main/release/beta/PR #56, runner, services, firewall, Defender, SecureBoot, MemoryIntegrity, network, external repository, automation, VNC, kernel driver, WFP filter, NDISRD, signed driver work, ProxiFyre, vendor binary, closed PR40, C++ payload or paid action is modified.
