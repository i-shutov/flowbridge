# R129 — exact-key BFE diagnostic after the first reported native Rust PASS

Date: 2026-11-12. Repository i-shutov/flowbridge, ONLY branch
research/windows-wfp-ale-attribution-20261107. Baseline HEAD:
de29e67ff28f94668e2f3a36b76d9211712103cc; base tree:
440ac23ff394210f75814987fb2ec50ed9b6c2ed. Main observed read-only:
5b5afc2feeda2195f302380e615ba003d4906e09.

## Evidence actually received

The owner supplied a Windows 10 Pro 19045 console transcript: exact R113 Rust blob
49506ca07145c18947a0845f2a1a63b3de1f54ec; rustc 1.91.0
x86_64-pc-windows-msvc; metadata exit 0, native synthetic tests 5/5, inspector link
success, then `baseline_not_visible`, internal code 1, inspector exit 2.
This is owner-supplied native evidence, NOT a Windows run by this executor. Raw
Windows report and binary SHA have not been independently acquired. It establishes
reported compiler/linker/test progress, NOT WFP interception. Do not repeat R113's
stale enumeration; R128 in the baseline already restricts that resume path.

## Functional change, not another abstract NO-GO

r129_filter_get_by_key.rs asks ONLY for four fixed R19 filter GUIDs using
FwpmFilterGetByKey0. It does not enumerate any policy or deserialize FWPM_FILTER0.
There is no broad BFE transaction, subscription, socket, process lookup, driver,
policy write, dependency, automatic installation or telemetry upload.

Four allowed imported API symbols: FwpmEngineOpen0, FwpmFilterGetByKey0,
FwpmFreeMemory0, FwpmEngineClose0. Session is local (NULL server, default credentials,
NULL session), and each successful returned allocation is released without
inspecting its contents. Errors preserve the unsigned API return verbatim,
including hex; success+NULL and error+non-NULL are INVALID_API_RESULT. Error outputs
are not treated as owned pointers. Engine close is attempted before printing rows;
a close failure is never hidden by an apparently good lookup result.

| Raw result | Observation (not a protection assertion) |
|---|---|
| 0 plus non-null output | FOUND_BY_KEY |
| FWP_E_FILTER_NOT_FOUND / 0x80320003 | NOT_FOUND_RETURNED |
| ERROR_ACCESS_DENIED / 5 | ACCESS_DENIED_RETURNED |
| other Win32/WFP/RPC code | OTHER_API_ERROR, raw code retained |
| contradictory code/output pointer | INVALID_API_RESULT |

The four GUIDs are 1649f030..1649f033-25b3-4e01-9ca1-5ca803010019 in
AUTH_CONNECT_V4, AUTH_CONNECT_V6, CONNECT_REDIRECT_V4, CONNECT_REDIRECT_V6 order.
Verified source: policy_windows.rs blob acf60334320d970f58af3349ee75fbaa59826602;
policy_plan.rs blob c8ab344551f1adfc20fd0019c4606cf3ca3c81c4.

A missing reply is a reply for THAT key at THAT call. Separate GETs are not an
atomic snapshot. Found does not validate action/conditions/registration/ownership.
Denied does not establish presence or absence. No assertion about other policies
or whole-system protection follows. Every output has kernel_proof=false and
no_direct_proof=false; the summary also has atomic_snapshot=false.

Live exits: 2=query/open/close error; 3=all four GETs succeeded, not proof;
4=one or more NOT_FOUND replies (no denied/error); 5=ACCESS_DENIED seen (no other
query/close error). There is deliberately NO live exit 0. Absence on a clean host
is a useful diagnostic, not a compiler failure and not permission to install R19.

## Delivery and checks

FlowBridge-R129-ReadOnly-ByKey.ps1 uses existing Windows x86_64 MSVC Rust, writes
only a fresh temporary evidence directory, downloads at most one immutable source
blob from this repository, verifies Git SHA1 AND SHA256, then compiles/tests.
A local LF-exact source can be used offline; a differing local checkout is left
untouched and the exact Git blob is retrieved instead. No git clone, checkout or
network-setting mutation. -RunReadOnlyBfe is required for API execution; default
runs synthetic checks; -CompileOnly stops after compiler metadata.

The executable's --contract-matrix mode does not call BFE. The harness compares
its exact 1,250-line result (LF-normalized for transport) with the independently
computed SHA256 before allowing the four read-only GETs. It validates JSON key
order, cardinality, integer and boolean types, raw code/hex, output-pointer state,
summary/exit consistency, close result and false proof flags. It saves stdout and
stderr separately, plus source/binary SHA, rustc -vV, Windows build and JSON report.

Local execution: 18/18 Python tests PASS. Independently implemented Node oracle
agrees with Python on all 1,250 ordered decisions. SHA256:
54335b8741c0b52c0dd5d71f6e511dcf1b2f64f9356773cf21c8c9cd904f28d4.
Exit distribution: 2=1169, 3=1, 4=15, 5=65 (synthetic combinatorics, NOT Windows rates).
The Rust file includes 14 pure unit tests; Windows live module is excluded from
test builds. Rust compilation, PowerShell 5.1 parse/runtime and new live BFE GETs
are NOT RUN in this Linux executor. Do not transfer the old R113 native PASS to R129.

LOCAL_REVIEW_TASKS.md provides three bounded small-model assignments. No subagent
executor/model selector is available here; no model delegation is claimed.

## Next decisive experiment and trust boundary

Owner executes the exact published R129 script with -RunReadOnlyBfe on the already
used Windows 10 Pro x64. Capture R129_EVIDENCE.json and bfe-by-key.jsonl. No driver
or filter is needed. The next decision is based on four raw codes: absent replies,
permission refusals, readable objects, or an API failure, rather than generic
baseline_not_visible. An inaccessible/absent filter must NOT be installed for this test.

This says nothing about kernel-original process reference -> PID/creation epoch /
canonical EXE and AppId -> native ALE CONNECT_REDIRECT and AUTH_CONNECT ->
redirected accepted SOCKET records/context -> one-use CLAIM -> SSH egress.
Process death/PID reuse, reused 5-tuple, IPv4/IPv6 runtime attribution, sibling
DIRECT, DNS/UDP/QUIC and WFP/SSH loss remain NO-GO. No G1 dd1ab3c transfer,
PacketBound/G2 PASS, no-DIRECT or leak-free claim is made.

## Primary Microsoft contracts

- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltergetbykey0
- https://learn.microsoft.com/en-us/windows/win32/fwp/wfp-error-codes
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfreememory0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0

Scope: new research/r129 files only. No main/release/beta/PR56, runners, services,
firewall/UFW, Defender, SecureBoot, MemoryIntegrity, networks or automation changes.
No driver/callout/filter creation, NDISRD, VNC, signing, ProxiFyre/PR40/vendor binary,
C++ payload or paid operations. Git ref updates require expected SHA and force=false.
