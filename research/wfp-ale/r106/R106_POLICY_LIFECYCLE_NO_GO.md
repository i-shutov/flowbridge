# R106 — lifecycle NO-GO for four owned R19 WFP rules

2026-11-11. Independent read-only architecture R&D, exclusively in \`i-shutov/flowbridge\` branch \`research/windows-wfp-ale-attribution-20261107\`. Baseline research HEAD \`9edbb4807ae451ba005535fd58131467b58f70de\`; main \`5b5afc2feeda2195f302380e615ba003d4906e09\`. Not beta, PR #56, G1 dd1ab3c, PacketBound/G2 PASS or a leak-free assertion.

## Source-anchored result

The exact R19 \`kernel-r19/broker.rs\` blob \`ce6c549a9ae488cc7c0ca9a7e7be68871b9d7f2c\` calls \`device.arm(&selection,ports[0],ports[1])?\` before \`Installed::activate_admitted(&plan)\`. Those operations are not atomic. Selected TCP can be attempted before this session installs its four owned filters. The presence or default action of foreign filters was not tested.

The exact R19 \`kernel-r19/policy_windows.rs\` blob \`acf60334320d970f58af3349ee75fbaa59826602\` opens BFE with \`FWPM_SESSION_FLAG_DYNAMIC\`, creates filters with \`f.flags=0\`, and retains the engine handle in \`Installed\`. It explicitly closes the handle via \`FwpmEngineClose0\`, and Drop does likewise. Microsoft documents that BFE automatically removes objects of a dynamic session when the session ends, including on client-process termination. Thus broker crash or graceful close removes *R19-owned filters*, independent of whether a selected process is still alive; no persistent fail-closed barrier is implemented in this module.

\`broker.rs\` finishes workers before closing policy but only requires the external test harness to terminate selected clients before teardown. It does not natively prove that requirement for all selected processes. On a broker crash the 250 ms heartbeat / STOP handling cannot keep session-owned filters installed after the session vanishes.

This is a documented **policy-ownership coverage gap**. It does **not** demonstrate that Windows permitted any packet, that another filter was absent, that DIRECT traffic occurred, or that an actual WFP classify event ran. Kernel/SSH revocation and dynamic BFE lifetime are different mechanisms.

## Verification

\`r106_source_guard.py\` validates exact original Git blobs and nine source-ordering/flags properties. These nine predicates were independently executed against fresh GitHub connector blobs: 9/9 PASS.

Two offline, independent state-machine programs (\`r106_lifecycle_negative.py\`, \`r106_lifecycle_independent.mjs\`) each enumerate 48 states: six phases × selected process alive × connect attempted × independent guard. The synthetic inventory is 24 states with R19-owned filters absent, 16 with them present and eight with unknown BFE state. Six selected-alive/attempt states occur in the absent phases, three with no hypothetical external guard. These are **conditional candidates**, NOT observed DIRECT leaks. Both models were executed on Python/Node and gave matrix SHA-256 \`5fef8e2d1307ca8d13ec949b4725e163fb0576ce074700b0f7382e78f48d3ef0\`.

No native Windows compilation, real BFE snapshot, kernel callback, packet capture, WFP filter or driver installation was performed.

## Trust boundaries and next decisive experiment

A sound chain still needs pinned \`PS_CREATE_NOTIFY_INFO.FileObject\` and referenced EPROCESS, \`PsGetProcessCreateTimeQuadPart\`, \`PsGetProcessStartKey\`, canonical EXE and AppId through \`FwpmGetAppIdFromFileName0\`, then continuous v4/v6 ALE CONNECT_REDIRECT and AUTH_CONNECT coverage, authentic \`FWPS_INCOMING_METADATA_VALUES0\`, \`FwpsQueryConnectionRedirectState0\`, one-use endpoint/context receipt, accepted socket \`SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS\`, kernel CLAIM and \`SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS\` before physical SSH connect, and pinned SSH. R19's owned policy does not provide continuous coverage through broker loss. Process death/PID reuse, reused 5-tuple, sibling DIRECT, UDP/DNS/QUIC and WFP/SSH loss remain NO-GO. Management visibility is not runtime proof.

Next permitted step: **only** compile exact Git R99/R103 read-only user-mode tools on an already authorized Windows x86_64 host, verify ABI with installed SDK and record Windows build, binary SHA-256, native BFE JSON and exit codes. Existing, separately authorized session evidence may be reviewed before/after session termination; **do not initiate a new driver/VNC/filter/network experiment**. Durable fail-closed policy would require an explicit owner architecture/cost decision and independent safety/rescue/rollback gates. Do not assume it exists.

Microsoft documentation:
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0
- https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineclose0

Do not touch main/release, integration/windows-rust-capture-agent-20261031, PR #56, any other repository, runner, service, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, network, automation or paid resource. Never use ProxiFyre, closed PR40, vendor binaries or C++ WFP payload. Ref updates must use exact expected_sha and force=false, STOP on conflict.
