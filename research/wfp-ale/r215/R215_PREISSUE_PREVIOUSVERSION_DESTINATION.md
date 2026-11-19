# R215 — predecessor modifier before R19 ticket issue (conditional NO-GO)

2026-11-19. Sole scope i-shutov/flowbridge, research/windows-wfp-ale-attribution-20261107; independent architectural R&D, not beta, PR #56, G1, PacketBound/G2 PASS, no-DIRECT or leak-free.

Initial research HEAD: 7e39242c431d8fe0f2137dfd3d2095ab89dd25fb. Main read-only: 5b5afc2feeda2195f302380e615ba003d4906e09. Source R19 redirect.rs blob a093f049d162987981a957aac90db1014bc6ff09; handoff.rs blob e1d17217db50362ba9c4efc83af820b6beb094cf.

Microsoft FWPS_CONNECT_REQUEST0 documents its read-only previousVersion modification history: NULL if no previous modification by another WFP filter, non-NULL otherwise. Other callouts may modify remoteAddressAndPort. FwpsQueryConnectionRedirectState0 checks a DIFFERENT redirect-record/handle state. Current R19 takes the CURRENT request.remoteAddressAndPort as Book::issue destination without examining request.previousVersion or modifierFilterId, and queries redirect state only when metadata reports redirectRecords.

Conditional predecessor witness: if another WFP filter changed the remote destination before R19 acquired writable data, and no redirect-record handle identifies the change, its ticket describes the modified destination rather than necessarily the application's initial destination. If AUTH originalDestination retains the true initial address, R19's Book::attest comparison rejects this case. Only if AUTH originalDestination equals the modified/current value is a locally successful attestation candidate possible without proof of the earliest original address. The native availability of these conditions, final WFP arbitration, accepted-socket reachability, CLAIM and physical SSH are ALL UNKNOWN. This is not an observed bypass or DIRECT/leak.

PRE-ISSUE predecessor provenance is distinct from R212 ISSUE-to-APPLY race and R214 post-AUTH arbitration. A conservative design could reject any unexplained non-NULL previousVersion, but may sacrifice compatibility; a correct choice requires actual native history observations under separately approved gates.

Deterministic tests executed: Python 36/36 and independent Node 36/36, two CONDITIONAL evidence gaps (one per IPv4/IPv6). Canonical ordered JSONL SHA-256 matches: abc4a55be5b3bcd834eb4763736098ec21adb973f856ecd5f68ce98f37148a09. Python py_compile and Node --check passed. Independent source checks against exact Git blob: 5 expected anchors present, 2 predecessor guards absent. Optional --source test not run in this Linux container (checkout unavailable); Windows kernel classify/BFE/SSH and Rust compile NOT run.

Reproduce in checkout:
  python3 research/wfp-ale/r215/r215_prior_modifier_negative.py --source research/wfp-ale/kernel-r19/kernel/src/redirect.rs
  node research/wfp-ale/r215/r215_prior_modifier_oracle.mjs

Trust chain: referenced process EPROCESS + FileObject (PsSetCreateProcessNotifyRoutineEx), PID/creation epoch/start key/canonical EXE versus ALE AppId (FwpmGetAppIdFromFileName0) -> ALE_CONNECT_REDIRECT V4/V6 plus previousVersion and redirect state (FwpsAcquireWritableLayerDataPointer0, FwpsQueryConnectionRedirectState0, FwpsApplyModifiedLayerData0) -> ALE_AUTH_CONNECT actual originalDestination and final WFP arbitration -> accepted-socket WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/_RECORDS) -> terminal CLAIM -> outbound SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS, trusted SSH and loss handling. Neither PID/5-tuple/time correlations nor BFE inventory constitute kernel proof.

Next permitted test: pinned standalone read-only Rust R201/R202 and passive R199 on admitted Windows 10 Pro x64, with source/binary SHA-256, native API codes and independent verifier. To resolve R215 requires a separately authorized and fully gated native classify trace with previousVersion (both families), initial/current destination, redirectRecord state, AUTH originalDestination, accepted receipt and CLAIM.

Other NO-GO: PID and 5-tuple reuse, process death/endpoint closure, sibling DIRECT, DNS/UDP/QUIC, compartments, reauthorization, WFP/BFE/SSH loss and physical SSH. No changes to other branches, PR #56, drivers, filters, NDISRD, runner, network, services, OS security, other repositories, automations/controllers or paid operations. No ProxiFyre AGPL, closed PR40, vendor binaries, or C++ WFP payload.

Official sources checked 2026-11-19:
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-_fwps_connect_request0
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
