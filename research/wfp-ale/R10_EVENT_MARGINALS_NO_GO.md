# R10 — WFP AppId: marginals are NOT same-event proof
2026-11-07. Scope: only branch research/windows-wfp-ale-attribution-20261107.
Baseline research: 0e7262de074b0663c8ad4e9d4db1f4bd811bc123.
Baseline main: 5b5afc2feeda2195f302380e615ba003d4906e09.
Beta: c339df2e4d20edf1d11d45786581a68451a71929 — read only.

## Discovery

Real historical Windows Actions run 42339966586, Windows job 128305303067,
test merge ab6ed5273db6e9741915a96c74809433af125870,
artifact 13560942739, outer archive SHA256
95560460776b802da5ccd1a608495609715144a59a7fac5fbfaed331542faa92.
Exact redacted diagnostic SHA256
ad1341b53b8cac676394877a1b5f28cf6e42ebd527ba9fdb89d39e460ce17039.

The historical Rust function event_identity_probe in
crates/flowbridge-capture/src/windows_wfp_dynamic_lab.rs, lines 485–625,
collects separate marginal counters of FWPM_NET_EVENT0 AppId and native
file-handle path matches. It does NOT produce one-event conjunctions.

The authenticated diagnostic shows (in BOTH loopback and same-host IPv4):
exact filter CLASSIFY_DROP events=3, selected native-handle-path matches=1,
selected handle-AppId matches=1, other native-path matches=1, other
handle-AppId matches=1, original selected AppId matches=0, original other
AppId matches=0, Python comparator AppId matches=1, original-input
unresolved events=2. It does NOT prove one event satisfied both
handle-derived predicates.

For two sets in an N-event universe with counts a,b, the intersection
is bounded by max(0,a+b-N) <= joint <= min(a,b).
At N=3, a=b=1, joint is 0..1 per comparator, 0..2 total. The number of
same-event pairings *proved from the archived marginals* is zero, not two.
Independent adversarial assignments with identical marginals but
different conjunctions establish the gap. This CORRECTS the earlier R9
prose that overclaimed event co-occurrence. It does not deny the real
Windows filter drops or infer a Windows bug. Root cause of the
input-AppId vs handle-AppId mismatch remains undetermined.

## Code and independently verified QA

Added event_marginal_bounds.py, an offline, read-only, SHA-pinned,
standard-library Python verifier. It checks exact provenance,
redacted source digest, input bounds, duplicate JSON keys, strict
integer counters, complete original-source partition, filter
verification, negative security flags and same-host IPv4 scope.
Output contains only counters, mathematical bounds and explicit
NO-GO flags, never raw paths, AppIds, PIDs, filter IDs or endpoints.

The expanded local independent test suite passed 21/21 tests. Its
oracle exhaustively enumerated 139 combinations of two subsets with
universe sizes 1..6, independently confirming the closed-form bounds.
Six deliberately unsafe mutants were detected (false intersection,
lost forced intersection, disabled partition, bypassed SHA,
wrongly promoted event authority, forged joint proof).
Actual pinned historical diagnostic: offline CLI PASS.
Python py_compile PASS. No rustc or native Windows executor available.
The compact repository test suite reproduces the core oracle,
counterexamples and fail-closed negative checks.

To reproduce with the historical extracted diagnostic JSON:

    python3 research/wfp-ale/event_marginal_bounds.py /path/to/windows-wfp-dynamic-lifecycle.json
    python3 -m unittest discover -s research/wfp-ale -p test_event_marginal_bounds.py -v

## Trust chain and remaining NO-GO

1. FWPM_NET_EVENT_HEADER0.appId plus exact CLASSIFY_DROP.filterId
   proves only historical event/filter correlation. No process epoch
   or original socket ownership. NO-GO.
2. FwpmGetAppIdFromFileName0 / FwpmFreeMemory0: read-only file-name
   AppId lookup. Input and handle-derived AppId mismatch unresolved;
   R8 same-basename/different-directory/alias matrix NOT RUN. NO-GO.
3. FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6:
   FWPS_METADATA_FIELD_PROCESS_ID and original ALE_APP_ID / ORIGINAL_APP_ID
   must be tied to one original kernel classify, with referenced EPROCESS
   and PsGetProcessCreateTimeQuadPart from THAT pinned object. Deferred
   PID lookups and matching 5-tuples are insufficient. NO-GO.
4. FwpsQueryConnectionRedirectState0 anti-loop states:
   NOT_REDIRECTED may proceed, REDIRECTED_BY_SELF must not redirect
   again, PREVIOUSLY_REDIRECTED_BY_SELF MUST NOT redirect, OTHER
   must be handled explicitly. For a real driver, apply
   FwpsAcquireClassifyHandle0, FwpsAcquireWritableLayerDataPointer0,
   FWPS_CONNECT_REQUEST0 and FwpsApplyModifiedLayerData0. NOT EXECUTED.
5. ALE_AUTH_CONNECT_V4/V6 reauthorization flag
   FWP_CONDITION_FLAG_IS_REAUTHORIZE is not a new connection;
   ALE_ENDPOINT_CLOSURE_V4/V6 and the transport endpoint handle delimit
   lifetime. R7 handles process death, PID reuse, re-used 5-tuple and
   endpoint replay in synthetic models only. MODEL ONLY.
6. Accepted TCP socket: WSAIoctl SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS
   and SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT on ACTUAL accepted
   socket; SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS on outbound socket
   BEFORE connect. UDP record transport uses WSARecvMsg/WSASendMsg.
   No borrowed/guessed receipt accepted. NO-GO.
7. OS enforcement of sibling DIRECT, IPv4/IPv6, DNS/UDP/QUIC,
   WFP/SSH failure, crash survival and independent no-DIRECT/leak
   observations unproved. Proxy ingress refusal is insufficient. NO-GO.
8. Independent NDISRD per-frame PacketBound is not inferred from ALE
   or WFP event histograms. NO-GO.

Next decisive, non-driver experiment: execute existing R8
appid_native_matrix.py --native-only on an already authorized Windows x64
Python executor. It does not install filters or drivers and can check
alias path behavior, but cannot prove kernel owner. Windows execution
channel is currently unavailable. Future controlled per-event WFP
drop diagnostics require a separate owner decision because creating
filters is prohibited in this R&D. Do not rerun historical workflows
with filter operations as a workaround.

No main/release, beta/PR #56, runner, service, network, WFP filter,
driver, NDISRD, VNC, firewall, Defender, security policy, other repo,
automation state or schedule was altered. Historical G1 dd1ab3c
cannot be transferred; PacketBound/G2 and no-DIRECT remain NO-GO.
SOCKS-only beta is a separate acceptance track.

## Official Microsoft APIs, verified 2026-11-07
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_net_event_header0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_net_event_classify_drop1
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetprocesscreatetimequadpart
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ale-endpoint-lifetime-management
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records
