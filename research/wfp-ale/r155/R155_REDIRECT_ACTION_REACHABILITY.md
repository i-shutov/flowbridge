# FlowBridge WFP/ALE R155 — self-redirect action ambiguity (offline)

Date: 2026-11-13. Research branch only: research/windows-wfp-ale-attribution-20261107.
Preflight research HEAD: 137eff7bd21bdb29b25ecce67559caa171febca3.
Main (read-only): 5b5afc2feeda2195f302380e615ba003d4906e09.

## Source-level finding

In pinned kernel-r19/policy_windows.rs, a Redirect rule is FWP_ACTION_CALLOUT_UNKNOWN, while a separate AttestOriginal/AUTH rule is FWP_ACTION_CALLOUT_TERMINATING. This distinction matters: UNKNOWN allows BLOCK/PERMIT/CONTINUE. In kernel/src/redirect.rs::classify, if FwpsQueryConnectionRedirectState0 returns FWPS_CONNECTION_REDIRECTED_BY_SELF or FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF, the function returns without explicitly assigning classifyOut.actionType or rights. It does so *before* FwpsAcquireWritableLayerDataPointer0 (whose documented actionType/rights reset is therefore irrelevant to these paths). As a consequence, the callback cannot independently establish a deterministic action for either state. It inherits the incoming action/rights. This is an auditable source-level gap, NOT a witnessed Windows block or leak.

Microsoft states that REDIRECTED_BY_SELF should return PERMIT/CONTINUE. PREVIOUSLY_REDIRECTED_BY_SELF must not be redirected again, with permit/block resolved at ALE_AUTH_CONNECT. The exact real input action and rights, callback reachability, prior filter arbitration and AUTH verdict remain unproven. Neither the synthetic input PERMIT nor an inherited CONTINUE establishes physical traffic behavior.

## Sources and APIs

Verified Git blobs at the exact research HEAD:
- research/wfp-ale/kernel-r19/kernel/src/redirect.rs = a093f049d162987981a957aac90db1014bc6ff09
- research/wfp-ale/kernel-r19/policy_windows.rs = acf60334320d970f58af3349ee75fbaa59826602

Official Microsoft docs:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_action0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_classify_out0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsacquirewritablelayerdatapointer0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection

## Executed and independently verified tests

Files: r155_terminating_action_negative.py (legacy filename, correctly models UNKNOWN, NOT TERMINATING), r155_independent.mjs, test_r155.py. The Python model requires either --source-root with exact Git blob pins or an explicit --model-only. The latter was used here; no local full R19 checkout was available. Source SHA and the two decisive code branches were separately inspected directly from GitHub. The negative source-drift test rejects an altered mock source. Node implements the matrix separately.

32 synthetic input combinations: IPv4/IPv6, SELF/PREVIOUS_SELF, four inherited action values, action-write right present/absent. 16 SELF and 16 PREVIOUS_SELF return without explicit action; inherited PERMIT/BLOCK/CONTINUE each 8; remaining 8 fall outside the documented action subset and are intentionally classified UNSPECIFIED rather than assigned a packet result. Python normal/-O/-OO match independent Node with zero disagreements. 11/11 adversarial unit tests PASS in each Python mode.

Row matrix SHA-256: 5f6e12df8c6a3b582ed50e57de2a75251f4369e269febd9db92e13b74d4d823f.

Run at repository root:
  python -B research/wfp-ale/r155/r155_terminating_action_negative.py --source-root research/wfp-ale/kernel-r19
  python -O -B research/wfp-ale/r155/r155_terminating_action_negative.py --source-root research/wfp-ale/kernel-r19
  node research/wfp-ale/r155/r155_independent.mjs
  python -B research/wfp-ale/r155/test_r155.py

## Trust boundary and next decisive gate

Kernel process-event FileObject/referenced PEPROCESS + PID/create epoch/PsGetProcessStartKey + canonical EXE/AppId -> actual ALE_CONNECT_REDIRECT/AUTH_CONNECT v4/v6 with typed compartment/transport-endpoint handle -> FwpsQueryConnectionRedirectState0 + input/output FWPS_CLASSIFY_OUT0 rights and action -> FWPS_CONNECT_REQUEST0 -> original accepted socket SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS -> one-use CLAIM -> SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS before physical SSH socket connect. An offline simulation does not authenticate that chain; neither ETW/PID nor 5-tuple correlation is a substitute. Also open: reauthorization, process death/PID reuse, same 5-tuple, sibling DIRECT, DNS/UDP/QUIC, BFE/SSH loss and IPv6 compartments.

Next allowed: run the source-pinned suite on exact checkout and inspect read-only existing WFP definitions. A native action/right/classify trace would require separately approved signed-driver, VNC/SYSTEM rescue, rollback, and VM gates. No such experiment executed.

NO-GO for PacketBound/G2/release; no no-DIRECT/leak-free assertion or historical G1 promotion. No mutation of main/release, beta, PR #56, other repo, driver, filter, runner, service, firewall, Defender, SecureBoot, MemoryIntegrity, network or automation.
