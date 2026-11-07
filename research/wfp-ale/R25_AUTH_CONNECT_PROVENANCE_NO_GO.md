# R25 — AUTH_CONNECT provenance is not established by R24 BFE rules

2026-11-07; **research branch only**, starting from
`80e6016b7cae2918ca465948572ce686e0807756`.
Main observed `5b5afc2feeda2195f302380e615ba003d4906e09`.

## Source-verified architectural NO-GO

R24 has 2 `ALE_CONNECT_REDIRECT_V4/V6` native callouts but **no**
`FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6` native classifyFn. Its 4 AUTH_CONNECT
filters are static `FWP_ACTION_BLOCK` conditions: selected AppId and TCP and
(remote IP != loopback OR remote port != broker port).

The filters cannot distinguish, for IPv4 **or** IPv6, a genuine connection
redirected to loopback broker from a direct connection by the *same* selected
executable to that port. Their match inputs are identical; redirected metadata,
original destination, process epoch/generation and ticket do not occur in the
filter conditions. A simulated flow with reused PID/5-tuple is likewise not
distinguished by these static fields. This is a mathematically sufficient
indistinguishability counterexample, **not observed traffic**.

Crucial caveat: an own-filter result of `NO_OWN_BLOCK_MATCH` is **not**
a Windows PERMIT. Other filters may apply. The broker's separate accepted-socket
`SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT` and one-shot kernel CLAIM
are still active in the R24 implementation and can reject ordinary ingress.
No physical bypass, leak or PacketBound result is asserted.

Microsoft's connect-redirection documentation advises registering at
`ALE_AUTH_CONNECT_V4/V6` to check
`FWP_CONDITION_FLAG_IS_CONNECTION_REDIRECTED`,
`FWPS_METADATA_FIELD_LOCAL_REDIRECT_TARGET_PID` and
`FWPS_METADATA_FIELD_ORIGINAL_DESTINATION`. The current R24 static filters
cannot make that per-connection check. Nor would it prove EPROCESS epoch unless
independently associated with the original kernel classification.

## Evidence and tests

Read directly from GitHub at the stated source HEAD: `policy_plan.rs`,
`policy_windows.rs`, `kernel/src/lib.rs`, `kernel/src/redirect.rs`,
`broker_windows.rs`. Exact Git blobs pinned by the test source:
`2aa7468f`, `b487ce24`, `aff4be74`, `5b09b668`, `f315d2cf`.
The connector source audit confirmed 6 rules, 2 redirect-only callouts,
the two static AUTH layers and lack of kernel AUTH classify.

Executed offline: independent 1024-world Boolean reference oracle,
62 distinguishable histories that the static filters cannot distinguish,
and 5/5 executable Python regression methods PASS (plus an expanded independent
13/13 suite run locally). An intentionally incorrect AND-rather-than-OR
block mutant is detected. The included source-pin check requires an exact
checkout; it has **not run locally**, because no exact checkout is mounted.
Native WFP, kernel callouts, real OS arbitration, DNS/UDP/QUIC, IPv6 routing
and live PID reuse have **not run**.

Run from an exact research checkout:

```sh
python3 research/wfp-ale/r25_auth_gate_negative.py
```

## Decision

**AUTH-origin proof / G2 / PacketBound / system no-DIRECT: NO-GO.**
A kernel AUTH classify receipt linked to the original process, actual redirect
context and accepted socket would be necessary for any later proof, as would
independent system egress observations and WFP/SSH-loss evidence. User-mode
read-only inventory cannot supply that kernel receipt. Driver creation,
modification, load/installation, WFP filter modifications, signed-driver work,
VNC, runner and network experiments remain forbidden. No changes to main,
release, beta or PR #56; no historical G1 promotion.

Next decision: whether to *separately authorize* a gated native AUTH callback
proof at all. Until then, the useful safe step is to execute this exact pinned
source check on a local, non-runner checkout; a changed source requires STOP
and re-audit, never silent adaptation.

Official: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v4_
https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
