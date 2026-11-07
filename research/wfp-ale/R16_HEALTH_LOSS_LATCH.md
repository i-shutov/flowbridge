# R16 — observed WFP/SSH loss must revoke the entire synthetic trust session

Research-only: `research/windows-wfp-ale-attribution-20261107`.
Baseline head: `f92d2e580b6c394b29e977d76466918fb6000cc7`;
observed `main`: `5b5afc2feeda2195f302380e615ba003d4906e09`.
No beta, PR #56, main or release edits. No runner, driver, callout,
WFP filter, socket/network, service, Defender, firewall, VNC or automation changes.

## Concrete R15 synthetic counterexample

The prior `TrustGate::decide` in `trust_contract.rs` inspected `Health`
only for the current request. It left an unconsumed ticket live after
a failed health check. With the same `TrustGate` instance:

1. Full matching, assumed-kernel `Capture` and `Accepted`; filter/callout
   healthy but SSH unavailable -> `RejectOwnedIngress`.
2. The same capture and ticket with SSH reported ready again ->
   `RouteOnOwnedProxySocket` under the old implementation.
3. Analogously, filter/callout loss -> `UnprotectedByWfp`;
   a later healthy snapshot -> the *same* model admission.
4. An entirely fresh ticket was also admitted in the old session after
   the observed outage. This defeats the intended fail-closed *model*
   lifecycle even without any PID or endpoint reuse.

This is **not a demonstrated kernel exploit**. `Health` remains an untrusted
hypothetical input, and no actual external flow has been intercepted.

## Patch / invariant

`TrustGate` now records two monotonic, session-local flags:

- `observed_wfp_loss` is latched on either missing owned filter
  enforcement or missing callout, with `UnprotectedByWfp` taking priority
  over every other state even after a later healthy observation.
- `observed_ssh_loss` is latched when SSH is not ready and returns
  `RejectOwnedIngress` when WFP has not been observed missing.
- No original or new ticket can receive the synthetic route verdict
  again from that gate. A **new, independently authorized session and new
  classify/redirect proof** would be required for eventual real restart;
  creating a new Rust object is not an OS-enforced recovery protocol.

This patch does not infer that a brief WFP outage was observed.
It models only loss states that `decide` actually receives, and says
**nothing** about protection of sibling DIRECT, DNS, UDP/QUIC, IPv6,
connections created while the filter is gone, or failure of a real proxy.

## Deterministic independent QA

- `r16_health_latch_audit.py` is an independently written Python
  temporal oracle, not a transliteration of the Rust source.
- Seven tests: SSH recovery, filter/callout recovery, loss escalation,
  all eight health combinations, 4096 exhaustive four-observation histories,
  explicit detection of the old stateless mutant, and a Rust-source
  structure/unsafe-surface check when the checkout is available.
- Local Python 3.13.5: 6 PASS, 1 SKIP (Rust checkout not mounted in
  the isolated local executor); 4096/4096 reference histories PASS.
  The old stateless mutant is rejected by the recovery counterexamples.
- Three `#[test]` Rust regressions were added for the real Rust state
  machine, raising the source test count from 17 to 20. **Rust tests and
  rustc compilation were not executed in this environment** (no Rust
  toolchain, and touching CI/runner is outside this run's permission).
- The independent source-surface check is included so a future local
  `python3 -m unittest r16_health_latch_audit` in this directory also
  checks the checked-out Rust source.

Reproduction in an authorized local checkout:

```sh
python3 -m unittest discover -s research/wfp-ale -p r16_health_latch_audit.py -v
rustc --edition=2021 --test research/wfp-ale/trust_contract.rs -o /tmp/wfp-trust-model-r16
/tmp/wfp-trust-model-r16
```

No tests issue or modify operating-system WFP state.

## Documented API and boundary

`FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6` and
`FWPS_METADATA_FIELD_PROCESS_ID` (when present) plus fixed
`ALE_APP_ID` are candidates for a same-classify kernel observation;
`PsLookupProcessByProcessId` / `PsGetProcessCreateTimeQuadPart`
require a legitimately referenced `EPROCESS`, safe IRQL and lifetime.
`FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6` includes possible reauthorization,
not an automatically new flow. `FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4/V6`
needs proper per-endpoint cleanup and TCP/UDP lifetime differentiation.

An owned redirect context `FWPS_CONNECT_REQUEST0` and
`FwpsQueryConnectionRedirectState0` must be linked through Windows WFP
records obtained via `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS)`
and context on the actual accepted socket, followed by
`SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on the outbound TCP socket.
None of those kernel/accepted-socket steps has been proved by R16.
User-mode `FwpmGetAppIdFromFileName0` supplies path-oriented AppId bytes,
**not** a pinned connection owner or canonical immutable EXE identity.

Microsoft primary documentation:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ale-endpoint-lifetime-management
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records

**GO/NO-GO:** model-only monotonic revocation is GO for offline
regression; kernel-origin owner, transient outage detection, dual-stack
no-DIRECT and G2/PacketBound remain **NO-GO**. Historical G1 on
`dd1ab3c` is not transferred. `release_accepted=false`.

**Next decisive noninvasive experiment:** compile/run all 20 pure-Rust
model tests in a permitted local Rust environment (without triggering
Actions/runner), including the loss/recovery counterexamples. This cannot
prove kernel-origin capture. Any later real ALE-to-accepted-socket chain
requires separate owner approval and all driver/VNC/SYSTEM rescue/rollback
gates; no such experiment is authorized here.
