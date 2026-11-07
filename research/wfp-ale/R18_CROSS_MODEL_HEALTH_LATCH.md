# R18 — close the model-only R7 ↔ R16 observed-health recovery gap

Date: 2026-11-07. Scope: **only** `research/windows-wfp-ale-attribution-20261107`.
Parent observed: `dd1690a8cc1b30b51a002a655abe41f37533e0b2`.
Main observed: `5b5afc2feeda2195f302380e615ba003d4906e09`.

**This is a repair of an offline synthetic contract, not kernel enforcement,
PacketBound, G2 PASS, release acceptance, or a no-DIRECT claim.**
No driver/callout/WFP filter, BFE/runner, network, service, VNC, firewall,
Defender, SecureBoot, MemoryIntegrity, automation or beta/PR #56 change.

## The reproducible cross-model inconsistency

The R16 Rust `TrustGate` already latched *observed* WFP and SSH loss for
the full model session. But R7/R13 `endpoint_witness_model.py` did not:
`ResearchGate.loss('ssh')` retired pending tickets but never stored an
irrevocable session-health state. After optimistic reassignment
`gate.ssh_ready = True`, a **fresh** redirect ticket from the same
selected process could be classified and eventually produce
`CONDITIONAL_MODEL_ONLY` with synthetic supporting AUTH and receipt.
The same was possible for filter/callout loss after resetting the
`active_filter`/`active_callout` booleans.

Moreover, a failure observed only by an explicit health snapshot
(`gate.active_filter = False` before `classify` or `accept`) returned
`UNPROTECTED` for that request but could allow a fresh ticket after the
boolean became true again. Existing R13 reauthorization revocation and
endpoint poisoning do **not** close this cross-ticket, same-session gap.

These examples are **not kernel exploits**. Health fields, process owner,
ticket and receipt remain hypothetical user-mode data. They only expose a
fault in our desired temporal contract.

## Concrete modification

The ResearchGate instance now records `observed_wfp_loss` and
`observed_ssh_loss` monotonically. Both `classify` and `accept` call
`_observe_health` before processing a ticket. The first newly observed
loss retires every pending endpoint and AUTH observation. A later
apparently healthy sample cannot clear the latch. WFP loss dominates SSH
loss (`UNPROTECTED` vs `REJECT_INGRESS`). Explicit `loss` uses the
same monotonic state and retires tickets as before. An unknown event
does not poison the gate.

This is deliberately conservative: it can deny valid new connections
until a **new, independently authorized** trust session. Constructing
another Python gate alone is *not* an OS-recognized restart protocol.
The model does not detect brief outages that occur **between** health
observations. In particular, service-side reject cannot block a selected
process's sibling DIRECT, UDP, QUIC, DNS or IPv6 bypass paths.

## Independent negative QA and exact limits

- `r18_loss_epoch_regressions.py`: 7 behavioral tests to execute
  against the actual in-repository `ResearchGate`: healthy IPv4/IPv6
  positive controls, explicit SSH/WFP/callout losses followed by manual
  optimistic health recovery, snapshot-only losses at classify and
  accept, priority escalation, unknown event and fresh-model object.
- The same file has two independent oracle tests, including exhaustive
  4096 four-sample health histories and a positive witness of the
  **pre-R18 stateless mutant**.
- On the available Linux/Python 3.13.5 executor the actual GitHub
  `endpoint_witness_model.py` source was not locally mounted. Exact
  repository-model runtime tests therefore were **NOT run here**:
  2 independent oracle tests PASS, 7 repository tests SKIP.
- A reduced and explicitly labelled **method mirror**, used only for
  inspecting these health transitions, ran 9/9 PASS locally. This is
  NOT an execution of the complete GitHub model; it has simplified
  start_process, AUTH, and receipt paths.
- R16's source Rust model and R17's native Rust module were not
  compiled; no native Windows runtime was exercised in this cycle.
  Static anchor and repository-surface checks are separate from tests.

To obtain an exact-source acceptance signal on an authorized **local**
checkout without launching any CI or Windows network activity:

```sh
python3 -m unittest discover -s research/wfp-ale -p r18_loss_epoch_regressions.py -v
python3 research/wfp-ale/endpoint_witness_model.py
python3 -m unittest discover -s research/wfp-ale -p r16_health_latch_audit.py -v
```

If any test fails, the research model remains rejected; do not promote
the local model through optimistic logs or a substituted fixture.

## WFP trust boundary, current GO/NO-GO

| Required evidence | Windows API / reference | Status |
|---|---|---|
| Selected canonical executable | `FwpmGetAppIdFromFileName0`, opaque `ALE_APP_ID`; file object/namespace handling | Path-level evidence only; immutable canonical EXE NO-GO |
| Kernel-origin owner from a single classify | `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6`, validated `FWPS_METADATA_FIELD_PROCESS_ID` | Not obtained |
| Same original process instance | `PsLookupProcessByProcessId` with legal IRQL/reference, `PsGetProcessCreateTimeQuadPart` or `PsGetProcessStartKey` on the correct `EPROCESS` | No lawful same-event proof |
| Initial AUTH / reauthorization / closure | `FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6`, reauthorize flags, `FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4/V6` | Model-only, not executed |
| Redirect context through accepted socket | `FwpsQueryConnectionRedirectState0`, `FWPS_CONNECT_REQUEST0`, `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT)` | Socket-local R17 collector written, no native R17 run or origin binding |
| Outbound chain, loop protection | `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` **before** outbound connect | Not executed |
| PID reuse, reused 5-tuple, other EXE same basename | Referenced kernel owner + connection-specific context | Synthetic negative tests only |
| Sibling DIRECT, DNS/UDP/QUIC, IPv4/IPv6, WFP/SSH outages | Independently enforced OS-level fail-closed, native adversarial tests | NO-GO |

R16's latching criterion is **only observed health loss**. R18
brings the older Python candidate model into alignment with it, and
does not add an independent kernel signal or bridge NDISRD bytes to WFP
ownership. System no-DIRECT and PacketBound/G2 remain NO-GO.

Microsoft primary references checked:
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ale-endpoint-lifetime-management
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/nf-fwpsu-fwpsaleendpointgetbyid0

**Next decisive non-invasive experiment:** run the **actual checked-out
source** regression and complete `endpoint_witness_model.py` assertions
offline on an authorized local Python environment; run R16 Rust tests in
a locally permitted Rust installation without touching runner/Actions.
These only validate the contract. A native original-EXE ALE redirect
with OS fail-closed remains separately approval- and driver-gated.

No G1 acceptance transfers from `dd1ab3c`. `release_accepted=false`.
