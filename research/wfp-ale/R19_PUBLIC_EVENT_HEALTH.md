# R19 — observed health at AUTH/start event boundaries (offline research)

2026-11-07. Branch: `research/windows-wfp-ale-attribution-20261107`.
Parent: `d48acf340dafbdf9dbb2861c265dd505bd9a49ba`.
Read-only base main: `5b5afc2feeda2195f302380e615ba003d4906e09`.
No changes to main, beta, PR #56, Windows services, runner, schedules, network, firewall, drivers or filters.

## Counterexample (previous R18 code)

R18's `ResearchGate._observe_health()` is invoked from `classify` and
`accept`, but not from the public `observe_auth`, `start_process` or
`stop_process`.
The following six independent (IPv4/IPv6 × three loss flags) synthetic
traces all had the same effect **before** this patch:

1. Register an assumed referenced process; classify a candidate while healthy.
2. Set one of `active_filter`, `active_callout`, `ssh_ready` false.
3. Receive `observe_auth` while that health flag is false. It returned
   `SUPPORTING_OBSERVATION_ONLY` despite the sampled-event failure.
4. Restore the flag to true before `accept`.
5. `accept` produced `CONDITIONAL_MODEL_ONLY` based on old AUTH/ticket.

This is a real deterministic *model* counterexample, not a Windows leak.
A separate trace registered a new owner through `start_process` while
health was false and could then proceed after recovery. A third trace
stopped an unrelated PID during the outage and retained the original
pending ticket despite the intervening observed event.

## Patch, scope and non-goals

The `start_process` and `observe_auth` entrypoints first invoke the existing monotonic
`_observe_health` state machine. They return `UNPROTECTED` after WFP
filter/callout loss or `REJECT_INGRESS` after SSH loss, without minting
AUTH evidence or registering the owner. Pending tickets and AUTH are retired
by the already-existing health latch. There is **no** reset operation.

`classify` and `accept` already sampled health (R18). A second counterexample
was observed: `stop_process` for an unrelated live PID, while WFP or SSH was
down, did not sample health. Pending tickets from another PID survived the
revocation event and could be conditionally accepted after recovery.
`stop_process` now calls `_observe_health()` but **continues** normal owner
cleanup and retains its revocation-result API. Every public gate method
that can observe live session state now latches outages. No actual Windows
loss monitor is implemented. The model still cannot sense a loss between *all* observed
events, and user-mode snapshots cannot establish OS-enforced no-DIRECT.

## Executed tests and independent verification

- Before patch, a reduced R18 method mirror reproduced
  `SUPPORTING_OBSERVATION_ONLY -> CONDITIONAL_MODEL_ONLY` in all 6
  IPv4/IPv6×health-failure cases. Local R19 test suite failed with
  10 assertions across the AUTH/start tests.
- With the public-event patch applied to the same mirror, 7/7 unittest
  methods PASS; independent 4096/4096 four-observation histories PASS.
  Three stateless mutant families (AUTH, start and unrelated PID exit) were explicitly rejected.
- The new tests in this commit **import the actual checkout model**; no
  skip/fallback to a mirror occurs in a real checkout.
- **Limit:** this executor had no full repository checkout or native Windows
  environment. The exact GitHub-source runtime regression has NOT been
  executed here. Mirror PASS and static source checks must not be
  misreported as a full-source PASS. Rust compilation and native WFP runs
  were not performed.

To run in a permitted local checkout without touching CI:

```sh
python3 -m unittest discover -s research/wfp-ale -p test_r19_public_event_health.py -v
python3 -m unittest discover -s research/wfp-ale -p r18_loss_epoch_regressions.py -v
python3 research/wfp-ale/endpoint_witness_model.py
```

## WFP chain (must remain NO-GO until independently proven)

| Required link | Official Windows API | Evidence status |
|---|---|---|
| Selected canonical EXE | `FwpmGetAppIdFromFileName0`, `FWPM_CONDITION_ALE_APP_ID`, exact file object | AppId path ≠ pinned canonical EXE; NO-GO |
| Same original process | `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6`; `FWPS_METADATA_FIELD_PROCESS_ID` only when present; referenced `PsLookupProcessByProcessId` `EPROCESS`, `PsGetProcessCreateTimeQuadPart` at legal IRQL | No same-event kernel reference/epoch; NO-GO |
| Endpoint and AUTH | `FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6`, `FWP_CONDITION_FLAG_IS_REAUTHORIZE`, `ALE_ENDPOINT_CLOSURE_V4/V6` | Model-only; no kernel origin/lifetime proof |
| Redirect receipt | `FwpsQueryConnectionRedirectState0`, `FWPS_CONNECT_REQUEST0`, `SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT` on actual accepted socket, `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` before outbound connect | R17 user-mode collector not Windows-native validated or bound to originating owner; NO-GO |
| Bypass and loss | Separate ALE_AUTH_CONNECT enforcement for selected sibling DIRECT, DNS UDP/QUIC, IPv4/IPv6, WFP/SSH loss; OS-level kill switch | No native no-DIRECT evidence; NO-GO |
| NDISRD packet → process owner | Kernel-provided per-frame owner witness, not PID/5-tuple/time correlation | Missing; PacketBound/G2 NO-GO |

Primary Microsoft sources:
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pslookupprocessbyprocessid
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetprocesscreatetimequadpart

**Next decisive permitted experiment:** exact-source offline R18+R19 regression
on a local checkout, followed by native user-mode R17 endpoint/AppId query
on an authorized Windows x64 executor. Neither proves originating process;
driver/callout installation still requires separate driver/VNC/SYSTEM rescue,
rollback and security gates. `release_accepted=false`.
