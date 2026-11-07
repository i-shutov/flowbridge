# R7 — AUTH_CONNECT observation lifetime and reauthorization (2026-11-07)

## Immutable baseline and scope

Only research branch `research/windows-wfp-ale-attribution-20261107`. Parent `aec64d6e48550a751cbb09cdc7f45dbdbe167a49`, main observed `5b5afc2feeda2195f302380e615ba003d4906e09`, beta last observed `c339df2e4d20edf1d11d45786581a68451a71929`. No other refs, runner, services, BFE filters, driver, callout, firewall, Defender, security policy, VNC, network experiment, billing or task schedule were altered.

## New counterexamples found by inspecting R5

1. **Pre-registration AUTH laundering.** R5 `observe_auth` accepted an AUTH tuple while no process or pending classify was registered; later `start_process` and `classify` could consume that stale observation and report `CONDITIONAL_MODEL_ONLY`. The event was not anchored to a process creation epoch or a pending ticket.
2. **Post-consumption endpoint replay.** R5 retained `auth[endpoint]` after a successful model `accept`. A second classify with a different ticket but the same PID/generation/endpoint could reuse that single AUTH observation for another `CONDITIONAL_MODEL_ONLY` decision. There was no endpoint retirement on accept.
3. **Simultaneously pending redirect tickets on one endpoint.** R5 admitted different tickets sharing the same endpoint, and one AUTH observation was sufficient for more than one model acceptance.
4. **Missing ALE reauthorization distinction.** Microsoft documents `FWP_CONDITION_FLAG_IS_REAUTHORIZE`: a policy/interface/pending-connection reauthorization at `ALE_AUTH_CONNECT` is not necessarily a newly established flow. The R5 `Authorization` data type had no reauthorization marker. These are **model counterexamples**, not observed Windows exploitation or driver evidence.

## Fix: conservative synthetic-event discipline

- Reject unattached AUTH observations as `UNBOUND_AUTH`; AUTH must match exactly one existing pending classify, a live referenced *assumed* owner, family, PID/generation, exact opaque AppId and image identity, and is stored against exactly one ticket.
- New `reauthorize` flag makes explicit reauthorization non-evidence (`REAUTHORIZE_NOT_NEW_PROOF`); a duplicate or conflicting initial AUTH poisons that endpoint and retires queued tickets.
- At accept, use the **classified endpoint**, not caller-supplied endpoint, to retrieve the bound observation, and retire it after one attempt (including failed receipt); never replay on another ticket.
- Poison the endpoint if a second pending classify attempts to use it or if the owner exits / an active component fails. Resource lifetime is deliberately conservative: endpoint numbers remain unusable in the current synthetic session because actual `ALE_ENDPOINT_CLOSURE` events are not available. This may refuse legitimate traffic; it is NOT a production algorithm.
- Updated R5 independent audit changes one formerly accepted orphan AUTH-only event to `UNBOUND_AUTH` and checks no observation survives.

## Verification

The exact locally tested model-prefix git blob is `b204cff9dc383d92e089fddb09f63d930f8df4b2`; its full GitHub blob with retained legacy R5 tests is `fa38e61cd1403887bc0a5280c792f23a98367977`. Independent R7 audit blob `5621ba84ca55ca02ef727665998ebc8554784011`, mutation-sensitivity blob `f881cda2dccc2f785f371fe15fed1f43df6cb981`. GitHub generated blob SHA agreed byte-for-byte with exact locally tested independent files.

Python 3.13.5 in isolated Linux: `python3 -m py_compile endpoint_witness_model.py auth_lifetime_audit.py` PASS; independent `auth_lifetime_audit.py` 80/80 deterministic sequences PASS (8 **model-only** conditional paths, 72 negative); re-run of the original R5 256-case Cartesian lifecycle specification on the patched model: 256/256 PASS; 5/5 deliberate unsafe mutants detected by an independent Python subprocess test (missing endpoint retirement, duplicate AUTH, reauthorization, overlapping endpoint tickets, wrong-image path acceptance). This is offline code/specification QA, NOT native Windows API validation. The full R5 legacy self-test source is retained unchanged in the model, but was not executed in this local executor in this R7 run. Rust was not compiled. R6 Windows AppId remains **BLOCKED/NOT EXECUTED**.

Reproduce on any Python 3.13 interpreter from repository root:
```sh
python3 research/wfp-ale/endpoint_witness_model.py
python3 research/wfp-ale/epoch_replay_audit.py
python3 research/wfp-ale/auth_lifetime_audit.py
python3 research/wfp-ale/mutation_sensitivity.py
```

## API boundary and GO/NO-GO

Microsoft says `FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE` may be present at both ALE layers, and `FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4/V6` can report endpoint closure; the uniqueness is scoped to endpoint lifetime. `FWP_CONDITION_FLAG_IS_REAUTHORIZE` identifies ALE reauthorization. These documents do **not** prove that an AUTH observation, even with a matching endpoint handle, belongs to the same original redirected socket/process epoch, or that endpoint numbers cannot be recycled. The candidate native chain still needs:

1. Kernel `ALE_CONNECT_REDIRECT_V4/V6` fixed AppId and valid process ID metadata, a *same-classify* pinned `EPROCESS` generation/creation time and canonical image provenance (not a deferred PID lookup).
2. Owned redirect via `FwpsQueryConnectionRedirectState0`, `FwpsAcquireWritableLayerDataPointer0`, `FWPS_CONNECT_REQUEST0.localRedirectContext/localRedirectHandle/localRedirectTargetPID`, `FwpsApplyModifiedLayerData0`.
3. Separate initial vs reauthorization `ALE_AUTH_CONNECT_V4/V6` event contract and explicit `ALE_ENDPOINT_CLOSURE_V4/V6` lifecycle, including IPv4/IPv6, endpoint collisions and reused 5-tuples.
4. Read `SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT` on the **actual accepted** TCP socket, then `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on the outbound socket before `connect`.
5. Independent, native OS-enforced selected-app DIRECT-denial checks under SSH/callout/filter loss, sibling DIRECT, UDP/QUIC/DNS/system resolver, dual-stack; proxy ingress refusal does not prove system fail-closed.

All native kernel-origin / accepted-socket linkage / NDISRD per-frame PacketBound / G2 / system no-DIRECT remain **NO-GO**. No historical G1 result is transferred from `dd1ab3c`.

## Next decisive experiment

Execute existing R6 read-only Rust + Win32 API AppId matrix on an authorized Windows x64 instance **without** adding a driver/filter or touching live system policy; it can establish AppId alias behavior only, never kernel ownership. Independently, a future kernel experiment would require a separate signed-driver/isolated VM, VNC/SYSTEM rescue, rollback and owner decision; do not launch it in this track.

Official sources consulted 2026-11-07:
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts-asynchronously
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ale-endpoint-lifetime-management
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
