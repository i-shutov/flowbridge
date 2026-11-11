# FlowBridge WFP/ALE R114 — strict BFE JSONL transcript integrity (NO-GO)

Date: 2026-11-11. Repository: `i-shutov/flowbridge`.
Branch (ONLY): `research/windows-wfp-ale-attribution-20261107`.
Parent research HEAD at intake: `e24f3c2d866e9374e8873ecdab325dd7b06049ee`.
Read-only main at intake: `5b5afc2feeda2195f302380e615ba003d4906e09`.

## Reproducible R113 mismatch / new hardening

The R113 Windows PowerShell 5.1 harness (`research/wfp-ale/r112/R112_WINDOWS_NATIVE_READONLY_CHECK.ps1`, Git blob `6cab4c1e8aee20506bb3ba9ae17cf348ec19b7df`) validates a four-row BFE diagnostic plus one terminal row. But it **does not check the terminal `visible_filters` counter at all**, while the R103 Rust implementation increments `counts.visible` for each enumerated `FWPM_FILTER0` (including four mandatory owned baselines). A transcript claiming a visible competitor and `visible_filters=4` is physically inconsistent with that specific Rust counting algorithm, yet the R113 Python oracle accepts it as a valid exit-3 diagnostic. This is an evidence parser gap, not an observed WFP leak or a proof of hostile input to the real Rust binary.

Also R113 accepts any `[ValueType]` for the counters: the .NET `System.ValueType` category includes numeric floating-point and Boolean types, unlike the `u64` counters emitted by Rust. The terminal Booleans and per-rule `match_and_runtime_action_unverified` used PowerShell comparison (`-cne`) with no explicit `[bool]` gate; PowerShell coercion could hide type mismatches. **No PowerShell 5.1 runtime execution was performed here**, so these are source/type-contract findings, not empirical claims about every `ConvertFrom-Json` conversion.

### Precise R114 change

1. Four labelled rule rows; each flag must be genuine JSON Boolean (`-is [bool]`) and each counter must deserialize as `[int]` or `[long]`, with `0 <= count <= 131072`. Reject `true`, `0.5`, negative values and overbudget counters; no generic `[ValueType]`.
2. Require the terminal `visible_filters` to be an integer in `[4,131072]` (the Rust `MAX_VISIBLE`), plus the necessary cardinality invariant `sum(four rules x four count buckets) <= visible_filters - 4`. Each filter belongs to exactly one of the four distinct ALE layers, and the four owned keyed baselines are all required for a diagnostic success. This is only a **necessary** consistency test: other visible filters may be in other layers or sublayers.
3. Require genuine JSON Booleans for each terminal proof boundary flag. Keep `kernel_proof=false`, `no_direct_proof=false`, `single_enum_snapshot=true`, `acl_hidden_filters_possible=true` and the existing fail-closed exit-code mapping `2/3/4`.
4. Leave the exact R103 Rust source and its Git blob gate (`49506ca07145c18947a0845f2a1a63b3de1f54ec`) unchanged. No Windows system or infrastructure operations.

### Deterministic independent negative tests

From repository root:

```bash
python3 research/wfp-ale/r114/r114_bfe_transcript_negative.py
python3 research/wfp-ale/r114/r114_bfe_transcript_negative.py --matrix
node research/wfp-ale/r114/r114_bfe_transcript_independent.mjs
```

Seven Python unittests, plus **1800 scenarios** checked by separate Python and Node implementations: 1796 unavailable/failed (exit 2), 3 visible-candidate diagnostics (exit 3), 1 no-visible-candidate diagnostic (exit 4). Both serialize the same canonical scenario rows with SHA-256:

`8b2a04994969f8daaf1e9ad2581a86e6f6232637fa1eb0fed37755d47a7da443`

One test imports the original committed R113 Python verdict implementation and proves it **accepts** a concrete inconsistent cardinality witness (`visible_higher=1`, `visible_filters=4`, exit 3), while R114 rejects it. A source contract test checks the actual edited `.ps1` for the strict gates. These tests are *off-host static/model tests*, NOT PowerShell runtime validation or native Rust tests. The Python/Node cross-language agreement is not independent Windows API evidence.

## Trust chain, dependencies and explicit proof gaps

| Trust boundary | Candidate documented API | Evidence required for GO | Current R114 conclusion |
| --- | --- | --- | --- |
| Exact selected program | `FwpmGetAppIdFromFileName0`, WFP `FWPM_CONDITION_ALE_APP_ID`, image-section process identity; user-mode `QueryFullProcessImageNameW` is only contemporaneous | Match original kernel AppId to canonical pinned executable, not basename or unrelated PID | NO-GO |
| Origin and lifecycle | `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6`, `FWPS_METADATA_FIELD_PROCESS_ID` when present; `PsLookupProcessByProcessId`, `PsGetProcessCreateTimeQuadPart` only at a proven IRQL/lifetime | Same classify-bound original PID, process epoch and endpoint, process exit/PID reuse accounted for | NO-GO |
| Redirect and handoff | `FwpsQueryConnectionRedirectState0`, `FwpsAcquireWritableLayerDataPointer0`, `FwpsApplyModifiedLayerData0`, `FWPS_CONNECT_REQUEST0` | Immutable, bounded ticket; redirect state and proxy handoff bound to one classified attempt, no self-loop/reused 5-tuple equivalence | NO-GO |
| Socket evidence | `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT)` on the **actual accepted socket**, `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on each outbound socket | Original owner and ticket bound to receipt, no impersonated/replayed context; outbound chain validated | NO-GO |
| Continuous enforcement | `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` with real authorized classify and independent deny policy | Selected-app sibling DIRECT blocked during startup, SSH failure, BFE loss, filter removal and revocation | NO-GO |
| Protocol coverage | WFP per-family ALE data and physical captures under future authorization | IPv4/IPv6 incl. source-bound/compartment/scope; UDP, DNS, QUIC, resolver service attribution; reauth & PID/5-tuple churn | NO-GO |
| **Read-only management observation** | `FwpmEngineOpen0` → `FwpmFilterCreateEnumHandle0` → `FwpmFilterEnum0` → `FwpmFreeMemory0` → `FwpmEngineClose0` | Accurately describe one ACL-limited snapshot and its non-claims; never imply live callback proof | **R114 improves off-host evidence integrity only** |

The managed BFE enumerator returns an ACL-dependent snapshot at its creation, not an atomic per-flow verdict, not proof that the kernel callout is installed/executing, and not an exclusion of higher-priority other sublayers. Even with perfect transcript parsing, owner identity, sibling DIRECT, process death, tuple reuse, DNS/UDP and SSH/WFP loss cannot be certified. G1 `dd1ab3c` is not transferred; PacketBound/G2, no-DIRECT, leak-free and beta/release remain NO-GO.

Official Microsoft sources:
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilterenum0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
- https://learn.microsoft.com/en-us/windows/win32/api/fwptypes/ns-fwptypes-fwp_value0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_condition0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records

## Next decisive permitted experiment

On an **already-authorized Windows x64 host with pre-existing Rust + SDK**, obtain the exact R114 commit and run the PowerShell 5.1 harness: metadata-only, then synthetic ABI tests, optionally read-only BFE enumeration. Collect Windows build, `rustc -vV`, exact source blob SHA, binary SHA-256, test stdout, JSONL, process exit code and `R112_WINDOWS_EVIDENCE.json`. Additionally execute PS5.1-only parser probes with a synthetic inconsistent-cardinality JSONL fixture *without* running the BFE or launching network activity. Verify all evidence independently; nonzero 3/4 remain UNKNOWN and do not confer policy proof. Owner authorization is additionally required for any future actual kernel/driver, WFP filter, VNC or network trials.

Explicitly untouched: `main`, releases, beta `integration/windows-rust-capture-agent-20261031`, PR #56, runner/CI, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, services, system/network, other repos and automation schedules/states. No kernel driver/callout/filter/NDISRD, ProxiFyre AGPL, PR40, vendor binaries, C++ WFP payload or paid operations.
