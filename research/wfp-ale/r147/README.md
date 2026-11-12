# R147 — executable offline regression gate, not WFP acceptance

Date: 2026-11-12. Repository: `i-shutov/flowbridge`.
Only branch: `research/windows-wfp-ale-attribution-20261107`.
Development base: `ce046f20289da250c7eccde7410e5d216219b1ff` (R146).
Observed main: `5b5afc2feeda2195f302380e615ba003d4906e09`.
Status: **OFFLINE_QA_PASS; native WFP / PacketBound / G2 / release NO-GO**.

## Implemented and actually tested

R147 closes the previously unexecuted complete R143/R144 regression and adds a
bounded artifact-verification CLI, an independent Node-generated black-box
campaign against the real Python validator, and a source-pinned test launcher.
These are working offline QA tools, not another simulated Windows callout.

### Reproduced false-green defect

Original R144 Git blob `10bc53909c30f6620a849028201d9ee5366d159e` used
`assert` for its acceptance checks and printed a constant success summary.
With an isolated in-memory mutation replacing `validate_blueprint` by a no-op:

| Original R144 invocation | Exit | Corrupt artifacts accepted | Claimed zero false accepts |
| --- | ---: | ---: | --- |
| Normal Python | 1 | 0 completed rows | No |
| Python `-O` | 0 | 8 | Yes |

The current R143 validator did not exhibit that bypass. This is a defect in the
regression harness's ability to detect a broken validator, not a native WFP
vulnerability. R144 now uses explicit exceptions, measured counts and an exact
completion check. R147 verifies detection of the permissive-validator mutant in
normal, `-O`, and `-OO` modes, and detects an empty case set.

### Functional changes

- `r147_blueprint_verify.py` verifies actual R143 JSON/JSONL artifacts with bounded
  reads: 65,536 bytes per record, 4,096 records and 16 MiB per stream. Exit 0 is
  only `VALID_DESIGN_ONLY`; any rejection returns 2. No output grants native or
  release authority. Malformed JSON, duplicate keys and missing input fail.
- `r147_blackbox.mjs` independently generates substitutions, deletions, extra
  fields and malformed JSON, recalculates hashes, and invokes the actual CLI.
  It does not substitute a second acceptance model for the implementation.
- `r147_regression_gate.py` verifies nine source pins before any test payload is
  executed, stages a private temporary snapshot and collects original stdout,
  stderr, exit codes and SHA-256. Only CRLF-to-LF conversion that recovers the
  exact expected Git blob is accepted. Existing output directories are refused.
- Four fixed groups can be combined only after checking their source pins,
  command sets, completion states, logs and result contents. Preflight, partial
  groups and interrupted runs are not a complete QA acceptance.
- R143 now emits canonical bytes through `sys.stdout.buffer`, avoiding text-mode
  CRLF conversion. The validation semantics and blueprint bytes are unchanged.
  CRLF behavior was tested with a translating Python text stream on Linux,
  **not** with native Windows execution.

## Executed acceptance

Environment: Linux, CPython 3.13.5, Node.js 22.16.0.

| Test | Observed result |
| --- | --- |
| Exact baseline R143, before modification | 74/74 normal and 74/74 `-O` |
| Final R143 regression | 74/74 normal and 74/74 `-O` |
| Fixed R144 real validator regression | 8/8 normal and 8/8 `-O` |
| Existing independent R144 Node oracle | Same eight output rows |
| R147 CLI/bounds/source-gate/mutant tests | 36/36 normal and 36/36 `-O` |
| Real CLI black-box campaign | 2,125 cases in each of normal and `-O` |
| Per-mode black-box result | 3 valid designs; 2,122 rejected; no native acceptance |
| Group receipt mutation campaign | 1 valid control + 13 corruptions rejected, normal and `-O` |
| Final aggregate | 9/9 command executions accepted from four fixed groups |
| Native Windows / Rust / WFP | NOT RUN |

Black-box matrix SHA-256:
`79bb1b4f251e06225fa175601c768b85faffe48c6b8ad8400a249cd105d7a49b`.
Receipt-mutation matrix SHA-256:
`9a21d5277b0b02ce159b9a2d0f5a59a1644f030396065dbb77644776d9d42f18`.
Unchanged blueprint file SHA-256:
`f1f08d056e88010fee2cf9bc4f47ea6e3dfc2af22231117a98bffda62f605ebb`.
Its internal payload digest excludes its own digest field:
`0709309dd0f1b4b79e1a3bda4940a03bde30be5c5702c3a16065b388ebf3873e`.

Two earlier all-in-one executions were interrupted by the executor limit and
are NOT counted as PASS. The final successful result is the verified aggregate
of four completed groups, not a claim that a single unsharded run completed.
Raw logs, original baseline bytes, the false-green reproduction and final group
receipts are retained in the accompanying self-contained checkpoint. Their
hashes and the code blob inventory are in `R147_RESULTS.json`.

## Reproduce without elevation or installation

Use Python 3.10+ and Node.js 22 (tested versions above). Run at repository root.
Every `--output` directory below must be new. No package installation is needed.
The following grouped form is the one completed in this development cycle:

```sh
python -B research/wfp-ale/r147/r147_regression_gate.py --group baseline --output evidence/r147/baseline
python -B research/wfp-ale/r147/r147_regression_gate.py --group boundary --output evidence/r147/boundary
python -B research/wfp-ale/r147/r147_regression_gate.py --group boundary_optimized --output evidence/r147/boundary_optimized
python -B research/wfp-ale/r147/r147_regression_gate.py --group blackbox --output evidence/r147/blackbox
python -B research/wfp-ale/r147/r147_regression_gate.py --aggregate evidence/r147/baseline evidence/r147/boundary evidence/r147/boundary_optimized evidence/r147/blackbox --output evidence/r147/accepted
python -B research/wfp-ale/r147/r147_receipt_mutations.py evidence/r147
python -O -B research/wfp-ale/r147/r147_receipt_mutations.py evidence/r147
```

An unrestricted local executor can alternatively use the default all-in-one
mode; that mode was interrupted here and is not independently accepted here:

```sh
python -B research/wfp-ale/r147/r147_regression_gate.py --output evidence/r147-full
```

`--preflight-only` checks pins without executing tests and explicitly reports
`PREFLIGHT_ONLY_NOT_TESTED`, never `OFFLINE_QA_PASS`. The artifact verifier can
also be used directly: `python -B research/wfp-ale/r147/r147_blueprint_verify.py
path/to/blueprint.json`. It accepts only the pinned non-installable design.

## Trust boundary and next decisive experiment

Git/SHA checks detect accidental substitution and the tested mutations; they
are not signatures, remote attestation or protection from a compromised local
executor. The runner is trusted code and records its own hash without claiming
self-authentication. Independent verification here means a separately written
Node case generator and black-box execution, not an independent human review.

Nothing in R147 binds a historical process to an actual WFP flow. The remaining
chain is kernel-origin process reference / PID / creation epoch / canonical EXE
and AppId -> actual `ALE_CONNECT_REDIRECT` / `ALE_AUTH_CONNECT` -> redirected
accepted socket -> `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS)`
-> one-time CLAIM -> `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on the physical
outbound socket before connect -> authenticated SSH and independent enforcement.
Microsoft documents the query/set APIs and ALE reauthorization, but passing
these offline tests proves none of those native events:

- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection

Next permitted experiment: run this exact offline group suite on the authorized
Windows 10 Pro x64 host and return original receipts/logs. The stdout CRLF
regression and all input/source gates must pass there before calling it native
Windows QA. This still does not authorize a kernel experiment. Read-only BFE
inventory is a separate diagnostic, not flow proof.

PID/process death, 5-tuple reuse, sibling DIRECT, IPv4/IPv6 compartments,
reauthorization, DNS/UDP/QUIC and WFP/BFE/SSH loss remain NO-GO without sufficient
native evidence. No kernel payload or R19 implementation was changed. No driver,
filter, network, service, security setting, runner, automation, main/release,
beta branch, PR56 or other repository was changed. No G1 acceptance is promoted.
