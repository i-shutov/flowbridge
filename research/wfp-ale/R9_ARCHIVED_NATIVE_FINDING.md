# R9 — recover real Windows AppId evidence, do not recycle synthetic PASS

Date: 2026-11-07. Research-only update on
`research/windows-wfp-ale-attribution-20261107`, based on `8e760d109eca2a12c70f9456391c61e6bfec8737`.
No changes to beta, PR #56, main, release, workflows, runners, services, protections,
automations or other repositories. No binaries were executed and no WFP filters or
network experiments were started in this cycle.

## Native evidence recovered rather than another simulated owner

The authenticated GitHub artifact API returned a previously completed Windows-2025
job with original Rust AppId observations. Its artifact was downloaded and independently
checked offline. This is historical Windows evidence, NOT a fresh R6/R8 experiment.

| Provenance | Exact value |
|---|---|
| Repository / run | i-shutov/flowbridge / 42339966586, attempt 1 |
| Windows job | 128305303067, integration (windows-2025), SUCCESS |
| Overall workflow | FAILURE; separate g2-kernel-connection-owner job failed |
| Artifact | 13560942739, FlowBridge-Rust-Capture-windows-2025 |
| Recorded PR source | c339df2e4d20edf1d11d45786581a68451a71929 |
| Actual test merge | ab6ed5273db6e9741915a96c74809433af125870 |
| Test-merge parents | 5b5afc2feeda2195f302380e615ba003d4906e09 + c339df2e4d20edf1d11d45786581a68451a71929 |
| Archive SHA256 (matches GitHub digest) | 95560460776b802da5ccd1a608495609715144a59a7fac5fbfaed331542faa92 |
| Nested payload ZIP SHA256 | a7320e2dce38c7e294a85492bb3a6ca4f2e8c28e68f4a12c7222724077a77be5 |
| Rust agent SHA256 | 8d682c9391c2d5e8241e97e6f028100e9c421d8ecd4bc0a6540e4ffb7e90a201 |

The merge parents were read from the Git data API, not guessed from a PR description.
The outer ZIP passed CRC; its digest matches the authenticated GitHub response. The
nested ZIP, all manifest payload hashes, Windows x64 PE header and the agent hash in
both relevant reports also agree. No PE file was extracted or executed by the auditor.

## Actual observations (including the negative result)

`windows-wfp-dynamic-lifecycle.json` records:

- `selected_self_matches_target=true`;
- `different_copy_self_matches_target=false` and `agent_self_matches_target=false`;
- **`selected_input_equals_handle_appid=false`**;
- **`different_input_equals_handle_appid=false`**;
- **`selected_running_image_equals_handle=false`** and the equivalent different-copy comparison is also false;
- the event diagnostic has **`event_appid_expected_source_identity_complete=false`**.

Thus the historical run observed path-sensitive AppId distinctions despite equal EXE
bytes, but did NOT establish equivalence between the supplied path, a path obtained
from a file handle, and the running image path. The broad test's `passed=true` must not
flatten these negative diagnostic fields into a canonical identity PASS.

The cause is **undetermined**: the retained report is redacted, so namespace spelling,
reparse behavior and a possible comparison implementation defect cannot be separated
from these booleans. This is not evidence of a Windows vulnerability or a universal
claim that canonical paths never agree.

At the exact test merge, `tests/windows_wfp_dynamic_loopback.py` (Git blob
`cb60182863ab159b569b1e9db29c4ba73e437d08`) copies the same agent into **different
basenames in one temporary directory** and checks equal SHA256 values. It does NOT
exercise same-basename EXEs in separate directories or hardlink/reparse/case aliases.
Those R6/R8 cases remain unmeasured; they cannot be filled in from this artifact.

The original `identity_probe` in `crates/flowbridge-capture/src/windows_wfp_dynamic_lab.rs`
(blob `a219b8c564b4e4bcdfe8e9616afc88228433efca`) calls FwpmGetAppIdFromFileName0,
GetFinalPathNameByHandleW and QueryFullProcessImageNameW and compares the results without
creating a filter in that identity command. The encompassing historical QA job DID
create dynamic WFP filters for other tests. This audit does not rerun that job and does
not describe the entire historical job as read-only.

## Executable independent reader

`audit_archived_appid.py` checks the pinned outer archive, nested payload, provenance,
PE identity and explicit negative flags. It refuses changed sources, binary hashes,
missing fields, non-boolean truthy substitutes, promoted release/kernel flags, duplicate
JSON keys and unsafe ZIP entries. It emits only a sanitized projection, not raw paths,
AppIds, process identifiers, network endpoints, raw receipts or executable bytes.

Executed in this cycle on Linux/Python 3.13.5:
- actual downloaded archive audit: PASS, with canonical mapping explicitly MISMATCH;
- 19/19 independent reader-contract tests: PASS;
- Python syntax compilation: PASS;
- published verifier Git blob: `22a4d752303f0bba671d57c6477e19c4785e94bf`;
- published tests Git blob: `5b38d2ae55d3d539350df405162f7d2a7b5cd376`.

Reproduction (no subprocess or Windows execution):
```sh
python research/wfp-ale/audit_archived_appid.py <downloaded-artifact-13560942739.zip>
python -m unittest discover -s research/wfp-ale -p test_audit_archived_appid.py -v
```

The sanitized actual result is `R9_ARCHIVED_APPID_RESULT.json`. No independent native
reviewer sign-off is claimed. The tests use deliberately synthetic documents only to
check the reader; the actual archive audit is reported separately.

## Blocker narrowed, not falsely declared solved

We no longer lack *all* native AppId observations: a reproducible historical Windows
baseline exists, and it already falsifies assuming canonical-path equivalence without
checking it. But the fresh R8 same-basename/alias matrix is still NOT RUN. Current
session capabilities have source writes and Actions reads, no dispatch action, no
configured local GitHub CLI credentials, and no Windows command executor. No push/issue
trigger workaround, rerun, paid browser, new token, new agent or protection change was
used. Another Rust installation or another simulated owner model cannot provide that
missing execution capability.

The next useful no-driver measurement is specifically to discriminate original DOS
spelling, file-handle DOS/NT spelling and file identity for the same file and controlled
aliases. Do not claim kernel ownership from any of these comparisons: AppId is a path
identifier, not a process creation epoch or a per-frame connection token. The exact
Windows command execution channel remains the blocker for this new measurement.

G2, original-classify EPROCESS provenance, NDISRD PacketBound and physical no-DIRECT
remain OPEN/NO-GO. Historical G1 stays bound to dd1ab3c. The SOCKS-only beta does not gain
an unrelated WFP prerequisite from this research and receives no acceptance transfer.

## Primary sources

- Existing run: https://github.com/i-shutov/flowbridge/actions/runs/42339966586
- Exact harness: https://github.com/i-shutov/flowbridge/blob/ab6ed5273db6e9741915a96c74809433af125870/tests/windows_wfp_dynamic_loopback.py
- Exact Rust comparison: https://github.com/i-shutov/flowbridge/blob/ab6ed5273db6e9741915a96c74809433af125870/crates/flowbridge-capture/src/windows_wfp_dynamic_lab.rs
- Microsoft defines ALE_APP_ID as the lower-case fully qualified device path returned by FwpmGetAppIdFromFileName0: https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-
- API contract: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0
