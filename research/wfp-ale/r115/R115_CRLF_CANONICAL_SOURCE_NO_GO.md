# R115 — fail-closed CRLF checkout attestation repair (NO-GO)

Date: 2026-11-11. Scope **only** `research/windows-wfp-ale-attribution-20261107` in `i-shutov/flowbridge`.
Intake research HEAD `09991c1e11597ce1b8fd22d7a78f30e2e9f78988`; read-only main `5b5afc2feeda2195f302380e615ba003d4906e09`. Not beta, PR #56, PacketBound/G2 PASS or historical G1 acceptance.

## Material Windows blocker

On the owner's authorized Windows 10 Pro 19045, detached R113 checkout `e24f3c2d866e9374e8873ecdab325dd7b06049ee` passed Git object identity checks for the harness blob `6cab4c1e8aee20506bb3ba9ae17cf348ec19b7df` and Rust source blob `49506ca07145c18947a0845f2a1a63b3de1f54ec`. The original nested harness returned **2** with `Source Git blob mismatch: refuse unverified source`, before invoking rustc or BFE.

A reproduced explanation is inconsistent verification domains: `git hash-object` can apply Git clean filters, while the nested PowerShell harness hashes raw worktree bytes. Git's `core.autocrlf=true` can produce CRLF worktree bytes that normalize to the exact pinned LF Git blob. Simulated complete CRLF transformation hashes as `619dc8a3c7b9ed56171cce781c1daa15c7b7b40f`; canonical LF hashes as `49506ca07145c18947a0845f2a1a63b3de1f54ec`. **The owner's raw Windows file bytes were not retrieved**; do not assert their exact observed hash.

## Functional change

Modify the existing `research/wfp-ale/r112/R112_WINDOWS_NATIVE_READONLY_CHECK.ps1` (R114 parser remains intact). Raw source bytes and their SHA256 and Git-blob SHA1 are always logged. If raw Git-blob SHA1 is already the expected pinned value, compile the original file. Otherwise normalize **only CRLF byte pairs to LF**, save the candidate as a separate TEMP evidence file, recompute the canonical Git-blob SHA1 using the existing in-process .NET implementation, and **reject unless it equals the exact pinned SHA**. Only verified canonical bytes are passed to Rust. Log `source_crlf_normalized`, `source_normalized_git_blob` and `source_compilation_sha256`.

This never considers `git hash-object` output a substitute for raw-byte verification, never disables the pinned source check, never fetches/install tools, never changes the worktree or Git refs, never installs WFP filters/callouts/drivers, and never configures services/network/firewall/Defender/security. It is not a proof that the actual Windows failure was solely CRLF; the native retest is still needed.

## Deterministic negatives and independent review

Run from the research branch checkout (with Git, Python 3 and Node installed):

```sh
python3 research/wfp-ale/r115/r115_crlf_attestation_negative.py
node research/wfp-ale/r115/r115_crlf_independent.mjs
```

Both independently generate **135 exact-byte cases**: canonical LF, all CRLF, mixed CRLF/LF (3 accepts), and corruption cases including 127 distinct one-byte changes (132 rejects). Both confirm the same ordered CSV SHA256:

`0abcfc37018f43751e1e2d19419c4be048d075a0ae4abef56b338db7d2bfc8e3`

Python also cross-checks each input against Git CLI `hash-object --stdin` and statically asserts the patched PowerShell gates. In an isolated local Git repository `core.autocrlf=true` was reproduced independently with the original exact source, demonstrating the clean-filter/raw-worktree mismatch. The tests and hash agreement are **offline byte-level evidence**, not a PowerShell 5.1 runtime or kernel proof.

## Required trust chain remains unproven

| Link | Native API / structured evidence | Requirement / status |
| --- | --- | --- |
| Selected canonical EXE | `FwpmGetAppIdFromFileName0`, `FWPM_CONDITION_ALE_APP_ID` | Same opaque application identity, not basename: **NO-GO** |
| Kernel-origin process + epoch | `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6` and valid `FWPS_METADATA_FIELD_PROCESS_ID`; `PsLookupProcessByProcessId` / `PsGetProcessCreateTimeQuadPart` with correct object lifetime and IRQL | Same classify binds owner, creation epoch, target; PID death/reuse: **NO-GO** |
| Redirect continuity | `FwpsQueryConnectionRedirectState0`, `FWPS_CONNECT_REQUEST0`, `FwpsAcquireWritableLayerDataPointer0`, `FwpsApplyModifiedLayerData0`, `FwpsRedirectHandleCreate0` | v4/v6 original destination/context, no self-loop: **NO-GO** |
| Real accepted socket | `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS / _CONTEXT)` | Authenticate **that socket**, not matching 5-tuple or timestamps; deny ABA/endpoint replay: **NO-GO** |
| Outbound transport | `WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS)` | Before outbound connect, authenticated SSH handoff and revocation: **NO-GO** |
| Independent enforcement | `FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6`, reauthorization/filter lifecycle | Sibling DIRECT, IPv4/v6, DNS UDP/QUIC, loss of WFP/BFE/SSH: **NO-GO** |
| Management-only visibility | `FwpmEngineOpen0`, `FwpmFilterCreateEnumHandle0`, `FwpmFilterEnum0` | ACL-limited snapshot, not runtime `classifyFn` or no-DIRECT: **DIAGNOSTIC ONLY** |

Microsoft contracts:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-_fwps_connect_request0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetprocesscreatetimequadpart
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltercreateenumhandle0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilterenum0

## Next decisive experiment

On the **already authorized** Windows x64 host, inspect the exact R115 checkout and run the repaired harness first in metadata-only mode, then with `-RunUnitTests` and (separately) opt-in `-RunReadOnlyBfe`. Record Windows build, Rust toolchain, pinned source raw/canonical hashes, exit codes, JSONL/logs and evidence SHA256. A successful build or BFE read does **not** certify kernel-origin attribution or no-DIRECT. No driver, callout, active filter, network traffic experiment, VNC or SYSTEM rescue is authorized by this cycle.

Main/release, beta integration branch, PR #56, runners, services, network, security, automation schedules and other repositories are out of scope and remain untouched.
