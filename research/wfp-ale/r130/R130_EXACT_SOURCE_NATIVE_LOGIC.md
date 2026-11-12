# R130 — move from BFE absence diagnostics to exact-source native logic tests

2026-11-12. Only i-shutov/flowbridge, branch
`research/windows-wfp-ale-attribution-20261107`. Starting HEAD
`cad7317a7d7cf652e6ea010349e8bd24d30016ba`; main read-only observation
`5b5afc2feeda2195f302380e615ba003d4906e09`. Not beta, release, PR #56 or G2.

## R129 owner-supplied native evidence: a completed negative diagnostic

`R129_OWNER_OBSERVATION.jsonl` contains only the five intact JSON lines from the
owner's pasted console output, not the surrounding mixed clipboard text. All four
exact-key GETs returned unsigned 2150760451 / `0x80320003`
(`FWP_E_FILTER_NOT_FOUND`), with a null result pointer. Engine close returned 0;
summary is `NOT_FOUND_OBSERVED`, exit 4, `atomic_snapshot=false`.

The console additionally reports source blob
`4003a17b4213072605994427080038becd11c092` and wrapper status
`READONLY_DIAGNOSTIC_COMPLETED_NOT_PROOF`. The known host from preceding owner
messages is Windows 10 Pro build 19045, with rustc 1.91.0 MSVC x64.
These are OWNER-SUPPLIED observations, not a remote run by this executor. Raw
R129_EVIDENCE.json, full test stdout, Windows runtime timestamps and binary SHA256
have not been received. R129 native test counts are not independently re-asserted.

The exact R129 validator (blob `6e4d23dac3c2c579760e23632b169067e695e15e`)
accepts those five records with exit 4. A separately implemented Node check agrees.
The former baseline-not-visible ambiguity is therefore narrowed to the four API
replies, not access denial. This does NOT assert an atomic global absence, the
absence of other Windows filters, or any physical DIRECT traffic.
No R19 filters/driver should be installed merely to turn this diagnostic green.

## Executable next step: original pure modules, not another proxy model

`r130_exact_logic_suite.rs` imports EXACT existing modules by relative path:

| Original file | Git blob | Existing tests |
|---|---|---:|
| kernel-r19/kernel/src/ledger.rs | b88c4c9237c4c118517978fc454f5048f522aa7f | 11 |
| kernel-r19/kernel/src/handoff.rs | e1d17217db50362ba9c4efc83af820b6beb094cf | 19 |
| kernel-r19/kernel/src/auth_appid.rs | f16ab6ad0f618c74ed4e79ce606583169084970d | 7 |
| kernel-r19/policy_plan.rs | c8ab344551f1adfc20fd0019c4606cf3ca3c81c4 | 9 |

These four files are UNMODIFIED. The additional 14 cross-module tests produce
60 expected Rust tests total. `#![forbid(unsafe_code)]` applies to the whole suite.
The driver adapter lib.rs, redirect.rs, native policy_windows.rs, broker and SSH
implementation are not imported or compiled. policy_plan's install function is
exercised only through its in-memory Fake Operations tests: no BFE installer runs.
No Windows APIs, sockets, FFI, services, real-process termination or packet I/O.

The suite checks process epoch/start-key/generation mismatches, PID-reuse latch,
death before dequeue, two IP-family payloads, same-basename/different-full-path
AppId, BFE versus kernel AppId terminator conventions, one-use CLAIM, invalid
payload consumption, endpoint tombstones, expiry boundary, revocation, and UDP
wire-field rejection. Same-destination/new-endpoint tests do NOT claim actual
5-tuple reuse was generated on Windows.

One positive test intentionally demonstrates the boundary: Book alone can retain
authenticated synthetic state after Ledger.died. A test-only composition checks
Ledger first. This is NOT a new discovered production bug or an atomic liveness
fix; the production adapter has separate checks. Process/file/endpoint integer
values in this suite are synthetic, not referenced EPROCESS/FILE_OBJECT/socket
handles. A 60/60 result cannot attest kernel ownership, race freedom or no-DIRECT.

## Windows delivery

`FlowBridge-R130-ExactLogic.ps1` uses the already installed native MSVC Rust. It
fetches only five immutable Git blobs (four originals + test harness), verifies
both Git blob SHA1 and SHA256, and writes them with exact bytes in a fresh temp
source tree. An explicit OfflineBundleRoot uses local exact bytes with no fallback
download. No old checkout, Git ref changes, normalization, Cargo, build.rs,
packages or elevated permissions are needed. No changes to global PATH.

The script first typechecks the test configuration, then builds, lists and runs
all 60 tests. It rejects missing/duplicate tests, unexpected module counts,
skipped/filtered tests and nonzero test status. Default execution performs tests
only; there is NO RunReadOnlyBfe switch. -CompileOnly stops before native tests.
RUST_MIN_STACK is 8 MiB for child test threads only, restored with PATH on exit.

Output: R130_EVIDENCE.json, separate stdout/stderr logs, exact source hashes,
compiler version, Windows build, test executable SHA256 and evidence-only.zip.
The archive intentionally excludes native binaries. Status 0 means either
EXACT_SOURCE_METADATA_ONLY or EXACT_SOURCE_NATIVE_TESTS_PASS_NOT_KERNEL_PROOF,
never kernel acceptance; any failure exits 2 with reason and preserved logs.

## Local verification actually executed

- Four fetched repository module blobs match local byte copies exactly.
- 14/14 Python integrity/negative tests PASS, including verification of the actual
  supplied R129 result using its pinned validator.
- Independent Node implementation confirms 5/5 exact sources, rejects 60/60 byte
  mutations (bit flips, CRLF, BOM and truncation), checks supplied R129 outcomes
  and independently counts 60 Rust test functions.
- NOT RUN: R130 Rust compilation/tests or Windows PowerShell parse/runtime. This
  executor has no rustc/cargo/Windows runtime. These checks must be run on the
  already approved Windows host. R113/R129 native results are NOT transferred.

Source copies needed for local testing were materialized from connector-returned
content and verified against Git blob SHA; no code fragment was treated as the
full source. Source attestation tests do not execute or prove the Rust algorithm.

## Bounded small-model review tasks

No callable model-selector/subagent executor is available; NONE dispatched and
no cost incurred. Independent Python/Node programs are not independent model
reviewers. The following scoped tasks are ready for an owner-approved executor:

A. Pure-Rust reviewer: inspect the five pinned files; validate import closure,
absence of unsafe/FFI and the 14 integration assertions. Deliver line-specific
findings; do not edit kernel adapter or original modules.
B. Attestation reviewer: run r130_acceptance.py and r130_independent.mjs; mutate
source bytes, evidence types/cardinality and expected test counts. Deliver
counterexamples only within r130; no Git writes or network experiment.
C. Windows PowerShell reviewer: parse the exact launcher, execute -CompileOnly,
then default synthetic tests on the approved Windows host. Preserve report,
stdout/stderr and hashes. No BFE, runner, driver or toolchain installation.

## Next decisive experiment and remaining NO-GO

Run the published R130 launcher once on the host that completed R129. Obtain the
60-test output and evidence ZIP. Failing tests/compile diagnostics are evidence,
not a reason to weaken pins or bypass conditions. A passing result closes only
the exact-source user-mode execution step, including reproduction of known
fail-closed capacity limits (R91/R104) and ticket replay rejection.

Native ALE_AUTH_CONNECT/CONNECT_REDIRECT, referenced original PID + creation epoch
+ canonical EXE/AppId, accepted SOCKET redirect context/records -> CLAIM -> SSH,
process-death races, reused PID and 5-tuple, sibling DIRECT, DNS/UDP/QUIC and
WFP/SSH-loss enforcement remain unproven. No PacketBound/G2 PASS, historical G1
transfer, no-DIRECT or leak-free assertion.

Primary contracts consulted:
- https://learn.microsoft.com/en-us/windows/win32/fwp/wfp-error-codes
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltergetbykey0
- https://doc.rust-lang.org/rustc/tests/index.html
- https://doc.rust-lang.org/rustc/command-line-arguments.html

Diff scope: new r130 files only. No main/release/beta/PR56, runner, services,
firewall/UFW, Defender, SecureBoot, MemoryIntegrity, network settings, automation
or other-repository changes. No kernel driver/callout/filter, NDISRD, VNC, signed
driver work, vendor binary, C++ payload or paid operation.
