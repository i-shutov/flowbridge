# R156 — full-callback correction and consolidated executable regression

Date: 2026-11-13. Repository: `i-shutov/flowbridge`.
Only branch: `research/windows-wfp-ale-attribution-20261107`.
Analysis base: `0b9a0d720d68fc160d1a08c089fbf03ce86cd80e`.
Observed main: `5b5afc2feeda2195f302380e615ba003d4906e09`.
**Offline source/model regressions PASS; Rust compilation NOT RUN;
native Windows/WFP, PacketBound/G2 and release remain NO-GO.**

## 1. Withdraw the false R155 SELF-action conclusion

R155 modelled the inner `redirect::classify` return without composing it with
its registered caller. That was an analysis error, not a newly discovered
runtime defect. This block leaves the R19 implementation unchanged and adds an
explicit correction above the published R155 report. The old model is retained
only as a regression witness; reproducing it does not validate its conclusion.

The pinned complete control flow is:

1. `lib.rs::classify` writes `FWP_ACTION_CONTINUE` when ACTION_WRITE is present,
   before rundown/STOP checks and before invoking `redirect::classify`.
2. The inner callback rejects missing write permission before calling
   `FwpsQueryConnectionRedirectState0`.
3. Thus a reachable SELF/PREVIOUS_SELF early return preserves the wrapper's
   CONTINUE, not an arbitrary action from the original callback input.
4. Without write permission the SELF query/return is unreachable in this path.
   `guarded_block` may veto prior PERMIT, otherwise it preserves the action.
5. The Redirect rule is CALLOUT_UNKNOWN; AUTH is a separate terminating rule.

Across the original 32 R155 combinations, the composed model changes 16 action
predictions and identifies 16 cases that cannot reach the supposed SELF branch.
These sets overlap and must not be added as independent defects. R156 covers
720 inputs, including unrelated rights bits and 15 distinct control-flow
boundaries. All 48 reachable SELF/PREVIOUS_SELF returns have CONTINUE.

This removes the narrow inherited/unspecified-SELF-action NO-GO. It does NOT
prove native callback delivery, AUTH acceptance, arbitration, actual redirect
state, no-DIRECT, or continuity after failure. CONTINUE delegates a decision;
it is not permission for the connection. Stages are explicitly assumed first
applicable boundaries, not measured Windows events. The modifying redirect path
is marked NOT_MODELLED rather than assigned a guessed packet verdict.

## 2. Exact source boundary

Live repository reads were compared with the local bytes before testing:

| Source under kernel-r19 | Git blob |
| --- | --- |
| kernel/src/lib.rs | 53f5ce6faa0f9f591974287f38ea890cafeb0dd2 |
| kernel/src/redirect.rs | a093f049d162987981a957aac90db1014bc6ff09 |
| kernel/src/action_rights.rs | c6a4a107255cc5ecca82266481935c93467a01ed |
| policy_windows.rs | acf60334320d970f58af3349ee75fbaa59826602 |
| kernel/src/handoff.rs | e1d17217db50362ba9c4efc83af820b6beb094cf |
| kernel/src/ledger.rs | b88c4c9237c4c118517978fc454f5048f522aa7f |

The first four participate in the callback source gate. The frozen R155 Python
model is also pinned: `57ebe7287f4b0593ee8896fff1eb2b85cd5f4fd7`.
Only CRLF-to-LF that recovers the exact expected Git blob is accepted. BOM,
whitespace changes, bare CR and missing final newline are not repaired.
Source-shape checks enforce the relevant call/guard order but are intentionally
not represented as a general Rust parser, formal verification, or compilation.

The working directory is a pinned source slice restored from checkpoints and
live source reads, not a full Git checkout. Execution manifests record exact
bytes; the extended R155 checkpoint narrative was not byte-identical to its
published report, so the published report was fetched and pinned separately
before adding the correction. No checkpoint filename was treated as Git proof.

## 3. Executed tests (Linux; Python 3.13.5, Node 22.16.0)

| Campaign | Observed result |
| --- | --- |
| R156 callback composition | 28/28 tests in normal, -O and -OO |
| R156 independent Node decision table | Matches all 720 matrix rows |
| R156 Python source-pinned matrix | Same hash in normal, -O and -OO |
| Native-test launcher's Python tests | 8/8 in each of normal, -O and -OO; mocks are NOT Rust evidence |
| R148-R154 including two R150 suites | 8,573 distinct model cases; all 32 Python/Node command runs match their pinned golden hashes |
| R147 full QA aggregation | 9/9 completed commands; R143 74 tests and R147 36 tests per mode, real CLI black-box 2,125 cases per mode |
| R147 receipt corruption check | One valid control accepted, 13 corruptions rejected, normal and -O |
| Pure Rust source gate | Four files checked; no compiler commands executed |
| Rust compiler / Windows / native WFP | NOT RUN; rustc unavailable |

R156 matrix SHA-256:
`54d4a483c38d0d0e4bff979a8881798a1dcf3eb0cde31adcd674c7ac7f52e78a`.

The R148-R154 runs now use actual pinned source inputs rather than --model-only.
Their PASS means reproduction of bounded source/model properties, including
known-invalid candidate designs, not a native or production acceptance. In
particular the endpoint budget, global ledger exhaustion, ABA/closure ordering
and compartment proof obligations remain open for product architecture.

An interrupted R147 optimized boundary run was excluded and rerun successfully.
The R148-R154 batch was interrupted after 26 completed commands; their raw log
hashes and exits were rechecked before completing the remaining six. The first
collection attempt stopped on a collector JSON-field mismatch and was excluded.
No interrupted or failed command is promoted to PASS. R147 receipts retain the
historical development-base field of that launcher; R156 separately records its
current analysis base and source pins.

Independent here means separately implemented Node logic and black-box tests,
not another human or model reviewer. No subagents were launched: the available
integration did not expose a subagent runtime or model selector.

## Concurrent publication and non-destructive integration

Before the ref update, research HEAD advanced to
`f4c73be7ca0e66800f670f9256bd3979edbe1470`. Publication was stopped and the
complete diff and relevant new files were reread. Its five new R156 files are
preserved unchanged. Our colliding filenames were renamed to
`test_r156_fullchain.py` and `r156_comprehensive_oracle.mjs`; the original
`test_r156.py` and `r156_independent.mjs` remain the concurrent author's files.
The earlier prepared commit `34da85b7b03d68956c81e9b39779ee28bfa4928e` was
never attached to the branch and is not the delivered revision.

The concurrent correction fixes the writable wrapper but still models a
no-write SELF return as reachable. The full-chain regression directly imports
its pinned `r156_callback_composition.py` blob
`d9e4798a7c734bafd4584302434373c3bd1e4066`: all 16 no-write SELF cases miss the
pre-query guard; four prior-PERMIT action predictions differ because the guard
vetoes PERMIT before querying redirect state. That narrower claim in
`R156_WRAPPER_ACTION_CORRECTION.md` is superseded by this addendum. No concurrent
model/report was overwritten, and its reported matrix is not promoted to native
proof. All 28 full-chain tests were rerun in three Python modes after renaming
and adding this integration regression. Original R19 source pins did not change.

## 4. Pure Rust harness prepared, NOT compiled

`r156_pure_regressions.rs` includes only the existing pure `ledger`, `handoff`
and `action_rights` modules. It declares 40 existing tests and 12 new tests for
32/33 live slots, 4096/4097 endpoint tombstones, 256/257 process entries, PID
reuse, separate broker/selected roles, death after AUTH, and composed action
rights. It forbids unsafe code. Its composition helper is a test model, not the
actual kernel callback. No DriverEntry, FFI, WDK, lib.rs, redirect.rs or policy
installer is compiled by this harness.

`run_r156_native.py` validates source bytes before staging a private snapshot.
It invokes only an existing rustc with --test, never Cargo/build.rs or an
installer. It records compiler version, binary hash, test listing, count, exit
codes and stdout/stderr. Missing compiler returns exit 3 and the explicit
NOT_RUN_COMPILER_UNAVAILABLE result. A preflight is not a test PASS.
The actual run in this block returned that NOT_RUN result with zero commands.
52 is the expected declared count, not an observed Rust test result.

## 5. Reproduction and next permitted decisive experiment

From the repository root, without elevation:

```sh
python -B research/wfp-ale/r156/test_r156_fullchain.py
python -O -B research/wfp-ale/r156/test_r156_fullchain.py
python -OO -B research/wfp-ale/r156/test_r156_fullchain.py
node research/wfp-ale/r156/r156_comprehensive_oracle.mjs
python -B research/wfp-ale/r156/test_native_gate.py
python -B research/wfp-ale/r156/run_r156_native.py --output evidence/r156-pure-new
```

The last output directory must not already exist. An already installed compiler
can be selected with --rustc. On the authorized Windows x64 host this is the
next useful no-driver test: compile and execute the unchanged pure Rust modules
with the boundary regressions and return original receipts/logs. Even 52/52
there would establish only pure user-mode Rust tests, not Windows kernel proof.
The checkpoint includes the restored source slice, raw logs, the successful
R147 aggregate, the resumed 32-command campaign and file SHA-256 manifest.

## 6. Remaining trust chain and official sources

Required proof still runs from a kernel-origin process/FileObject reference,
PID + creation epoch + start key + canonical EXE/AppId, through actual
ALE_CONNECT_REDIRECT and ALE_AUTH_CONNECT events, typed endpoint/compartment
identity, the actual redirected accepted socket, WFP context/records, one-time
CLAIM and SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS on the physical SSH socket
before connect. Late PID lookup, matching timestamps or a reused 5-tuple cannot
supply the missing provenance. No new generation counter alone solves ABA.

Official sources checked for this block:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_classify_out0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_action0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ale-endpoint-lifetime-management

Process death/PID reuse, endpoint and 5-tuple reuse, IPv4/IPv6 compartments,
reauthorization, sibling DIRECT, DNS/UDP/QUIC and WFP/BFE/SSH loss remain without
end-to-end native acceptance. A separately authorized kernel laboratory with
all owner/rescue/rollback gates is required before such claims. No new driver,
callout or filter was created, built, installed or run. Main/release, beta,
PR56, other repositories, runners, services, network/security and automations
were not changed. No historical G1 evidence is promoted.
