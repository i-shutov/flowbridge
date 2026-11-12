# R132 — from R130 native unit PASS to exact-source event-order differential testing

Date recorded: 2026-11-12. Scope: i-shutov/flowbridge ONLY,
research/windows-wfp-ale-attribution-20261107. Baseline research HEAD:
3dca8693c754a8ff5b5280ac7055b42c4f1e5db1; tree:
8925f06b1801a73074c7b99e63a8e8c716e75e13.
Main read-only: 5b5afc2feeda2195f302380e615ba003d4906e09.
No beta, PR56, release, infrastructure, services, runner, security or automation changes.

## Accepted owner observation, with provenance

The owner supplied the console output of R130: all five source blob checks passed,
60 tests passed, zero failed/ignored, time reported 0.07s, status
EXACT_SOURCE_NATIVE_TESTS_PASS_NOT_KERNEL_PROOF and exit 0. This follows the same
Windows 10 Pro x64 / Rust 1.91.0 MSVC workflow reported in prior messages.
The raw evidence-only.zip and test binary SHA have NOT been independently received.
R130_OWNER_RESULT.json records the result as owner-supplied transcript evidence,
not a native execution by this Linux executor. No kernel proof is inferred.

R130's process/book/AppId/policy source modules remain byte-identical. R132 adds
no implementation change to R19. This is the next test campaign, not a repeated
claim of discovering the already known ledger/tombstone capacity limitations.

## Experiment

The new Rust program imports the SAME four pinned pure modules by path. It runs
64 unit tests (46 unchanged module tests plus 18 new schedule/concurrency tests),
then emits an exact deterministic transcript of 36,000 event orders:

2 address families x 5 applied hazards x 5 primary-claim payload variants x 6!.
Each order has 6 steps, hence 216,000 event steps. A fresh issuance precedes every
trace. Six uniquely labelled events are AUTH, repeated AUTH, primary CLAIM, valid
retry CLAIM, one hazard, and clock advancement strictly beyond the ticket TTL.

Hazards: neutral; selected process exit OBSERVED in Ledger; PID rebirth OBSERVED;
STOP APPLIED to Book; re-issuance of an already tombstoned endpoint. Claim payloads:
exact; changed destination payload; foreign session; unknown sequence; changed
TCP/UDP protocol byte. The last is malformed receipt DATA, not a UDP network test.

The test-only composition uses actual Ledger lookup and Book issue/attest/take/kill
methods. Its CLAIM follows the source ordering of redirect.rs: Book::take consumes
first, then live Ledger lookup and origin/name validation. It does NOT compile
redirect.rs, execute classify, or reproduce the entire kernel adapter. Relevant
adapter source blob: 9a07e026134d46ef646d39862bd982cc48bbc5f6 (read-only audit).

All observations/callbacks in this experiment have already been applied. Synthetic
broker identity stays live, and its lease is assumed refreshed independently.
Advancing TTL is not a test of heartbeat/LEASE timing. No WFP field provenance,
IRQL, missing callback, original AppId inheritance or physical process death is
validated. Test Mutex serialization is not the real kernel spinlock implementation.

For each trace the program writes:
family|hazard|payload|event-order|result-bits|book-lost-bits|ledger-lost-bits|live-bits.
It asserts at most one AUTH and at most one successful claim, and no claim after
an already applied relevant hazard or TTL advancement. These are composition
invariants, not egress assertions.

There are also actual user-mode thread tests: two simultaneous claimants sharing
one Mutex (16 repetitions per IP family), observed death before claim, claim before
observed death, and STOP before claim. A channel/join establishes the controlled
happens-before edges. These tests do not exhaust all OS/thread interleavings.
Rust Mutex poisoning is not treated as recovery: lock/join failures fail the test.

## Independent oracle and negative controls

Python uses a small logical state machine and itertools permutations. Node uses
six-digit base-6 enumeration and bit flags. Neither imports the Rust implementation
or the other oracle. Local execution agrees on all 36,000 full trace lines:
SHA256 c2af3f996ec4c52620c973f0fb34dc4ead470e94f6805edeb9a8d49fcf278e37.
There are 4,944 conditional successful CLAIMs and 13,536 successful AUTHs in this
synthetic campaign. Counts are NOT Windows failure probabilities or observations.

Two deliberate WEAK ORACLE controls are distinguishable:
- omit post-take owner-liveness gate: 352 altered traces / 352 additional claims;
- failed CLAIM not terminal: 6,176 altered traces / 1,312 additional claims.
These are mutations of the independent specification, NOT changes to source R19
and NOT actual attacks on Windows. Exact-source Rust tests cover the corresponding
counterexamples; their native execution remains to be supplied by the owner.

Local acceptance: 18/18 Python tests PASS, including source pins, exact test counts,
script surface, trace invariants, full SHA, Node agreement and mutation witnesses.
NOT RUN here: Rust compilation/execution, Windows PowerShell parser/runtime,
new native trace campaign. rustc/cargo are absent; official compiler download DNS
was unavailable. No toolchain was installed. R130 native PASS does not transfer.

## Native delivery

FlowBridge-R132-EventOrders.ps1 is derived from the R130 harness already executed
by the owner. It fetches five immutable Git blobs from this repository (or uses an
explicit offline bundle), verifies both hashes, and compiles only pure Rust.
No checkout, dependency manager or system installation. Source bytes are never
normalized. It checks exactly 64 uniquely listed tests and all expected groups,
zero ignored tests, then runs the campaign executable and checks all 36,000 lines
against the independently fixed transcript SHA. A discrepancy yields failure,
not a revised oracle. stdout/stderr, executable SHAs, versions, counts and statuses
are written into a fresh temp directory and evidence-only.zip.
A 180s bound applies to each own compiler/test child; only that child may be stopped
on timeout. PATH and RUST_MIN_STACK are process-local and restored. The campaign
thread has an explicit 8 MiB stack. No WFP API, network socket, driver or filter is
executed by either test binary. Source retrieval is the only network access.

Expected native result (NOT yet claimed):
EXACT_SOURCE_EVENT_ORDERS_PASS_NOT_KERNEL_PROOF, 64/64, 36,000 traces, exit 0.
The useful next evidence is R132_EVIDENCE.json plus the campaign transcript/hash,
not another BFE enumeration. Do not install filters merely to get positive BFE reads.

## Bounded small-model review work

Dispatch status: NOT_DISPATCHED; no callable junior-model/subagent executor exists
in this session. Independent programs do not constitute a second-model review.
A: read only Rust Machine::claim/ready/auth and pinned redirect.rs; report semantic
omissions (especially consumed-before-liveness order), never edit kernel code.
B: review oracle independence and try a concrete counterexample to 6-event coverage;
submit one fixture and expected result, no model/result rewriting.
C: on the already approved Windows host, parse the pinned script, run R132, return
source/binary hashes and raw evidence ZIP; no driver/filter/network experiments.
All tasks are confined to research/wfp-ale/r132; no Git mutation delegated.

## Unchanged architectural boundary

Kernel-origin process reference -> PID/creation epoch/start key/canonical EXE and
AppId -> ALE CONNECT_REDIRECT/AUTH_CONNECT (IPv4/IPv6) -> actual accepted socket
redirect context/records -> CLAIM -> authenticated SSH egress remains unproven.
Process death notification is not modeled as instantaneous physical death. PID
reuse, 5-tuple reuse, sibling DIRECT, DNS/UDP/QUIC, WFP/BFE/SSH loss and continuous
filter enforcement remain native NO-GO. No G1 dd1ab3c evidence transfer,
PacketBound/G2 PASS, no-DIRECT or leak-free claim. No callout/driver/filter code built.

Primary references checked for the boundary, not invoked:
- https://doc.rust-lang.org/std/sync/struct.Mutex.html
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pcreate_process_notify_routine_ex

Git publication uses exact expected research SHA and force=false; conflict means
STOP and reread. Only new r132 files are permitted in the diff.
