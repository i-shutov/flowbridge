# R140: conditional WFP action-rights patch; release still NO-GO

Date 2026-11-12. Scope ONLY i-shutov/flowbridge branch research/windows-wfp-ale-attribution-20261107.
Parent at design: 4670ab1ae6d6694315150325f1c2004999f35a99. Main read-only: 5b5afc2feeda2195f302380e615ba003d4906e09.

## R139 Windows evidence

The owner reported PowerShell 5.1 syntax PASS, four exact pinned R19 source blobs PASS,
R139_SOURCE_RECEIPT_VALIDATED_RELEASE_NO_GO, exit code 3. This is a chat transcript;
raw R139_EVIDENCE.json was not attached, so do not claim independent host attestation.

## Actual research code change

kernel-r19/kernel/src/lib.rs: 0af6d4539673d2894cbaa91af0ea8f3524862a26 -> 53f5ce6faa0f9f591974287f38ea890cafeb0dd2.
kernel-r19/kernel/src/redirect.rs: 9a07e026134d46ef646d39862bd982cc48bbc5f6 -> a093f049d162987981a957aac90db1014bc6ff09.
kernel-r19/kernel/src/action_rights.rs: NEW c6a4a107255cc5ecca82266481935c93467a01ed.

The no_std-compatible pure guard explicitly classifies three conditions:
(1) WRITE right present -> legal BLOCK; (2) WRITE absent, earlier PERMIT -> legal veto;
(3) WRITE absent with any other prior action -> MUST PRESERVE prior WFP action.
Root classify and AUTH STOP/rundown branches and redirect::block now use this common gate.
The successful redirect path restores its captured incoming write right before setting PERMIT.

FwpsAcquireWritableLayerDataPointer0 itself writes BLOCK and clears the write right;
subsequent error code paths preserve the WFP-owned BLOCK without redundant unauthorized writes.

## Hard limit

When no ACTION_WRITE and the previous action is CONTINUE/NONE, this callback cannot
legally force BLOCK. The patch therefore does NOT prove OS fail-closed behavior.
Persistent independent protection is required and is NOT implemented or installed.
policy_windows.rs remains acf60334320d970f58af3349ee75fbaa59826602,
still using FWPM_SESSION_FLAG_DYNAMIC; its filters disappear when the session ends.
No R19 kernel binary build/load, WFP callback, BFE filter, socket, or firewall setting
was performed. This is research-source correction, not RELEASE GO.

## Reproducible tests

10 Rust unit tests in the ACTUAL shared kernel guard, plus 3 in the no-unsafe
user-mode harness, are prepared for Windows native rustc. NOT RUN here.
Python and independently implemented Node oracles actually executed: 42/42 same output;
27 conditional BLOCKs allowed; 15 must preserve. SHA256 matrix:
4837dbb987fdd28bd006f553b688d0a0746575ce4533ef7366e01bbf0cabc654.
26 Python local negative/static tests passed in the checkpoint package.
The Windows PowerShell runner downloads pinned source blobs, checks exact Git hashes,
runs only pure Rust, and produces logs. Run a PowerShell 5.1 AST parse first.

## Unfinished gates / next release work

1. Native Windows pure guard: 13/13 tests and 42-row matrix, independent check.
2. Review WDK ABI and classify rights in all R19 paths, including writable data acquisition.
3. Design separate persistent default-deny policy with per-family scope, WFP arbitration
   and a demonstrably disjoint allowed redirect path; no blanket persistent block yet.
4. Separately authorized disposable VM, signed driver, snapshots, rescue and rollback;
   prove actual action rights, socket records, process origin, SSH, DNS/UDP/QUIC and
   negative DIRECT. No such lab run is authorized or claimed.

Sources:
https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_classify_out0
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsacquirewritablelayerdatapointer0
https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0
