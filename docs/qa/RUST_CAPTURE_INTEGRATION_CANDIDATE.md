# FlowBridge Windows Rust capture — G0–G6 current-source matrix

Updated **2026-11-06** for Draft [PR #56](https://github.com/i-shutov/flowbridge/pull/56).
This is a candidate, **not a release**. The exact source SHA and completed hosted checks must
be read from the PR/current Actions; no historical acceptance transfers between SHAs.
The archived prior narrative is retained separately in
[RUST_CAPTURE_INTEGRATION_CANDIDATE_2026-11-03_ARCHIVE.md](RUST_CAPTURE_INTEGRATION_CANDIDATE_2026-11-03_ARCHIVE.md).

| Gate | Current verdict |
| --- | --- |
| **G0 source / complete release evidence** | **OPEN.** Current source changes require their own hosted CI and independent binary/provenance audits. `release_accepted=false`, `native_response_digest_verified=false`, `raw_backend_512_stability_proved=false`. |
| **G1 historical NDISRD / reverse TCP / SSH** | **ACCEPTED ONLY for product `dd1ab3c5644b4000e75e32385d1322c89240f03c`**: 10/10 controlled sequential signed-driver trials, 230/230 phases, 190/190 closed-origin receipts, 30/30 ZIP audits. **NOT ACCEPTED for current G2 source.** |
| **G2 unprepared EXE packet→PID/epoch** | **OPEN.** No native independent per-frame packet owner witness. No PacketBound producer. IP Helper + pinned process metadata is a *candidate*, not authorization. New read-only Rust flow quarantine and process-exit liveness checks are not native G2 acceptance. |
| **G3 crash-persistent selected-app fail-closed** | **OPEN.** An agent-local gate or NDISRD mode zero cannot prove crash-persistent no-DIRECT. |
| **G4 DNS/UDP/IPv6/QUIC containment** | **OPEN.** Hosted tests alone cannot establish leak-free routing/blocking of selected EXE traffic. |
| **G5 finished Windows product** | **OPEN.** Installer, GUI and service checks do not establish protected routing. |
| **G6 Win10/Win11 native release** | **OPEN.** Real OS-specific, VNC-gated acceptance, soak, rollback and independent owner approval missing. |

## G2 engineering delta in this iteration

The native Windows process-object liveness check had a concrete semantic hole:
`GetExitCodeProcess == STILL_ACTIVE (259)` can also mean the process **already exited
with code 259**. The query-only process handle now additionally asks for
`SYNCHRONIZE`, uses `WaitForSingleObject(handle, 0)` and rejects a signaled
process. The two-snapshot IP Helper candidate lookup refuses a process that
died before or during observation. A real native Windows no-driver regression
spawns a short-lived process that exits with 259 and checks the pinned object.

The NDISRD **LISTEN_ONLY** diagnostic now keeps a bounded, terminal
per-oriented-tuple quarantine for first packet without outbound initial SYN,
missing/ambiguous initial owner, changed PID/creation epoch/path and tuple
reuse. Later snapshots may not resurrect that tuple; IPv4 and IPv6 regressions
cover both. No capture/divert permission is minted. The owned SOCKS relay
also revokes the entire pending lease ledger if destination preflight fails
*before* its async cancellation guard is armed. A dual-stack real-loopback
test checks that an untrusted snapshot cannot dial SOCKS or retain a ticket.

The first code commit [`71769517`](https://github.com/i-shutov/flowbridge/commit/71769517b8013857eabec9c7fd0f63ee19ededaa)
exposed a **hosted compile failure**, not a native-driver failure:
`tokio::net::TcpListener::try_accept` does not exist (E0599).
The test now uses a bounded `tokio::time::timeout(..., accept())`.
The same diagnostic identified rustfmt-only layout differences; both are
corrected in the follow-up source commit. No failed workflow attempt was rerun.

## Evidence boundary and outstanding architecture blocker

The current `capture_pipeline.rs` `OwnerEvidence` is opaque to callers,
production can construct only `snapshot_candidate`, and `begin` and
`rewrite` refuse it. `owned_relay.rs` cannot upgrade that witness. The
read-only `windows_wfp_readonly.rs` enumerates filters, not per-packet owners.
NDISRD packet bytes, IP Helper TCP snapshots, process-handle identity and WFP
filter inventory **do not share a trusted per-frame kernel-origin identity**.
Matching 5-tuples, nearby timestamps or an OS process handle alone cannot
meet G2's packet→PID/creation-epoch proof obligation. A distinct trustworthy
native per-frame owner source and independent validation are still required;
no custom kernel driver was created as a workaround.

No new driver lab was dispatched. Until exact-SHA signed-driver provenance,
fresh VNC proof, SYSTEM rescue, firewall/Defender and rollback gates and an
authorized executor are all verified, native G2 driver activation is forbidden.
Hosted Windows Server tests are **no-driver code QA**, not Win10/11 acceptance.
No main merge, release, firewall, runner-label or automation change.
