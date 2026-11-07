## Owner-approved limited beta — explicit SOCKS5 + supervised OpenSSH (2026-11-07)

**Scope decision:** limited **SOCKS-only beta** is authorized; a transparent
Windows WFP/ALE proof is a separately scheduled research track in
`research/windows-wfp-ale-attribution-20261107` based on main. Research has
no authority to alter PR #56, activate a driver/filter, or claim G2 acceptance.

**Functional implementation:** Draft PR #56 includes `flowbridge serve-managed
--config <profile.json>` in `flowbridge-cli`; initial functional commit
`31b34a03c491d191885d75669f71968e1fa7eb5b`. This is one foreground
user-owned Rust SOCKS5 listener with a supervised external OpenSSH `-D`
upstream. Before binding the listener, the upstream gate is CLOSED. The gate
opens only for a supervised ready SSH child and closes on observed loss.
Initial connection rejection and reconnect do not substitute DIRECT.
Shutdown independently attempts gate closure, Engine stop and SSH stop.

**Enforced explicit-mode contract:**
- Exact `RUST_MANAGED_SSH_SOCKS_CANDIDATE` consent and bounded strict JSON.
- One local SOCKS5 hop at `127.0.0.1`; one default PROXY only, no DIRECT,
  chains, app-specific rules, or implicit proxy authentication.
- Explicit absolute SSH binary, key and pinned known_hosts paths; strict
  host-key validation belongs to OpenSSH. Engine and SSH configuration must
  independently validate. Maximum 128 concurrent SOCKS sessions.
- Supplied SOCKS hostname targets remain hostnames through the proxy;
  FlowBridge does not take ownership of independent application DNS.
- Never claims OS interception, trusted originating PID, DNS/UDP/QUIC coverage,
  protection against application bypass, system-wide physical no-DIRECT,
  system kill-switch, or native WFP/NDISRD acceptance.

**QA and release matrix:** code compilation/format/Clippy/unit tests and any
real hosted SSH traffic are exact-source CI obligations, not automatically
accepted on a pushed commit. Failed G2 ETW `kernel_connection_id_missing`
and existing raw512 characterization remain separate OPEN/FAIL observations.
G0 is OPEN until full exact-source CI and artifact provenance are reviewed;
G1 10/10 stays historical **only on product `dd1ab3c`**; G2 is OPEN/NO-GO
for per-NDISRD-frame PacketBound; G3–G6 require beta-scope-specific acceptance
and remain OPEN. `release_accepted=false`,
`native_response_digest_verified=false`, and
`raw_backend_512_stability_proved=false`.

No driver/native trial was run for the beta CLI change. Any future G2 native
experiment still needs the original independent VNC, signed-driver, SYSTEM
rescue, defender/firewall, exact-SHA and rollback gates.

---

## G2 independent kernel connection evidence — 2026-11-06

A new bounded no-driver collector (`tests/g2_etw_owner_probe.py`) replaces
IP Helper as the source in this independent experiment. It records built-in
Kernel-Network, TCPIP and Networking-Correlation ETW providers while four
unmodified System32 curl processes connect over IPv4/IPv6. Query-only process
handles bind each observed payload PID to its live creation epoch and exact
system executable. Header `Execution/ProcessID` is never treated as socket
owner. Trace loss, unknown accounting, incomplete client evidence, duplicate
payload fields and stale/recycled process epochs fail the experiment.

The collector is guarded to disposable GitHub-hosted Windows, uses one private
transient ETW session, changes no driver/filter/service/audit-policy settings,
and removes its raw ETL/XML and all owned resources. Only a sanitized JSON
verdict is uploaded. Fifteen synthetic verifier tests pass locally; this is
NOT evidence that the native collection already succeeded. The existing
capture workflow now has an explicitly named independent ETW job; no new
trigger, branch or self-hosted dispatch is introduced.

### Remaining exact trust boundary (do not waive)

Successful ETW evidence would establish **kernel connection → payload PID →
live process epoch/path**, not **specific NDISRD delivery → that connection**.
The documented NDISRD `INTERMEDIATE_BUFFER` carries bytes, direction, flags,
VLAN and filter index, but no TCP connection cookie, process epoch or ETW
activity lineage. `connid` in TCPIP events identifies that connection only.
An ETW activity transfer graph may join ETW events across layers; it does not
by itself attach the graph identity to the separately returned NDISRD object.
A byte hash, tuple, ISN, timing match or WFP rule presence cannot silently fill
this gap. ETW also allows event loss. Production `PacketBound` remains sealed.

References (primary sources):
- https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_intermediate_buffer/
- https://learn.microsoft.com/en-us/windows/win32/etw/tcpip-sendipv4
- https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing
- https://www.digitaloperatives.com/2012/10/16/process-attribution-in-network-traffic/
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-context

A stronger transparent-routing backend would need a trusted kernel endpoint /
connection identity delivered with redirected data and process lifetime, such
as an ALE redirect context. Microsoft documents that this comes from a kernel
callout, not a user-mode filter inventory. Introducing a different signed
backend or a custom callout is an architectural change, NOT authorized by the
current NDISRD-only scope. Until independently demonstrated, G2 is OPEN and
protected arbitrary-EXE routing stays disabled. The safe existing explicit
SOCKS path is not relabeled as transparent-mode acceptance.

Historical G1 acceptance remains tied to `dd1ab3c` only. G0/G2–G6 OPEN;
`release_accepted=false`. No additional native driver trial is authorized.

---

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

## G2 fail-closed selected-packet boundary — new functional source (2026-11-06)

`capture_pipeline.rs` now **permanently shuts down** all selected-flow leases on
wrong adapter, mismatched frame tuple, malformed selected frame, transactional
rewrite rejection, or ambiguous owner/ticket in destination/retire. No rejected
frame is rewritten; the old session cannot be revived by a later accepted
snapshot, and no rejected path converts to DIRECT. New dual-stack tests
exercise these negative states with synthetic test-only PacketBound. This
hardens the *post-admission* fail-closed enforcement; it **does not create**
a native PacketBound producer, independently prove packet→PID/creation-epoch,
or establish physical no-DIRECT on a real Windows adapter.

Current-source hosted CI and independent reviewer evidence are required before
even code-level QA can be accepted. Historical G1 acceptance remains pinned to
`dd1ab3c5644b4000e75e32385d1322c89240f03c`. G0 and G2–G6 stay OPEN.

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

Additional functional G2 fail-closed hardening: [`125470f0`](https://github.com/i-shutov/flowbridge/commit/125470f0aa163d88539af7ab2336bc278fb25134) stores the outbound SYN initial sequence alongside each *read-only* process candidate. A later SYN with a different ISN, or FIN/RST on either leg, permanently quarantines that tuple before another owner lookup; exhausting the 24-snapshot budget invalidates an earlier positive candidate instead of leaving stale state. Exact-sequence retransmits and unrelated sibling tuples remain observable, never authorized. Five new multi-family negative/continuity tests check IPv4/IPv6, tuple recycle with identical PID/epoch/path, FIN/RST, budget exhaustion and sibling isolation. Linux hosted capture unit tests at the initial commit passed **75/75**, while the strict format gate rejected test layout (not a runtime assertion). This is a source-format RCA, not native attribution evidence. The subsequent source commit applies the exact rustfmt diff; hosted results are separately pinned to their final SHA. No driver was activated.

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
