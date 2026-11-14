# R182 — retained per-flow reauthorization authority (pure Rust research)

Date: 2026-11-14. Separate experimental follow-up to R181.
**Status: MODEL ONLY; native G2 and protected routing remain NO-GO.**
No changes to main, beta PRs, Windows drivers, system filters or network.

## Actual functional delta

R181 found that kernel R19 Book::attest is one-shot, while Book::take
consumes the context after CLAIM. Simply removing the IS_REAUTHORIZE
flag check cannot create a safe later AUTH. This experiment implements a
**separate retained flow-authority record** in user-mode Rust, without
modifying or arming any WFP callout.

File retained_authority.rs contains:

- A pinned complete Binding: session, policy/BFE/SSH generations,
  transaction and transport endpoint, PID, process-object/file-object
  references, creation epoch, start key, canonical full UTF-16 AppId,
  address family, original destination and compartment. Values are
  SYNTHETIC inputs; the file does not obtain kernel-authenticated identity.
- Lifecycle: Redirected => InitialAuth => Claimed => EgressAttached,
  then zero or more ContinueExisting decisions on reauthorization.
  CLAIM can happen only once, yet its original authorization record is
  retained until terminal revocation; repeated initial AUTH/CLAIM deny.
- CLAIM requires a separately attested accepted socket and exact
  transaction context with bounded nonempty opaque records.
  Pre-connect attach must match exact original records and be reported
  successful before connect. This does not prove a real Winsock IOCTL.
- Re-AUTH requires the same immutable process, canonical AppId,
  epoch/start key, endpoint, original destination, compartment,
  generation and real REAUTHORIZE flag. Reverse-direction reclassification
  can be recognized, but never upgraded to a fresh initial permit.
- Incomplete metadata, FWP_EMPTY, no action-write, stale PID, replay,
  invalid/missing records, post-connect attach, BFE/SSH/policy generation
  changes, monotonic clock reversal, overflow and resource budgets reject.
- Bounded 64 flows, 2048 bytes of record data, maximum 64 re-AUTH
  decisions per flow, no eviction or same-session rearm. Research bounds,
  not production capacity acceptance.

## CI and test contract

- 26 Rust unit tests in retained_authority.rs, including v4/v6,
  reverse-direction re-AUTH, sibling isolation, process-epoch reuse,
  BFE/SSH loss, action-write, context/records and terminal replay tests.
- run_tests.py executes real rustc --test on the host and refuses any
  failure/ignored tests or a suite smaller than 24 tests. It writes JSON
  where native_packet_attribution_proved, native_reauthorization_proved,
  physical_no_direct_proved and release_1_0_accepted are always false.
- Separate r182-retained-authority.yml workflow uses hosted Linux,
  Windows and macOS; no driver, system privilege or network mutation.

Operator command:

    python research/wfp-ale/r182/run_tests.py --report build/r182/report.json

A model-only CI PASS must not be promoted to native G2 or product release.

## Native trust chain still missing

1. OS-owned process/FileObject identity, PID+creation epoch/start key and
   canonical AppId tied to a single native ALE redirect transaction.
2. Original/redirected socket metadata, compartment and reauthorization
   in both directions; unknown fields during re-AUTH may remain FWP_EMPTY,
   in which case this model conservatively refuses continuity. Thus a
   valid connection may still be disrupted; availability not yet solved.
3. Real accepted-socket Winsock redirect records/context and exclusive
   claim; SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS on actual outbound
   socket before connect; no user-supplied byte-array authority.
4. Real WFP arbitration, ACTION_WRITE rights, source/process lifetime,
   policy/BFE and SSH revocation, kernel signing, native selected app egress,
   DNS/UDP/QUIC negative captures, clean stop/rollback on Win10/Win11.
5. A separately approved production kernel backend. Issue #41 still
   authorizes NDISRD-only product; experimental WFP code is not approved
   for integration or execution on the owner's working machine.

References:
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts-asynchronously
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records

**Decision:** This tests a necessary retained authorization state and
falsifies some unsafe designs. It does not close actual R181 source/kernel
callout, G2 PacketBound, no-DIRECT or FlowBridge v1.0.0. No signing,
driver install, BFE/filters, SecureBoot/Defender/firewall, RDP, runner,
user OS or other product changes were authorized or performed.
