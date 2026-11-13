# R173 — conditional WITNESS consumer/backpressure NO-GO

Date: 2026-11-14. Research-only: i-shutov/flowbridge, research/windows-wfp-ale-attribution-20261107. Not beta, PR #56, PacketBound/G2, leak-free or historical G1.

## Source-level result

Baseline research 8bc41518be1c6c98480b319d3c194e8f839b4654; read-only main 5b5afc2feeda2195f302380e615ba003d4906e09.

R165 already established that the current R19 runtime has no Ledger::observe producer, so real ALE traffic does NOT presently populate the WITNESS queue. This finding is specifically about the proposed repair of R165, not a witnessed Windows failure.

- kernel/src/ledger.rs blob b88c4c9237c4c118517978fc454f5048f522aa7f: MAX_RECORDS=32; the 33rd undrained successful observe attempt latches Ledger.lost=true. Once lost, pop returns Lost and lookup returns None.
- kernel/src/lib.rs blob 53f5ce6faa0f9f591974287f38ea890cafeb0dd2: the kernel has an FB_WITNESS_IOCTL reader invoking destructive Ledger::pop(), but no runtime observe caller.
- broker_windows.rs blob 329ef14b63e70226bfad7372b0014559213abd04: Device::command permits only ARM, CLAIM, PING and STOP. Its one DeviceIoControl invocation is restricted to those commands. Accepted-socket WSAIoctl redirect-record/context queries are a separate facility and do not drain WITNESS.
- User-mode source-closure check additionally covered broker.rs (6163e84aea08ddde7e51a7fb94ccb6d68ae951fb), broker_lifecycle.rs (211b5e5cee03f4d8ea13fc23e1be0777cbfa09c1), policy_plan.rs (0c3d0e88eb9d06f4030131d9533da2d629dbdab0), policy_windows.rs (acf60334320d970f58af3349ee75fbaa59826602), transport.rs (414458795896f02ac7f6c92ec5f455b9268551e4), trusted-ssh-r37/src/lib.rs (c6d8c8746fac45073c11557de893164e49d830eb) and the broker-package manifest. No WITNESS consumer in the compiled user-mode source closure.
- kernel/src/redirect.rs blob a093f049d162987981a957aac90db1014bc6ff09: ready() checks Ledger::lookup(broker PID), so a lost ledger causes lose() and Book::kill() upon the next ready/heartbeat.

Conditional consequence: simply adding one valid Ledger::observe for each selected event while leaving the broker unchanged lets 32 sequential successful observations accumulate; on the 33rd, the queue poisons the driver ledger. A reader added only after overflow cannot recover. This is an integration/availability NO-GO, not proof of a current driver failure, a network leak, or a live ALE count. Successful observations are not synonymous with all connection attempts; other existing fail-closed limitations apply.

## Independent offline tests

Python stdlib 8/8 PASS in normal, -O and -OO modes. Independent Node.js FIFO oracle: 84/84 byte-identical JSON rows (IPv4/v6 x producer on/off x no reader/each/late x 0,1,31,32,33,34,40 events). Matrix SHA-256: 85ddba426a05c2e838ecb4e8ab2b93183d2651ce6b36b97db9b39c70991a908d. Actual current no-producer condition never enqueues. Hypothetical undrained 32 events: healthy/full; 33: lost; late drain cannot recover; hypothetical continuous reader avoids queue-full in this abstract model.

Files: r173_witness_backpressure.py (unit tests + pinned Git blob/source checker) and r173_independent.mjs (independent FIFO oracle). The exact source snapshots were independently read through the GitHub connector; full local checkout source gate NOT run, as no full checkout was available in isolated runtime. Two snapshot Git blob SHA/mutation checks passed. Rust compiler and native WFP were NOT run; these are deterministic negative models, not kernel or Rust proofs.

## Trust boundary / decisive experiment

Before wiring runtime observe, define broker-exclusive vs non-authoritative diagnostic readers; validate original IRP requester with IoGetRequestorProcess and a lifecycle-bound process/session capability; preserve sequence/ack, queue loss, PID+creation epoch+start key and process-death semantics; test slow, dead, competing privileged, and post-overflow readers. R172 also blocks simply exposing destructive reads to any permitted administrator. A clean-room Rust user-mode/no-driver state-machine test with an independent oracle is the next permitted experiment. Native ALE proof is still subject to separate driver/VNC/SYSTEM rescue/rollback gates and owner authorization.

Unproven chain: referenced PEPROCESS/FileObject plus canonical EXE and process epoch/start key -> original/current WFP AppId at ALE_CONNECT_REDIRECT_V4/V6 and ALE_AUTH_CONNECT_V4/V6 -> endpoint/compartment/IPv6 remote scope and redirect context -> accepted socket SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT -> terminal CLAIM -> SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS on actual SSH socket. PID/endpoint reuse, reused 5-tuple, reauthorization, sibling DIRECT, DNS/UDP/QUIC, BFE/SSH-loss remain NO-GO.

Official Windows API: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection ; https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-iogetrequestorprocess ; https://learn.microsoft.com/en-us/windows-hardware/drivers/network/sio-query-wfp-connection-redirect-records ; https://learn.microsoft.com/en-us/windows-hardware/drivers/network/sio-set-wfp-connection-redirect-records .

Scope exclusions: no main/release, integration/windows-rust-capture-agent-20261031, PR #56, runner, driver, callout, WFP filter, NDISRD, VNC, signed-driver, SYSTEM, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, services, networking modifications, paid operations, automation changes, ProxiFyre AGPL, PR40, vendor binaries, or C++ WFP payload.
