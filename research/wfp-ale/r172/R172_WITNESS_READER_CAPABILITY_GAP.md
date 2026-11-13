# R172 — WITNESS reader capability gap (conditional NO-GO)
Date: 2026-11-14. Research-only branch `research/windows-wfp-ale-attribution-20261107`; base f656998099c74c655710008c201af54d53a6d00b; main 5b5afc2feeda2195f302380e615ba003d4906e09 (read-only). Not beta/PR #56/PacketBound/G2/G1/no-DIRECT.

## Finding
The WITNESS IOCTL in R19 is not authenticated to the configured broker. Device SDDL `D:P(A;;GRGW;;;SY)(A;;GRGW;;;BA)` permits read/write access to SYSTEM and built-in Administrators. `wrapper.h` defines `FB_WITNESS_IOCTL=CTL_CODE(FILE_DEVICE_UNKNOWN,0x900,METHOD_BUFFERED,FILE_READ_DATA)`. In `lib.rs::dispatch`, ARM/CLAIM/PING/STOP carry `IoGetRequestorProcess(irp)` to `redirect::ioctl`, but the separate WITNESS branch checks only code and output length, then calls `Ledger::pop()`. `ledger.rs::pop` destructively dequeues before checking `owner.live`.

**Counterexample, conditional on a later producer being connected:** two privileged readers A=another elevated administrator and B=the intended broker; queue contains one live Witness. A's read gets SUCCESS and consumes the record; B's read gets EMPTY. If owner died, A gets NOT_READY but consumes it. This is neither unprivileged access nor proof of current record theft: R165 showed the runtime has **no call to Ledger::observe**, so the present queue has no successful Witness to drain. Scope is a **future repair-path evidence exclusivity/reliability blocker** if the threat model excludes independent privileged readers, not a current exploit, driver execution, WFP failure, packet leak, or PacketBound PASS.

## Exact source, independent checks
- `research/wfp-ale/kernel-r19/kernel/src/lib.rs` SHA1 Git blob `53f5ce6faa0f9f591974287f38ea890cafeb0dd2`
- `research/wfp-ale/kernel-r19/kernel/wrapper.h` SHA1 Git blob `3fc86a6cc03528c1384954490b796bd97f34338c`
- `research/wfp-ale/kernel-r19/kernel/src/ledger.rs` SHA1 Git blob `b88c4c9237c4c118517978fc454f5048f522aa7f` (read through GitHub, not locally source-gated).
- Exact-source gate for first two blobs, 10/10 Python tests normal/-O/-OO, independent Python and Node.js **384/384** row agreement; SHA256 `9d21f2fd27a773ded0a3eb6db792e486afa982296499ce5294a33ecf230e916a`. Two deliberately altered-source controls rejected. The model's no-producer cases have zero successful reads; eight hypothetical producer-wired cases exhibit `admin_other:SUCCESS/broker:EMPTY`. IPv4/v6, epoch and reused 5-tuple are labels, not permission evidence. No real WFP, Windows, driver or Rust execution.
- Reproduce with `python3 research/wfp-ale/r172/r172_witness_read.py -v`, repeat `python3 -O` and `-OO`; `--matrix` outputs JSONL, compare with `node research/wfp-ale/r172/r172_independent.mjs`.

Official Microsoft: [Device SDDL](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/sddl-for-device-objects), [Defining IOCTL](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes), [IOCTL security](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/security-issues-for-i-o-control-codes). More read-right checks such as `WdmlibIoValidateDeviceIoControlAccess` do **not** themselves bind evidence to a broker process identity.

## Next deciding test
Prior to wiring `Ledger::observe`, choose and test broker-exclusive evidence retrieval with referenced requestor identity, session and loss accounting, **or** explicitly downgrade Witness to multi-reader non-authoritative telemetry. An offline Rust source-pinned state-machine/typed-capability test can be compared with this negative oracle without driver access. A kernel-origin ALE/accepted-socket proof still requires separate owner approval and rescue/rollback gates.

Still NO-GO: full `PEPROCESS/FileObject` birth/epoch/start-key + WFP AppId + ALE_CONNECT_REDIRECT/AUTH_CONNECT + compartment/IPv6 scope + redirect context/records + actual accepted-socket WSAIoctl + one-shot CLAIM + physical SSH SET_RECORDS and independently enforced sibling DIRECT; PID reuse, reused 5-tuple, reauthorization, DNS/UDP/QUIC, BFE/SSH loss. No kernel proof or no-DIRECT/leak-free guarantee.

No changes outside this research branch: main/release, beta integration/windows-rust-capture-agent-20261031, PR #56, runner, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, networking, automations, any driver/filter/callout/NDISRD/VNC/SYSTEM experiments. No ProxiFyre AGPL, closed PR40, vendor binaries, C++ WFP payload, or paid work.
