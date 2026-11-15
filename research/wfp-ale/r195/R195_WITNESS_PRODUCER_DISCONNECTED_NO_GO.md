# R195 — legacy WITNESS producer disconnected in R19 (source-level NO-GO)

Date: 2026-11-15. Independent WFP/ALE R&D in research/windows-wfp-ale-attribution-20261107 only; not beta, PR #56, PacketBound/G2 PASS, native driver acceptance or leak-free evidence.

## Pinned source, exact trust boundary

Input research HEAD: a74a32862ae22c63bdfda8c93075558b5d93d961. Read-only main: 5b5afc2feeda2195f302380e615ba003d4906e09.

- kernel-r19/kernel/src/lib.rs, Git blob 53f5ce6faa0f9f591974287f38ea890cafeb0dd2: process-event path calls Ledger::born/died; classify callbacks call redirect::classify/auth_classify; device dispatch handles FB_WITNESS_IOCTL by (*STATE.0.get()).pop(). No production Ledger::observe call.
- kernel-r19/kernel/src/ledger.rs, Git blob b88c4c9237c4c118517978fc454f5048f522aa7f: initial queue count=0. Only Ledger::observe enqueues Witness and increments count. Ledger::pop returns Ok(None) at count=0. Positive ledger unit tests explicitly call observe, unlike production.
- kernel-r19/kernel/src/redirect.rs, Git blob a093f049d162987981a957aac90db1014bc6ff09: distinct handoff::Book issue/attest/take ticket path; no Ledger::observe call. Remaining declared modules handoff.rs, auth_appid.rs, action_rights.rs contain no such producer.

Finding: pinned ordinary R19 Rust execution graph provides no means to enqueue the legacy read-only WITNESS receipt. Consequently its IOCTL cannot yield a positive receipt after successful ordinary classification; it returns EMPTY or a loss/error state. This is source-level disconnected functionality, not observed on native Windows. It does NOT show that newer accepted-socket / CLAIM path is dead — it uses a distinct Book mechanism. Nor does it prove DIRECT leakage. Do not replace missing evidence with PID+5-tuple correlations.

## Reproducible independent negative tests

r195_negative.py and r195_independent.mjs inspect the exact Rust module graph, reject a changed/unknown graph, verify queue write/read locations and count production calls to observe. Python mutation test inserts observe into a production source and must flip the verdict; adding an unknown module must error. Both report NO_RUNTIME_WITNESS_PRODUCER for the pinned sources. These are conservative lexical/source checks, not a Rust compiler call graph, kernel scheduling proof or Windows API observation. Hidden dynamic producer code would require re-review.

Commands in clean checkout:
- python3 research/wfp-ale/r195/r195_negative.py
- python3 research/wfp-ale/r195/r195_negative.py --test
- node research/wfp-ale/r195/r195_independent.mjs

## Required external proof and next decision

Trust chain remains: process-create callback + referenced EPROCESS/FileObject + PID/creation epoch/PsGetProcessStartKey + canonical EXE -> WFP ALE_CONNECT_REDIRECT_V4/V6 appId/endpoint -> FwpsAcquireWritableLayerDataPointer0, redirect handle/context -> ALE_AUTH_CONNECT_V4/V6 with genuine action rights -> WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT) on exact accepted socket -> terminal CLAIM -> SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS on physical broker socket -> SSH.

A BFE inventory via FwpmEngineOpen0, FWPM_TXN_READ_ONLY and FwpmFilterEnum0 reports visible policy, not actual callbacks. Selected sibling DIRECT, PID reuse, reused 5-tuple, IPv4/IPv6, process death, DNS/UDP/QUIC, other redirect providers, reauthorization and WFP/SSH loss remain unproved.

Next decisive safe experiment: run both source checks in an independent clean checkout and verify byte-identical JSON plus Python mutation test; independently compile R190 Rust (read-only, no driver) on an already admitted Windows 10 Pro x64 host and record OS/toolchain/bin SHA, BFE API codes and ACL gaps. Architecturally decide whether legacy WITNESS is required. If yes, implement a real same-ALE-classify producer, not correlation, in a separately authorized implementation track; if deprecated, remove it from acceptance claims.

No driver/callout/filter installation, NDISRD, WFP policy, signed-driver work, network/sockets, VNC/SYSTEM, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, services, runner, main/release, beta, PR #56, other repositories or automation state are touched. No ProxiFyre AGPL, closed PR40, vendor binaries or C++ WFP payload.
