# R207 — stale AUTH ticket after ALE reauthorization: source-level conditional NO-GO

2026-11-16. **ONLY** research/windows-wfp-ale-attribution-20261107. Source parent: 6e1e01dd1e9b9b5922b9d3cf17fbd71cfc9ba26d; main observed read-only: 5b5afc2feeda2195f302380e615ba003d4906e09. Not beta, PR #56, packet G2, leak-free or native kernel evidence.

## Finding

Pinned R19 Git blobs: redirect.rs a093f049d162987981a957aac90db1014bc6ff09; handoff.rs e1d17217db50362ba9c4efc83af820b6beb094cf. An initial valid AUTH sets Book slot.auth_seen=true. AUTH_CHECK rejects an ALE reauthorization (IS_REAUTHORIZE bit 0x4), and auth_classify calls block(out), but neither that rejection nor a subsequent malformed AUTH retires the live slot. A later broker CLAIM can still pass Book.take using the earlier auth_seen flag, provided the ticket/lease/TTL and origin are otherwise valid. A bad AUTH before the first good AUTH likewise does not retire the issued ticket. R201/selective_ledger.rs (blob bc4c02daf2f09609cfa11b595d842e5ad2608625) reproduces this retention. R13_REAUTH_INVALIDATION.md already fixed this *category* of bug in the earlier R7 model, so no novelty is claimed for Windows.

**Critical limitation:** BLOCK at WFP might tear down the actual socket before such a CLAIM could occur. This is a conditional **state-evidence counterexample**, NOT a demonstrated native ordering, DIRECT leak, kernel exploit or SSH egress. No driver, WFP filters, BFE objects, network or system modifications were made. It means terminal CLAIM is not internally bound to latest AUTH revocation in the pinned R19 implementation.

## Tests and evidence

Python r207_reauth_negative.py: six unit methods with v4/v6, reauth before/after initial, malformed metadata/original AppId, independent endpoint, epoch mismatch, one-shot and loss. Independent Node r207_reauth_oracle.mjs: 13 distinct scenario traces. Both compare the R19-equivalent retained-evidence behavior against a stricter endpoint-terminal alternative. Tests PASS only if the *negative counterexample* is reproduced; they are NOT a passing WFP safety gate.

Run from a full research checkout:
    python research/wfp-ale/r205/r207_reauth_negative.py --source
    node research/wfp-ale/r205/r207_reauth_oracle.mjs --source

--source verifies pinned Git blob SHA-1 and eight structural guards in each runtime. Executed in authoring environment: Python 7/7 on expanded checkpoint, Node 13/13, python py_compile and node --check PASS; nine read-only, exact-Git-blob source checks independently PASS via GitHub connector. The committed compact Python variant has six tests. No rustc, Windows, native classify or BFE execution here.

Files deliberately stay inside existing R205 research tooling allowlist; no change to pinned R19/R201 blobs or R203v6 collector lineage gate.

## Trust chain / next decision

Only a native classify record from FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6 and FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6 could authenticate per-flow PID/epoch/start key/AppId, referenced EPROCESS/FileObject, endpoint handle, redirect flags, original destination, reauthorization and endpoint closure. It must then be linked to the actual accepted socket via WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT), one-shot kernel CLAIM, and outbound SSH socket via SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS. None is established here.

Microsoft references:
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ale-endpoint-lifetime-management
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking

Proposed trust invariant (not implemented in kernel): once any **verified same-endpoint** AUTH reauthorization or invalid evidence occurs, retire and tombstone its pending claim. If authentic endpoint identity is unavailable, don't guess via PID/5-tuple; conservatively revoke a bounded affected session. Reauthorization can have FWP_EMPTY fields. Repeated 5-tuples, PID reuse, unrelated sibling DIRECT, IPv4/v6 compartments, DNS/UDP/QUIC, WFP/SSH loss, R198 SSH self-block and R202 dynamic policy disappearance remain open.

Next allowed experiment remains R201/R202 standalone Rust tests and optional read-only R199 BFE scan on approved Win10 Pro x64; native reauth-to-CLAIM experiment requires separate owner approval for kernel/driver/VNC/SYSTEM safety and rollback gates. **Architectural WFP/SSH NO-GO, no PacketBound/G2 PASS or leak-free claim.**
