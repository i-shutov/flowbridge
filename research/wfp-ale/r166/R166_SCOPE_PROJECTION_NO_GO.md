# R166 — identity projection omits three routing scope dimensions

Research-only evidence, 2026-11-13. Exclusive branch: research/windows-wfp-ale-attribution-20261107. No driver, WFP filters, native ALE traffic, PR #56, beta or release acceptance.

Pinned R19 blobs: handoff.rs e1d17217db50362ba9c4efc83af820b6beb094cf, redirect.rs a093f049d162987981a957aac90db1014bc6ff09, lib.rs 53f5ce6faa0f9f591974287f38ea890cafeb0dd2.

The 128-byte FBR3 Context and Origin bind PID, epoch/start key, endpoint numeric handle, owner generation, original target, family, session/sequence/time. They do not encode network compartment, parent endpoint handle or IPv6 remote scope. Book::attest has no such comparison. R19 does not read those dimensions in redirect/auth classify.

Microsoft's documented metadata-layer table lists PARENT_ENDPOINT_HANDLE at both ALE_CONNECT_REDIRECT v4/v6 and ALE_AUTH_CONNECT v4/v6. COMPARTMENT_ID and REMOTE_SCOPE_ID appear for AUTH_CONNECT, but are not listed for CONNECT_REDIRECT. This describes documented availability, not a native proof of absence on every Windows version. See https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer and https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-field-identifiers .

Executable tests: Python 5/5, independent Node.js 18/18 projection pairs, parsed JSON comparison 18/18, mutation of Python compartment serialization caught 6 differences. Two local full-source Git blobs match, third handoff blob inspected through GitHub; full checkout source-gate, Rust compilation and native Windows classify NOT RUN. Matrix SHA-256 1c6e08528e7f7a749173ae9fd37f5d738f9a1085a47de11bedaf78015a6e4445.

IMPORTANT: Fixed session/sequence/time cross-event projections are COUNTERFACTUAL. Book increments sequence and tombstones endpoints. Equality of the two model projections is not proof of Windows reusing handles across compartments, cross-compartment authorization, DIRECT leak or exploit. It shows only that R19 itself does not establish the scope invariant. Missing OS guarantees must not be filled with PID/tuple/time correlation.

Offline:
python3 research/wfp-ale/r166/r166_scope.py
node research/wfp-ale/r166/r166_independent.mjs
python3 research/wfp-ale/r166/r166_scope.py --source-gate research/wfp-ale/kernel-r19/kernel/src

Next decisive experiment: independently authenticated, native multi-layer REDIRECT/AUTH events showing endpoint handle, parent endpoint handle (when valid), compartment and remote scope (at AUTH if valid), AppId, PID/epoch, final action and actual accepted-socket WFP records. Without owner-approved driver/SYSTEM rescue/rollback gates this experiment is NO-GO; read-only source-pinned models do not substitute it.

Current global NO-GO remains: kernel-to-accepted-socket attribution, witness producer (R165), PID/endpoint ABA, reauth, IPv4/6 scope, sibling DIRECT, DNS/UDP/QUIC, WFP/BFE/SSH loss. PacketBound/G2 PASS and leak-free NOT claimed.
