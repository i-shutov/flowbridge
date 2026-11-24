# R225 — AUTH originalDestination: family-before-extent safety precondition

2026-11-24. Sole scope i-shutov/flowbridge research/windows-wfp-ale-attribution-20261107. Parent c6155a2a0d851b8b409cdd50a5607082561abe05; read-only main 5b5afc2feeda2195f302380e615ba003d4906e09. Not beta, PR #56, driver QA, G2 or PacketBound PASS, historical G1, no-DIRECT or leak-free.

## Narrow source finding, conditional only

R19 kernel-r19/kernel/src/redirect.rs Git blob a093f049d162987981a957aac90db1014bc6ff09: auth_check derives socklen (16 or 28) from the ALE layer, checks metadata presence and non-null originalDestination, copies socklen bytes via ptr::copy_nonoverlapping, then calls destination(&storage,family), which checks the actual family in the copied bytes. The family check is too late to establish the preceding read's extent. Five source anchors independently checked against that exact blob.

Microsoft's FWPS_INCOMING_METADATA_VALUES0 declares originalDestination as SOCKADDR*, not SOCKADDR_STORAGE*; the description gives the original redirected destination but no separate byte length or explicit same-family allocation guarantee in that description. SOCKADDR_IN is 16 bytes, SOCKADDR_IN6 is 28 bytes. If a V6 indication were accompanied by a valid 16-byte AF_INET originalDestination, the existing copy would require 12 more readable bytes BEFORE rejecting the mismatch. This is a conditional memory-contract counterexample, NOT evidence Windows supplies that combination, an exploitable crash, native memory violation, bypass or DIRECT. The documented mapped IPv6 scenario from R216 is not evidence for a short AF_INET pointer. If the platform contract guarantees the extent independently, the counterexample is unreachable. R120/R215/R216 do not establish that guarantee.

A future adapter needs the trusted extent and lifetime of the metadata pointer. Under the documented family-tagged SOCKADDR layout, inspect the family first and reject mismatch before a larger read; this still relies on provider validity and sufficient extent of a matching-family object. A value-only bounded parser cannot certify a native pointer; never infer length from arbitrary bytes, use speculative probing, or treat a non-null pointer as a full storage allocation.

## Executed independent negative tests

Python byte-fixture model and independent Node decision table, 30 rows each; six rows where copy-first needs an unproven extent and family-first rejects. Of those, the meaningful well-formed alternative-family witness is V6 + AF_INET + 16 bytes; truncated/unsupported fixtures exercise only the generic parser contract. MATCH means family and length only, not a valid destination, AUTH, CLAIM or flow. No unsafe read or native calls executed.

Both ordered matrices SHA-256: 275cd2d8abe19838fb3625e46f88eba8c17b477954930ad3da7c0f15bd57654c. Python/Node execution, py_compile and node --check passed after correcting the initial expected count from 10 to 6. Exact tested Git blobs: negative.py 675532f3bec39b3e5f2f2935c99131c312547fba; independent.mjs 5fc5cf6589ae05d962a0a94679419004beb25411.

    python3 research/wfp-ale/r225/negative.py
    node research/wfp-ale/r225/independent.mjs

## API boundary and next decision

Referenced EPROCESS/FileObject from PsSetCreateProcessNotifyRoutineEx -> PID/creation epoch/start key/canonical EXE, exact opaque AppId via FwpmGetAppIdFromFileName0 -> ALE_CONNECT_REDIRECT V4/V6, FwpsQueryConnectionRedirectState0 and writable request -> ALE_AUTH_CONNECT V4/V6, originalDestination family/extent, final WFP arbitration -> actual accepted socket SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS -> terminal CLAIM -> outbound SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS and authenticated physical SSH. No proof for any complete native chain, process death/PID reuse, re-used 5-tuple, sibling DIRECT, DNS/UDP/QUIC or WFP/BFE/SSH loss.

Next allowed deciding action remains compiling existing std-only Rust models in a trusted offline environment. rustc/cargo absent. For this new conditional boundary, seek authoritative WFP metadata extent/family guarantee before native implementation approval. No driver/callout creation or modification, native experiment, filters, runners, infrastructure, other branches/repos, PRs, paid operations or automation changes.

Official contracts consulted:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_incoming_metadata_values0_
- https://learn.microsoft.com/en-us/windows/win32/winsock/sockaddr-2
- https://learn.microsoft.com/en-us/windows/win32/api/ws2def/ns-ws2def-sockaddr_in
- https://learn.microsoft.com/en-us/windows/win32/api/ws2ipdef/ns-ws2ipdef-sockaddr_in6_lh
