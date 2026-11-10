# R88 — Conditional self-block: original-AppId on record-tagged SSH

Date: 2026-11-10. Independent FlowBridge WFP/ALE R&D, research branch only. Not beta, PR #56, PacketBound/G2 PASS, no-DIRECT/leak-free, or historical G1 acceptance.

## Source pins and concrete conflict

Initial research HEAD: `ec6f6d018594d3479ebdcd1b276db09bc37b5242`; main: `5b5afc2feeda2195f302380e615ba003d4906e09`. Exact blobs:
- `kernel-r19/policy_windows.rs`: `acf60334320d970f58af3349ee75fbaa59826602`
- `kernel-r19/kernel/src/redirect.rs`: `9a07e026134d46ef646d39862bd982cc48bbc5f6`
- `kernel-r19/broker_windows.rs`: `16ec8853d322b40f0e00e14d49ae3410741b9395`

`policy_windows.rs` installs TCP filters for the selected opaque `FWPM_CONDITION_ALE_ORIGINAL_APP_ID` at both `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`; they use `FWP_ACTION_CALLOUT_TERMINATING`. `redirect.rs::auth_check` rejects a non-loopback remote destination, and `auth_classify` blocks failed checks. The `Received::claim_and_connect_trusted_ssh` broker path calls `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on an **IPv4 physical SSH socket before connecting it to a remote SSH server**; the original IPv4/IPv6 destination is later carried inside the authenticated SSH `direct-tcpip` channel.

**Conditional source-derived self-block:** If WFP classifies that record-tagged SSH connection with `ALE_ORIGINAL_APP_ID == selected EXE`, the selected-app AUTH filter matches and the SSH remote endpoint fails the loopback test. Actual enforced block additionally depends on action-write/veto provenance and live native classifier conditions (R85/R86). If the connection instead has `ALE_ORIGINAL_APP_ID == broker`, that filter does not inspect it, but this does not prove inherited original ownership. Unknown provenance remains unknown. Neither branch is proved by `SIO_SET` returning success. No actual Windows callback or network fate is claimed.

This is distinct from selected application's sibling DIRECT attempts, which also may match the selected filter and reject non-loopback; blocking one *synthetic* path does not demonstrate a universal no-DIRECT guarantee. Microsoft documents `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on the new socket **to the final destination**; treating an SSH-server endpoint carrying the final destination inside a tunnel as equivalent is **outside an established documented guarantee**.

## Executable deterministic negative checks

Run from a full checkout at the research HEAD:

```sh
python3 research/wfp-ale/r88/r88_ssh_origin_collision.py
node research/wfp-ale/r88/r88_ssh_origin_independent.mjs
```

Independent Python/Node models cover 192 ordered states: IPv4/IPv6 × `SELECTED/BROKER/UNKNOWN` original-AppId observation × loopback/remote × redirected flag × metadata × action-write right × ticket. Results: `SOURCE_BLOCK=30`, `AUTH_CANDIDATE=2`, `RIGHTS_UNPROVEN=32`, `FILTER_NOT_SELECTED=64`, `UNKNOWN_FILTER_MATCH=64`; full ordered SHA-256 `6764f67ccb750eee4e619ad31ab770d721aec475e7b920afb07e80965e39a335`. SOURCE_BLOCK is a conditional **source-code branch**, not an observed Windows veto. AUTH_CANDIDATE is never a physical GO.

Independent local execution of the R88 package before publication: Python 6 PASS / 1 SKIP (full repo checkout unavailable), Node 192/192 identical and same digest. Separately checked nine literal source contracts against the *actual* fetched GitHub blobs: 9/9 PASS. No Rust compiler or Windows native execution; no driver/filter/packet changes. The optional source-contract unittest executes only in a full checkout and reports SKIP elsewhere.

## Trust chain and explicit limits

An actual GO would require kernel-origin `ALE_CONNECT_REDIRECT_V4/V6` process evidence (PID, creation epoch/start-key, exact AppId and referenced `EPROCESS`), original destination and endpoint generation, `ALE_AUTH_CONNECT` with valid metadata/action rights, `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT)` on the **actual accepted socket**, terminal one-use `CLAIM`, `SIO_SET` on the outbound socket, native classification evidence for physical SSH, authenticated pinned-host-key SSH, and independently effective selected-app sibling flow controls. AppId and redirect records alone are not a kernel-authenticated receipt-to-CLAIM chain. Preserve NO-GO for PID reuse, process death, 5-tuple reuse, sibling DIRECT, IPv4/IPv6 physical coverage, UDP/DNS/QUIC, BFE/WFP/SSH loss, PacketBound/G2 and leak-free.

The **decisive** experiment is classification-time evidence for both families comparing: (a) tagged physical SSH, (b) untagged physical SSH and (c) real redirected accepted loopback. Capture `ALE_ORIGINAL_APP_ID`, actual remote endpoint and prior action/right provenance. Any such kernel/WFP driver/filter/callout test is **outside authorization** without a separate owner decision and driver/VNC/SYSTEM rescue/rollback gates. An allowed read-only user-mode R83 WinSock test cannot decide R88.

Official Windows contracts:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-
- https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_classify_out0

Isolation: never touch main/release, `integration/windows-rust-capture-agent-20261031`, PR #56, runners, services, firewalls/UFW, Defender, SecureBoot, MemoryIntegrity, networks, other repositories or automations. Do not create/install/run drivers/callouts/WFP filters/NDISRD/VNC tests, vendor binaries, ProxiFyre AGPL, closed PR40 or C++ WFP payload.
