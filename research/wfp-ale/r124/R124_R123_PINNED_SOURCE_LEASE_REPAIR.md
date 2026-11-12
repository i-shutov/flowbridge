# R124 — native source-attestation blocker repaired

2026-11-12. Research scope only: `research/windows-wfp-ale-attribution-20261107`. Parent `99d930444223a78a3e1f4c1eaec0f043a1f7bad8`; main observed read-only `5b5afc2feeda2195f302380e615ba003d4906e09`. Not beta, PR #56, G2 or release.

## Material reproducer

R123 changed R103 source to detect lower-weight same-sublayer CONNECT_REDIRECT filters. Its Git blob became `06c677b484ef2cf5fa0330f819524dfa6b52e55a`, verified independently by git hash-object and GitHub fetch_file. R112's Windows PowerShell 5.1 harness still demanded pre-R123 `49506ca07145c18947a0845f2a1a63b3de1f54ec`. Therefore any unmodified R123 checkout would fail Git-BlobSha1 before rustc, including after strict CRLF normalization: a deterministic false reject.

R124 changes only the pinned blob literal in R112, preserving the byte-for-byte Git blob attestation, CRLF-only canonicalization, explicit opt-in read-only BFE, fail-closed error paths, and exit codes. No driver/kernel/BFE/network behavior changes.

## Independent negative evidence

- Local Python stdlib unittest: **7/7 PASS**, checks exact source/pin, old pin rejected, CRLF accepted, 100 deterministic 1-bit source mutations rejected, 3 truncation/addition/BOM mutations rejected, PowerShell guards and non-GO defaults.
- Independent Node.js crypto oracle: source blob/pin agree, CRLF accepted, **103/103 negative mutations rejected**. Git CLI independently confirms the source blob. R103 source SHA-256: `8ed15e5feb531947802dcaec1971c3a7f9b80da8fae95e213b302072b540c2d2`.
- **NOT RUN:** Windows PowerShell parser, native Windows x64 rustc/ABI, actual BFE enumeration or packet-level WFP classify. Source hash consistency is *not* kernel identity, driver signing, PacketBound/G2, no-DIRECT or leak-free proof.

## Remaining trust chain / explicit NO-GO

`FwpmGetAppIdFromFileName0`, exact `FWPM_CONDITION_ALE_APP_ID` and `ALE_ORIGINAL_APP_ID` → real `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6` classify and `FwpsQueryConnectionRedirectState0` with PID + referenced process epoch/start key/canonical EXE, original destination, endpoint and redirect state → `FWPS_CONNECT_REQUEST0` / `FwpsApplyModifiedLayerData0` → real `ALE_AUTH_CONNECT_V4/V6` authorizations including reauthorization → actual accepted socket `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT)` → one-use kernel CLAIM → `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on the outbound socket → SSH `direct-tcpip` with authenticated egress. These are separate unproven stages. IPv4/v6 compartments, PID reuse/death, 5-tuple reuse, sibling DIRECT, DNS/UDP/QUIC and WFP/BFE/SSH loss remain NO-GO.

Next authorized decisive experiment: exact native x64 metadata-only PowerShell/Rust R112 check on already permitted Windows 10 Pro, capture raw/normalized Git blobs, rustc -vV, exit code and evidence JSON; synthetic tests only with explicit switch. Read-only BFE separately optional and still UNKNOWN/candidate, not kernel proof. Physical classify requires independent owner driver/VNC/SYSTEM rescue/rollback approval.

Official Microsoft docs checked 2026-11-12:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilterenum0

All prohibited branches/PRs, runner, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, networks, scheduling/automations, kernel driver/filter, NDISRD, VNC, ProxiFyre AGPL, PR40, vendor binaries and paid work untouched. Git ref mutation exact expected SHA and force=false.
