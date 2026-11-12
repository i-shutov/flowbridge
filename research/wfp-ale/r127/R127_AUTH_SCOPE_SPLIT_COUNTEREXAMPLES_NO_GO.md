# R127: AUTH_CONNECT split scope is not a general ORIGINAL_APP_ID fix — conditional NO-GO

Date: 2026-11-12. Independent FlowBridge WFP/ALE architectural research only. Starting research HEAD 0c90b213ed179ad93b3f7a22bb87f4d7419c7c7d; main HEAD 5b5afc2feeda2195f302380e615ba003d4906e09. No kernel tests or installations.

## Immutable R19 source anchors

- policy_windows.rs Git blob acf60334320d970f58af3349ee75fbaa59826602: AUTH_CONNECT V4/V6 terminating callout conditioned on ORIGINAL_APP_ID=selected and protocol TCP.
- kernel/src/redirect.rs blob 9a07e026134d46ef646d39862bd982cc48bbc5f6: auth_check requires redirected flag, loopback, PID/endpoint metadata, original destination, selected process and live ticket.
- broker_windows.rs blob 16ec8853d322b40f0e00e14d49ae3410741b9395: physical SSH socket receives SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS before connect.
- kernel/src/handoff.rs blob e1d17217db50362ba9c4efc83af820b6beb094cf: Book::attest is one-shot; CLAIM consumes ticket.

## Result: new coverage gap in tempting mitigation

Consider two hypothetical BFE AUTH_CONNECT TCP rules: A) current ALE_APP_ID == selected (any destination); B) ALE_ORIGINAL_APP_ID == selected AND IP_REMOTE_ADDRESS is loopback. This is not implemented and is NOT a safe fix.

Both IPv4 and IPv6, conditional per-socket cases:
- Selected sibling DIRECT (current=selected, original=selected, external): A matches.
- Initial selected redirect (current=broker, original=selected, loopback): B matches.
- Record-bearing physical broker SSH (current=broker, original=selected, external): neither matches, potentially avoiding R126 self-block.
- Third-party proxy (current=third_party, original=selected, external): neither matches, **newly uncovered candidate flow**, not proven leak.
- Redirect (current=selected, original=selected, loopback): **A and B overlap**; actual classification/arbitration/one-shot attestation is unknown.
- A proxy for unrelated origin (current=selected, original=unrelated, external): new possible candidate block.
- UDP/QUIC/DNS: no match under either TCP-only policy.

Python 8 unit tests and independent Node.js 13 assertions passed locally, exhaustively enumerating 144 synthetic states (3 original IDs x 4 current IDs x 3 destinations x 2 IP families x 2 protocols). Canonical ordered JSONL SHA-256 eff09263ae96b8388ff8da5e1be1ad43a17af7611524b1095ec439148d8d39b0. Original-only scope: 24 matches; hypothetical split: 24; **12 old matches lost, 12 new matches gained, 2 A/B overlaps**. Equal totals do not mean equivalent protection. Synthetic Boolean coverage is not kernel evidence.

## Required trust chain and decision

Kernel FWPS_INCOMING_VALUES0 (ALE_CONNECT_REDIRECT_V4/V6) + FWPS_METADATA_FIELD_PROCESS_ID, TRANSPORT_ENDPOINT_HANDLE + referenced originating EPROCESS, creation epoch/start key, captured EXE identity -> FWPS_CONNECT_REQUEST0 redirect handle/context + FwpsQueryConnectionRedirectState0 -> ALE_AUTH_CONNECT_V4/V6 with actual original/current AppId, flags and endpoint ticket -> WSAIoctl SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS and CONTEXT on the accepted socket -> one-use kernel CLAIM -> SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS on a separately owned physical SSH socket -> verified SSH peer and destination. No current PID, 5-tuple or time-window correlation may substitute kernel proof.

Next decisive experiment (separate driver/VNC/SYSTEM rescue/rollback owner authorization required): observe actual current/original AppIds, filter hits, classifies and outcomes for original loopback, physical SSH, sibling DIRECT and a second proxy, both V4/V6. Read-only BFE inventory and user-mode Rust x64 ABI tests can precede it but do not prove origin. NO-GO remains for reauthorization, PID/process death and reuse, 5-tuple reuse, IPv4/IPv6, compartments, DNS/UDP/QUIC, WFP/BFE/SSH loss, PacketBound/G2 and no-DIRECT/leak-free.

Official Microsoft documentation checked 2026-11-12:
https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection

Do not touch main/release, beta integration/windows-rust-capture-agent-20261031, PR #56, runners, services, networks/firewall/UFW, Defender, SecureBoot, MemoryIntegrity, other repos, automations/controllers, driver/callout/NDISRD/WFP filters, VNC, signing or paid work. No ProxiFyre AGPL, closed PR40, vendor binaries or C++ WFP payload.
