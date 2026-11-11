# R101 — Proxy SSH outbound records / ORIGINAL_APP_ID conditional self-block

Date: 2026-11-11. Independent FlowBridge WFP/ALE research. ONLY branch `research/windows-wfp-ale-attribution-20261107`. Parent inspected: `f4e3ba26c6d80e1361cec93acf0f20bb782e7704`. Main inspected: `5b5afc2feeda2195f302380e615ba003d4906e09`.

## New conditional functional NO-GO, NOT a demonstrated Windows failure or DIRECT leak

R19 `policy_windows.rs::conditions` installs two TCP/6 AUTH_CONNECT filters (IPv4/IPv6) with `FWPM_CONDITION_ALE_ORIGINAL_APP_ID == selected` but no remote loopback condition. Each has `FWP_ACTION_CALLOUT_TERMINATING`. R19 `redirect.rs::auth_check` allows only a loopback destination/port and an available same-origin ticket; otherwise `auth_classify` returns BLOCK.

After accepting a real WFP-redirected socket, R19 `broker_windows.rs::claim_and_connect_trusted_ssh` consumes the one-use kernel ticket via CLAIM, sets `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on the *new* physical SSH TCP socket, then calls `connect` to the SSH server. `handoff.rs::Book::take` marks the consumed ticket `s.live=false`.

**Conditional witness:** If WFP exposes the selected original application's `ALE_ORIGINAL_APP_ID` on this outbound SSH socket following redirect-record transfer, and the scoped AUTH filter actually invokes its callback, the SSH socket is rejected by the existing AUTH predicate: the remote SSH endpoint is not the loopback broker, and the original ticket has already been consumed. This is possible *proxy self-block / availability failure*, not proof of an observed leak or Windows failure. The runtime propagation of ORIGINAL_APP_ID onto precisely that outbound socket is still unmeasured. R99 BFE management inventory cannot prove kernel classify invocation.

This is distinct from R100, which concerns an earlier CONNECT_REDIRECT/AppId mismatch CONTINUE branch.

## Exact source blobs and static source guards

Nine source predicates were verified against authenticated GitHub read of these exact blobs (9/9 PASS):
- `research/wfp-ale/kernel-r19/policy_windows.rs`: `acf60334320d970f58af3349ee75fbaa59826602` (ORIGINAL_APP_ID filter + TCP/6, terminating action)
- `research/wfp-ale/kernel-r19/broker_windows.rs`: `16ec8853d322b40f0e00e14d49ae3410741b9395` (CLAIM precedes SIO_SET and SSH TCP connect)
- `research/wfp-ale/kernel-r19/kernel/src/handoff.rs`: `e1d17217db50362ba9c4efc83af820b6beb094cf` (CLAIM consumes `s.live`)
- `research/wfp-ale/kernel-r19/kernel/src/redirect.rs`: `9a07e026134d46ef646d39862bd982cc48bbc5f6` (loopback + original AppId + Book::attest enforced)

## Independent deterministic negative tests

Run `python3 research/wfp-ale/r101/r101_proxy_ssh_negative.py` and `node research/wfp-ale/r101/r101_proxy_ssh_independent.mjs`. Each independently enumerates 256 model inputs across v4/v6, record presence, selected ORIGINAL_APP_ID, AUTH filter/callback presence, claimed ticket, destination loopback, and SSH availability. Both produce matrix SHA-256 `235725d48f8b873f02410313fd6ca90cf45f65a46124efc725c34a76652bafef`. Counts: NO_WFP_RECORD=128, SSH_UNAVAILABLE=64, ORIGINAL_APPID_NOT_SELECTED_UNPROVED=32, AUTH_ENFORCEMENT_UNPROVED=24, R19_AUTH_CALLBACK_BLOCK=6, SYNTHETIC_AUTH_ALLOW_NOT_WINDOWS_PASS=2. Witness: family=4/6, records=1, original_selected=1, auth_filter=1, auth_invoked=1, claim_consumed=1, remote_loopback=0, ssh_ready=1 -> R19_AUTH_CALLBACK_BLOCK. Models give other metadata every favorable condition; real kernel or BFE execution was NOT tested.

## Official API documentation and boundary

- [Using Bind or Connect Redirection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection): new proxy socket must receive redirect records.
- [SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS](https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records): preserves logical connection tracking, not a transferable security proof.
- [ALE_AUTH_CONNECT_V4 fields](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v4_): ORIGINAL_APP_ID for proxied flows.
- [FWPS_CLASSIFY_OUT0](https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_classify_out0): difference between BLOCK, CONTINUE, PERMIT.

The docs do **not** establish that the specific post-CLAIM SSH socket exposes selected ORIGINAL_APP_ID or that external policy invokes this callout. No guaranteed no-DIRECT, leak-free, PacketBound or G2 PASS is asserted. PID/epoch/EXE kernel source, socket records-to-CLAIM identity, sibling DIRECT, repeated 5-tuple, IPv4/IPv6, process exit, DNS/UDP/QUIC and WFP/SSH loss remain unproved.

**Next decision experiment:** compile exact R99 read-only Rust on already-authorized Windows x86_64, confirm Windows SDK FFI and BFE inventory. Correlate *only already authorized evidence* on original and outbound ORIGINAL_APP_ID if available. No driver/filter installation or network experiment may occur without separate owner and rescue gates. No writes to main/release/beta/PR56, runner, services, firewall, Defender, SecureBoot, MemoryIntegrity, networks, automations or other repositories. No ProxiFyre/closed PR40/vendor binaries/C++ payload.
