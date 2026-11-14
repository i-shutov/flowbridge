# R179 — AUTH original-AppId filter may self-block outbound SSH

Date: 2026-11-14. Research-only branch research/windows-wfp-ale-attribution-20261107; never beta, main/release, or PR #56. No WFP filters, driver, network or Windows operations.

## Source-level conflict

- policy_windows.rs Git blob acf60334320d970f58af3349ee75fbaa59826602: at ALE_AUTH_CONNECT_V4/V6, the TCP filter matches selected FWPM_CONDITION_ALE_ORIGINAL_APP_ID with FWP_ACTION_CALLOUT_TERMINATING and no destination/IS_PROXY_CONNECTION exclusion.
- redirect.rs Git blob a093f049d162987981a957aac90db1014bc6ff09: auth_classify denies on auth_check failure. auth_check requires a redirected original leg with loopback service address/port, selected PID/start-key/endpoint and native original-destination metadata.
- broker_windows.rs Git blob 329ef14b63e70226bfad7372b0014559213abd04: claim_and_connect_trusted_ssh sets SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS on the newly created physical SSH socket before connecting to an external SSH endpoint.
- auth_appid.rs Git blob f16ab6ad0f618c74ed4e79ce606583169084970d: current AppId may be the broker while original AppId must be the selected application.

Microsoft documents ALE_ORIGINAL_APP_ID as the original application on proxied connections. **If** this identity propagates via the transferred opaque WFP record to the physical SSH connection, the broad R19 AUTH filter can also select that new outbound connection. Because its destination is an external SSH server, not the local redirected proxy, and its live process is the broker, R19's AUTH predicate rejects it. This is a conditional self-block design defect, not a Windows runtime result.

## Executed offline negative model

The independent Python and Node.js programs committed with this report enumerate 192 synthetic cases across v4/v6, accepted redirected vs external SSH vs DIRECT, original/current AppId, redirect/proxy flags, and local-target correctness. Their canonical JSONL output matched byte-for-byte: SHA-256 0ca23592dec257d16580d134e2536fc064be901f8fab0475e609496b19f1d78c. Counts: 8 PERMIT_MODEL_ONLY, 88 BLOCK, 96 OUTSIDE_FILTER. All 32 test cases for physical SSH plus selected original AppId are modeled BLOCK; all 32 with broker original AppId are OUTSIDE_FILTER, which does NOT authorize untagged outbound flow.

An extended local test suite independently passed 8/8 tests in each of Python normal, -O and -OO and matched a distinct Node oracle 192/192 (SHA-256 c1e6f51cf0633cac2278a1ef9c4cdb12b31ef61cfdf66ba9b2eb8304d33dd5d0). The extended tests and source-pin report are in the R179 checkpoint archive, not a native Windows experiment. Rust toolchain unavailable, so no Rust execution claimed.

## Decision and next decisive experiment

Conditional architectural NO-GO: original-AppId AUTH filters require a documented and experimentally verified **leg discriminator** that distinguishes the selected redirected original connection from the WFP-record-bearing outbound proxy socket, without accepting untagged SSH sockets or permitting sibling DIRECT. Merely removing the records or whitelisting the broker is not an acceptable proof.

Future owner-gated native proof would capture both V4/V6 legs at authentic WFP classify, including original/current AppId, FWP_CONDITION_FLAG_IS_PROXY_CONNECTION vs IS_CONNECTION_REDIRECTED, actual destination, original destination, PID/epoch/endpoint, compartment, filterId, classify verdict, accepted-socket context, CLAIM and SSH tag. A read-only BFE inventory can only inspect installed scope, not prove classified socket behavior. No driver/callout/filter activation or signed-driver/VNC/SYSTEM experiment authorized here.

All existing Witness producer/consumer/exclusive reader/ACK blockers (R165–R178), original process/FileObject and canonical EXE, IPv6 scope, PID/endpoint/5-tuple reuse, sibling DIRECT, DNS/UDP/QUIC, reauthorization and WFP/BFE/SSH loss remain NO-GO. This is not PacketBound/G2 PASS and not a no-DIRECT/leak-free proof.

Official sources:
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v4_
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v6_
https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records
