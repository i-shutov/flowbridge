# FlowBridge R145 — Conditional selected-original-AppId SSH egress collision

Date: 2026-11-12. Research-only branch research/windows-wfp-ale-attribution-20261107. Baseline R144 e361b97068e535c7f15eea5b3f663bce1b110ec5; main 5b5afc2feeda2195f302380e615ba003d4906e09. RELEASE NO-GO. No native WFP proof.

## Decisive source-contract counterexample

R19 has v4/v6 ALE_AUTH_CONNECT TCP filter conditions matching FWPM_CONDITION_ALE_ORIGINAL_APP_ID for the selected process (policy_windows.rs Git blob acf60334320d970f58af3349ee75fbaa59826602). The trusted SSH branch calls WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS) on the physical SSH socket *before* connect(remote_ip, remote_port) (broker_windows.rs 16ec8853d322b40f0e00e14d49ae3410741b9395). Its AUTH callback accepts only current remote 127.0.0.1 or ::1 and rejects IS_REAUTHORIZE (redirect.rs a093f049d162987981a957aac90db1014bc6ff09).

IF the physical SSH connection retains the selected original-AppId through those records AND R19's AUTH_CONNECT filter classifies it, the external SSH remote cannot satisfy auth_check. With ACTION_WRITE, callback requests BLOCK. Without ACTION_WRITE, guarded veto is limited; a non-PERMIT prior action is preserved. This is a *conditional source-supported availability/fail-closed contradiction*, not native-observed traffic denial or DIRECT leak. The R141 generic warning about original-AppId and hard BLOCK is thereby sharpened to the actual R19 trusted SSH path.

The physical test can falsify the premise: WFP might not retain the selected original AppId on outbound SSH, or filter/classification behavior might differ. No amount of synthetic test results establishes either property.

## Independent deterministic tests

Python source-contract test r145_auth_egress_negative.py checks three immutable Git blobs and source signatures from exact checkout (or model-only mode when code is not locally available). Independent Node oracle r145_independent_oracle.mjs enumerates the same states through separate code. 2 families x 3 connection kinds (local redirected, physical SSH, sibling DIRECT) x 256 status/identity/rights combinations = 1536 canonical rows. The records-present bit is deliberately NOT a kernel authorization token.

Python 3 / Node 22: 1536/1536 same output, zero differences. Matrix SHA256: 649b319840bdd74d39c27ff6d49976e88f6e80ffc95f5bd36dd482c12d0a49e2.
LOCAL: 8 synthetic permit candidates; SSH/DIRECT: 0 permit candidates where selected original AppId matched. 64 of 256 selected SSH states are PRESERVE_UNPROVEN rather than guaranteed BLOCK because action-write/veto rights matter. Reauthorization yields no permit candidate. Native classification: NOT EXECUTED.
Three source blob SHA pins and their fragments independently checked against GitHub baseline. Exact repo-backed execution of pin validator, Rust and Windows not performed.

Run from exact research checkout:
  python -B research/wfp-ale/r145/r145_auth_egress_negative.py
  node research/wfp-ale/r145/r145_independent_oracle.mjs

## Trust and next decisive experiment

Original kernel process object/PID/epoch/start-key, FWPS_METADATA_FIELD_PROCESS_ID, current and original ALE AppIds, FwpsQueryConnectionRedirectState0, FWPS_CONNECT_REQUEST0, accepted socket SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS and SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, and outbound SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS are separate evidence boundaries. For the *same* native flow, only kernel capture of actual original/current AppIds, destination, filter hit, action rights, process context and classification outcome can resolve the contradiction. No late PID/tuple correlation qualifies. The native experiment remains forbidden until separate owner authorization and all disposable VM/driver/VNC/SYSTEM rescue/rollback gates.

NO-GO remains for IPv4/IPv6 compartments, PID reuse/creation epoch, 5-tuple reuse, reauthorization, DNS/UDP/QUIC, sibling DIRECT, BFE/WFP/SSH failure and physical no-DIRECT. No PacketBound/G2 PASS, leak-free or historical G1 promotion. No driver, WFP filter, service, network, firewall, security, runner, automation, main, release, beta or PR #56 changes.

Microsoft primary sources:
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v4_
https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
