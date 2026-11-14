# R180 — AUTH_CONNECT policy-honor phase is not a redirected-loopback receipt

Date: 2026-11-14. Scope: `i-shutov/flowbridge`, **only** branch `research/windows-wfp-ale-attribution-20261107`. Independent architecture R&D, not beta, PR #56, PacketBound/G2 or a leak-free proof.

## Exact source and documentation boundary

Read-only baseline: research `17066e1907145a4441fd78edc93858914ca9354d`; main `5b5afc2feeda2195f302380e615ba003d4906e09`. Git blobs:

- `research/wfp-ale/kernel-r19/kernel/src/redirect.rs` = `a093f049d162987981a957aac90db1014bc6ff09`, specifically `auth_check` and `auth_classify`.
- `research/wfp-ale/kernel-r19/policy_windows.rs` = `acf60334320d970f58af3349ee75fbaa59826602`, specifically `conditions`, `filter`.
- `research/wfp-ale/kernel-r19/kernel/src/auth_appid.rs` = `f16ab6ad0f618c74ed4e79ce606583169084970d`.

Windows Filtering Platform documents `FWP_CONDITION_FLAG_IS_HONORING_POLICY_AUTHORIZE = 0x02000000` on `ALE_AUTH_CONNECT_V4/V6` for a redirected Universal Windows app. The flagged classification uses field values as though it had **not** been redirected; a future classification for the effective redirected destination is promised in that documented scenario. It is **not** by itself a redirected-loopback event. The same reference defines `IS_CONNECTION_REDIRECTED = 0x00100000`, `IS_PROXY_CONNECTION = 0x00200000`, and `IS_REAUTHORIZE = 0x00000004`.

The current R19 BFE AUTH filter matches `FWPM_CONDITION_ALE_ORIGINAL_APP_ID == selected` and TCP, with no phase discriminator. R19 `auth_check` requires the redirected flag, **rejects the policy-honor flag**, mandates exact loopback service destination and port, the required metadata, referenced selected process ledger and one-use ticket. Its failure triggers `auth_classify` -> `guarded_block`. Thus if an eligible selected UWP app produces a documented policy-honor AUTH indication through this filter, R19 **requests a BLOCK**, not a provisional success/deferral. This is a **source-level conditional availability incompatibility**, not native evidence that Windows dropped a connection or that every Win32 app sees the phase.

Crucially, the current source's `IS_PROXY_CONNECTION` bit is not checked by `auth_check`. A synthetic combined `REDIRECTED | PROXY` loopback indication still reaches an attestation candidate when the other requirements pass, while a physical SSH-server endpoint fails the loopback test. The Microsoft flag documentation does **not** establish that this synthetic combined bit pattern occurs on a real host; neither flag is an authenticated kernel origin transaction ID. R88/R179 already documented the *separate* conditional SSH self-block issue. R180 adds the UWP policy-honor phase and a regression oracle, not a second claim that R179 was newly found.

## Executed deterministic negatives

Run from the `r180` directory (standard Python 3 + Node 22, no network):

```sh
python3 -m unittest -v test_r180_policy_phase.py
python3 -O -m unittest test_r180_policy_phase.py
python3 -OO -m unittest test_r180_policy_phase.py
python3 r180_policy_phase_matrix.py > python.jsonl
node r180_policy_phase_oracle.mjs > node.jsonl
cmp python.jsonl node.jsonl
sha256sum python.jsonl
```

Executed locally: 6/6 Python tests at each of normal, `-O`, `-OO`; independent Node oracle 2048/2048 ordered JSONL rows byte-identical to Python; SHA-256 `641d39b40f4d9d436d51dcdbcdd6aa99545d88f36453310354e8f53d03f590f9`. Results: `OUTSIDE_FILTER` 1024, `SOURCE_BLOCK_REQUEST` 1020, `ATTEST_CANDIDATE_ONLY` 4. Across both address families, all 128 selected-original policy-honor cases request BLOCK; all 128 selected-original proxy-tagged SSH cases request BLOCK; all 256 selected-original sibling DIRECT cases request BLOCK. Synthetic `REDIRECTED|PROXY` contributes two of the four candidate rows. These are **model case counts, not probabilities, packet drops or native callback counts**. One semantic matrix deliberately varies flags independently of stages to detect unsafe assumptions and hence includes impossible or unobserved Windows combinations; the source guard is applied mechanically. AppId filter dispatch, action rights, exact metadata availability, and actual Windows redirection chronology remain unproven.

## Proof chain / design gate

Referenced `PEPROCESS`/image and `PsSetCreateProcessNotifyRoutineEx`, process PID/creation time/start key/canonical executable -> ALE_CONNECT_REDIRECT_V4/V6 AppId/compartment/endpoint and `FwpsQueryConnectionRedirectState0` -> redirect issuance + original destination -> ALE_AUTH_CONNECT_V4/V6 **phase + flags + metadata + current/original AppId** -> accepted socket WFP `SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT` -> kernel-owned Witness with a common transaction ID and durable ACK -> one-shot CLAIM -> physical SSH socket `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` and host-key-pinned SSH -> fail-closed liveness and sibling DIRECT, DNS/UDP coverage.

The policy-honor stage may not be equated to the effective-redirected stage or converted directly to PERMIT: documented future classification needs a separate, demonstrably safe phase contract. It would be unsafe to globally exempt proxy/honoring flows or remove WFP record transfer. The next *authorized* experiment is a clean-room user-mode Rust state-machine with explicit `HONOR -> EFFECTIVE_REDIRECT -> PROXY` transitions, transaction provenance, failed future classification, reauthorization, PID/endpoint ABA and BFE/SSH loss, compared to these independent traces. Rust toolchain is unavailable locally, so no Rust build was performed. Native classify evidence requires separate owner decision and all driver/VNC/SYSTEM rescue and rollback gates; **none authorized here**.

Existing R165–R179 producer/reader/lease/ACK/CLAIM/SSH blockers, identity, IPv4/IPv6 compartment/scope, process death, reused 5-tuple, sibling DIRECT, DNS/UDP/QUIC, WFP/BFE/SSH loss remain NO-GO. No historical G1 acceptance transfer. No main/release/beta/PR #56 modifications; no driver, WFP filter, NDISRD, service, runner, firewall/UFW, security toggle, network, VNC, signed driver, vendor binary, ProxiFyre/PR40, automation or paid operation.

Official documentation:

- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-flags
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records
