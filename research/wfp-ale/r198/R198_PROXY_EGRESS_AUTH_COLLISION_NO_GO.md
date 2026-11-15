# R198 — physical SSH egress and selected-original-AppId AUTH collision

Research only; **conditional architectural NO-GO**, not Windows native proof. No driver, callout, filter, service, firewall, runner, network setup, beta, PR #56 or main change.

## Exact research source (parent 1ed2a584627ee8a756e4cac1f2fe37967d2c308b)

- `research/wfp-ale/kernel-r19/policy_windows.rs` blob `acf60334320d970f58af3349ee75fbaa59826602`: selected `FWPM_CONDITION_ALE_ORIGINAL_APP_ID` + TCP 6 used for terminating `ALE_AUTH_CONNECT_V4/V6` filters.
- `research/wfp-ale/kernel-r19/kernel/src/redirect.rs` blob `a093f049d162987981a957aac90db1014bc6ff09`: `auth_check` requires remote loopback, broker port, selected live PID/epoch/start-key/endpoint, native redirect metadata and one-shot ticket; non-loopback -> false -> `block(out)`.
- `research/wfp-ale/kernel-r19/broker_windows.rs` blob `329ef14b63e70226bfad7372b0014559213abd04`: `claim_and_connect_trusted_ssh` applies `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` to a new TCP socket before connecting to external SSH server IP/port.

Microsoft:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer

## Counterexample (conditional, source+documentation)

If the outbound SSH TCP socket tagged with redirect records exposes the **selected original** AppId as Microsoft documents for proxied connections, then the selected-original-AppId AUTH filter matches the physical SSH socket. Its remote address is the actual SSH server, not the local broker loopback port. The R19 AUTH callout therefore invokes BLOCK. Even a hypothetical selected processId does not satisfy the loopback requirement. If Windows presents broker OriginalAppId instead, this filter does not match but that does **not** prove end-to-end provenance or lack of DIRECT. The difference must be measured on an admitted Windows kernel host. Do **not** bypass the AUTH filter using broker PID/AppId alone, since that could invalidate sibling-DIRECT protection.

Conditional negative tests: `python research/wfp-ale/r198/r198_selfblock_negative.py` and `node research/wfp-ale/r198/r198_independent.mjs` (complete checkout). `--model-only` tests the model without validating the source. Both are independent test implementations; neither proves native Windows behavior.

### Six scenario outcomes

1. Selected sibling DIRECT to Internet: BLOCK under active AUTH filter.
2. Matching redirected loopback with valid one-shot kernel receipt: MODEL_PERMIT only.
3. Records-tagged external SSH, broker PID, original selected: BLOCK.
4. Records-tagged external SSH, hypothetical selected PID, original selected: BLOCK.
5. Untagged broker-original external SSH: UNCLASSIFIED by this filter, not automatic permit.
6. IPv6 selected flow, records-tagged IPv4 physical SSH: BLOCK when original selected persists.

### Trust boundary and next experiment

Kernel process creation `PsSetCreateProcessNotifyRoutineEx`, `PsGetProcessCreateTimeQuadPart`, `PsGetProcessStartKey`, referenced EPROCESS/FileObject and AppId -> ALE_CONNECT_REDIRECT V4/V6 -> ALE_AUTH_CONNECT V4/V6 -> accepted-socket `SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT` -> one-shot CLAIM -> `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` -> physical SSH socket. On gated Windows host independently capture the actual `ALE_APP_ID`, `ALE_ORIGINAL_APP_ID`, processId, localRedirectTargetPID, originalDestination, endpoint and remote address for **both** original and physical SSH AUTHORIZE callbacks, including reauthorization. Until then this is conditional NO-GO. Such native kernel instrumentation requires separate driver/VNC/SYSTEM gates; it is NOT authorized by this file.

Allowed next step remains `cargo build --locked` for R190 plus **read-only** BFE snapshot with ACL/error codes, which cannot resolve this counterexample. IPv4/v6, process death/PID reuse, endpoint/5-tuple reuse, sibling DIRECT, UDP/DNS/QUIC, WFP/SSH loss remain unproven. No PacketBound/G2 PASS and no leak-free claim.

Tests in this cycle: source-bound remote JavaScript checks 8/8 PASS; independent scenario models Python 6/6, Node 6/6 model-only PASS. Source-bound Python/Node full checkout and native Rust/Windows execution NOT RUN. Model is not kernel proof.
