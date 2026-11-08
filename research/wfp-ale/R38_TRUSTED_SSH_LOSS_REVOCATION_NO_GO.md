# R38 — Trusted SSH worker ignores kernel lease STOP after admission

Date: 2026-11-08. Exclusive research ref `research/windows-wfp-ale-attribution-20261107`; not beta / PR #56 / release.

## Source-pinned finding (not a native Windows exploit)

Research parent `b983986b4ec62da644ce0f37f116a223ffb3758c`, parent tree `9b3467f6807c9641d1287f8d4cf33443fa73016f`.

- `research/wfp-ale/kernel-r19/broker.rs`, blob `0ecff2e8c115a2d4bfec0151103745b99ed41742`, lines 38–42: PING error sets shared `stop=true`.
- Same file, lines 60–76: workers get the stop Arc; legacy SOCKS does `admitted.relay(s.clone())`, but `VerifiedSsh` calls `trusted.relay(authority)` without the stop signal.
- `research/wfp-ale/kernel-r19/broker_windows.rs`, blob `00b4dde45f5860abc4a15df9d4165f5eb5dbaed1`, lines 163–179: the `TrustedSshRelay::relay` interface accepts only the `ChannelAuthority`; it does not accept or read a stop/health guard.
- `research/wfp-ale/kernel-r19/trusted-ssh-r37/src/lib.rs`, blob `7ce5d82670492e2cbb23452a9375766857da8a90`: `relay_over_pinned_ssh` authenticates the pinned host and SSH user and opens `direct-tcpip`, then awaits a 60s timeout around `tokio::io::copy_bidirectional`, without observing kernel lease loss or global broker stop.
- `research/wfp-ale/kernel-r19/broker.rs` lines 81–87: broker sets stop and joins the workers before policy teardown, so an already-established SSH worker may continue until socket EOF/error or its 60s timeout. Heartbeat failure does not cause immediate worker cancellation.

Conditional failure trace: valid CLAIM and pinned SSH handshake/channel open → app starts streaming → PING fails and sets stop → existing `copy_bidirectional` remains live and can transfer more bytes if both sockets remain open. This is a **source-code lifecycle NO-GO** for local loss-revocation, not an observed Windows kernel fault or packet escape. Exact post-loss scheduling, buffered bytes, and any WFP system enforcement are unmeasured.

## Test evidence

- `python3 research/wfp-ale/r38_loss_stop_negative.py`: 8/8 deterministic tests. Both original families and kernel-loss/normal-stop, SSH failure, 60s expiry, selected scope and non-proofs for sibling/PID reuse are represented.
- `python3 research/wfp-ale/r38_independent_oracle.py`: 384 independent truth-table states, including 12 conditional stale-copy states. It does not import the model-under-test.
- Independent **source-pin check** is required on every future head before claiming the finding still applies. No native driver/callout, BFE policy, VNC, runner, service, network, paid operation or Windows host was exercised. Rust was not compiled in the isolated executor.

## Necessary repair and non-goals

An R39 repair candidate must pass an owned revocation receiver/capability to the **trusted SSH worker itself**; the worker must race copying with revocation (`tokio::select!` / cancellation + controlled socket closure), and treat kernel PING failure, explicit STOP, process exit, policy teardown and SSH transport loss as terminal. A flag checked only before SSH connect, or only before `channel_open_direct_tcpip`, is insufficient. Race-sensitive bytes already in an OS buffer need separate accounting; user-mode cancellation alone is not a kernel/system-wide kill switch.

Minimum user-mode acceptance: source-pinned executable tests start a *live* worker, inject loss after channel open, verify no new application writes complete after the revocation barrier; repeat IPv4/IPv6, traffic bursts, process/policy loss, and stop during handshake. This requires read-only/no-driver user-mode testing only. Before any physically accepted G2 flow, owner-approved signed-driver/VNC/SYSTEM rescue/rollback/independent-capture gates remain mandatory.

Relevant API boundaries: `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6` original classify, `FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6` origin check, `FwpsQueryConnectionRedirectState0`, accepted-socket `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS)`, outgoing physical-socket `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS`, `FwpsPendOperation0` reauthorization caveat. None of these APIs authenticates a missing user-mode revocation listener. PID + creation epoch + canonical AppId, an issuance-bound ticket, 5-tuple and actual stream/SSH authentication are *separate* evidence, not substitutes for runtime lease health.

Overall status: kernel-origin/issuance native proof NO-GO; periodic revocation continuity NO-GO; reauthorization NO-GO; sibling DIRECT and DNS/UDP/QUIC/IPv6 physical coverage NO-GO; crash-persistent kill-switch NO-GO; PacketBound/G2, leak-free and historical G1 promotion prohibited.

Microsoft reference: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection and https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
