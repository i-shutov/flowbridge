# R81 — TCP-only scope and ambiguous BFE close acknowledgement: NO-GO

Date 2026-11-10. Scope **only** research/windows-wfp-ale-attribution-20261107. Base commit 20f87086c419b86c0e430142b75958f850b9d444; main read-only 5b5afc2feeda2195f302380e615ba003d4906e09. Independent R&D only; not beta/PR #56, not PacketBound/G2 or historical G1.

## Two material source-backed results

**A — UDP/QUIC/DNS-UDP are excluded from all four installed R19 lab filters by design.** Source `kernel-r19/policy_windows.rs` immutable blob `acf60334320d970f58af3349ee75fbaa59826602` creates precisely `vec![app,tcp]`; `tcp.fieldKey=FWPM_CONDITION_IP_PROTOCOL`, `tcp.conditionValue.r#type=FWP_UINT8`, `tcp.conditionValue.Anonymous.uint8=6`. Both ALE_CONNECT_REDIRECT and ALE_AUTH_CONNECT rules are instantiated for IPv4/IPv6. Protocol 6 is TCP; UDP is protocol 17. Therefore the four R19 filters do **not** match IPv4/IPv6 UDP (including UDP DNS and QUIC). This does *not* assert that traffic actually leaks; other Windows filters might block it. It means R19 provides no all-protocol no-DIRECT/leak-free proof. TCP matching alone remains a candidate, NOT proof of correct original-app or accepted-socket identity.

**B — failed `FwpmEngineClose0` loses the only Rust owning handle before the result is known.** Same source: `fn close(mut self)` uses `std::mem::replace(&mut self.handle,ptr::null_mut())` BEFORE `check(FwpmEngineClose0(h), "close_dynamic_session")`. `Installed::close(self)` consumes that owner, and `broker.rs` blob `ce6c549a9ae488cc7c0ca9a7e7be68871b9d7f2c` reduces close errors to `lab_policy_close_failed`. The close call may fail or return an RPC error. Its returned error does NOT prove either success or continued filter installation; correct evidence state is **UNKNOWN**. The original handle is no longer retained for a controlled inspection. Do NOT blindly retry when completion/ack is ambiguous.

The policy session is flagged `FWPM_SESSION_FLAG_DYNAMIC`; Microsoft documents dynamic WFP objects are deleted when the session ends, including on broker process termination. Hence same-process watchdogs cannot guarantee crash-surviving containment. `broker_lifecycle.rs` blob `211b5e5cee03f4d8ea13fc23e1be0777cbfa09c1` joins all workers, which may block before reaching policy close (R79/R80). These are three distinct outcomes: blocked clean teardown, close-ack uncertainty, owner death removes dynamic filters.

## Offline proof and limitations

- Source-review assertions: **9/9** on immutable Git blobs for scope, dynamic session, close handle and worker ordering.
- `r81/r81_compact.py`: **7/7 Python tests PASS**; independently authored `r81/r81_compact.mjs` matches all 2,304 ordered IPv4/IPv6/protocol/owner/close/barrier/worker/BFE/SSH synthetic decisions and SHA-256 `7557f324e85dbb5da6b7df58caaa2fc2ccf7275738e3c563eb3e53a038bc51fe`.
- Extended local suite: **14/14 Python PASS**, independently derived Node oracle 2,304/2,304. Source-bound counts: 1,728 out-of-filter synthetic protocol states, 384 close-UNKNOWN, 384 modeled lost-handle states, 564 hypothetical cases without R19 coverage. These are NOT measurements or observed leaks.
- `r81/r81_escrow.rs`: safe Rust pure user-mode **control-flow model**, no FFI/driver/sockets/network. Holds simulated output-buffer resources until an *externally asserted* terminal event; cancellation and timeout do not imply terminal completion. **8 unit tests authored but NOT run**: rustc/cargo missing. The model is not actual WinSock lifetime proof: `complete()` requires a trusted future native completion witness.
- Hypothetical independent barrier in the matrix is an input, NOT an installed filter or a verified control.

## Trust-chain status

1. Kernel ALE_CONNECT_REDIRECT_V4/V6: `FWPS_METADATA_FIELD_PROCESS_ID` and `processPath` where present, `FwpsQueryConnectionRedirectState0`; reference historical process with independently verified creation epoch and canonical EXE. `FWPS_INCOMING_METADATA_VALUES0` does **not** document a process-creation-time field. **NO-GO** historical owner and PID reuse.
2. ALE_AUTH_CONNECT_V4/V6: current versus original `FWPM_CONDITION_ALE_APP_ID`/`FWPM_CONDITION_ALE_ORIGINAL_APP_ID`; verify original and endpoint lifetime across reauthorization. **NO-GO** causal continuity and 5-tuple reuse.
3. Accepted socket: `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT)`; one-use `DeviceIoControl(CLAIM)`; `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on outbound TCP socket before pinned SSH/auth/channel. **NO-GO** independent kernel attestation of the particular accepted socket.
4. IPv4/IPv6 sibling DIRECT, UDP DNS/QUIC/ICMP, SSH/BFE loss, process death, rollback and crash-sustained denial: **NO-GO**. R19 filters demonstrably TCP-only, dynamic session lifetime is tied to owner. None of this is PacketBound/G2 PASS or proof of no-DIRECT/leak-free.

## Next decisive R82 experiment

With separate authorization for a user-mode Windows research workstation, compile Rust model and run **only** owned ordinary-socket read-only `WSAIoctl` query baseline; verify `WSAOVERLAPPED` output/handle lifetime and actual `WSAGetOverlappedResult` terminal status for IPv4/v6, not a positive redirect proof. Evaluate read-only `FwpmFilterEnum0`/`FwpmSessionEnum0` snapshots as evidence *after an ambiguous close*; a snapshot must never be confused with continuous enforcement or original-flow identity. No new driver/filter/callout/rules/system changes without gates.

Official contracts consulted: 
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-data-types
- https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-socket
- https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/ns-fwpsu-fwps_incoming_metadata_values0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0
- https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineclose0
- https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaioctl

Safety: No edits to main/release/beta/PR #56/runner/CI/services/firewall/UFW/Defender/SecureBoot/MemoryIntegrity/network/other repos/automations, no signed driver/NDISRD/filter/VNC/Vendor/ProxiFyre/PR40/C++ WFP payload, no payments. 
