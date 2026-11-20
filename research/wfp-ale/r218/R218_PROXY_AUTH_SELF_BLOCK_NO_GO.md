# R218 — Conditional AUTH_CONNECT self-block of record-tagged physical SSH

2026-11-21. Scope: ONLY i-shutov/flowbridge, research/windows-wfp-ale-attribution-20261107. Start HEAD cbb1559bacb39ab9984f8bcf05eaf7eb381d0a23, read-only main 5b5afc2feeda2195f302380e615ba003d4906e09. Independent R&D; not beta, PR #56, driver acceptance, G2/PacketBound, no-DIRECT or leak-free.

## Source-supported conditional counterexample

1. R19 policy_windows.rs (Git blob acf60334320d970f58af3349ee75fbaa59826602) installs terminating ALE_AUTH_CONNECT V4/V6 filters matching ORIGINAL_APP_ID=selected and TCP. They are not restricted to the original loopback leg.
2. R19 broker_windows.rs (blob 329ef14b63e70226bfad7372b0014559213abd04), claim_and_connect_trusted_ssh, calls WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS) on the outbound broker-owned TCP socket BEFORE connecting to a remote SSH server.
3. Microsoft's original-app condition describes the originating application when the flow is proxied. If redirect-record-tagged physical SSH receives the selected ORIGINAL_APP_ID in its ALE_AUTH_CONNECT classification, that same terminating filter matches the broker-owned SSH leg.
4. R19 kernel/src/redirect.rs (blob a093f049d162987981a957aac90db1014bc6ff09), auth_check/auth_classify, only permits the redirected connection to the exact broker loopback address/port with a matching selected process and one-use native ticket. An external SSH destination fails that condition and is BLOCKed.

Conditional finding: The existing AUTH policy and legitimate physical SSH socket can interfere. This is a possible availability/policy self-block, not proof that Windows actually classified or blocked a physical connection. WFP runtime propagation, full arbitration, and exact socket linkage remain unproven. It does not demonstrate DIRECT/leaks, nor justify bypassing the guard based merely on the broker's current AppId.

## Deterministic negative check

- r218_proxy_auth_model.rs: original pure Rust, user-mode, forbid(unsafe_code), six unit tests for original TCP loopback, tagged physical SSH V4/V6 semantics, direct TCP/UDP boundary, reauthorization, ticket loss. Rust toolchain is unavailable here: these Rust tests were NOT compiled or run.
- r218_independent_oracle.mjs: independently implemented Node 22.16.0 predicate matrix, 12/12 PASS; mutation tests detected 4 disagreements for swapping original->current AppId and 1 for dropping the loopback guard; node --check PASS.
- Exact transcript SHA-256: 34a6ab519f3f0e51a02ef5d8b5a887556df06399b61efdf613e8f2ccca4eae83. No WFP calls, filters, network traffic, drivers, services or OS configuration were used.

## Trust boundary and next decisive experiment

Original-app scope -> redirect-record-tagged physical SSH -> ALE_AUTH_CONNECT authorization requires actual native proof. Read-only FwpmEngineOpen0 / FwpmFilterGetByKey0 can inspect the BFE rules but cannot demonstrate the real socket's original AppId or final authorization. First compile/run the pure Rust model in a permissible user-mode toolchain and re-run independent Node oracle, with SHA-256. Next kernel classify observation needs separate owner authorization and all driver/VNC/SYSTEM rescue/rollback gates; without them the finding remains conditional NO-GO.

Existing independent NO-GOs remain: R201/R202 origin/epoch/process trust and dynamic BFE-session survival, R215 previousVersion, R216 mapped-V6, sibling DIRECT, reused 5-tuple/PID, process death, DNS/UDP/QUIC, WFP/SSH loss. No PacketBound/G2 PASS, no-DIRECT, leak-free or historical G1 is claimed.

Microsoft contracts:
- https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-
- https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsacquirewritablelayerdatapointer0 (a separate false-open suspicion is ruled out because acquisition sets BLOCK and removes ACTION_WRITE)

Only research ref may be advanced by expected-current-SHA CAS, force=false. No main/release/beta/PR #56, runner, filters, driver, service, firewall, Defender, SecureBoot, MemoryIntegrity, network, other repo or automation changes.
