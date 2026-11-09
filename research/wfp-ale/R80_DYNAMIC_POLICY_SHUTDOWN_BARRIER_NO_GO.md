# R80 — BFE dynamic-session rollback liveness vs shutdown containment

Date: 2026-11-10. Scope: research/windows-wfp-ale-attribution-20261107 ONLY. Baseline research HEAD d16426fd5098f808dbfcd933d8ff896541c6248a; main 5b5afc2feeda2195f302380e615ba003d4906e09 (read-only).

## Material result

Source-reviewed at immutable blob IDs:
- research/wfp-ale/kernel-r19/broker.rs (ce6c549a9ae488cc7c0ca9a7e7be68871b9d7f2c): revoke -> heartbeat.join -> workers.finish -> policy.close.
- research/wfp-ale/kernel-r19/broker_lifecycle.rs (211b5e5cee03f4d8ea13fc23e1be0777cbfa09c1): finish unconditionally joins all active workers.
- research/wfp-ale/kernel-r19/broker_windows.rs (16ec8853d322b40f0e00e14d49ae3410741b9395): synchronous WSAIoctl on accepted sockets for both redirect queries.
- research/wfp-ale/kernel-r19/policy_windows.rs (acf60334320d970f58af3349ee75fbaa59826602): FWPM_SESSION_FLAG_DYNAMIC, Installed.close -> FwpmEngineClose0; Drop only after scope exit.

Documented WSAIoctl may block indefinitely, provider dependent. Thus *if* one receipt worker remains blocked even after a completed heartbeat, workers.finish can indefinitely prevent policy.close in the living process: bounded rollback is NO-GO. If heartbeat.join itself does not finish, the block occurs earlier. This is a source-and-contract counterexample, **not** an observed Windows WFP hang.

Moving FwpmEngineClose0 earlier removes session-scoped WFP objects while selected applications may still connect; without independently proven client quiescence or an independent deny barrier, the absence of sibling DIRECT is NOT established. This is a conditional containment gap, NOT an observed leak. The source comment requires external harness termination of selected clients, but the broker does not itself certify that condition. Terminating the process also closes the dynamic session by Win32 contract; that is not fail-closed network isolation. SSH heartbeat is not a BFE containment attestation. WFP/BFE-loss remains NO-GO.

## Executable negative proof (offline only)

- r80/r80_order.py and independently derived r80/r80_independent.mjs enumerate 288 states: IPv4/v6; heartbeat completion; pending workers 0/1/32; possible selected-app future connection; independent deny barrier hypothetical true/false; FwpmEngineClose acknowledgement; healthy/SSH-loss/BFE-loss.
- Both were executed locally on 2026-11-10, 288/288 outcomes coincide, SHA-256 ordered decisions cd69863f3ceebc3d0eb3c46195bc55f7b944b0e434e8ffdd6ddb948e0ccc3135.
- Extended local negative suite: 12/12 Python tests PASS, separate independent Node oracle matches 288/288, ordered SHA-256 bcddc1a31089bbeee437c5729dbbc9f4dd40df4b96fa053772bab364a2f3829e. Includes executed real user-mode thread/join gate that keeps cleanup unreachable until the worker is deliberately released. No Windows native, no Rust compilation (rustc/cargo unavailable).
- Synthetic states are NOT physical traffic or incident frequencies. Any hypothetical verified barrier is an unimplemented **input**, not a claim that a barrier exists. Close acknowledgement is also modeled, not observed.

## Trust chain and continuing NO-GO

Kernel original-process/epoch/canonical AppId captured under ALE_CONNECT_REDIRECT_V4/V6; FwpsQueryConnectionRedirectState0; ALE_AUTH_CONNECT_V4/V6 original-app/endpoint validation; ticket with epoch + endpoint generation; accepted-socket-owned SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS and ...CONTEXT; one-use DeviceIoControl(CLAIM); SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS on the physical SSH socket; SSH host-key+auth; independent sibling-DIRECT denial. These arrows are NOT established as one kernel proof. In particular current CLAIM does not authenticate the accepted SOCKET.

OpenProcess, GetProcessTimes, QueryFullProcessImageNameW and FwpmGetAppIdFromFileName0 attest present process/file observations, NOT historical ALE flow origin. PID death/reuse, reused 5-tuples, IPv6 scope/compartments, sibling DIRECT, DNS/UDP/QUIC, BFE/SSH loss, PacketBound/G2, physical no-DIRECT/leak-free and G1 at dd1ab3c remain NO-GO.

## Next decisive experiment

R81: isolated read-only user-mode probe / simulated overlapped WSAIoctl completion escrow, ensuring socket-generation/WSAOVERLAPPED/output-buffer retention until terminal completion, plus explicit check for independently verifiable process quiescence before dynamic session teardown. Ordinary self-owned unredirected sockets only provide a negative baseline. Without Windows compiler/runtime or independent barrier proof, retain NO-GO. No driver/callout/NDISRD, WFP filter, runner, VNC, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, network change, other repo, beta, PR #56, main/release, or automation mutation.

## Microsoft official API contracts (reviewed 2026-11-10)

- https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaioctl
- https://learn.microsoft.com/en-us/windows/win32/fileio/canceling-pending-i-o-operations
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineclose0
- https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsagetoverlappedresult
