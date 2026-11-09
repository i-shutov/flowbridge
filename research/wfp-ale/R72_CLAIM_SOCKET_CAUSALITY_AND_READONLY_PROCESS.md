# R72 — CLAIM/accepted-socket authority cut; read-only process identity probe

**2026-11-09**, independent R&D, **ONLY** `i-shutov/flowbridge` branch `research/windows-wfp-ale-attribution-20261107`. No beta, PR #56, PacketBound/G2 or historic G1 `dd1ab3c` promotion. Source pinned **research HEAD** `0bcc807f1db11f311210e480febb533e8135b5db`; **main HEAD** `5b5afc2feeda2195f302380e615ba003d4906e09` (both checked before edits). No repo file outside research scope changed.

## New source-derived distinction: source-owned accepted socket versus kernel CLAIM

**Exact read source blobs:**

- `research/wfp-ale/kernel-r19/kernel/src/redirect.rs` blob `9a07e026134d46ef646d39862bd982cc48bbc5f6`: `redirect::auth_check()` uses `Book::attest(origin,original_destination,now)`; `redirect::ioctl(CLAIM,input,caller)` checks `IoGetRequestorProcess(irp)` identity of broker and then `Book::take(context,now)` plus *original owner ledger* `(pid,epoch,start_key,generation,EXE)`. No accepted-socket `HANDLE` or WFP accepted-socket query passes through CLAIM.
- `research/wfp-ale/kernel-r19/kernel/src/handoff.rs` blob `e1d17217db50362ba9c4efc83af820b6beb094cf`: `Book::attest` matches `(pid,epoch,start_key,endpoint,generation,destination)` and marks `auth_seen`; `Book::take` checks one-shot session/sequence/context/TTL/`auth_seen`. Neither function has a socket parameter or verifies the accepted socket.
- `research/wfp-ale/kernel-r19/kernel/src/lib.rs` blob `0af6d4539673d2894cbaa91af0ea8f3524862a26`: `IRP_MJ_DEVICE_CONTROL` calls `redirect::ioctl(code,input,IoGetRequestorProcess(irp))`, not a socket-carrying witness.
- `research/wfp-ale/kernel-r19/broker_windows.rs` blob `16ec8853d322b40f0e00e14d49ae3410741b9395`: `receive(accepted)` queries `SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS` and `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` **on that accepted `TcpStream`**, stores it together in private `Received{accepted,context,records}`; `claim_and_connect_trusted_ssh` then sends `Device::command(CLAIM,&self.context.0)`. The actual broker's normal safe-Rust code preserves this pairing, but the kernel IOCTL itself cannot independently test it.
- `research/wfp-ale/kernel-r19/broker.rs` blob `ce6c549a9ae488cc7c0ca9a7e7be68871b9d7f2c`: normal worker gets `Received` from `receive(client)` and relays; trusted-broker construction is part of the **TCB**. No assertion that an unmodified broker actually swaps contexts.

### Precise counterexample / why it matters

Two legitimate, simultaneously live redirected connections A and B exist for the same selected executable (both have kernel-issued, AUTH-attested, unused, nonexpired tickets; their original owners remain alive). Suppose the **same authenticated broker process** makes a CLAIM with valid ticket A while the application-level flow under consideration is accepted socket B. The kernel's CLAIM inputs contain ticket A and the calling broker process, **not socket B**. Therefore the kernel accepts A's valid ticket, independently of B's existence. This is a *protocol-level non-binding counterexample*, not an exploit demonstrated in the shipped broker. With a trusted, unmodified, ownership-preserving `Received` type, the broker normally binds WSAIoctl output to its socket; a claim that **the kernel independently proved that same binding** is nevertheless false.

The distinction is material: `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` is documented on an **accepted socket**, and the opaque WFP records logically associate redirected original and proxy connections. Such evidence is obtained in user mode; `DeviceIoControl(CLAIM,context)` subsequently carries bytes, not a socket reference. The boundary has not been closed across the IOCTL. No PID/creation epoch/EXE/5-tuple equality can create the missing causal edge, and no read-only polling can establish it retrospectively.

**Trust-model split:**

1. **GO (narrow, source-level):** the unmodified `Received` safe-Rust path couples accepted stream and its WSAIoctl output; the kernel validates one-shot receipt and recorded original owner using its own ledger. This is a *broker-trusted design assumption*.
2. **NO-GO (kernel-independent):** no kernel-enforced equality of `(accepted SOCKET, WFP context/records, consumed CLAIM)` in current `DeviceIoControl`; credential/handle ownership and process epoch alone do not add socket provenance. A compromised broker or internal programmer error is a different threat model from an external unprivileged local socket: do **not** claim the normal broker is exploitable without further evidence.
3. **NO-GO (physical scope):** even a socket-bound successful claim is not proof that sibling DIRECT, DNS/UDP/QUIC, WFP bypass, IPv4/v6 physical egress or SSH loss are suppressed.

## Executable offline experiment

- `r72_claim_socket_cut.py`: independently source-derived 16-bit state model; **17 unittest tests PASS**. Simulates conditional claim/same-broker and mandatory ticket/owner checks independently of five unobserved socket/physical properties. Its switched-accepted-sockets negative case explicitly assumes a misbehaving *in-process* broker. Both IPv4/IPv6; no network access.
- `r72_independent_oracle.mjs`: **separate Node implementation** using a different bitmask strategy; both evaluate **131,072** deterministic synthetic states and produce the **same full ordered stream SHA256**: `9acdf1ee103c5c185a0b56ad2e6b4307e8c86db666c8fe63cdc1086b8dff76d7`.
- Model counters: `CLAIM_CANDIDATE=64`, `FULL_HYPOTHETICAL_EVIDENCE=2`; **32** of the 64 claim candidates each may lack socket association, successful socket-WFP query, non-reused 5-tuple, no-sibling-DIRECT or SSH-health respectively. Marginal counts overlap. These are hypothetical worlds and **NOT** actual Windows traffic, actual packet drops, bypass findings, or real broker misuse.
- `r72_win_process_readonly.rs`: **Windows-only std-only, single-process observational Rust diagnostic**, explicitly prints all three NO-PROOF results. `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`, `GetProcessTimes`, `QueryFullProcessImageNameW`, `FwpmGetAppIdFromFileName0`, `FwpmFreeMemory0`, `CloseHandle`. Does NOT call WFP engine or filters, network sockets, device IOCTL, kernel API or alter protection policies. Windows binary **NOT compiled or run**: available runtime has no `rustc/cargo`, and the owner's RDP workstation is not exposed as a tool-controlled computer. Local static tests are **NOT** a Windows build substitute.
- `test_r72_source_contract.py`: **5/5** executable independent static whitelist/negative checks for the observational probe. Static checks do not establish Windows ABI correctness; requires compilation under Windows and inspection before optional execution.

## API evidence, proof scope and exact NO-GO

| Evidence | API / source | What it proves | What it does NOT prove |
|---|---|---|---|
| Process snapshot | `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `GetProcessTimes` | handle to *currently queried* process, creation FILETIME | original EPROCESS in a historic classify; socket ownership; process ever owned 5-tuple |
| Reported image | `QueryFullProcessImageNameW` | process image path at query time | canonical image-section / `PS_CREATE_NOTIFY_INFO.FileObject` provenance; historical EXE binding |
| WFP AppId blob | `FwpmGetAppIdFromFileName0` | path-derived filter identity | immutable file object, proof of original owner, WFP packet success |
| Source-owned process | `PsSetCreateProcessNotifyRoutineEx`, `PsGetProcessCreateTimeQuadPart`, `PsGetProcessStartKey`, referenced `PEPROCESS` / `FileObject` | kernel-observed process birth and epoch when actually executed | historic endpoint owner when AUTH metadata represents a foreign proxy; no-DIRECT |
| ALE scope/record | `FWPS_FIELD_ALE_*_ALE_APP_ID` vs `ALE_ORIGINAL_APP_ID`, `FWPS_INCOMING_METADATA_VALUES0`, `FwpsQueryConnectionRedirectState0` | filter selection / redirect history *subject to native callback and non-NULL metadata* | accepted SOCKET to CLAIM binding, physical egress |
| Accepted-socket WFP context | `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT / RECORDS)` | context and opaque records supplied for **that accepted socket** if queried successfully | independently kernel-validated CLAIM association; trustworthiness of an arbitrary in-process broker |
| Socket handoff to SSH | `WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS)` | returns status for outbound socket record transfer | SSH remote authenticated, no sibling direct, packet-bound isolation |

**Official documents checked 2026-11-09:**

- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfreememory0
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-context
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetprocesscreatetimequadpart
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetprocessstartkey

## Next decisive R73

Decide threat boundary before any native experiment: whether a **trusted broker TCB** is acceptable for a scoped experimental proof, or whether an **independent kernel socket binding** is a hard requirement. If the latter, investigate **documented, non-activating** Windows APIs capable of carrying verified accepted-socket identity across CLAIM; absent such an API, **architectural NO-GO** for the existing wire protocol. Independently source-audit the expiry/stop/teardown matrix and `Book::attest` ordering against native WFP reauthorization. On a separately admitted Windows development workstation, optional offline `rustc --test` build/read-only observation only; no filters, drivers or network experiments under current authorization.

**Preserved protections:** main/release, integration/windows-rust-capture-agent-20261031, PR #56, runner, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, external network, Windows machine, automation schedules/controller, any other repository untouched. No ProxiFyre, vendor binaries, C++ WFP payload, signed-driver work, kernel callout, WFP filters, VNC or cost incurred. No PacketBound/G2 PASS, leak-free, no-DIRECT or historical G1 acceptance claim.
