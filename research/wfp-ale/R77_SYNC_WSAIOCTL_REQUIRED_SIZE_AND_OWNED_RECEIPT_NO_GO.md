# R77 — synchronous redirect-record sizing contract, typed accepted-socket guard

Date: 2026-11-09. Research branch ONLY `research/windows-wfp-ale-attribution-20261107`.
Observed HEAD before: `a54d8215b4ac1f493d9ab2e31923c098afa021e4`.
Observed main: `5b5afc2feeda2195f302380e615ba003d4906e09`.
No driver, WFP filter, installed tooling, network changes, Windows runtime, CI/runner, beta, PR #56, or other-branch mutation.

## Specific source cut and Microsoft contract

`kernel-r19/broker_windows.rs` (blob `16ec8853d322b40f0e00e14d49ae3410741b9395`) invokes `WSAIoctl(QUERY_RECORDS)` **once** on the accepted `TcpStream` using 65,536 output bytes. It reports the same generic failure for WSA errors, empty response, and inconsistent length. It then queries a custom 128-byte redirect context on that same socket. A provider buffer larger than 64KiB is not supported by this code; the actual native failure mode and sizes are **unmeasured**.

Microsoft documents a synchronous (`lpOverlapped=NULL`) output buffer of at least `sizeof(ULONG)` and nonzero returned byte count on success. Its **parameters** section says a short output buffer fails with `WSAEINVAL` and `lpcbBytesReturned=0`. Its **return-code** table also allows `ERROR_INSUFFICIENT_BUFFER` with a returned required size. These descriptions cannot safely be collapsed into the claim that every undersized operation returns the required size. A zero-length sizing probe violates the documented synchronous minimum. A blanket retry after `WSAEINVAL` is an unsound assumed sizing oracle. `WSA_IO_PENDING` is not a successful synchronous receipt.

A NARROW conditional GO for a future user-mode implementation: on an explicit `ERROR_INSUFFICIENT_BUFFER` with trustworthy `required > current_cap`, `required <= bounded_budget`, perform **at most one** retry on the **same owned accepted socket** and only accept a nonzero successful byte count in bounds. On any `WSAEINVAL`, zero/invalid returned size, retry error, provider unsupported, interruption, socket replacement, or WSA pending, fail per-flow without CLAIM; no fallback to guessed records. 1 MiB here is **just a test-model limit** and not a Windows sizing guarantee. Query redirect context separately from the same accepted socket; check FBR3 structure and ticket before kernel CLAIM. Successful retrieval does **not** attest original process or socket-to-CLAIM kernel causality.

Official sources, reviewed 2026-11-09:
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-context
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking

## Experimental results (synthetic only)

`r77/r77_negative.py`: 16/16 unittest PASS, exhaustively checks **6,720** synthetic observations for IPv4/IPv6, 7 first-call results, 6 required lengths, 4 returned lengths, same/different socket, valid/invalid context and 5 possible retry outcomes. `r77/r77_independent.mjs` is a separately written Node/JS oracle. Both agree on classification counts and SHA-256 of ordered decisions: `01fd8f9756b0b62c7d0db8cbdafb71252accf3d7b2185c59ff61b5710d3f225e`.

Outcomes: 132 `CANDIDATE_NOT_PROOF`, 3,376 `REJECT_DIFFERENT_SOCKET`, 1,680 `REJECT_BAD_CONTEXT`, 1,200 `REJECT_UNVERIFIABLE_ERROR`, 160 `REJECT_INVALID_REQUIRED_LENGTH`, 124 `REJECT_BAD_LENGTH`, 48 `REJECT_RETRY_FAILED`. These are artificial combinations, **not observed WFP failures or security rates**. Every candidate remains non-admitted until independently validated original process, endpoint, ticket and SSH.

`r77/r77_owned_receipt.rs` implements a pure, safe Rust typestate model: ownership flows `Accepted<S> -> WithRecords<S> -> WithContext<S> -> ClaimAttempted<S>`. No raw socket ID API or external driver/FFI. It has 16 unit tests, **not executed** because rustc/cargo are absent in this Linux executor and the reported Windows 10 RDP machine lacks Rust. Python static checks verify the source is `forbid(unsafe_code)` and contains no FFI. This does not replace compiling/running the Rust tests.

## Trust chain and unchanged NO-GO

Only a kernel callout at `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6` can supply kernel-origin connection identity, with `FWPS_METADATA_FIELD_PROCESS_ID`, original APP_ID and a referenced *original* process creation epoch captured under legal IRQL and protected lifetime. Check redirect state before issue, coordinate AUTH_CONNECT V4/V6, record original v4/v6 destination including scope; a new ticket must survive process death/PID reuse and reused 5-tuple without mistaken join. User-mode AppId lookup and OpenProcess/GetProcessTimes/QueryFullProcessImageNameW observe current images, not historical owner. Opaque redirect records/context are retrievable using socket-owned WSAIoctl but are not a signed kernel origin certificate. `DeviceIoControl(CLAIM, bytes)` is not bound to that socket by existing kernel protocol. Proxy-level SSH host-key/authentication loss, DNS/UDP/QUIC, IPv6 scope/compartment and sibling DIRECT need separate physical kernel-enforced containment proofs. WFP net events cannot close the missing witness (R76).

NO-GO remains for PacketBound/G2, no-DIRECT/leak-free, all OS-lifetime edge cases, SSH/WFP crash containment and transfer of old G1 at `dd1ab3c`.

## Next decisive experiment (R78)

On a separately approved user-mode Windows research workstation *only after it actually has Rust/MSVC*, compile/run R77 typestate tests; optionally run **read-only** `WSAIoctl` on a process-owned ordinary socket to determine exact error code and required-size behavior. Ordinary unredirected sockets are a **negative baseline only** and cannot certify positive redirect-record buffer behavior. Any positive native test requires a separately authorized and gated redirect setup: not permitted now. Do not install drivers, configure WFP, alter networking, execute unapproved connection experiments or interpret a successful synthetic guard as kernel proof.
