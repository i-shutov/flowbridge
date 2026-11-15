# FlowBridge Windows WIN-01 — terminal AUTH CLAIM, driver ABI 4

**Date:** 2026-11-15. **Product engineering only.** Draft PR stacked on WFP AUTH/R198 PR #70. Owner-approved WFP/ALE development/tests; no native signed driver load, security downgrade, owner workstation changes or 1.0 release.

## The P0 source gap corrected

Before this change, `service.cpp::handle` used WSAIoctl on a local accepted redirected TCP socket to obtain WFP context and opaque redirect records. It then immediately called `fb_native_stream_open_wfp_json`. It did **not** demand that the kernel one-shot ticket had actually passed `ALE_AUTH_CONNECT`, nor did it consume the ticket to prevent reuse.

New sequence (all stages must succeed):

1. Kernel process-create callback caches OS PID, birth epoch and start key. A real `ALE_CONNECT_REDIRECT_V4/V6` issues an original endpoint record, unique flow ID and target broker PID. A real `ALE_AUTH_CONNECT_V4/V6` must consume its one-shot initial ticket (state `1 -> 2`), not an IP Helper/ETW snapshot or user-provided process ID.
2. Trusted, elevated exclusive `FlowBridgeCapture.exe` **accepts a TCP socket** on its local IPv4/IPv6 loopback broker listener. It calls OS `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` and `SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS` on **that accepted socket**. Any unavailable or malformed OS result fails without network fallback.
3. It checks `getsockname(accepted)` against the own armed loopback family/address and exact port, with the redirect context family agreeing. A foreign listener or mismatched loopback cannot use that claim path.
4. It invokes `DeviceIoControl(FB_IOCTL_CLAIM)` on the **same process's exclusive driver FileObject**, using a strict, versioned, 2144-byte request (`size`, `ABI4`, entire v3 redirect context). Driver validates request shape, trusted owner PID/FileObject, captured process's current kernel epoch/start key, original endpoint/flow ID/address/port and existing AUTH state 2. Only exact kernel-authenticated match moves ticket **terminally** to state 3; early/replayed/foreign/retired/invalid claims are denied.
5. **Only after successful CLAIM** does the helper evaluate Rust policy and call `fb_native_stream_open_wfp_json` with the opaque OS redirect records. Rust rejects WFP selected DIRECT/zero-hop routes before any outbound socket and requires record install before proxy connect. Failed CLAIM rejects and closes the accepted socket.

Device ABI raised **3 -> 4**; old helpers cannot operate with a new driver while skipping CLAIM. Win32 `Capture` holds a mutex across claim and `stop` to prevent use-after-close of driver HANDLE.

## Security and trust limits (DO NOT mark G2 accepted)

- CLAIM matches a **kernel-issued initial AUTH ticket** to a context that an exclusive privileged helper claims came from a specific accepted socket. The kernel IOCTL does NOT independently receive or resolve that accepted socket's AFD/kernel object. Thus a compromised elevated helper could submit copied context bytes; success alone is **not authenticated socket-object binding**.
- WFP accepted-socket `WSAIoctl` context/records are OS-provided data, but their exact continuity through CLAIM, outbound `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS`, actual kernel AUTH, and physical SSH egress must be witnessed on signed native Win10/Win11. A test fixture cannot prove this.
- 512 non-reusable AUTH tickets per driver session remain a fail-closed bounded prototype, not a production 10k-flow solution. Reauthorization is explicitly denied until an idempotent, generation-safe kernel contract passes.
- Existing research R198 original/current AppId collision on records-tagged external SSH remains **physical/unverified**. No broker-PID-wide DIRECT exemption is added.
- BFE dynamic session loss, foreign hard permits, process death/5-tuple reuse, DNS/UDP/IPv6/QUIC/DoH, OpenSSH outage/no-DIRECT, independent packet captures, signer/Code Integrity, initial ticket issuance/CLAIM/native loopback flow and recovery still require genuine isolated lab evidence.

## Test coverage

`tests/windows_wfp_auth_receipt_r198.cpp` compiles the **production C** `auth_receipt.h` into native MSVC code and now runs 13 cases (previous 9 plus early claim, terminal/replay, bad PID/epoch/broker/port/flow/family/address, process death/driver stop, null/zero claim). The Python `test_windows_wfp_claim_source.py` traces actual `driver.c`, `capture.cpp`, `capture.h`, `service.cpp` and shared ABI headers, and rejects 11 deliberate source mutations, including removing kernel claim, removing epoch check, using old ABI3, sending before claim, allowing foreign socket port and reusing terminal tickets.

Windows WDK compiles the actual unsigned kernel, and general CI compiles Windows GUI/helper/installer plus portable Rust on Windows/Linux/macOS. Source/CI pass does not install/load/sign a driver or prove physical G2.

## Next real release blocker

On independently admitted disposable Windows 10 Pro 22H2 and Windows 11 Pro x64 with **verified signed WFP driver, backup snapshot, VNC/SYSTEM rescue and rollback**, record exact signed SHA, WFP current/original AppIds, source PID/epoch, redirect loopback metadata, initial AUTH state, exact accepted socket WSA context/records, terminal claim outcome, outbound SSH receipt and independent selected/unselected pcap/dual-stack fail-closed behavior. Deny GO if any stage fails. No production driver deployment is authorized by merely creating this document.

**Gate state:** `WIN-01.accepted=false`, `R01/G2=NO_GO`, `windows_1_0_accepted=false`. Never treat hosted WDK or native C logic tests as signed native packet attribution.

Official Microsoft references:

- [Using Bind or Connect Redirection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection)
- [SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT](https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-context)
- [SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS](https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records)
- [SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS](https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records)
