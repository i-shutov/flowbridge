# Windows IP Helper ownership candidate — isolated Rust vertical

Scope: **read-only diagnostic, not a protected-route or real NDISRD interception acceptance**. This stacked draft follows the Rust NDISRD foundation in PR #42 and uses public Microsoft Win32 IP Helper and process APIs, not ProxiFyre or its AGPL implementation.

## Win32 data source and algorithm

- Read exact IPv4/IPv6 TCP connection rows from GetExtendedTcpTable with TCP_TABLE_OWNER_PID_CONNECTIONS, bounded to 8 MiB and 100,000 rows per response. Reject truncated headers, impossible counts, oversized tables, repeated sizing changes, mismatching families and ambiguous ownership. Ports are decoded from network order.
- Match an exact local-address/port + remote-address/port tuple; no substring matching, DNS inference, PID-from-filename inference, wildcard remote endpoints or listener-only authorization. Preserve IPv6 link-local scope IDs in network byte order. Reject rows in CLOSED/LISTEN/TIME_WAIT/DELETE_TCB states (accepted candidate states: SYN_SENT through LAST_ACK inclusive) and duplicate exact tuples **even when reported PIDs match**: a repeated row is not evidence of a unique live socket.
- Open the candidate PID with PROCESS_QUERY_LIMITED_INFORMATION, no inheritance and no mutation rights. Query both its process-creation FILETIME and QueryFullProcessImageNameW full executable path from that single pinned process object. Re-read IP Helper rows, require identical PID for the same tuple, and re-read process identity. RAII closes the process handle on every path.
- Return the candidate through the Rust C ABI fb_windows_tcp_owner_candidate_json with explicit authorizes_capture=false and native_packet_attribution_proved=false on every result. Never log the returned path by default. This API is for local diagnostics and may expose private file paths to the caller.

Input example: {"local":"127.0.0.1:51001","remote":"127.0.0.1:443"}. For IPv6, use bracketed socket addresses such as {"local":"[::1]:51001","remote":"[::1]:443"}.

## Negative contracts and tests

Windows unit tests cover network-endian TCP port conversion, exact five-tuple discrimination, IPv6 scope-id matching, stale TIME_WAIT/LISTEN rejection, duplicate exact tuples with identical or different PIDs, changing PIDs, disappearing endpoints, bounded row count, and a real local IPv4 TcpListener/TcpStream query owned by the running test process. The real socket test requires a nonzero process-creation timestamp and explicit no-capture authorization. These tests must execute on the PR exact-head Windows CI.

- PID+creation time does not alone prove packet ownership. IP Helper snapshots are asynchronous; endpoint reuse between observations and first SYN attribution can still race. The process handle pins only the queried process object.
- The test is not evidence that NDISRD is installed, signed, active, copying packets, reinjecting correctly or assigning traffic to the right application. No packet redirect, firewall change, signing change or installer is performed.
- No UDP or IPv6 real-loopback runtime test is asserted by this narrow vertical; IPv6 table decoding exists but native Windows 10/11 and UDP acceptance are outstanding.
- SYSTEM, protected process, UWP/packaged app, PID reuse under load, process path aliases, volumes and symlink/reparse-point canonicalization need explicit Win10/11 native negative tests before any trusted-routing verdict.

## Remaining promotion gates

1. Bind packet metadata and IP Helper snapshots to a well-defined earliest-observation epoch, process-creation time, and verified path/identity policy; deny all ambiguous or unavailable evidence in protected mode. A packet must never become authorized solely because this API returned a candidate.
2. Introduce UDP IPv4/IPv6 table ownership and an explicit DNS/QUIC deny-or-route policy, with leak traces.
3. Execute on owner's Windows 10 22H2 / Windows 11 x64 with Secure Boot, Memory Integrity and Defender enabled and signed official NDISRD installed separately. Pin exact source and binary SHA, save JSON and packet trace with explicit selected/unselected app assertions.
4. Only then integrate Rust packet receive/rewrite, supervised FlowBridge SOCKS → OpenSSH, protected fail-closed and rollback. MacOS NE remains independent.

## Primary public ABI references

- https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable
- https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_pid
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew
