# Windows UDP bind ownership — read-only Rust vertical (stacked)

**Scope and provenance:** Standalone diagnostic module written independently using documented Microsoft IP Helper APIs; no ProxiFyre source, binary or vendor driver. This draft builds on PR #43 (TCP PID/creation-time candidate), which builds on PR #42 (read-only NDISRD probe). None authorizes capture, changes DNS or installs a driver.

## Why UDP is different from TCP

Windows GetExtendedUdpTable with UDP_TABLE_OWNER_PID describes **local UDP socket binds**, not outbound packets or remote endpoint attribution. An IPv4/IPv6 UDP bind may receive or transmit any number of datagrams, and 0.0.0.0/:: sockets are wildcards. Different sockets can reuse the same local address/port.

- Require the exact local IPv4/IPv6 address, local port and IPv6 scope ID. Never expand a wildcard binding to a concrete destination/source IP and never infer a peer IP/hostname.
- Reject duplicate matching rows **even if their PIDs are equal**, PID 0, changing snapshots and oversized/malformed table data. Return found=false for a clean absence.
- Query with PROCESS_QUERY_LIMITED_INFORMATION only; pin the process handle through the second UDP table read; require unchanged PID, creation FILETIME and full image path. Close via RAII.
- Report bind_only=true, remote_endpoint_known=false, authorizes_capture=false, native_packet_attribution_proved=false, dns_leak_test_passed=false. A successful two-snapshot local binder lookup is **not** evidence of origin for any captured DNS/QUIC/UDP packet.
- Never use this result for protected-mode Direct/Proxy/Block until actual packet-to-process evidence exists. Protected unknown identity must fail closed.

## Public local C ABI

fb_windows_udp_owner_candidate_json(const char *query_json), returns an owned JSON string freed with fb_string_free.

Valid input example: {"local":"127.0.0.1:53001"}. IPv6: {"local":"[::1]:53001"}. A remote key is rejected; the UDP PID table contains no peer. Non-Windows returns unavailable error. Response can contain a private executable path; never log it by default.

The TCP counterpart fb_windows_tcp_owner_candidate_json remains separately documented. Both are diagnostic only.

## Implemented regression coverage

- IPv4/IPv6 table-byte-order and exact local endpoint/port matching tests.
- Bounded table reads (8 MiB, 100,000 rows, at most four retry attempts), checked row-size/count arithmetic, truncated/malformed table negatives.
- Duplicate-same-PID and duplicate-different-PID ambiguity tests, missing bind, zero PID and changed binding negatives.
- **Real local Windows UDP socket test**: bind 127.0.0.1:0 and require the queried PID to equal the current test process, check nonzero creation time; all capture/DNS claims remain false.
- C foreign-caller link smoke on all platforms: zero-port TCP/UDP owner requests fail and never return authorized.

These prove only bounded Win32 diagnostic execution on hosted Windows Server. They do not verify NDISRD kernel packet interception, Win10/11, signatures, per-app DNS, IPv6 UDP runtime, QUIC, DoH/DoT or leaks.

## Next gated work

1. Real Windows 10 22H2 and Windows 11 x64 **with separately installed official NDISRD**, Secure Boot, Memory Integrity and Defender unchanged: obtain exact EXE/PID/creation-time binding and outbound UDP packet captures; identify wildcard bind/reuse/races under load, IPv6 scope/dual-stack, DNS/QUIC cases. Preserve PCAP/JSON and source/binary SHA.
2. Add independent Rust NDISRD packet I/O receive/reinject worker with strict queue bounds, adapter lifecycle and safe rollback; prove actual packet-to-flow correlation before changing a routing verdict.
3. Enforce fail-closed behavior for selected UDP/DNS unless a **separately proven** protected path exists. No silent DIRECT fallback; no DNS leak-free claim from IP Helper alone.

## Official ABI documentation

- https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable
- https://learn.microsoft.com/en-us/windows/win32/api/udpmib/ns-udpmib-mib_udprow_owner_pid
- https://learn.microsoft.com/en-us/windows/win32/api/udpmib/ns-udpmib-mib_udp6row_owner_pid
- https://learn.microsoft.com/en-us/windows/win32/api/udpmib/ns-udpmib-mib_udptable_owner_pid
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes
