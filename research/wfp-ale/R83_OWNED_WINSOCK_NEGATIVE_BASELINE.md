# R83 — owned-socket WinSock read-only negative baseline

2026-11-10. Only i-shutov/flowbridge research/windows-wfp-ale-attribution-20261107. Baseline HEAD d88957ddbde96a79733c35b6906629ed10af66fd; main read-only 5b5afc2feeda2195f302380e615ba003d4906e09. Independent R&D, NOT beta/PR #56, not PacketBound/G2 or historic G1.

## Concrete artifact
R83 includes std-only x86_64 Windows Rust probe r83/r83_winsock_readonly.rs. It uses only WSASocketW on *owned unconnected* IPv4/v6 TCP sockets, WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT), and WSAGetOverlappedResult(FALSE) with event-based overlapped completion. It never binds, connects, sends, receives or modifies WFP, drivers, policy, services or networks. This deliberately **cannot** yield a positive WFP redirect or origin proof. The Rust program was NOT compiled or executed; this Linux environment has no rustc or Windows runtime. Build candidate after separate Windows workstation permission: rustc --edition=2021 r83_winsock_readonly.rs -o r83.exe. Do not treat any result from ordinary sockets as redirected receipt.

## Verified completion constraints
- WSAIoctl return 0 = immediate terminal call success (not origin proof); SOCKET_ERROR plus WSA_IO_PENDING = not terminal. Overlapped immediate bytesReturned=0 means nothing about missing redirect record.
- WSAGetOverlappedResult on same SOCKET and same WSAOVERLAPPED with FALSE, TRUE return = successful terminal; FALSE+WSA_IO_INCOMPLETE = pending; FALSE+WSA_OPERATION_ABORTED = terminal error. Other errors can also signify invalid parameters, thus UNKNOWN; event signal and timeouts are not enough.
- Output, returned-DWORD, event, OVERLAPPED must survive unresolved I/O. This short-lived probe conservatively retains/leaks them if completion cannot be established, and skips the second query on that socket. No claim about prompt cancellation.
- It links official WinSock2 and Kernel32 system libraries, uses no vendor binaries or external crates. Windows x64 WSADATA and WSAOVERLAPPED layouts are size-asserted; real ABI correctness is still subject to native compilation/verification.

## Offline independent evidence
8/8 Python unit tests passed (see r83_completion_oracle.py). Python and independently written Node.js implementations agreed for all 576 ordered cases, SHA-256 92cb8d11e449bcf2af21b3fca6513314a8f3435d02d3ae20f1818d067d302785; counts: 208 TERMINAL_OK_NO_PROOF, 132 TERMINAL_ERROR_NO_PROOF, 236 UNKNOWN_RETAIN. These are pure finite-state models, NOT Windows I/O observations. Local pre-publication source-gate tests 12/12 checked forbidden API absence and escrow; they do not compile Rust.

## Kernel trust boundary and NO-GO
ALE_CONNECT_REDIRECT_V4/V6 and ALE_AUTH_CONNECT_V4/V6 must provide authenticated original process (kernel-pinned process handle/creation epoch/canonical EXE, not a later PID re-query), current/original FWPM_CONDITION_ALE_APP_ID, connection-generation identity surviving reauthorization and re-used 5-tuple. No document-supported binding of accepted SOCKET to raw DeviceIoControl(CLAIM, bytes) is demonstrated. WSAIoctl receipt and SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS preserve proxy redirection chain only, NOT final SSH proof or sibling DIRECT exclusion. R19 FWPM_CONDITION_IP_PROTOCOL=6 is TCP-only for v4/v6; UDP DNS/QUIC not covered. Non-TCP redirect needs WSAMSG IP_CONNECTION_REDIRECT_RECORD on first flow-creating packet via WSARecvMsg and WSASendMsg. Process death/PID reuse, IPv4/v6 sibling DIRECT, UDP/ICMP, BFE/WFP/SSH loss, dynamic policy teardown, PacketBound/G2 and physical leak-free all remain NO-GO.

Next decisive R84: compile and execute read-only unconnected-socket x64 Rust probe on separately authorized Windows research workstation, capture exact ABI/errors and I/O completions; this is only a negative baseline. Without native Windows execution, do not promote R83 to physical proof. Driver/callout/filter/VNC work still forbidden without owner's gates.

Microsoft API documents:
https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-context
https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaioctl
https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsagetoverlappedresult
https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketw
https://learn.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-wsadata
https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-overlapped

No main/release/beta/PR #56/CI/runner/services/firewall/UFW/Defender/SecureBoot/MemoryIntegrity/network/other repos/automations changes; no filters, driver, NDISRD, VNC, vendor/AGPL, C++ WFP payload, payments.
