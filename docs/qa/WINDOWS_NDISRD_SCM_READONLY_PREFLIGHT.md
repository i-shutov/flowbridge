# NDISRD SCM read-only preflight: Windows Rust vertical R1a

**Scope:** observational preflight only, stacked after PR #45 (which stacks on #44 → #43 → #42). Implemented independently in Rust using Microsoft's SCM API. The official Windows Packet Filter (NDISRD) kernel driver must be separately installed by the owner under its own terms; FlowBridge does not include or install the driver or ProxiFyre.

## Contract

- Query only the **local active SCM database** for exact service name NDISRD with OpenSCManagerW(SC_MANAGER_CONNECT), OpenServiceW(SERVICE_QUERY_STATUS) and QueryServiceStatus. Close both handles with RAII on every path.
- service_registered=false only on Win32 ERROR_SERVICE_DOES_NOT_EXIST (1060). Other open failures including ERROR_ACCESS_DENIED (5) return **null/unknown**, never absent or permitted.
- A successfully queried service reports its current state and whether SCM declares its service type as a kernel driver. Query failure leaves state/type unknown. Pending, stopped or even running are **diagnostic observations**, not a packet capture or routing permission.
- Existing independent, passive NDISRD device version IOCTL probe remains read-only and separate from SCM observation. API compatibility plus running service is still *not* verified signed vendor provenance, adapter binding, NDIS packet interception or safe process attribution.
- Report always returns driver_signing_verified=false, adapter_binding_verified=false, capture_authorized=false, driver_installation_attempted=false, packet_capture_active=false, native_routing_accepted=false, dns_leak_test_passed=false.
- The owned C-ABI JSON string is still freed by fb_string_free. No new privileged API, no start/stop/configuration commands, driver payload, settings change, or secrets.

## Negative regressions

1. Running kernel driver type does **not** authorize capture, signature or adapter binding.
2. Missing service (1060) is explicitly distinguished from access denied/inaccessible SCM and from status-query failure.
3. Wrong service type and pending state cannot authorize protected capture.
4. Real local observation calls only read-only SCM APIs and cannot report successful driver signing/interception; foreign-C smoke checks the output invariants on Windows.

## CI versus native evidence

The required CI jobs are Windows Server 2025 Rust fmt/clippy/test + native C ABI, Linux/macOS unchanged, DNS regressions and real OpenSSH 128/1152/10000/4. Record exact PR HEAD SHA and run/artifact SHA after completion. This only establishes **API/build correctness on a hosted runner**, not kernel capture on a personal Windows 10/11 host.

### Still open (issue #41 R1–R9)

- Prove official Microsoft-signed NDISRD ndisrd.sys provenance and supported OS/driver pairing using actual loaded image path, signature chain and hash. SCM + version alone must never stand in for this.
- Native Win10 22H2 and Win11 x64 verification with Secure Boot, Memory Integrity and Defender intact. Driver adapter binding, packet RX/TX, robust PID+creation-time packet attribution, protected fail-closed and DNS/UDP pcap artifacts remain untested.
- Independent Rust driver I/O, packet queue cancellation, TCP state, SOCKS→SSH, DNS/QUIC semantics, service/IPC, installer/rollback and macOS NE are separate future verticals.

The read-only SCM query must never be silently promoted into a “ready/protected” UI badge. Fail closed until the actual driver and source flow have been independently bound and verified.

## Public API references

- Microsoft: https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatus
- Microsoft: https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status
- Windows Packet Filter official downloads (separately installed): https://www.ntkernel.com/windows-packet-filter/download/
