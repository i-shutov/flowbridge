# NDISRD read-only adapter inventory — Rust R2 preflight

**Date:** 2026-10-31. **Stacked base:** PR #52 exact SHA `9d3d400a8cd0f76f391c95ed40cf51d9c1325222`.

## Independent ABI evidence

The published Windows Packet Filter driver ABI defines `IOCTL_NDISRD_GET_TCPIP_INTERFACES` as `CTL_CODE(0x8300, 0x831, METHOD_BUFFERED, FILE_ANY_ACCESS)`, which evaluates to `0x830020c4`. The public `TCP_AdapterList` contract has at most 32 entries, 256-byte adapter names, opaque native handles, medium, 6-byte MAC and 16-bit MTU. The x64 structure is 8-byte aligned, 8,840 bytes long, with fixed offsets asserted in unit tests. This is independently implemented in `crates/flowbridge-ffi/src/windows_packet_filter.rs`; no DLL, C++ helper, ProxiFyre executable or AGPL source is embedded.

Primary public sources:
- https://www.ntkernel.com/docs/windows-packet-filter-documentation/c-api/gettcpipboundadaptersinfo/
- https://www.ntkernel.com/docs/windows-packet-filter-documentation/structures/_tcp_adapterlist/
- Official vendor ABI header `wiresock/ndisapi:include/Common.h`, observed blob SHA `ba42da741693816d2d843f59b241aa827c1a3d3d`. **ABI constants only** were used; no header has been copied into FlowBridge.

## Behavior and safety

- The diagnostic first runs the existing passive NDISRD driver-version check. On incompatible or inaccessible versions, adapter inventory stays `not_checked`.
- It opens `\\.\NDISRD` with **zero requested file access**, submits **one read-only** `GET_TCPIP_INTERFACES` buffered IOCTL and closes the handle on every return. It never sets filter modes, starts/stops the service, queues, reads or injects packets, or modifies an adapter.
- Input and output use separate, initialized, bounded native buffers. The reported byte count must exactly match the x64 ABI. Adapter count must not exceed 32; each returned name must be a terminated, nonempty, unique printable ASCII identifier. Invalid output is an explicit failure, not a usable adapter list.
- The JSON diagnostics include `adapter_inventory_status`, `adapter_count`, and a list of bounded adapter metadata (`name`, `medium`, `mtu`, `mac`, `handle_present`) or an explicit error. **Opaque driver handles are not serialized**.
- On non-x64 Windows the read-only inventory API returns an explicit unsupported-architecture failure. Underlying driver presence, signature, Windows policy compatibility, and interception remain unverified.
- `signature_status=not_checked`, `packet_capture_active=false`, `native_routing_accepted=false`, `dns_leak_test_passed=false` remain mandatory regardless of any successful inventory reply.

## Verification plan

1. Windows x64 compile, Rust format/Clippy and unit tests verify ABI constant/size/field offsets and validate synthetic zero/one/out-of-range counts, truncated buffer, unterminated, duplicated or invalid names.
2. CI must complete on the **exact branch HEAD/merge SHA**; record individual workflow run conclusions and artifacts. Hosted Windows Server 2025 validates code, **not Win10/11 driver I/O**.
3. Native Win10 22H2 and Win11 x64 with a separately installed official signed NDISRD: compare returned adapter IDs, MAC and MTU to OS adapters and verify version/SCM/signature independently without changing Secure Boot, Memory Integrity or Defender.
4. After that evidence, introduce a separately gated writable device I/O worker with adapter changes, tunnel-mode rollback, bounded packet buffers, process ownership and fail-closed semantics. Merely listing adapters does not authorize capture or any protected route.

**Not accepted:** real NDISRD interception, selected-app SOCKS→SSH, protected fail-closed, IPv4/IPv6 on wire, DNS leak-free, or release 1.0.