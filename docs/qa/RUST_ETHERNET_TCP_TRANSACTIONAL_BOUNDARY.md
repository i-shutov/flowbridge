# Transactional Ethernet-to-TCP boundary (OFFLINE R2/R4 prerequisite)

**Research/base:** 2026-10-31, stacked on PR #49 exact SHA `3ce173a595db022b88152138f59c2ad3b42050ee` (which itself is stacked on #47). Source file: `crates/flowbridge-core/src/ndis_frame_tcp.rs`.

## Explicit boundaries

- This is a **pure Rust, offline** bridge from `ndis_ethernet::inspect_l2_ip` to `tcp_packet::inspect_tcp/rewrite_tcp_tuple`. It contains no NDISRD device calls, no read/write IOCTL, no adapter mode, no process ownership, no traffic forwarding, and no packet injection.
- It consumes a complete Ethernet-II frame (up to two permitted VLAN tags), extracts the **declared** IP datagram, and validates the full TCP packet including its checksums and supported option policy. All unsupported input is an error, not permission to use DIRECT.
- `rewrite_ethernet_tcp_tuple` is intentionally transactional. The caller must provide reusable scratch storage covering the validated datagram length; the function copies only the datagram into scratch, rewrites and revalidates **there**, and copies it back **only on success**. On any failure the input L2 frame is unchanged. Missing scratch produces `ScratchTooSmall`, not truncated output. Header, VLAN and Ethernet padding are never altered.
- Scratch is bounded by the existing frame size ceiling, and no allocation occurs inside either public function. A future worker should allocate reusable, per-worker scratch outside its packet hot path; its capacity and cancellation policy must be part of native driver acceptance.

## TCP option security integration (2026-10-31)

This follow-up draft is **stacked on #51 exact HEAD `5ceefbf54bed969661eb49da37db1c08a772a81e`**. It integrates the existing original Rust TCP-option admission policy from #48 exact HEAD `319741e51217b42a7e2c01f505f7093d6f47177f` into the Ethernet/VLAN transactional boundary. No source or binaries from ProxiFyre (AGPL-3.0) were used. #48's independent tunnel CI-fixture change is **not** imported by this focused security branch; #50 tracks that separately.

Supported TCP options: EOL with zero padding, NOP, MSS, window scale, SACK permitted, correctly sized SACK blocks, and timestamps. Authenticated/multipath/unknown/experimental options and malformed layouts return `PacketError::Unsupported` before any Ethernet frame update. Additional L2-level regressions build valid IPv4/IPv6 and TCP checksums, exercise 0/2 VLAN tags, and prove rejected frames remain byte-for-byte unchanged. A passing offline check is **not** an authorization to inject or to forward traffic outside the tunnel.

## Offline regression matrix

| Case | Required result |
| --- | --- |
| IPv4 and IPv6, untagged and QinQ, both rewrite directions | Valid TCP checksum each way; original bytes recovered exactly |
| Ethernet header, VLAN and minimum-frame zero padding | Identical before and after successful rewrite |
| Scratch shorter than IP datagram | `ScratchTooSmall`, original frame byte-for-byte unchanged |
| Original tuple mismatch | Explicit TCP error, original frame unchanged |
| Corrupt TCP checksum | TCP checksum error, original frame unchanged |
| Unsupported Ethernet type or nonzero padding | L2 error, original frame unchanged |
| IPv6 fragment extension | Unsupported TCP boundary, unchanged frame |

## Still unproven / mandatory next steps

1. Validate **official** NDISRD buffer layout, adapter/direction metadata, driver version and package provenance independently, without importing vendor binaries or AGPL ProxiFyre. Read-only preflight cannot enable capture.
2. Native Rust driver I/O: enumerate adapters, bounded receive and inject, filter-mode transitions, stop/rollback, failure atomicity, packet ordering and adapter changes.
3. Packet-to-process PID+creation-time binding, flow ownership/reuse, sequence/ACK state tracking, SOCKS redirect, carrier exclusion, protected fail-closed and local-vs-remote DNS decisions.
4. Actual Win10/11 x64 proof (Secure Boot, Memory Integrity, Defender intact) with installed signed NDISRD, selected/unselected app, IPv4/IPv6 and DNS/UDP packet captures, SSH loss and cleanup. GitHub hosted Windows Server 2025 CI is only code/test evidence.

**Do not claim interception PASS, DNS leak-free, real selected-app proxy routing, Win10/11 acceptance or release 1.0 on the basis of this module.**
