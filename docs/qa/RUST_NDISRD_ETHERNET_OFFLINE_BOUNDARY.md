# R2 prerequisite: conservative NDISRD Ethernet/VLAN to IP boundary

**Status:** offline Rust-only, draft stacked on #47 (and thus #45 → #44 → #43 → #42), no privileged driver I/O. Do not claim protected traffic acceptance or release 1.0.

## Why this boundary exists

Official vendor WinpkFilter documentation describes `ReadPacket`/`INTERMEDIATE_BUFFER` data as raw **Ethernet frames**, including the link header, whereas `flowbridge-core::tcp_packet` requires a complete bare IPv4/IPv6 datagram. Blind `frame[14..]` stripping would shift VLAN-tagged packets and misinterpret Ethernet padding as IP payload.

Vendor references (functional ABI documentation, **not** ProxiFyre source): https://www.ntkernel.com/docs/windows-packet-filter-documentation/c-api/readpacket/ and https://www.ntkernel.com/windows-packet-filter/.

## Original Rust contract

- `ndis_ethernet::inspect_l2_ip` accepts a bounded Ethernet-II frame (max 9216 bytes as an **offline safety ceiling**, not a claimed adapter MTU), at most two 802.1Q/802.1ad tags, IPv4 or IPv6 only. Rejects reserved VLAN ID 4095, unknown EtherType including ARP/802.3 LLC, three VLAN tags, malformed headers, length inconsistency and oversize.
- The output `IpRegion {offset,length,padding,vlan_tags,version}` identifies **only** declared IP bytes. IPv4 uses Total Length; IPv6 uses base-header payload length. Zero IPv6 payload/jumbogram extension semantics are unsupported.
- Accepts zero-valued minimum-frame Ethernet padding only; rejects nonzero or excess trailers (FCS not expected). This restrictive diagnostic rule may need revision against genuine vendor NIC traces, and must *never* silently fall back to forwarding frames it does not recognize.
- `ip_packet_mut` bounds the mutable IP slice to that region: Ethernet MACs, VLAN headers and trailer bytes remain outside the returned slice. This is not proof of source MAC, adapter ownership, driver queue ordering, packet direction or per-process attribution.
- **No kernel mode changes**: no `CreateFile`, mode setting, kernel driver loading, read/send IOCTL, packet reinjection, DNS handling, route permission or provider/agent dependency.

## Negative/positive regressions

IPv4/IPv6 with 0/1/2 VLAN tags; exact offsets; byte-preserving split; minimum-size padding; nonzero trailer; excess/truncated IP; unknown EtherType; reserved VLAN ID; three tags; wrong IP version; invalid IPv4 IHL; truncated IPv6; bounded frame size.

## Required next stage (not yet delivered)

1. Verify *actual* signed official NDISRD driver ABI, services, adapters, capabilities and version **read-only** on Windows 10/11 with OS protections enabled; separate vendor installation and licensing.
2. Bind every packet to a validated adapter, ingress/egress direction, active mode epoch, driver packet length and owner confidence. Do not use IP Helper snapshots as packet-origin proof.
3. Construct guarded RX/TX queue handling with cancellation, strict per-adapter bounded resources and crash-safe mode rollback before any native tunnel intercept. NDISRD loopback traffic normally bypasses filters unless configured explicitly; redirecting to local SOCKS cannot assume it is already intercepted. Vendor reference: https://www.ntkernel.com/docs/windows-packet-filter-documentation/c-api/getadaptermode/.
4. Record native Win10/11 pcap/JSON/SHA evidence for TCP/UDP IPv4/IPv6 and offline-versus-native checks. Hosted Windows Server 2025 Rust CI is only a compilation/regression gate, not an interception claim.
