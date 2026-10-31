# Rust TCP flow-lease ledger — offline R3 prerequisite

**Research date:** 2026-10-31. **Exact parent:** PR #53 HEAD
`f3489d241085ff49c7da26b6fe5cf9be5010c16c`. This is a stacked, separate draft change, not a merge to main.

## Safety contract

- Pure Rust `flowbridge-core::tcp_flow_lease`. No NDISRD calls, packet receive/inject, Windows service mutation, privilege elevation or external driver binaries.
- The table is a bounded **admission and lifetime bookkeeping** primitive, not an executable policy engine. The production caller must independently obtain an OS-verifiable process identity from the Windows IP Helper resolver (PID **and creation time** and full executable path); compare that identity to the selected application policy and exclude the SSH/carrier process **before** inserting a lease. A caller-supplied OwnerStamp alone is untrusted.
- Directed TCP tuple includes addresses and ports in both IPv4 and IPv6. Initial SYN (without ACK, FIN, RST) is required. A SYN retransmission can only confirm a previously pending lease and does not extend its lifetime. A tuple collision never replaces an active owner.
- New entries are **Pending** and are not routable. Only a verified upstream SOCKS5→SSH connection from a supervised worker may promote a pending lease to Active; failed upstream activation retires the lease and must not result in DIRECT fallback. State checks do not grant packet-write authority.
- The flow is bound to an owner stamp (PID+creation timestamp), a per-service-run nonzero session ID, and a monotonically increasing sequence. A changed owner stamp revokes the flow, and a stale session/sequence cannot attach to a recycled tuple. The runtime must generate a distinct ID for each new service run; the ID is **not** a cryptographic authorization token.
- The ledger is single-threaded; a future packet worker must own synchronization, ordering, and a monotonic millisecond clock. A backwards clock jump, counter wrap, or uncertain shutdown stops the entire ledger and revokes all leases.
- Capacity is 1..=65,536; idle expiry 1..=86,400,000 ms. Capacity exhaustion denies new flows instead of evicting active flows. Active traffic can refresh idle time; repeated pending SYN cannot.
- FIN bookkeeping permits reverse-direction traffic after the first FIN and retires after both FINs. It **does not** implement RFC 793 TCP sequence/ACK validation, retransmissions, RST injection or packet checksums; those require separate native and on-wire acceptance.
- Any error on a protected path must produce DROP, never DIRECT.

## Regression scope

Unit tests cover invalid limits/tuples/owners, IPv4/IPv6 separation, SYN-only admission, pending refusal, upstream failure and activation, duplicate/recycled tuples, capacity, PID-creation-time mismatch, old-session and sequence denial, retransmission/idle expiry, half-close, terminal stop, monotonic clock regression and sequence overflow.

These are offline deterministic tests. Hosted Windows Server 2025 CI can validate compilation and regressions but **cannot** prove packet interception, owner attestation, carrier exclusion, IPv4/IPv6 traffic redirection, lossless FIN/RST behavior, native fail-closed, DNS leak freedom or Windows 10/11 acceptance.

## Required integration sequence

1. R2: verify the official Windows Packet Filter NDISRD device ABI, live adapter selection, bounded read/reinject, cancellation and recovery with separately installed official signed driver.
2. R3: bind the ledger to an IP Helper result with an explicit time-of-check/time-of-use identity refresh; revalidate PID creation time and executable identity at selected-flow packet attribution points. Build a worker-side fixture for PID reuse, tuple recycle, fast close and carrier self-loop exclusion.
3. R4: implement real TCP 5-tuple bidirectional NAT/redirect state with OS checksums and sequence/ACK bookkeeping; connect selected TCP to existing FlowBridge SOCKS5→OpenSSH supervisor, including SSH death and rollback.
4. R5-R7: explicitly block or support UDP and local DNS, collect packet traces on native Win10/Win11 with protections enabled, add signed-driver verification, service lifecycle, installer and rollback. No vendor driver packaging without licensing approval.

**Not accepted:** real NDISRD driver I/O, native Win10/11 interception, selected-app SOCKS→SSH, protected fail-closed on wire, DNS leak-free or release 1.0.
