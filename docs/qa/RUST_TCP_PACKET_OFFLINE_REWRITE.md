# Rust TCP packet primitive: offline checksum and tuple rewrite

**Scope:** original clean-room Rust code in `flowbridge-core::tcp_packet`. Stack on PR #44 (which stacks on #43 → #42). It does **not** open `\\\\.\\NDISRD`, install a driver, inspect a process, route traffic, intercept/reinject packets or protect applications. **NO NATIVE PASS.**

## Contract

- Input is one *complete IP packet beginning with IPv4/IPv6*, not the Ethernet/VLAN frame returned by NDISRD. Future driver I/O must independently validate the link layer, adapter, direction, packet epoch and original destination. There is no automatic Ethernet stripping.
- `inspect_tcp` rejects incorrect lengths, invalid IPv4 header or TCP checksums, zero ports, IPv4 fragments (including reserved fragment flag), IPv6 extension headers and unsupported protocols. IPv4 header options are included in header checksum; TCP data offset is bounds-checked.
- `rewrite_tcp_tuple` requires a byte-for-byte match to an explicitly supplied original 4-tuple (address family, source/destination address/port); replacement cannot cross IPv4/IPv6 families or contain TCP port 0. The function validates before mutation, then fixes IPv4 header and IPv4/IPv6 TCP pseudo-header checksums, leaving TCP payload, SEQ, ACK, flags and options unchanged.
- A successful rewrite is **not permission to forward**. Only an upcoming driver-bound per-flow routing state machine may supply the expected/replacement tuples. There is no selected-process identity proof, SYN/FIN/RST state tracking, return-path mapping, checksum offload handling, fragment reassembly, IPv6 extension processing, local loopback guarantee or SOCKS connection created here.
- Callers in *protected mode* must **block and emit a reason** for unsupported/invalid/ambiguous packets, not fall back to DIRECT. This module does not implement that protected mode yet.

## Regressions

- IPv4 and IPv6 round-trip rewrite (including odd-byte TCP data), with full byte equality after inverse rewrite.
- Payload/header checksum mutation, truncated/trailing bytes and atomic no-change on preflight error.
- IPv4 MF/reserved fragment flags; IPv6 fragment header rejected.
- Wrong original tuple, mixed families and port zero leave packet unchanged.

## CI and acceptance

Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and workspace tests on Windows 2025, macOS 15 and Ubuntu. Pin the exact HEAD and GitHub Actions artifact hashes. These are **offline unit regressions only**.

**Not yet accepted:** actual official signed NDISRD presence/capture on Windows 10/11 x64, process ownership or IPv4/IPv6 TCP redirect, safe packet egress, DNS/UDP leak-free behavior, secure service lifecycle and installer/rollback. The user cannot run a native test at present; continue independent code and CI, leave native gates open.
