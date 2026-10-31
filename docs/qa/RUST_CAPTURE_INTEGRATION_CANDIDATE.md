# Rust capture integration candidate — NOT a protected beta or release

## What is now one component

`flowbridge-capture` consolidates the original Rust packet validators, Ethernet/VLAN
rewrite, process-stamp flow ledger and protected verdict gates into a stateful
bidirectional packet pipeline. A real asynchronous SOCKS5 connector activates a
reserved lease only after the server's CONNECT success reply. It preserves
half-close and binary data, bounds concurrency, aborts on supervisor loss, and
has no DIRECT retry path. A DNS hostname supplied to the explicit SOCKS interface
stays in the SOCKS request; native IP packets do not magically recover hostnames.

`flowbridge-agent` is an independently implemented Rust Windows NDISRD client.
It does not load ndisapi.dll, ProxiFyre.exe or a custom WFP driver. The official
signed kernel driver must be installed separately under its own terms. No driver
binary or installer is included in this candidate.

### Critical ABI repair

The preceding #53 adapter query mistakenly modeled the published `pack(1)`
NDISRD ABI as naturally aligned `repr(C)`. Its tests repeated that assumption.
This integration replaces it with explicit native-x64 little-endian byte codecs:
`TCP_AdapterList` 8836 bytes (handles at 8196), `ADAPTER_MODE` 12 bytes,
`ETH_REQUEST` 16 bytes, `INTERMEDIATE_BUFFER` data at offset 52. Independent
Python ctypes fixtures and literal Rust byte fixtures check the contract.
Do not infer native success from either fixture.

Published contract: wiresock/ndisapi `include/Common.h` blob
`ba42da741693816d2d843f59b241aa827c1a3d3d` (packing, layout and IOCTL numbers).
Only interface facts are used; no vendor user-mode implementation or ProxiFyre
AGPL source is included or translated. The x64 queue-size input is 8 bytes
(`sizeof(HANDLE)`), not an old x86 web documentation table's 4 bytes.

## Safe default commands

```
flowbridge-agent capabilities
flowbridge-agent status
```

Both are read-only. Status combines the original FlowBridge SCM observer from
#46 with device version and adapter inventory using the corrected ABI. The agent
does not install/start/stop the driver or change system security configuration.
Opaque driver handles, packet payloads and SSH secrets are not exposed in JSON.

## Explicit bounded laboratory operation (native verification still pending)

`lab` accepts a strict JSON object with `adapter_name`, `duration_ms` (1..60000),
`consent`, and optional `passthrough`. Adapter names are selected exactly from
read-only inventory, never provided as raw handles. The service must be running
as a kernel driver, device open is requested exclusive, media/MTU checked, and a
nonzero preexisting adapter mode causes rejection rather than takeover.

- `consent: "LISTEN_ONLY"`: listen/copy mode. Original networking remains intact;
  the agent reads bounded batches and NEVER injects copied packets.
- `passthrough: true` with `consent: "EXPERIMENTAL_DIVERT_AND_REINJECT"`: laboratory
  tunnel mode reads and reinjects original frames in their original directions.
  It does NOT proxy selected apps. It can temporarily interrupt connectivity if
  I/O fails; run only on a disposable native test environment after review.

Every normal exit or detected error explicitly restores adapter mode 0, verifies
it, flushes the queue and reports cleanup failures. Drop makes a final best-effort
attempt, not a guarantee. Forced termination, power loss, driver hangs and other
processes' device handles remain native test cases. **Mode 0 restores ordinary
networking; it is NOT a persistent kill switch or fail-closed protection.**
Out-of-band VLAN metadata and checksum-offload bytes are preserved unchanged in
passthrough mode. Packet mutation belongs only to the separately validated
policy pipeline, not to unconditional laboratory forwarding.

## Exact safety boundary

The native agent does not promote IP Helper snapshots to packet-owner proof.
`PacketBound` is a non-serializable in-process evidence label for a future trusted
native resolver; synthetic tests use it explicitly. The current CLI cannot turn
it on or advertise protected redirect. DNS/UDP containment and authenticated
carrier/relay binding are not implemented as a native protected product.

The existing C++ WFP research target and its old GUI/installer remain in the
repository for regression coverage, but are deliberately EXCLUDED from the
Rust candidate archive. This candidate is not a replacement full GUI installer.

## CI evidence, packaging and remaining gates

Existing workspace Rust/native/DNS/OpenSSH workflows stay enabled. Additional
Windows Server 2025, macOS and Linux integration jobs test the same driver
lifecycle using injected errors, real loopback SOCKS connections and strict
negative CLI cases. These are not native Win10/11 driver tests. The archive
manifest pins actual checked-out source SHA (including a PR test-merge SHA), PR
HEAD SHA, every payload hash and explicit false acceptance flags. Payload is
allow-listed to the original Rust agent, Rust CLI, this readme and manifest.

Unclosed release gates: actual Win10/11 NDISRD signature/provenance and RX/TX;
packet/process binding under PID and tuple reuse; selected app -> Rust relay ->
FlowBridge SOCKS -> SSH native trace; carrier exclusion; protected crash failure;
IPv4/IPv6 DNS/UDP/QUIC no-leak evidence; secure service/IPC/GUI and installer
upgrade/uninstall/rollback; native resource soak. macOS NE remains independent.
Do not mark 1.0 or DNS leak-free without evidence and owner approval.
