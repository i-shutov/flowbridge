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

## Real Rust relay coupled to supervised OpenSSH (still NOT native packet proof)

The existing isolated Linux and hosted Windows SSH fixtures now run the Rust
agent's explicitly consented `relay-probe` through the actual FlowBridge SOCKS
listener backed by a separately supervised OpenSSH process and a counted
loopback echo destination. The probe validates 4,097 exact binary bytes,
TCP half-close, release of the admission permit, denial with the upstream gate
closed (zero reconnect grace and zero target connections), and recovery after
the gate is reopened. It records the real SSH PID, exact source SHA and agent
binary SHA-256 in machine-readable evidence. Existing 128/1152/10000/4 and
raw-512 assertions remain intact. The helper may **never** claim driver
interception, packet-to-PID authority, DNS containment or Windows 10/11
acceptance, irrespective of the probe result.

## Cross-component owned TCP lease lifecycle (integration head after 529a9ead)

The new Rust owned-flow boundary joins the existing packet-policy ticket to a
**real** SOCKS5 connection and a real user-mode TCP ingress stream. Activation
is only after SOCKS CONNECT succeeds; STREAM termination, cancellation, upstream
supervisor disappearance, or Drop removes the exact ticket and alias without a
DIRECT fallback. The packet-worker mutex is **not** held across an awaited
network operation. An independent terminal-only cleanup API avoids advancing
(or rewinding) the packet clock from unrelated async I/O and refuses stale
generation/owner tokens. Lock poison or unprovable cleanup revokes the entire
offline pipeline. Cross-component tests cover IPv4/IPv6 VLAN-tagged synthetic
packets and bidirectional offline rewrite alongside actual binary/half-close
SOCKS streams, plus refusal, abandoned connections, PID/generation and
supervisor-loss negatives. This does **not** connect native NDISRD packets to
that relay, prove PID attribution, or provide protected crash persistence.

An aborted async SOCKS handshake additionally owns a pending-token guard: task
cancellation is tested against an actual TCP/SOCKS handshake stalled before
the CONNECT reply. Dropping that future must release the exact pending lease
and capacity slot without a direct dial.

## Windows foreground Rust control and explicit SOCKS lifecycle (R7 partial)

The independent Rust agent additionally supports a bounded, LOCAL named-pipe
control of the existing Rust SOCKS Engine in explicitly configured mode:

```powershell
flowbridge-agent.exe control-serve C:\path\to\explicit-profile.json
# From another terminal, same user:
flowbridge-agent.exe control status
flowbridge-agent.exe control reload
flowbridge-agent.exe control stop
```

The controller runs in the foreground as the invoking user, with a fixed named
pipe. Windows security is enforced at pipe creation with an explicit protected
ACL (SYSTEM, Administrators and pipe owner), rejects remote clients, requires
the first pipe instance, bounds input/output frames and deadlines, and provides
only three strict commands. Status contains bounded aggregate counters, NOT
SSH credentials, client destinations, EXE paths or opaque kernel handles.
No service registration, elevation, driver installation, SSH key acquisition
or NDISRD interception is performed by this feature.

The controller validates explicit SOCKS profiles, deliberately DENIES enabled
application-specific rules because the source process is not attested by
SOCKS5, and rejects live listener/capacity changes. An invalid reload leaves
the running engine's configuration generation unchanged; a valid reload
increments it. Stop closes the real listener and cancels its live connections.
This is NOT a persistent fail-closed kernel barrier. Profiles can contain
explicit DIRECT rules: the controller does not claim a security kill switch.

Windows Server hosted CI adds an actual second-process named-pipe control
test against an independently running Rust agent and real loopback SOCKS5
handshake. It checks blocked target connectivity, failed reload rollback,
successful hot reload and graceful stop; it writes SHA-tied JSON evidence into
the allow-listed candidate CI artifact. Other platforms test protocol
validations and real Rust Engine lifecycle without claiming native Windows
driver evidence. An actual Windows SCM service, restricted unauthenticated
GUI views, crash recovery, authenticated owner binding, selected-app packet
capture, protected DNS/UDP and Win10/11 installation remain OPEN.


## Native signed-driver proof on VDSina, 2026-10-31 (R1 read-only/RX partial)

This is **actual separately installed signed Windows Packet Filter NDISRD 3.6.2.1
on the owner's VDSina Windows Server 2025 VM**, driven by the original Rust
FlowBridge agent built for prior PR head
`51bdc3b16f46e6bee99ec3bf213ca47276335450` / hosted merge
`3b2f5867b7b6ee55f50dc3826008184a68e1d447`. It is **not**
Windows 10/11 acceptance. The owner's independent provider VNC was tested, the
self-hosted Windows x64 runner was elevated, Defender real-time remained active,
and neither secure boot nor memory integrity was disabled or claimed verified.

- Official separately installed MSI SHA-256
  `9c388c0b7f189f7fa98720bae2caecf7d64f30910838b80b438ecf8956b8502c`;
  Microsoft WHCP-signed driver SHA-256
  `8623a9c34531cf73de4286ad518b84af03a331c78959769a1ca38723e3258984`.
  No driver/ProxiFyre binaries are included in the FlowBridge candidate.
- The original independent Rust agent SHA-256
  `bd74827262da07c538c9a78ea6c96d048aa6a1df49026cf56e691435cd4ce92e`
  actually opened the NDISRD device and executed its real version/adapter
  query IOCTLs. Real API version `0x06023000`; one adapter, native
  packed adapter wire inventory 8836 bytes; invalid-consent lab request
  rejected. Exact self-hosted
  [read-only PASS](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41182781861),
  with sanitized private [proof](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6540906999).
- **First real Rust NDISRD LISTEN-only RX PASS**:
  [self-hosted run 41183317849](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41183317849),
  private workflow source SHA
  `4e2d14f45e60d28a885047ae9ae4f578d7f2e0de`.
  Native copy-only LISTEN_BOTH mode received 55 real packets in 5500 ms
  (28 outbound, 27 inbound), with **0 reinjections**, real Rust process exit
  code 0, successful loop, explicit verified restoration to adapter mode 0,
  working outbound network and active Defender after the test. A local SYSTEM
  scheduled emergency driver-uninstall watchdog was armed immediately before
  any adapter mode change and safely disarmed only after restoration and
  security/network checks. The driver remained installed. No packet payload,
  IP address, MAC, adapter name, SSH keys, or secrets entered artifacts.
  [Private JSON evidence](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6540972621);
  downloaded outer artifact ZIP SHA-256
  `052d5f6d6e03882a5251e3cc6934dc4087f29b8f41be2a7fca647819edf0e92a`,
  independently verified against GitHub artifact and JSON assertions.
- Prior native observations (70 and 62 real packets) already proved read-only
  device RX and mode-0 restoration, but private workflow verdicts were
  **FAIL because of Windows PowerShell harness Process.ExitCode handling**.
  Independent signed-driver/agent/status checks and healthy networking/
  Defender permitted safe rescue disarm; the final run above fixed the
  test harness without relaxing its exit-zero or rollback gates. Do not
  retroactively mark those earlier runs PASS.

This establishes **native signed-driver -> original Rust DeviceIoControl ->
packet copy-only receipt -> verified normal-network rollback**. It does
**not** close native packet divert/injection, process/PID creation-epoch
binding, packet-to-Rust-local-relay-to-SOCKS/SSH-selected-app routing and
reverse flow, persistent protected fail-closed, IPv4/IPv6 DNS/UDP/QUIC
containment, GUI/SCM/installer, or actual Win10/11 protected acceptance.
Returning to adapter mode 0 resumes **ordinary** connectivity and is not
a protective kill switch. No release or DNS-leak-free claim follows from
this result. See [issue #41](https://github.com/i-shutov/flowbridge/issues/41)
for the detailed independent evidence checkpoint.
