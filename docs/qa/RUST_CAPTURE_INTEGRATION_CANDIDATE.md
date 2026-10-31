## 2026-10-31: Native Windows UDP local-bind owner-candidate vertical (pending exact-HEAD CI)

A new original-Rust Windows-only UDP IP Helper vertical exercises actual IPv4
and, where available, IPv6 loopback UDP datagrams; two bounded
`GetExtendedUdpTable(UDP_TABLE_OWNER_PID)` snapshots; pinned process-object
PID, creation time and image consistency; and negative ambiguity rules for
wildcard, zero-PID, duplicate and IPv4-mapped binds. The public CI runs the
built x64 Rust executable and saves a privacy-redacted JSON report with a
strict negative checklist. Tests must confirm the report against the exact
PR head/merge SHA and Windows artifact before this can be accepted.

**Trust boundary:** UDP owner tables identify only a **local socket bind**,
not the remote tuple, intercepted NDISRD packet, DNS query, per-app routing,
or leak prevention. This diagnostic does not enable protected mode or change
NDISRD, firewall, DNS or SSH state. IPv6 loopback test availability must be
reported, not converted into a fabricated native IPv6 NDISRD acceptance.
It complements but does not supersede signed-driver VPS packet observations.

# Rust capture integration candidate — NOT a protected beta or release

## Windows reversible SCM staging/upgrade/removal candidate (pending exact-head CI)

The original Rust agent now has explicit, admin-only Windows SCM operations:
`service-stage <absolute config>`, `service-replace <old absolute config> <new absolute config>`,
and `service-remove <absolute config>`. These are not invoked by packaging
or ordinary startup. They manage ONLY the fixed on-demand candidate service
`FlowBridgeRustCandidateCI`; no service is auto-started, no driver is
installed or supplied, no NDISRD mode is changed, and no protected mode is
enabled. Strict profile validation rejects application-specific SOCKS rules
without packet ownership evidence and non-loopback SCM listeners. SCM install
refuses any existing record. Upgrade requires the old exact binary command,
an already STOPPED service, and a valid new profile, then verifies the
changed SCM config and attempts rollback of the old command if verification
fails. Removal requires a stopped service with EXACT prior executable and
config path matching, refusing to delete a foreign/modified service. Status
remains redacted and explicitly reports protected=false, dns_leak_free=false.

A separate actual hosted Windows integration script must prove full
stage -> SCM start -> live SOCKS5 -> running-upgrade refusal -> SCM stop ->
invalid-upgrade refusal -> stopped upgrade -> new-port real SOCKS5 ->
named-pipe stop -> exact Rust removal, and pre-existing/other config
ownership denial. This is service-lifecycle/installer staging only, NOT a
complete production upgrade/rollback with signed releases or protected
selected-app interception. Do not mark this block accepted until exact
HEAD + test-merge CI and separately hashed Windows candidate artifacts
have been examined and recorded in issue #41.

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


## 2026-10-31 — independently verified real native original-frame RX/TX on VDSina

Advance beyond prior read-only LISTEN_BOTH: a guarded, bounded real NDISRD
TUNNEL_BOTH lab session received **109 native frames (53 outgoing, 56 incoming)**
and completed **109 successful original-frame sends**, with actual driver I/O
from the original Rust agent, no ProxiFyre and no distributed driver. This is
still not selected-app proxying, DNS containment, protected kill switch or Win10/11
acceptance. Tested Windows Server 2025 only. Agent source HEAD
51bdc3b16f46e6bee99ec3bf213ca47276335450, prior tested merge
3b2f5867b7b6ee55f50dc3826008184a68e1d447, agent SHA-256
bd74827262da07c538c9a78ea6c96d048aa6a1df49026cf56e691435cd4ce92e.

- [Private native run 41184740167](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41184740167)
  and [sanitized evidence](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6541158423):
  workflow SHA 708f5ca08ffdc000a3ef186accfabe699f409c57; 7503 ms; process
  exit 0, loop completed; in-session TCP/443 and post-session network PASS;
  signed official kernel driver and active Defender PASS. Independently armed
  local SYSTEM uninstall rescue was disarmed only after mode-0 restoration and
  health verification. NDISRD remains installed.
- Downloaded private artifact 13035917293 ZIP SHA-256
  27f08238aabdd71d8f201cb5a44adf2d47245cd4297d0833af0c02c345d02588
  matches GitHub digest. Independent checks verified receipt/sends, both packet
  directions, reset, watchdog and Defender. No packet payload, IP/MAC/adapter
  names or credentials were written to evidence.
- These were the **original, unmodified packets**. No reliable packet ownership
  binding to PID + creation epoch, no TCP selected-app redirect to relay/SSH,
  no reverse-path proxy rewrite, and no persistent fail-closed. Restoring NDISRD
  adapter mode 0 resumes ordinary DIRECT-capable networking; not a kill switch.

Prior documentation-only HEAD f44070c74c5ef489e88956179e7285c64c8bfec4
had tested PR merge 754b39b9cf568254917bb2f4c949d3da581ea68d.
All four exact-head CI workflows succeeded:
[capture 3/3](https://github.com/i-shutov/flowbridge/actions/runs/41183457267),
[Rust/native 5/5](https://github.com/i-shutov/flowbridge/actions/runs/41183457221),
[DNS 3/3](https://github.com/i-shutov/flowbridge/actions/runs/41183457222), and
[real Windows managed OpenSSH](https://github.com/i-shutov/flowbridge/actions/runs/41183457268).
The Windows capture Actions ZIP SHA-256 was independently reproduced as
c7468766066029a7fe082e2d56b2d9d6b2d944f7fd4b233a46666e2305b0400c,
and nested allowlisted candidate ZIP as
ce0152d47dc9a64b7b43db0e6dc4a67e3a7662e24618c2c559c0307209707e26.
Real Windows SSH Actions artifact SHA-256 was
51b207771f423417621486050c098d1562f6236e0211742b62ef6c960643a2b0.
Managed OpenSSH acceptance remains 128 actual held/1152 rejections/10000
byte-verified successes with zero errors/4 distinct subprocesses. Separate
raw OpenSSH characterization only reached 246 held, not stable 512.

All protected, DNS leak-free and release claims remain explicitly FALSE.


## Windows IP Helper owner candidate integration (unaccepted until exact-head CI)

The Rust capture crate now owns the single original read-only implementation
of Windows GetExtendedTcpTable TCP owner-candidate lookup used by BOTH
flowbridge-agent and the existing flowbridge-ffi API. The FFI ABI remains
unchanged, and the former duplicated lookup module is a thin reuse layer.
Only the Windows APIs and Rust code written for FlowBridge are used; no
ProxiFyre/AGPL source or shipped vendor user-mode binaries are involved.

The new CLI command 'flowbridge-agent owner-selftest' executes an actual
self-owned loopback TCP socket while retaining both TCP endpoints, samples
the native IP Helper TCP table TWICE, pins a query-only process handle,
compares PID, creation FILETIME and queried image identity, and fails if
the live socket or process epoch cannot be confirmed. CLI output deliberately
suppresses PID, process creation timestamp, executable path, endpoint and
payload. A real Windows hosted integration test requires the CLI to succeed
and verifies the absence of sensitive identity fields. Regression tests
preserve exact tuple, stale/duplicate-state and IPv6 scope checks.

IMPORTANT evidence boundary: this is a real native Windows TCP owner
snapshot CANDIDATE, not a kernel-authenticated assignment of an NDISRD
packet. IP Helper lookup does NOT grant PacketBound, CapturePolicy, a
selected-app route, or protected allow. Selftest never opens NDISRD or
changes adapter modes; no DNS/UDP containment, fail-closed, service,
Win10/11 acceptance or release claim. The current protected gate remains
DENIED. Native packet binding and selected-app ingress/return path remain OPEN.

Exact GitHub CI run, PR HEAD/merge SHA and independently checked artifact
digests will be added only after verification; no PASS from source alone.


## Bounded native NDISRD-to-IP Helper candidate observation (Windows Server native evidence; NOT PacketBound)

The **same** native x64 Rust PacketSession now offers a copy-only packet
observer that is explicitly denied in divert/passthrough mode. An additional
owner-candidate laboratory request requires `owner_candidates:true`, explicit
consent `LISTEN_ONLY_OWNER_CANDIDATES`, an exact adapter name, and <=15 seconds.
It reads genuine NDISRD LISTEN_BOTH frames when executed on an eligible host,
parses supported checksummed IPv4/IPv6 Ethernet TCP frames, and attempts at most
24 IP Helper double-snapshot process-creation-epoch candidate lookups. Reverse
wire direction is reversed before a local/remote socket query; IPv6 link-local
frames are excluded because Ethernet does not supply the scope ID. All frames
and process/tuple identities are discarded, with **only redacted counters**
returned. The observation callback cannot mutate raw frames or reinject them.

These counters are a diagnostic cross-check, NOT kernel-authenticated
packet-to-PID proof. In particular, an IP Helper row can race NDIS receive,
so even a consistent two-snapshot PID/path/creation time does not produce the
CapturePolicy `PacketBound` authority. `native_packet_attribution_proved`,
`authorizes_capture` and `protected_redirect_available` remain false.
No selected-app route, fail-closed safety, DNS leak-free or Windows 10/11
acceptance is claimed. Dangerous protected operation is not enabled. A VPS
native run, if performed, requires pre-armed independent rescue and owner-
confirmed emergency VNC; no unsolicited divert, installer or kernel changes.

### Exact-head GitHub and real NDISRD outcome, 2026-10-31

- Original Rust integration source: PR #56 HEAD `f8951bf2af69fbbfbd6cd8ccfbb662c8d65a735f`, tested pull-request merge `8a6dc373c809f06419964c1865ca7866ad09be20`. Strict hosted [capture integration 41193920767](https://github.com/i-shutov/flowbridge/actions/runs/41193920767) 3/3 PASS; [Rust/native 41193920774](https://github.com/i-shutov/flowbridge/actions/runs/41193920774) 5/5 PASS; [DNS 41193920895](https://github.com/i-shutov/flowbridge/actions/runs/41193920895) 3/3 PASS. Windows SSH 41193920780 was still running at this checkpoint; no overall pass claimed early.
- Independently downloaded hosted Windows capture artifact #13039838605: outer ZIP SHA-256 `318038b34a28f98e0aebb353c32ce2f1687c63bc0aa460ae12d318161dfbefe7`; nested four-file allowlisted Rust-only candidate ZIP `97076498b274c243e24e61f0deabb26150f3d4b9ca8d10947026319cc8deb95f`; original `flowbridge-agent.exe` `491f1a07fb610b0ca75b2c94f8e8da49c252390f2242e59ace6eed28887fe922`. All manifest payload hashes independently matched, PR HEAD and tested merge both matched.
- Real VDSina Windows Server 2025 Standard build 26100, signed separately installed NDISRD, Defender active, owner-confirmed VNC, independently prearmed SYSTEM recovery, **copy-only LISTEN_BOTH**: [private native Actions 41194272084](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41194272084), private workflow SHA `42b8ff7820dc42f779799dd0398c383814ac49d4`. 6504 ms, **71 actual driver frames (31 outbound / 40 inbound), zero injected**, 24 bounded live IP Helper double-snapshot queries: **18 consistent process candidates, 4 absent, 2 indeterminate**. The adapter was restored to mode 0; in-session capture completed, network and Defender checked healthy, independent rescue DISARMED, no MSI uninstall. Only aggregate counts were written.
- Independently downloaded private sanitized evidence artifact #13040235105: ZIP SHA-256 `f0c1ad2d7b0ae42b37cc261725d3a5c3e461f4dfab914bba22dc2c2b08ab362d`; internal `listen-only.json` SHA-256 `c70d5800131c152e139e2fdd86174e12fd7db907867d0a837b3cfdc46303c679`. Both source/merge SHA and mandatory rollback/no-reinjection security booleans checked against downloaded bytes. Evidence is also copied to private [VPS issue #1](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6542425846).

**Important:** Even 18 consistent IP Helper PID + creation-time snapshots are temporal *candidate associations*, NOT kernel-authenticated assignment of NDISRD frames to process identity. The implementation does not synthesize `PacketBound` or authorize a selected app, and cannot yet route intercepted TCP through the SOCKS/SSH relay. No protected fail-closed, DNS/UDP/IPv6 leak containment, Windows 10/11 native acceptance, complete service/installer, macOS NE acceptance or release is proved. Mode 0 returns to ordinary networking, NOT a protected kill switch. Raw unprotected OpenSSH 512-channel stability is still not established.


## Windows native SCM candidate — cross-component beta staging (pending verified CI)

The original Rust capture agent now has an **on-demand, manually installed**
SCM dispatch entrypoint `service-run <absolute-config>`. No kernel driver,
ProxiFyre executable, custom WFP component or extra dependency is installed.
The test-only SCM service identity is `FlowBridgeRustCandidateCI`; no service
is installed during package creation or ordinary agent invocation. It refuses
an unbounded/non-absolute profile path and refuses non-loopback SOCKS listeners
**before** the Engine begins listening. It opens the same real SOCKS Engine and
same fixed-ACL local-only Windows named pipe as the previous foreground mode.
Service STOP/SHUTDOWN signals request graceful engine stop, close the listener
and report SERVICE_STOPPED; pipe STOP also terminates its SCM instance.
No opaque service command can change NDISRD mode, set a trusted PID token,
or change the service identity/configuration path.

On hosted Windows, a dedicated script tests REAL SCM create/start/stop/restart,
real TCP SOCKS5 handshake, local IPC/status/reload, generation reset and
termination via both SCM STOP and pipe STOP. It always attempts to remove its
own manually-created test service. This is independent process/SCM evidence,
**not** Win10/11 NDISRD, protected packet routing, crash-persistent fail-closed,
remote-DNS containment, automatic upgrade or installer acceptance. The SCM
candidate starts **only with explicit SOCKS and loopback bind** and never
activates native capture. Any claim of a protected Windows beta still requires
a separate native interposition/safety/installer implementation and acceptance.

## Native controlled self-owned Windows TCP → NDISRD → Rust relay → SOCKS/OpenSSH: first verified chain

2026-10-31 exact *code* SHA `f947bf9f27923a6a669f6f2c521f6235796cc74c`,
PR #56 test merge `22c3b698ef01a7b945e6360d6ed37bfddea11413`.
The public capture 3/3, Rust/native 5/5 and DNS regression 3/3 GitHub Actions
passed on this source. The **separate** Windows OpenSSH workflow **FAILED**
its experimental raw 512-channel characterization (Winsock 10054 /
sshd "Too many open files") even though managed 128 held / 1152 denied /
10,000 byte-verified successes / four independent SSH processes passed.
Do not represent raw 512 as PASS or the overall SSH workflow as green.

Actual VDSina VPS #3293462 Windows Server 2025 [native run
41207789454](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41207789454)
**PASS**, private workflow SHA `f04e7fbb2cec46532828381055e825659fa4d827`;
[private truthful evidence](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6544300447).
An internally-owned and live socket was captured via official separately
installed signed NDISRD, reflected to the Windows TCP stack and the original
Rust relay, then genuine FlowBridge SOCKS and authenticated supervised
Microsoft-signed OpenSSH; the HTTP response returned through inverse
reflection. Connected: 5/4 reflected client/relay frames, 57/313 bytes.
Gate denied: 4/3 reflected frames, no HTTP reply and no SOCKS CONNECT.
Recovered: 5/4 reflected frames, 57/315 bytes on the SAME SSH supervisor.
All three native runs report zero selected original frames sent to adapter,
an internally verified owner PID+epoch, and mode rollback.

Independent SYSTEM recovery armed and later disarmed; temporary scoped
firewall rule removed; mode zero/network/Defender healthy. Actual downloaded
artifact #13044882622 outer SHA-256
`2a381eafdf040e50dc29c320cd1c35c8b16fc02348a9a2e9932327bc80a85359`
equals GitHub digest, one JSON entry SHA-256
`6ecdc8338249a9e7ae63895511238bb1500d2325ebcad64cebee03cc14b06be0`.
Verified source/merge SHA and all acceptance/negative flags; no packet
payload or PID/IP identity persisted. See
[full native lab dossier](NATIVE_SELF_REDIRECT_LAB.md).

**NOT proof** of another application's packet ownership, not protected
system-wide interception/crash fail-closed, not DNS leak-free/UDP/IPv6,
not Windows 10/11 desktop native acceptance, not a beta/1.0 release.
Adapter mode 0 is normal networking. Private VPS is still useful for
additional negative native tests and owner/driver containment work.


## Real NDISRD parent/child cross-process TCP → Rust SOCKS → authenticated OpenSSH (6/6 PASS; 2026-10-31)

**Scope:** this advances beyond the parent-owned socket: an entirely separate
original Rust child process binds its own source port, waits for an explicit
parent GO handshake until NDISRD diversion is active, and completes real
HTTP request/response via actual native driver interception, Windows TCP
reflection, Rust relay, FlowBridge SOCKS5 and supervised OpenSSH. The parent
pins the child process object and verifies PID/creation FILETIME alongside
two consistent native IP Helper TCP table snapshots. The exact reserved
child flow is reflected, and the child is killed/joined **before** restoring
ordinary networking. A parent-spawned, known-socket canary is **NOT**
transparent arbitrary selected-app capture or authenticated packet ownership.

- Exact public source commit `81419f764ba51dab9c4aa91bda1de81ccb581383`,
  exact CI PR merge `dc70e093c40490aa728455fa52a22eca38bef7d7`.
  Public [capture integration 41210372566](https://github.com/i-shutov/flowbridge/actions/runs/41210372566)
  **3/3 PASS** (Windows/Linux/macOS, strict Clippy/rustfmt), [Rust/native
  41210372560](https://github.com/i-shutov/flowbridge/actions/runs/41210372560)
  **5/5 PASS**, and [DNS regression 41210372591](https://github.com/i-shutov/flowbridge/actions/runs/41210372591)
  **3/3 PASS**. [Windows OpenSSH 41210372578](https://github.com/i-shutov/flowbridge/actions/runs/41210372578)
  was still executing when this exact code was independently checked.
  Managed 128 held/1152 denied/10000 byte-verified completed/4 distinct SSH
  processes remain prior evidence; separate raw 512 stable channels are NOT proven.
- Independently downloaded public capture Windows artifact
  #`13045349444`: outer ZIP SHA-256
  `c616b6666d71d00b587a441c43c8ec08deac3458ba4383a010b729526c440c9b`,
  allowlisted Rust candidate ZIP
  `04a90b470a60530294511a89b5651796ab042df4c1f465d9895315cad0554a13`,
  original agent PE
  `3aa4ecaaa027f6b0f4091c83e7e445ba060cdce6caff14e185247307f9259283`.
  Separate *testing-only* native FFI/tools artifact #`13045109828`:
  outer SHA-256
  `d0011d624c6ac5081780193de629e8b0e39e3454cd4ce34386b4fb63dde8157a`,
  FFI DLL SHA-256
  `8ad037271bf3231180801a820b9a2880b0007bc6bc20af19963107fe4c2f9d63`.
  Both source/merge SHA and every file hash checked against the downloaded
  manifests. No driver, ProxiFyre binary, C++ WFP sidecar or keys in candidate.
- [VDSina Windows Server 2025 self-hosted native run #41210941526](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41210941526)
  **PASS**, private workflow SHA `68b690adde99fb730c9f8f7f9c6c67768437b812`.
  [Sanitized actual JSON in private issue #1](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6544806370).
  Six actual driver/SSH phases: parent connected/closed/recovered and
  **separate child connected/closed/recovered**, all 6/6 PASS. Child positive
  had **5 forward / 4 inverse reflected native TCP frames; 57 bytes sent,
  314 bytes received**, confirmed HTTP response. Child gate closed had
  **4 / 3 frames, 0 bytes received, no DIRECT, no SOCKS CONNECT**; recovery
  had **5 / 4, 57/314 bytes**, same authenticated SSH supervisor. The parent
  also passed its full positive/closed/recovery triple (57/311 success).
  All six report zero selected original frames sent to physical adapter.
- Independently downloaded private evidence artifact #`13045204941`:
  outer SHA-256
  `d9740fb5505eb8c884410b98755567ab630ae0f16de3c628761dec29d262317c`,
  exactly one sanitized JSON SHA-256
  `55d60ac595bb4024c406e14a5f043c126c96fb9f17200328fc7d5a5b7f5829b9`.
  Validated public and private SHAs, 6× native frames/HTTP/denied/recovery,
  child-vs-parent identity distinction, native driver access, agent/FFI binary
  hashes, no payload/process identity retention and **all false release gates**.
- Safety: independently scheduled local SYSTEM MSI-uninstall rescue armed
  beforehand and disarmed after positive **adapter mode 0** recheck,
  network and Microsoft Defender active, exact scoped firewall rule removed.
  `rollback_needed=false`, no teardown incident, vendor driver remains
  separately installed. Normal adapter mode 0 permits DIRECT traffic and is
  **NOT protected fail-closed**.

**Explicitly NOT ACCEPTED:** arbitrary application NDISRD packet→PID+creation
epoch authentication, transparent selected app routing, persistent protected
crash/SSH failure policy, DNS-leak-free, UDP/QUIC/IPv6 containment, personal
Windows 10/11 acceptance, macOS NE, raw OpenSSH 512 capacity or release 1.0.
Next genuine blocker: attach unrelated selected-app flow to *defensible* owner
authority and independently enforced protected drop, with native negative
tests under guaranteed rollback. Server 2025 is only an integration laboratory.


## Fixed Microsoft PowerShell test-client vertical (2026-10-31, native proof pending)

The Windows-only Rust agent now supports one further *bounded laboratory*
client type: the OS PowerShell executable in the fixed system directory,
running a static source-owned script to reserve an IPv4 TCP source port,
announce it to the Rust parent and wait for GO. The parent pins the distinct
process object and exact creation epoch; the same native packet-reflection
worker requires two consistent IP Helper TCP-owner snapshots before reflecting
the single reserved flow through Rust SOCKS and authenticated OpenSSH. The
PowerShell process is ONLY a traffic generator, not a router or privileged
backend. No caller-provided executable path, script or PID is accepted.

This mode requires the distinct NATIVE_POWERSHELL_CHILD_TCP_REFLECT consent,
rejects conflicting client modes, validates the live owner and returns the
socket child to a terminated/joined state before the NDISRD tunnel is
disarmed. The Python native harness requires connected, denied and recovered
phases for the PowerShell client, with separate identity and negative
PacketBound/release flags. Native VDSina execution MUST verify the system
PowerShell Authenticode signature before driver mutation, keep the independent
SYSTEM rescue armed, and check source/merge/binary/artifact SHA-256. This
paragraph records the new SOURCE CANDIDATE only, not a native test PASS.

Even if these further native phases eventually pass, a known parent-created
PowerShell process with an explicit GO handshake does NOT establish arbitrary
app packet attribution, persistent crash fail-closed, DNS/UDP/IPv6 containment
or personal Win10/11 acceptance. Mode zero remains ordinary DIRECT-capable
networking.


## VERIFIED native nine-phase parent/Rust-child/signed-OS-PowerShell NDISRD → Rust SOCKS → real SSH (2026-10-31)

The prior "native proof pending" source checkpoint above is historical: the
fixed Microsoft-signed OS PowerShell child has now passed **actual NDISRD**
interception and bidirectional reflection on a separately rented Windows
Server 2025 Standard system. This **does not** authorize arbitrary
selected-app/packet-to-PID binding, persistent fail-closed or a beta release.

**Pinned code and hosted CI:** PR #56 code HEAD
`6ec22db996276aef19e378aed799476a0068166a`, exact test merge
`6aaadd172cf7425ab314eb51a91d994c00e7be41`; public base `main`
`5b5afc2feeda2195f302380e615ba003d4906e09` unchanged. Hosted
[capture integration #41214148509](https://github.com/i-shutov/flowbridge/actions/runs/41214148509)
**3/3 PASS**, including Microsoft Authenticode-checked in-box PowerShell
negative GO (no connection before authorization) and real TCP half-close HTTP
response. Hosted [Rust/native #41214148179](https://github.com/i-shutov/flowbridge/actions/runs/41214148179)
**5/5 PASS** and [DNS regression #41214148223](https://github.com/i-shutov/flowbridge/actions/runs/41214148223)
**3/3 PASS**; *DNS regression is not leak-free acceptance*. Long
[real Windows OpenSSH #41214148092](https://github.com/i-shutov/flowbridge/actions/runs/41214148092)
was still running at this evidence checkpoint: no PASS claimed; separate raw
512-channel stability was not established.

**Independent downloaded public artifacts**, exact hosted source and test
merge cross-checked against internal manifests:
- Windows capture artifact `13047248828`: outer ZIP SHA-256
  `d0a4290ccf76717de437654eb30a0a1c5de6f6c4008d26caf3bac93e0ef60a48`;
  allowlisted four-file candidate ZIP
  `c5f559db68cd2ca8dda744463228dce29c366e1e994315acd9d2a9b8d51d3978`;
  Rust agent PE SHA-256
  `5cfd2fba229c6c5d3e0c7a9bc11070603d69ab930f931151cd2c9a98fbe82f69`.
- Separately allowlisted **test-only**, not product, native tooling
  `13047547909`: outer ZIP SHA-256
  `dd957942bdc0ffbb299539e8b17b667f49b1d4b2d3142c31efc61d1497300280`;
  Rust FFI DLL SHA-256
  `d0a341647436d5644c7fdadc0cdee876b6a06ea428bbdd6a543ece8104f21079`.
  Every manifest payload hash and file count passed independent inspection;
  no vendor driver, ProxiFyre, AGPL implementation, legacy C++ sidecar or
  credentials in the product candidate.
- Hosted `powershell-client-lifecycle.json` has `passed=true`,
  `negative_go_no_tcp=true`, `positive_half_close_http=true`,
  `verified_http_reply_bytes=57`, `native_driver_tested=false`.

**Actual VDSina VPS #3293462 native test:** [private Windows Server
2025 GitHub Actions #41214578775](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41214578775)
**PASS**, pinned private workflow SHA
`cf86df971cf4044963119b43c0bb3099453c46f9` and exactly the public
source/merge/binaries above; [sanitized evidence in private issue
#1](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6545349434).
Independent **signed Microsoft PowerShell executable prerequisite**, signed
NDISRD, Defender, firewall, exact adapter and owner-confirmed VNC were checked
*before* diversion. Independent SYSTEM rescue was armed before network
mutation, and then disarmed after confirmed mode-zero rollback, network,
firewall rule removal and Defender health; `rollback_needed=false`.

All **9/9 real NDISRD/real authenticated OpenSSH phases PASS**:
parent-owned socket **connected/denied/recovered**; distinct parent-spawned
Rust child **connected/denied/recovered**; distinct fixed Microsoft-signed OS
PowerShell child **connected/denied/recovered**. PowerShell connected:
**5/4** client/relay reflected native frames, **57/311 bytes** sent/received
and HTTP reply; closed upstream: **4/3** reflected frames, **0 reply
bytes**, no SOCKS connection or DIRECT; recovered: **5/5** frames,
**57/314 bytes** and same live SSH supervisor. Distinct PowerShell PID/creation
epoch and double-snapshot IP Helper ownership candidate matched the reserved
flow in all three phases, but no PID, endpoint or payload was recorded.
All nine native phases report **zero selected original frames sent to physical
adapter**; return traffic was reflected through Rust and the Windows TCP stack.

Independent downloaded **private native evidence** artifact `13047204447`:
ZIP SHA-256 `8bd0151566173fee517147c486e4935f1e7285197e042a7605364d6805fc8f8b`
matching GitHub digest, exactly one redacted JSON SHA-256
`548f0d3b185f3437955e23a6c18e192f6e4a3fe97c4a9b6090b45fab1156a916`.
All nine phase flags, counts, source/merge/workflow SHA, agent/FFI digests,
nine rollback flags and negative release claims were independently checked.

**Still open / explicitly FALSE:** arbitrary unrelated selected-app packet
ownership (the PowerShell canary is parent-created and pre-authorized),
kernel-authenticated `PacketBound`, transparent process redirect,
crash-persistent protected fail-closed, DNS/UDP/IPv6 leak containment, personal
Windows 10/11 native acceptance, macOS NE, raw 512 stable SSH channels,
DNS leak-free and release 1.0. Mode 0 restores ordinary DIRECT-capable
networking, not a protected kill switch. Keep the paid VPS only while further
bounded native tests materially advance these open gates; no deletion or
release without explicit owner approval.

## Verified independent signed-PowerShell sibling 12-phase native NDISRD / Rust SOCKS / OpenSSH integration (2026-10-31)

**Scope and safety:** This supersedes the historical **nine-phase** maximum
checkpoint above, without changing its original evidence. Native driver
integration passed for **four explicitly controlled traffic generators**,
each with connected / SOCKS-gate-closed / recovered phases: (1) Rust agent's
self-owned TCP socket; (2) parent-spawned distinct Rust child; (3) Rust
parent-spawned fixed Microsoft-signed OS PowerShell child; and **(4) an
independently QA-launched fixed Microsoft-signed OS PowerShell process,
not created by the Rust agent**. The fourth generator owns and reserves a
source TCP port before announcing a bounded loopback GO-control port; it is
still a **known, consenting test canary**, not arbitrary selected-app capture.

**Found and fixed a real false-ownership bug before accepting the run:**
private [failure 41216230392](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41216230392)
and the first pinned [failure 41217430715](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41217430715)
already demonstrated successful bidirectional traffic for the independent
PowerShell canary but the Rust report incorrectly returned both
`self_owned_socket_pid_epoch_consistent=true` and
`external_sibling_socket_pid_epoch_consistent=true` for one flow. The
private QA harness correctly failed. New original-Rust
`owner_evidence_flags` is an exclusive four-category assertion: self,
spawned Rust child, spawned signed OS PowerShell child, independent signed OS
PowerShell sibling; any ambiguous/unchecked observation produces all-false.
Dedicated negative/positive Rust unit tests verify every combination. This
fixes only the *reported laboratory ownership category*, not kernel
PacketBound or arbitrary-app authorization.

**Pinned source/build:** exact draft PR #56 source HEAD
`64118bbbf15d2c0fa2eb5d76c76c2eb36539ef37`, tested GitHub merge
`9b73dd051fd06eeb54b95ca24f92d3d8c3e31912`; base `main`
`5b5afc2feeda2195f302380e615ba003d4906e09` unchanged. Original
Rust capture [CI 41217812299](https://github.com/i-shutov/flowbridge/actions/runs/41217812299)
**3/3 PASS** (Linux/macOS/hosted Windows Server, Clippy/rustfmt, signed OS
PowerShell positive/negative tests), [Rust/native 41217812303](https://github.com/i-shutov/flowbridge/actions/runs/41217812303)
**5/5 PASS**, [DNS 41217812321](https://github.com/i-shutov/flowbridge/actions/runs/41217812321)
**3/3 PASS**; generic DNS CI is **not** DNS containment.
[Real Windows OpenSSH 41217812301](https://github.com/i-shutov/flowbridge/actions/runs/41217812301)
**1/1 PASS**, independently downloaded exact merge artifact `13048599045`
outer ZIP SHA-256
`de6a935d0a16bfbe36c213dc65d2cf4837f9bfc75e17bf058eb074b7a0c793b3`.
Verified all six JSON files: real supervised OpenSSH with **128 actual held**,
**1,152 admission denials**, **10,000 byte-verified successful churn** with
zero failures and half-close, **four distinct owned SSH processes**, plus
real Rust agent TCP→SOCKS→OpenSSH→TCP 4,097-byte round-trip and upstream-gate
denial/recovery. **Separate unprotected raw-backend capacity characterization
reached peak 246 held** and returned the Windows OS handle count to near
baseline; a stable **512 channels was NOT demonstrated** (the 512 tier
accepted 0 additional). OS HANDLE is not an internal OpenSSH FD slot count;
`windows_fd_limit_verified=false`. This is hosted Windows Server 2025 and
does not establish Win10/11 native protected packet capture.

**Independently downloaded and inspected binary provenance** from the exact
hosted test merge:
- Windows capture artifact `13048604939` outer ZIP SHA-256
  `46812abb7ffbe9253c4e0fa441518ed7cdc481881edd76b0169626b010dedda7`,
  allowlisted four-file inner Rust candidate ZIP
  `a6a6014774def5291064514b3e2842d8e580c465be7f864bc8984c92bdfaecab`,
  `flowbridge-agent.exe`
  `fad4638ac26603bf3b01cbcfad2298e07fde09c72ccf4261ef2bfafed372a0b1`.
  Every manifest payload digest and six hosted verification JSON booleans
  checked. Candidate contains **only** two Rust executables, README and
  manifest; no vendor driver, ProxiFyre binary, legacy C++/WFP research,
  private SSH keys or credentials.
- Separately allowlisted **test-only** tooling artifact `13049295236`,
  outer ZIP SHA-256
  `9e5854a4cdae32ade2df7122e6eafae2cb11e768bad7506da4a764602695daf5`,
  Rust `flowbridge_ffi.dll` SHA-256
  `0b656ecdcafcdc4cb9f51d6cbee874fda59edf38cb7aa7a8c5c3074f01ef35d0`,
  all ten payload hashes verified against test manifest. This DLL/test
  harness does **not** ship with the personal Windows product.

**Real signed-driver network evidence on rented VDSina VPS #3293462
(Windows Server 2025, NOT Win10/11):**
[private Actions 41218337232](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41218337232)
**12/12 PASS**, private QA workflow commit
`50323de71b019492ce0ef8081df18dfc08352c21`, pinned exact
public source/merge and Rust binary digests. The
[redacted private issue #1 report](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6545884850)
confirms **real NDISRD TUNNEL_BOTH, 12 bidirectional TCP experiments,
real FlowBridge SOCKS, authenticated supervised Microsoft OpenSSH and
HTTP response delivered to selected laboratory process**.
Each generator had a positive HTTP reply, an upstream gate-closed test with
**zero application reply bytes and no SOCKS CONNECT**, and a recovered
HTTP reply under the **same SSH supervisor**. No original selected frames
were sent directly to the physical adapter in any of the 12 trials.
Independent PowerShell sibling positive: **5 client / 5 relay native reflected
frames, 57 B sent / 311 B received**; gate closed: **4/2, 0 B received**;
recovered: **5/4, 57/311 B**. The mutually exclusive sibling flag remained
true and parent self-owned flag false in all three; the pinned process exited
before returning NDISRD adapter to normal mode. No PID, endpoint, SSH secret or
packet payload saved in evidence.

**Independent private artifact audit:** `13048839212`, outer ZIP SHA-256
`8ee5cd749277f95c3a26f5fe5c8bde5eba45849e12c2ea5fb5ef2d087f21b1fe`
matching GitHub digest, exactly one sanitized JSON SHA-256
`b2734bc57d1143fd4e4ce3a763400dc83a2c4a9db1c929d701765d21af033c9a`.
Verified every one of 12 phase flags and the independent process authority,
zero DIRECT selected original packets, no SOCKS while gate closed, rollback
and **all negative security/release claims**. Independently scheduled
local SYSTEM MSI-uninstall rescue armed before driver mutation and disarmed
after exact adapter **mode 0** recheck, network reachable, Defender active
and scoped Windows Firewall rule removed; no rollback incident.

**DO NOT PROMOTE THESE RESULTS:** A reported two-snapshot IP Helper
PID+creation-time candidate plus a preannounced source TCP port in a controlled
canary is **not kernel-authenticated packet-to-process authority**. The
general arbitrary selected-EXE `PacketBound` capability and transparent
routing are NOT accepted. NDISRD mode 0 **restores DIRECT-capable networking,
not persistent fail-closed**. Native crash/SSH-death protection, DNS/UDP/QUIC/
IPv6 containment, actual Win10/11 x64 signed-driver acceptance, production
upgrade/uninstall, macOS NE and personal beta/1.0 remain blocked. VDSina stays
useful only for further carefully bounded native testing with verified VNC
and independently armed rollback; never delete/disable protections or publish
release without the owner. [Public issue #41 checkpoint](https://github.com/i-shutov/flowbridge/issues/41#issuecomment-6545902118).

### 2026-10-31 — Bounded native packet protocol inventory (source candidate, not leak containment)

A new `LISTEN_ONLY_PROTOCOL_PROFILE` request collects **aggregate** Ethernet/IPv4/IPv6/TCP/UDP counters and DNS/DoT/QUIC/mDNS/LLMNR *port hints* with the real NDISRD listener. It never copies packet payload, port values, IP addresses, process identities, or DNS questions into reports. It recognizes up to two VLAN tags, bounded IPv6 extension headers and IPv4/IPv6 fragments, refusing to infer transport identity for fragments or truncated frames. An exclusive consent and 15-second cap prevent changing to divert or owner sampling in the same request. Results always explicitly say `dns_leak_free=false`, `native_packet_owner_proved=false`, and `selected_application_containment_proved=false`. TCP/443 DoH cannot be distinguished from HTTPS without deeper authorized testing. Network traffic not present in the observation window cannot be ruled out.

This source addition is distinct from previously verified 12/12 IPv4 TCP native routing; it is **not native VPS proof** until the exact commit is built, a supervised LISTEN_ONLY profile is run on VDSina with independent rollback, and its artifact SHA and actual source/merge SHA are checked. No Win10/11 acceptance or protected-routing claim follows from this inventory.

### 2026-10-31 — Verified native IPv4 UDP/53 *port-hint* detection (not real DNS traffic or containment)

**Exactly verified source HEAD** `b5db12e0cc5aadb3a4fc2e62897e06f297dd8388`, **public GitHub Actions PR merge SHA** `0c288d7bc2d59d433b5634f3250c636747a6e359`. At this executable source, [capture CI run 41219951857](https://github.com/i-shutov/flowbridge/actions/runs/41219951857) **3/3 PASS** (Windows 2025, Ubuntu and macOS, strict Rust tests, Clippy, rustfmt, Windows SCM/control/installer tests). [Rust/native CI 41219951849](https://github.com/i-shutov/flowbridge/actions/runs/41219951849) and [DNS regression 41219951846](https://github.com/i-shutov/flowbridge/actions/runs/41219951846) both **PASS**; DNS regression is NOT a DNS leak-free claim. The signed Windows artifact #13049801271 was actually downloaded and independently hashed: outer SHA-256 `07d8fb15a69438662fba4b0ff391bd92905fa83a832945139c9634448020f128`, allowlisted four-file inner Rust candidate ZIP `04acc679b78b3fc1d3df014194237fabbd15e82d5551d1e721282b5799ed145b`, native x64 PE agent `f8fc762fa9d4d446f391ce13ca6328ae4e7d8e7519005860fa1e4fa019f7f7b8`. Checked inner manifest SHA-256 for each payload file, binary PE machine type and exact manifest `pr_head_sha`/`source_commit`. No vendor binary, ProxiFyre, WFP research, keys or credentials distributed; `protected_mode_available=false`, `release_accepted=false`.

**Independent VDSina Windows Server 2025 x64 native NDISRD read-only PASS #1:** [private workflow 41220444067](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41220444067), native QA source SHA `3966d2bcb36fff369f4940556b341168a116b270`, [private issue #1 report](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6546165681). 5,504 ms of signed-driver LISTEN_BOTH: 10 copied real frames (4 outgoing, 6 incoming), all IPv4 TCP; **0 UDP, 0 IPv6** in that window. No re-injection or routing. The report artifact #13049358997 was independently downloaded: outer SHA-256 `641a8d640671ead6ced956c983d56d6d6f607a3a6405283bcb6ab48510093693`, one JSON SHA-256 `995ea179e95ba0ff888b0f8ba8bda1db0bfacce40e924c22adb0840899fdb7cf`.

**Independent native UDP port-hint PASS #2:** [private workflow 41220798994](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41220798994), private QA branch SHA `6559721afc09d7f2a49721bf768b5ad9877ec01f`, [private issue #1 report](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6546212998). A separate Windows socket transmitted exactly **three four-byte zero-only UDP datagrams** with TTL=1 to a reserved **RFC5737 TEST-NET-1 documentation address**, destination port 53. This fixture contains **no valid DNS query, domain or personal data** and should not propagate beyond the first hop; its sole purpose is to produce observable real NDISRD packets on the live NIC. The original Rust read-only observer returned **23 real frames** (9 outgoing, 14 incoming), **23 IPv4, 17 TCP, 3 UDP and 3 other IP transport**, **3 UDP/53 hints**, **0 native IPv6**, no truncation, and **0 packet modifications/reinjections** in 5,501 ms. These are *native protocol/port classification* results, **not actual DNS transaction semantics, process ownership, encrypted DNS detection, leak-freedom, redirection or fail-closed**. The native JSON omits `release_accepted`; no approval is inferred from omission, and the checked public candidate explicitly marks it false.

Both native tests prearmed and subsequently disarmed an **independent Windows SYSTEM scheduled rescue** able to uninstall only the hash-pinned official signed NDISRD MSI after runner/network failure; both verified adapter mode restoration to **normal DIRECT-capable mode 0**, active Defender, network recovery and unchanged Windows Firewall policy. The private test did not install an untrusted driver. Second independently downloaded native artifact #13049887754 outer ZIP SHA-256 `6ef1d72249d46441b1e92cdd9e56596680086660046ca7099a44292b1949a0b8`, single sanitized JSON SHA-256 `da9d36d76fd3af7b6d93771c4a9a6404548779cc6e46c37c48213e7cb8957c49`; hashes, original Rust agent binary, reported counts, source and PR merge SHAs, rescue/Defender/rollback and negative acceptance fields independently checked.

**Strict current full OpenSSH workflow is NOT PASS:** [GitHub Actions run 41219951979](https://github.com/i-shutov/flowbridge/actions/runs/41219951979) on the same tested source/merge **FAILED** in the separate single-process raw-backend characterization. The actual managed real OpenSSH result independently confirmed **128 held / 1,152 refused / 10,000 successful churn, 0 churn failures**, and **4 independent process lifecycle PASS**, genuine Rust relay 4,097-byte SOCKS/SSH/half-close and closed-gate denial PASS. But the subsequent unthrottled single OpenSSH process capacity probe reached **244 accepted channels and then an existing stream reset** (`WinError 10054`; sshd log `Too many open files`); it did **NOT** verify a stable 512 nor even the raw probe's full lifecycle. The full workflow must remain RED until separately fixed without weakening checks. Downloaded failed workflow artifact #13049484314 outer SHA-256 `352a14b07be0d233dfeb5f12b621b89ca5b2a7f5f3768aee3b8fe2bec0e73009`, six JSON files independently inspected; no SSH passwords/keys kept. Raw backend characterization is distinct from 128-flow FlowBridge-managed acceptance; do not conflate them.

**Open product blockers:** arbitrary app selected without known socket/parent-client control, authoritative packet→PID+creation time binding, persistent protected fail-closed across service/driver crash and SSH death, real DNS/DoT/DoH/UDP/IPv6 containment with leak tests, signed Windows 10/11 native acceptance, GUI/installer upgrade+rollback and owner sign-off. The 2026-10-31 private VDSina tests are Windows **Server 2025** only, not Win10/11. VPS remains useful for next explicitly safeguarded native tests; no unsupported kernel/security changes, no public release, no main merge. [Issue #41 baseline](https://github.com/i-shutov/flowbridge/issues/41#issuecomment-6546184307), [native IPv4 UDP addendum](https://github.com/i-shutov/flowbridge/issues/41#issuecomment-6546223924).


### 2026-10-31 — Candidate: privacy-safe UDP/53 first-question wire-shape gate (native proof pending)

The observe_protocol_profile_lab counter path now separates UDP/53 **port-only** frames from bounded standard RFC 1035 first-question *wire-shaped* queries/responses, without saving QNAME labels, addresses, process IDs, packet contents or raw ports. The parser checks DNS header and first uncompressed question, forbids overlong labels/truncation, and deliberately leaves compressed first questions, nonstandard opcodes, encrypted DNS, split TCP and unobserved packets unclassified. This is a heuristic only: **not** successful DNS resolution, definitive DNS authentication, selected-application containment or leak freedom. Exact source CI, native candidate and downloaded artifact evidence must be appended after execution. Old zero-only UDP/53 canaries remain port-only, NOT DNS-shaped queries. The flowbridge-tunnel macOS test accepts multiple verified pre-child bind collisions inside its existing bounded three-retry helper; every unrelated failure remains fatal. No release, protected mode or main merge is authorized.


### 2026-10-31 — NATIVE VDSina DNS-shaped/non-DNS UDP/53 discriminant VERIFIED (read-only, NOT containment)

**Functional source HEAD 35bc288388c1e0aa4b7765ef5b4d1f9e22fc063f**, exact GitHub PR merge 72f41929bb213c17c1ea6f22ea1c4615d71d516e, capture [run 41222055274](https://github.com/i-shutov/flowbridge/actions/runs/41222055274) 3/3 PASS, DNS [run 41222055231](https://github.com/i-shutov/flowbridge/actions/runs/41222055231) 3/3 PASS. Windows candidate [artifact 13050796112](https://github.com/i-shutov/flowbridge/actions/runs/41222055274) independently downloaded: outer SHA-256 ec14b2d63b5c01667c4cfbc94887753315570f3c56d98e372b9d2779aad3649e; exactly four-file inner ZIP SHA-256 dc013c7658f9c825f84cc716be39c839bd3dda68a6e53b006e4fb7dec353246a; PE x64 Rust agent SHA-256 7b6c0b20b447422911866932051815a3d22e37691b92d62529291af415ff3985. Verified every payload manifest hash and exact source/merge; no vendor binary, AGPL code, keys or driver bundled. All release/protected/Win10+11 acceptance flags false.

**Actual signed NDISRD Windows Server 2025 native run [41222511041](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41222511041) PASS** on private QA workflow ef0408b4adf7ba4a5e9689ceac54d60d51d94ef4; [private sanitized issue #1 report](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6546463379). Independent artifact 13050248367 ZIP SHA-256 25146bdf9e4eb30aa82d48d007d2fe071f62c8598f50678e73f957287e45ed11; exactly one JSON SHA-256 6debe374cef8812fb4bc3045021cd130363f740dcb3674b32a4fdec0672565bf, independently parsed with all negative acceptance gates. In 5.5 sec **22 real NDISRD packets** (10 outgoing, 12 incoming); 6 real IPv4 UDP/53 port hints: **3 first-question standard DNS wire-shaped** synthetic RFC2606 reserved example.invalid canaries and **3 non-DNS four-zero-byte payloads**, TTL=1 to RFC5737 documentation endpoint. No genuine OS resolver, DNS reply, production domain, native IPv6 or captured arbitrary application. **0 original frames reinjected**; active Defender, network reachability, restored adapter mode zero, separately armed/disarmed local SYSTEM rescue confirmed. Mode zero is ordinary DIRECT-capable networking, not a kill switch. No payload, DNS name, PID, endpoint or adapter identity stored in JSON.

**CI blocker identified without weakening tests:** Rust/native [run 41222055272](https://github.com/i-shutov/flowbridge/actions/runs/41222055272) had all Windows/macOS jobs pass, but Ubuntu real OpenSSH job failed on second repetition **before SSH launch**: three sequential close-then-bind(0) test-only allocations reused a port and tripped existing four-port uniqueness assertion. This checkpoint groups the correction in the same #56: reserve all three ephemeral listener ports simultaneously before releasing them, preserving the assertion and all functional SSH checks. A new exact-head workflow MUST pass before declaring this fix verified. The separate raw Windows OpenSSH 512 characterization is still not accepted; 128/1152/10000/4 managed requirements are never substituted by raw backend attempts. No claim of native arbitrary selected-app PID binding, DNS leak-free, protected fail-closed or Win10/11 acceptance.

## Stopped-only Rust executable upgrade and rollback candidate (pending exact-HEAD CI)

The original Rust `flowbridge-agent service-binary-replace <old-config> <next-sibling-x64-exe> <next-config> <sha256>` command only changes an *exactly owned, stopped, manual* SCM service. It requires a valid loopback-only profile, canonical same-folder sibling image, bounded x64 PE32+ validation and a Windows CNG SHA-256 match while an exclusive-read handle is retained across the SCM transition. It checks the new SCM command and STOPPED state and attempts verified rollback to the prior command if the postcondition fails. It neither installs NDISRD nor changes capture policy, firewall, service auto-start or Windows protections. No binary is downloaded, copied or installed by this command; the caller must separately stage files with controlled filesystem ACLs. Windows ACL hardening, crash-atomic on-disk upgrade and arbitrary native app routing are **not** claimed.

The Windows hosted integration workflow builds two distinct original Rust agent executables (release and debug), stages the next image beside the running one and performs real Windows SCM + explicit SOCKS5: stage/start/stop -> hash-pinned binary and profile replacement -> start/handshake/stop -> reverse binary and profile replacement -> restart/handshake/stop/remove. Negative checks reject wrong hashes, invalid executables, an already running service and a mismatched service record. Its JSON result is `scm-binary-upgrade-lifecycle.json`; **do not accept this block until the exact PR source/merge SHA, all CI steps and downloaded artifact hash have been independently verified**. This tests two compiled variants, not two product releases, driver capture or installer ACL/atomicity.


### 2026-10-31 — in-progress pinned TCP ownership freshness hardening (not native acceptance)

On integration branch #56 the original Rust bounded native TCP reflection laboratory now requires fresh two-snapshot IP Helper process ownership candidate evidence for **every selected original outbound TCP segment**, not only the first SYN. The pinned OS process handle and creation epoch are checked before and after the table observations; a change/ambiguous/missing tuple rejects the segment instead of silently accepting a previous candidate. The single-flow lab report records aggregate check/denial counters only, keeps native owner/PacketBound/protected/DNS/release flags false, and fails a trial if candidate validation was denied. A real Windows loopback unit regression covers exact tuple, wrong source/destination, stale epoch, and wrong PID. This deliberately does not claim kernel packet ownership and may expose legitimate race conditions; no genuine signed NDISRD acceptance is claimed for this new source until its own exact-SHA CI and bounded native VPS trial are obtained.


### 2026-10-31 — Real signed NDISRD TCP owner snapshot closure race (native FAIL preserved)

A new exact-source self-hosted 12-phase native test for `9bf51bd79a911dfb75979de2b2e7e8e514f3aeb3` (PR merge `2dc1194f12eb23faa58d8e6a2b483ae6f8b6c185`) exposed a real timing race in the *first* self-owned TCP HTTP canary: 57 request bytes, 311 reply bytes, four native client frames and four relay frames successfully reflected through actual NDISRD→Rust→SOCKS/SSH, but the fifth selected TCP packet could no longer be corroborated in two fresh IP Helper snapshots, producing `fresh_tcp_owner_candidate_denials=1`, `selected_frames_dropped=1` and **0 selected original frames to the wire**. Native trial correctly returned FAIL under a new over-strict `owner_candidate_denials == 0` expectation. Safety rollback was independently verified: rescue armed/disarmed, adapter mode 0, network and Defender healthy, scoped firewall rule removed. [Private failure report](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6548140331) and [native run 41234631625](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41234631625). The lost owner evidence **must always DROP that packet**; a post-closure missing row is not grounds to declare a previously completed HTTP transaction invalid or to send DIRECT. New original Rust negative test covers owner loss after established SYN (ACK, FIN, RST all DROP). The bounded laboratory now reports both the exact denied-count and the `fresh_tcp_owner_candidate_denials_dropped` invariant, and accepts completed HTTP only if *every* denied witness was safely dropped, all transport/rollback protections are true, and selected packets sent to adapter are zero. This does NOT authorize arbitrary application capture, general PacketBound, protected fail-closed or Win10/11 acceptance; fresh-source CI and new native rerun remain required.


### 2026-10-31 — verified signed-driver 12/12 fresh TCP owner candidate witness (not PacketBound)

Source-of-truth Rust implementation **`934c418284fa8f20645bc9cdde3a57888c61132f`** (actual PR #56 CI synthetic merge SHA **`b6b296f50112df7b1733177edd709ad454570e1a`**), with independent Windows executable manifest/hashes, was compiled and exercised on self-hosted Windows Server 2025 with official signed NDISRD, real SOCKS and supervised authenticated OpenSSH. No third-party code/binary or driver was distributed in the candidate.

The initial new per-packet two-snapshot IP Helper owner-candidate requirement produced a **truthful native FAIL** (source `9bf51bd...`, [private issue report](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6548140331)): the HTTP request and response had already completed, but later FIN/ACK traffic lost its active TCP table entry. A dropped owner candidate is **always DROP**, with no packet DIRECT. The corrected bounded lab accepts the completed HTTP exchange only when every owner-candidate rejection maps to a dropped segment, selected original adapter sends equal zero, transport and rollback checks all pass. The new negative unit regression explicitly checks that subsequent ACK/FIN/RST after a valid SYN cannot escape with missing ownership. This is not a production packet-owner capability; IP Helper is still only an observational candidate and is not efficient enough as a per-packet general routing implementation.

**Independent exact-source build:**
- [Capture CI #41235001162](https://github.com/i-shutov/flowbridge/actions/runs/41235001162): **3/3 PASS** on Linux/macOS/hosted Windows 2025, including x64 SCM and actual Windows loopback tests.
- [DNS CI #41235001097](https://github.com/i-shutov/flowbridge/actions/runs/41235001097): **3/3 PASS** without claiming leak-free.
- [Rust/native CI #41235001064](https://github.com/i-shutov/flowbridge/actions/runs/41235001064): all hosted matrix jobs PASS; real Windows OpenSSH #41235001158 is a separate long-running gate and is not assumed PASS until concluded.
- Independently fetched Windows Actions ZIP SHA-256 **`d28ef23b92d1c9af0f0a1add07b5c17ef4ff8da2892b57b7f21c2d387c8f1dd7`**, nested allowlisted candidate ZIP **`e4c27988f96b44df4c19e157b3d6fe5ca397cdc5d1425acbb29a2d8c26a93bab`**, agent x64 EXE **`ccbb94d5b7464dd9bbd57eca6b4e42ea19fb23524f0686f30c31697323c67257`**, companion x64 CLI **`97742703d9733a2c8f1438c4de667e3f472bd2018232f4e0c2e795b4081ef6b2`**, original Rust test FFI **`2029d318a9c57c6b2d0726ae3d4ec8727f6277e6ab73c19dd462105a6b200140`**. The manifest matched exact source SHA and merge SHA, all internal SHA-256, x64 PE, 4-file candidate and 11-file distinct test-tool allowlist. No vendor binaries or credentials.

**Real guarded native verification:** [self-hosted signed-NDISRD Actions #41235346068](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41235346068), private QA SHA **`077c23e22dc878cd93ec304005e499d80b251a32`**; [sanitized private issue #1 evidence](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6548237214); independently fetched SHA-256 of native report ZIP **`d65fe1699970a39cfd75045adb41130803e3eadd64b61496518dcf6fb80b2e14`**. **12/12 PASS** across self-created Rust socket, spawned Rust, spawned Microsoft-signed OS PowerShell and independent Microsoft-signed PowerShell client; each positive, closed-gate denial, and restored-gate HTTP scenario. Total **57 fresh selected-segment IP Helper candidate checks**, **10 absent/changed candidates all dropped**, **zero selected original packets reinjected to adapter**. HTTP positives delivered 311–314 bytes, denial phases 0 bytes. Each phase `rollback_confirmed=true`, and overall `rescue_armed=true`, `rescue_disarmed=true`, `rollback_needed=false`, `mode_zero_rechecked=true`, `scoped_firewall_rule_removed=true`, `post_network_healthy=true`, `defender_active_after=true`. Source binary/QA tooling hashes match manifest and private pinned SHA exactly.

**Explicit exclusions:** These are controlled known-socket laboratory clients and *not* arbitrary application selection or kernel PacketBound. Returning driver mode to 0 is ordinary networking and **not** persistent fail-closed after a process crash. DNS leak-free, UDP/IPv6 containment, actual Windows 10/11 signed NDISRD acceptance, macOS NE and public release 1.0 all remain **NOT ACCEPTED**. Preserve raw OpenSSH 512 ceiling as separate failure; managed 128/1152/10000/4 is not evidence of 512. The paid VDSina VPS remains useful for remaining native experiments, but Windows Server 2025 never substitutes for Win10/11. No `main` merge or release.

## Explicit Rust SSH identification-order A/B diagnostic (NOT a protected route)
Run `flowbridge ssh-diagnose --endpoint 192.0.2.10:22 --timeout-ms 2000 --consent DIRECT_SSH_DIAGNOSTIC`. It creates two explicitly consented DIRECT TCP connections to an IP literal, server-first and client-first identification; it neither authenticates nor alters OpenSSH, driver modes or packet routing. Bounded banners and binary packet-header checks produce only stage/timing JSON, not endpoint, identification, credentials or payload. A header is NOT KEX completion, and a differential result is NOT proof a banner-gate workaround helps the user's SSH stall. Cross-platform CI executes compiled CLI against a separate live loopback server plus no-consent negative. Native protected routing, DNS safety and Win10/11 acceptance remain open.
