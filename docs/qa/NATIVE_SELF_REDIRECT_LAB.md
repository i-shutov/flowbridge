# Native self-socket TCP redirection integration

## Native self-created TCP -> local relay -> SOCKS canary (not accepted yet)

`native-self-redirect` is a bounded, explicitly consented IPv4 laboratory
entrypoint, NOT a production protected mode. Unlike the previous copied
IP Helper candidates it owns the original TCP socket itself, holds its source
port/process object until teardown, checks PID/creation-time snapshots, and
reflects its original outbound TCP through the **local Windows TCP stack** to
an actual Rust listener. Return packets are inversely reflected. Only matching
client/listener tuples are changed; malformed selected frames are dropped,
and modified frames may only be injected to the stack, never to the wire.
The local listener accepts only the reserved reflected peer; it preserves the
original destination in the genuine SOCKS CONNECT. There is no DIRECT retry.

The application sends a fixed, nonsecret HTTP HEAD canary for example.com;
all packet contents, socket addresses, PIDs and paths are omitted from output.
An outer test must prove the separately supervised SSH hop and a failed
upstream case; unit fixtures are not native evidence. A scoped, temporary
inbound firewall allowance may be needed for this exact agent/peer only,
without disabling Defender/firewall. The owner has confirmed provider VNC;
independent timed SYSTEM recovery is mandatory before native diversion.
The agent joins/aborts its owned socket task BEFORE restoring ordinary
networking. This does not protect an arbitrary application after agent death.

No IP Helper result is converted to the existing `PacketBound` token.
Native arbitrary-process identity, DNS/UDP/IPv6 containment, persistent
fail-closed and Win10/11 acceptance remain OPEN, as does release approval.
Exact source/merge SHA, native experiment evidence and complete CI results
must be recorded before this can be used beyond the controlled self-socket.

## Verified real native positive / gate-denied / recovered SSH chain — 2026-10-31

**Important scope:** The original Rust process opens and owns its **own**
IPv4 TCP socket. This is a controlled lab canary, **not** a selected
third-party application, general packet-to-PID attestation, or protected
Windows beta. Both the NDISRD and SOCKS/SSH hops below are real, not mocks.

- Exact public source PR #56 HEAD `f947bf9f27923a6a669f6f2c521f6235796cc74c`;
  GitHub PR test merge `22c3b698ef01a7b945e6360d6ed37bfddea11413`;
  independent private workflow `f04e7fbb2cec46532828381055e825659fa4d827`.
- [Native self-hosted Windows Server 2025 Actions run #41207789454](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41207789454)
  **PASS**; [sanitized private source evidence in issue #1](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6544300447).
  Verified separately installed signed NDISRD, actual `TUNNEL_BOTH`,
  two-way reflected frames, Windows TCP stack, Rust relay, FlowBridge SOCKS,
  authenticated isolated Microsoft-signed OpenSSH, actual HTTP response.
- Three independent native runs, **each with rollback**:
  **connected** 5 client / 4 relay frames reflected, 57 bytes sent,
  313 bytes received, live HTTP reply, SOCKS through SSH;
  **gate closed** 4 / 3 frames reflected, upstream SOCKS refused, no HTTP
  reply; **recovered** 5 / 4 frames reflected, 57 bytes sent, 315 received,
  live HTTP reply on the **same** SSH supervisor.
  In all three `selected_original_frames_sent_to_adapter=0`,
  `self_owned_socket_pid_epoch_consistent=true`, no native checksum/option
  rejection, reported adapter rollback true.
- The independent SYSTEM timeout rescue was armed before mutation and
  disarmed **only after** adapter mode-0 recheck, network and Defender health,
  and deletion of the exact temporary scoped Windows Firewall rule.
  `rescue_armed=true`, `rescue_disarmed=true`, `rollback_needed=false`,
  `scoped_firewall_rule_removed=true`, `post_network_healthy=true`,
  `defender_active_after=true`. Mode 0 restores **ordinary network access**,
  never a persistent kill switch.
- GitHub-native uploaded artifact #`13044882622` was **independently
  downloaded and parsed**: outer ZIP SHA-256
  `2a381eafdf040e50dc29c320cd1c35c8b16fc02348a9a2e9932327bc80a85359`
  equals GitHub's reported digest. Exactly one redacted JSON entry,
  SHA-256 `6ecdc8338249a9e7ae63895511238bb1500d2325ebcad64cebee03cc14b06be0`,
  matches the public/merge/private workflow SHAs, all three positive/negative
  assertions, recovery checks and explicit negative release claims.
  Original Rust agent SHA-256 `9c13a893070ebb6de4760bfd6aad0424afb13c430fa07cb3632aff739ca8c913`;
  original Rust FFI SHA-256
  `8e476286e0f405110819fe2e6ca97399bd07520c0842c68227e88eeb22f56043`.
  OpenSSH binary hashes are recorded in sanitized private JSON, not bundled.
- The preceding private run [#41206756387](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41206756387)
  **FAILED before mutation**: downloaded OpenSSH ZIP did not equal its pinned
  SHA-256. The workflow did **not** accept changed bytes. It was replaced
  with verification of Microsoft's signed *in-box Windows Server 2025*
  `ssh.exe`, `sshd.exe` and `ssh-keygen.exe`; no server service or
  third-party ZIP installed. A transient invalid-workflow edit was repaired
  before execution; no native mutation was attempted by that failed run.

**Release/security boundary (all FALSE):** general NDISRD packet-to-process
ownership proof, arbitrary selected-app redirect, crash-persistent protected
fail-closed, DNS leak-free, UDP/QUIC and IPv6 containment, native Windows
10/11 acceptance, 512 stable raw OpenSSH channels, personal beta/1.0 release.
The signed-driver Windows Server 2025 canary **does not** grant these claims.

## Controlled separate-process Rust client (new candidate; native proof pending)

The integration can optionally spawn a separate `flowbridge-agent native-child`
process, whose own bound TCP source port and **OS process handle** are retained
by the parent before adapter diversion. A bounded stdin GO handshake ensures
the child cannot send its first SYN before the parent confirms the tunnel
session. During capture, two native IP Helper table snapshots must match the
**child**, not the parent, PID/creation epoch. The parent reflects exactly the
known child TCP tuple to a Rust relay and inverse response into the TCP stack;
the child is terminated/joined *before* restoring normal adapter mode, even
when the SOCKS gate is closed. Only redacted aggregate evidence is emitted.

The same isolated Microsoft OpenSSH + FlowBridge SOCKS fixture now runs a
second connected / gate-closed / recovered triple for the child process.
**This is not arbitrary selected-app acceptance.** A parent spawning and
holding the exact child socket/process is a stronger, specifically engineered
test than observing an unknown third-party flow. Neither IP Helper snapshots
nor process creation time authenticate arbitrary NDISRD packet ownership.
No persistent protected mode, DNS/UDP/IPv6 containment, Win10/11 evidence
or release is asserted without separate native checks.


## Native separate-process child — accepted bounded lab evidence, not arbitrary app (2026-10-31)

Unlike the original single-process canary, a separate `flowbridge-agent
native-child` creates and retains its own IPv4 TCP socket, announces only a
bound ephemeral port, and blocks awaiting GO over inherited stdin. The
parent pins a real read-only child process handle, validates process creation
FILETIME and two native exact-tuple IP Helper snapshots before forwarding
selected packets. No child SYN precedes confirmed NDISRD tunnel activation;
child process join/termination precedes return to ordinary adapter mode 0.

[Real VDSina workflow run #41210941526](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41210941526)
**PASS** on native Windows Server 2025, using publicly pinned source
`81419f764ba51dab9c4aa91bda1de81ccb581383` / CI merge
`dc70e093c40490aa728455fa52a22eca38bef7d7` and private
workflow `68b690adde99fb730c9f8f7f9c6c67768437b812`.
[Private truthful issue evidence](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6544806370).
All three child stages (connected/closed-gate/recovered) and all three
original parent stages passed with genuine NDISRD RX/rewrite/TX into stack and
isolated authenticated real OpenSSH. Child 57/314 transmitted/received
bytes on positive and recovered, zero bytes and no SOCKS CONNECT when closed;
5/4 forward/reverse frames on success, 4/3 on denial. Same SSH supervisor
survived the complete sequence. Child identity verified separately from
parent and neither identity was emitted in evidence. All six reflected
sessions had **zero selected original frames leaked to adapter**.

Independent private artifact #`13045204941`, outer ZIP SHA-256
`d9740fb5505eb8c884410b98755567ab630ae0f16de3c628761dec29d262317c`,
single redacted report SHA-256
`55d60ac595bb4024c406e14a5f043c126c96fb9f17200328fc7d5a5b7f5829b9`;
source/merge/workflow and binary hashes matched pinned public manifests.
An independent SYSTEM rescue remained armed for each bounded lab session,
then disarmed only after mode-zero, firewall, network and Defender checks.
No credentials or packet/PID/endpoint identities entered artifacts.

**Trust limit:** parent deliberately creates and supervises this known child,
so the result is **not proof of general NDISRD packet ownership or arbitrary
selected-app enforcement**. Protected crash-persistent fail-closed, DNS/UDP/IPv6
containment, Windows 10/11 desktop acceptance and beta release still remain
false. Mode 0 restores DIRECT-capable ordinary networking.


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


The fixed PowerShell script and its Authenticode probe use Windows PowerShell's UTF-16LE Base64 `-EncodedCommand` interface to avoid shell interpolation/argument quoting; the script body is compiled into original Rust and is never sourced from JSON. The hosted signed-PowerShell positive and negative GO/half-close regression remains mandatory; this change is not native driver proof.
