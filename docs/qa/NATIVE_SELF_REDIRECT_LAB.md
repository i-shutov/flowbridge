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
