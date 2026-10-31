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
