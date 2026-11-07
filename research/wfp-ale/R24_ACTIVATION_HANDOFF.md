# R24 — scoped BFE activation and accepted-socket-owned redirect handoff

2026-11-07. Research branch only: research/windows-wfp-ale-attribution-20261107.
Base R23: 3bb9fbcd4cae68700a87eacc6b8074bba7b35662.
Functional R24: ec5b1cecda073d5f53e3569adaafdd464604c728.
Executed corrected source: cf80986e85bb93a50d2a780f05123216a4e271af.
Main and beta/PR #56 were not modified. The owner-authorized push-trigger and
kernel development scope were used; no driver load or signing bypass occurred.

## Functional implementation (not a new model)

R23 already implemented FWPS_CONNECT_REQUEST0 rewriting, one-use kernel tickets,
redirect context and a SOCKS/SSH broker. This block extends that code rather than
creating a parallel implementation:

1. `Received` OWNS the actual accepted TcpStream. Context and redirect records
   are private and cannot be cloned/detached. Its consuming method performs a
   kernel CLAIM before creating the outbound socket, then SETs that socket's
   WFP redirect records BEFORE connect. `Admitted` privately retains that same
   ingress socket, outbound socket and destination until SOCKS CONNECT + relay.
2. `SelectedImage` retains a read-only file handle without write/delete sharing
   for the bounded lab run. BFE receives its exact native AppId blob including
   the UTF-16 terminator; kernel ARM strips only that terminator. This handle is
   not a substitute for the original process image-section identity.
3. Added an actual Windows BFE activation controller using pinned Microsoft
   windows-sys 0.61.2. In its own dynamic session/transaction it creates one
   sublayer, two callouts, two selected-AppId/TCP redirect filters and four
   selected-AppId/TCP AUTH_CONNECT blocks for non-loopback/wrong broker port.
   No global PERMIT, disabled filter or PERMIT_IF_CALLOUT_UNREGISTERED is used.
   It reads back exact filter conditions. REGISTERED is checked as a runtime
   registration snapshot only, never as an original-owner proof.
4. `--serve-admitted-lab` connects controller activation with the existing
   armed kernel lease, listener lifecycle and broker. It is NOT a host-admission
   verifier: the external native harness must have already checked signature,
   exact package, fresh VNC, SYSTEM rescue, protections and rollback. CI NEVER
   invokes this mode. Dynamic-session policy is not a crash-persistent kill
   switch. Selected test processes must end before session teardown.
5. Kernel classify now denies unconfigured selected callouts, rejects odd AppId
   sizes and avoids a second redirect in SELF/PREVIOUSLY_SELF states. It keeps
   the original ACTION_WRITE success convention: writable acquisition clears
   that bit; the successful rewrite restores only the right originally granted.
   Microsoft's WFPSampler does likewise. The early suggestion to remove that
   restoration was corrected before publication; no such false fix is claimed.

## Exact CI result and causal failure history

Run 42403031001 on ec5b1cec: kernel build succeeded, broker policy compilation
failed E0369 because windows-sys::GUID lacks PartialEq. Original failure was
retained, not rerun. Commit cf80986e compares all GUID fields explicitly and
adds a test that changes each field. No policy condition was weakened.

Run 42403336045 on cf80986e, attempt 1: ALL THREE JOBS SUCCESS.

- Windows kernel/broker job 128495644550: real .sys and broker executable built;
  27 actual broker tests passed. Those include shared wire/transport tests,
  policy transaction contract tests, Win32 policy STRUCTURE construction and
  native ordinary-socket rejection/selected-file AppId tests. No BFE filters
  were installed and no kernel callout executed by these tests.
- Windows compile contract: a valid control compiled and five invalid adapter
  uses were rejected with the expected compiler errors (private context,
  no Clone, moved socket, borrowed socket, private admitted upstream).
- Linux SSH job 128495644317: 21 Rust tests passed, including actual isolated
  OpenSSH SOCKS transfer to IPv4/IPv6 endpoints with exact response and TCP
  half-close. No fixture redirect context was used. Kernel redirect was NOT
  exercised; host SSH service was unchanged and fixtures/keys were removed.
- Windows read-only socket job 128495644608: R17 IPv4/IPv6 endpoint observations.
  Redirect IOCTL error 10022 stays QUERY_ERROR, not proven absence or origin.

Test groups overlap (shared wire/transport code); do not add them as a count of
independent native G2 trials. No independent human reviewer sign-off is claimed.

## Downloaded artifact audit

| Artifact | ID | SHA256 |
|---|---|---|
| Kernel/broker/sources | 13586198402 | 8315885a043dc5d9e4c7f8e33a93050903293189099184e7e950678b313f1c16 |
| SSH result | 13585934026 | 232a46928cd1e1219ef0f10c862afc4840002c0ecbd3f76eab2b5466b9c680ff |
| Socket results | 13586477437 | db1f8eb06628aa02e4e7246627b9b2966fe466392a8321b3c825fe98df8d30c9 |

An independently implemented stdlib PE/ZIP reader checked all three downloaded
archives against GitHub digests and CRC, 19 exact source files, six changed
source blob pins, native binary layouts/imports, source/adapter fingerprints,
negative acceptance flags and all five compiler-negative outcomes.
Its 16 adversarial reader tests passed locally. These tests verify evidence,
not the original kernel behavior. The verifier never executed either binary.

Driver: 205312 bytes, SHA256
3d8efda3d818d5dbc8a4cea1c5459396f209f8c6424ce574345ef2d87144e47f.
Broker: 342528 bytes, SHA256
609eeddc430be284f6333100ac853fb5f0f85d4ed98486c8a3dd10a8af759b6d.

Driver imports include actual writable-layer/Apply/redirect-handle operations.
Broker imports include WSAIoctl, DeviceIoControl and actual BFE transaction,
callout, filter-add/readback functions. These demonstrate linked implementation,
not execution of those operations. The driver has no embedded certificate and
no signed catalog accompanies this package. FORCE_INTEGRITY is not a signature.

## Remaining full-native acceptance gate — OPEN

The code path now contains the activation/controller and socket-owned handoff
pieces. A loaded-driver unprepared-EXE -> ALE -> redirect context -> accepted
broker socket -> SSH test has STILL NOT RUN. There is no signed exact package
or current independently verified VNC/SYSTEM-rescue admission available here.
The owner's existing authorization is sufficient to continue development; it
must not be confused with those missing concrete machine/package prerequisites.

Actual callback/IRQL/unload behavior, process-generation binding, expected
AUTH_CONNECT original/rewritten destination semantics, policy arbitration,
foreign/self redirect interaction, original-process death, sibling controls,
physical DIRECT trace and failure/rollback remain native obligations. Static
AUTH rules and dynamic-session cleanup do not themselves prove all of them.
Native Win10/11, DNS/UDP/QUIC and per-NDISRD-frame PacketBound are NOT established.
Historical G1 dd1ab3c acceptance is not transferred. g2_pass=false;
release_accepted=false.

This checkpoint is for review/reproduction, NOT an installable/signed release.
The next native test must run the actual --serve-admitted-lab mode on an already
admitted signed-driver host, start a fresh unmodified selected EXE after filter
commit, collect independent original-process/receipt/response evidence and
terminate selected clients before bounded teardown. No weakened safety gate is
suggested, and no native result is promised from the build alone.

Official semantics inspected:
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
https://github.com/microsoft/Windows-driver-samples/blob/main/network/trans/WFPSampler/sys/ClassifyFunctions_ProxyCallouts.cpp

CI: https://github.com/i-shutov/flowbridge/actions/runs/42403336045
