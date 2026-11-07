# R23 — actual ALE rewrite, one-use kernel context, Windows broker and real SSH transport

2026-11-07. Research branch only: `research/windows-wfp-ale-attribution-20261107`.
User-authorized new kernel backend and scoped push CI. This implements a candidate
redirect path; it is NOT a loaded-driver acceptance or a G2 PASS. Main, beta/PR56,
user runners, protections and automation settings are unchanged.

## Functional delta from R19

R19 only observed ALE. R23 now calls FwpsAcquireClassifyHandle0,
FwpsAcquireWritableLayerDataPointer0, changes FWPS_CONNECT_REQUEST0's remote
address/port to the configured local broker, sets localRedirectTargetPID,
localRedirectHandle and a nonpaged localRedirectContext, then applies and releases
exactly once. The original destination is preserved, not reconstructed from a TCP
table. IPv4/IPv6 TCP are implemented; scoped/link-local, mapped, multicast and
explicit non-loopback local bindings are conservatively rejected in this first
vertical. The unchanged process-birth registry retains original EPROCESS and
FILE_OBJECT references, epoch and start key. Existing/pre-driver processes remain
outside its authority; processes must be started after callback registration.

`handoff.rs` is compiled into BOTH the driver and broker: a fixed 128-byte
context, random 128-bit session, monotonic ticket, original PID/epoch/startkey,
endpoint/generation and destination. A private bounded kernel book records each
issued context. The same observed broker process must claim it; failed final
claims retire their ticket. Claims recheck the origin generation and live process.
No user-mode constructor can create a new positive kernel book entry.

`broker_windows.rs` queries records and context on the actual accepted stream,
parses only the strict wire representation, claims through the same driver, creates
a new outbound socket, sets WFP redirect records BEFORE connect, and connects only
to the configured local SOCKS next hop. No DIRECT-to-original-destination fallback.
It is a raw application-stream listener, NOT a SOCKS listener: `transport.rs`
generates SOCKS5 CONNECT from the context's original IP/port, then relays bytes
and half-close. A malformed/absent context or failed claim never reaches connect.

Configuration is one-shot, read/write access is restricted to SYSTEM/admin, the
broker is bound by actual IoGetRequestorProcess, and heartbeat loss permanently
disarms the experiment. The broker has a 300-second maximum run and 32-connection
cap; kernel owner history is still 256 entries. These are lab limits, not a
production service lifecycle or scalable policy engine.

## Exact source and real results

Executed source: `eb1e7561fd14ff05d1d899b7ca43e46988b883c7`.
GitHub Actions run **42398383944**, attempt 1:

| Job | Actual evidence |
|---|---|
| kernel-build-no-load / 128480609300 | Windows x64 redirect .sys + broker EXE built; ledger 11 tests and handoff 10 tests passed; actual broker rejected ordinary nonredirected IPv4/IPv6 sockets |
| socket-witness-no-driver / 128480609130 | R17 Rust compiled/tests ran; real Windows local socket->ALE endpoint/AppId observations for both IP families; redirect IOCTL error retained as error |
| redirect-ssh-transport-only / 128480609278 | 13 actual Rust tests passed; same broker SOCKS/relay functions passed real OpenSSH dynamic SOCKS, IPv4/IPv6 destinations, exact response and half-close |

The Linux transport test intentionally bypasses kernel admission and creates no
fake redirect receipt. It measures downstream transport ONLY. OpenSSH uses
strict host keys and StrictModes, ephemeral keys, own processes, a private mount
namespace for its /run, and the existing runner account. No host SSH service,
account/password, firewall or system configuration was changed. Namespace
separation and removal of processes/temporary keys are reported. This is NOT
Windows driver->SSH end-to-end evidence.

| Pinned artifact | ID / SHA256 |
|---|---|
| Kernel and broker ZIP | 13583989248 / `2e81dc9908ca69d42ee2c3a004a68f49ff5286478b1882512fbcaaa1827faed7` |
| SSH result ZIP | 13584670424 / `38d930eb30d47f910c20daf4785ab48cd454d0b22f2f97b459bc0cdca9432963` |
| R17 socket ZIP | 13584581818 / `35aee98cfa8d982dc962b5eac27a42eb913e0d2ea2e01e33e1fb26db7d3db138` |
| Unsigned redirect SYS, 205312 bytes | `94eb29c5c6c016bb52f387c1b2b3703bc8f8a12681b83e84e8df693e5cdbcc31` |
| Broker EXE, 311808 bytes | `c61bba5d6b6cd4c378454f1e4e39cd963d18a811a07a0b75687199befcf104ee` |

All three actual ZIPs were downloaded and SHA/CRC checked. An independent
stdlib-only PE reader verified the native kernel and console broker formats,
entrypoint, non-W+X sections, absent embedded certificates and imports. The kernel
imports actual redirect APIs from fwpkclnt.sys and BCryptGenRandom from cng.sys.
The broker imports WSAIoctl and DeviceIoControl. Binary imports alone do not prove
call order or execution; source inspection and native tests are different evidence.
The reader preserves ordinal imports without guessing their names. Its separate
negative suite passed **16/16**. No independent human/native reviewer sign-off.

## Failed attempts, preserved rather than rerun

- `547e48ea`, run 42396581365: missing bindgen pool constant and const/mutable
  classify ABI; early SSH setup failure lacked adequate redacted diagnostics.
- `a424e568`, run 42397241544: dangerous implicit raw-pointer autoref rejected by
  Rust; unprivileged SSH rejected authentication before transport tests.
- `643876ab`, run 42398078736: kernel/broker build and native negative passed;
  isolated root SSH reported key-path permissions. StrictModes rejected the
  world-writable ancestor of a private temporary key directory.
- `eb1e7561`, run 42398383944: private home directory fixed the key path WITHOUT
  disabling StrictModes; all three jobs succeeded.

No failed workflow was rerun. Changes were new-source commits with expected-SHA
fast-forward writes. Compiler warnings are not claimed eliminated. Cargo/SDK/
compiler dependency freezing and reproducible builds remain separate work.

## Native acceptance is still OPEN — exact remaining work

1. There is no driver signature accepted for loading, no verified current VNC/
   SYSTEM rescue/rollback set, and no driver was loaded. The new authorization
   permits installation but does not remove these safety prerequisites.
2. This block supplies kernel rewrite and broker handoff code, NOT the native lab
   activation controller: reviewed scoped BFE management filters, callout policy,
   startup sequencing and complete cleanup must still be installed/verified under
   the gated native harness. No filters are silently installed by DriverEntry.
3. The positive path — original unprepared EXE -> real ALE callback -> real context
   on accepted socket -> successful kernel claim -> WFP records set -> SSH response —
   has NOT been executed as one chain. Current broker native test is rejection of
   unredirected sockets, not successful redirected admission.
4. Driver IRQL/lifetime/unload, allocation and cancellation behavior, races after
   claim, reference coverage of older sockets/processes, all PID/endpoint reuse
   cases and path alias handling require independent review and native negatives.
5. The standalone broker consumes an externally configured loopback SOCKS endpoint.
   The real fixture is owned OpenSSH, but production managed-Supervisor integration
   and proof of SSH endpoint ownership are not completed by this test.
6. A heartbeat/ingress denial is NOT a persistent system kill switch. Driver/BFE
   disappearance, DNS/UDP/QUIC, already established flows, sibling DIRECT and
   physical traffic containment are not proved. NDISRD per-frame PacketBound does
   not follow from this WFP connection implementation. No G1 acceptance transfer.

`g2_pass=false`, `kernel_redirect_executed=false` in the accepted experiment;
`release_accepted=false`. Progress is functional compiled implementation plus
separate real downstream transport and native-negative checks, not full G2 closure.

## Reproduce independent artifact audit

```
python research/wfp-ale/verify_redirect_r23.py KERNEL.zip SSH.zip SOCKET.zip
R23_KERNEL_ZIP=KERNEL.zip R23_SSH_ZIP=SSH.zip R23_SOCKET_ZIP=SOCKET.zip \
  python -m unittest discover -s research/wfp-ale -p test_verify_redirect_r23.py -v
```

Primary API contracts checked:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsacquirewritablelayerdatapointer0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsapplymodifiedlayerdata0
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-
