# R26 — build-verified kernel-origin ALE_AUTH_CONNECT admission witness

Research branch: `research/windows-wfp-ale-attribution-20261107` only.
Build/tested source: `aa2d45ca552a8f51cd069e1f19e0ff7f41a93092`.

## Precisely what changed from R24/R25

The prior selected-AppId TCP AUTH_CONNECT policy blocked only destinations outside the local proxy address/port. Consequently it could not distinguish a genuine redirected connection from a direct selected-EXE connection to that same loopback endpoint. R26 replaces these static destination checks with native terminating **ALE_AUTH_CONNECT_V4 and V6** callouts.

The WFP AUTH callback checks: IS_CONNECTION_REDIRECTED, not a reauthorize or honoring-policy shortcut; present process ID, transport endpoint, original destination and local redirect target PID metadata; selected actual and original AppId; broker loopback address and port; an identical original destination and pinned owner PID/creation epoch/process start key/generation from the **same previously issued kernel ticket**.

The private kernel Book now carries `auth_seen`. A CLAIM fails terminally unless a matching actual kernel AUTH classification has previously marked the one-use ticket. Exact endpoint uniqueness and unrelated/expired/duplicate origin controls are enforced. The broker retains the accepted socket with its redirect records/context as private Rust-owned values, CLAIMs before connecting a new proxy socket, SETs the WFP records before outbound connect, then speaks SOCKS5 over the local SSH SOCKS endpoint. Source: `kernel-r19/kernel/src/lib.rs`, `redirect.rs`, `handoff.rs`, `policy_windows.rs`, `policy_plan.rs` and `broker_windows.rs`.

We intentionally scope BFE AUTH filters to the executable's **current** ALE_APP_ID and verify original app ID *inside the callback*. This avoids enrolling a proxy-owned outbound socket just because it legitimately retains the original image in redirect records; exact classification behavior still requires real Windows driver tests.

## Real no-load Windows evidence

CI [#42411101062](https://github.com/i-shutov/flowbridge/actions/runs/42411101062) at `aa2d45ca...`: all three jobs SUCCESS.

- Windows Server 2025: 207360-byte x64 native kernel .sys and 339968-byte broker EXE linked. Actual broker tests **33 PASS**; kernel ledger/handoff tests completed; five invalid Rust adapter ownership uses rejected by the compiler.
- Linux: 26 Rust tests PASS including real isolated OpenSSH SOCKS, IPv4/IPv6 target, exact response and TCP half-close. This is **transport-only**, not native redirect.
- Windows: real read-only local socket -> endpoint -> AppId queried for IPv4/IPv6; ordinary sockets have redirect-record/context IOCTL errors 10022. An error is not absence evidence.
- Independently downloaded original artifact ZIPs, checked GitHub SHA256 and all ZIP CRCs; verified 19 exact source files against their retained hashes; independently checked PE format, native subsystem, no embedded driver certificate, critical kernel imports and all negative result flags. This independent reader executed **no binary**.

| Artifact | SHA256 (authenticated GitHub digest) |
|---|---|
| Kernel+broker build ID 13589062678 | `d4e3178b3b8fd13cda539d6ba552d1a7d5ffe4458c54a59b5d5020a54941264b` |
| SSH ID 13589467773 | `58ff4ea18820719d45f24a280dffdcf97079ff884f50901310e25626a63d627a` |
| Read-only socket ID 13589920613 | `4b5ab6e0312135edf0ea262e932ee3e685528b7e29501789bcfffb5f5ec26293` |
| Driver SHA256 | `f2873b8fb12f12ba0168227aaad99de76eb2a2167d4b0c7d46bbed6e4b3fbf48` |
| Broker SHA256 | `9713a6466e8028fa4f95776040d92845b39707bcbbc0637e05cc5babbe60c81f` |

## Negative build history is retained

- `bc017877`, run #42410647675: two tests incorrectly reused one endpoint across distinct records. The new uniqueness rule rejected that synthetic collision as intended; both kernel and SSH test jobs failed.
- `b489c0f2`, run #42410843890: those two test fixtures corrected. SSH and read-only socket PASS; broker compilation stopped on safe Rust access to an `windows-sys` union field (`E0133`).
- `aa2d45ca`, run #42411101062: union access fixed, BFE match scopes current ALE_APP_ID, and kernel checks both current/original app ID; all jobs PASS.

No failed job was rerun. No beta/PR #56, main, self-hosted runner, security protection or automation was changed.

## What still stops native G2 acceptance

**No actual driver was installed, signed or loaded. No BFE filters were activated.**
No real unmodified selected EXE was redirected through the entire chain on a signed, independently admitted test host. The build's `FORCE_INTEGRITY` PE bit is **not a signature**. A real signed package, current VNC, independent SYSTEM rescue and rollback remain required. No test-signing/SecureBoot/MemoryIntegrity/Defender workaround was used.

The AUTH witness has not yet been observed on a real redirected connection. WFP's actual metadata, authorization and reauthorization ordering, filter arbitration, process/endpoint reuse and driver IRQL/unload are unverified. Even a successful signed driver load will not establish crash-persistent no-DIRECT: the BFE policy lives in a dynamic session and may disappear on broker crash. DNS, UDP/QUIC, IPv6 leak controls and NDISRD per-frame PacketBound remain separate acceptance gates.

The next **decisive** experiment is signed-driver admission and a single original EXE -> ALE_CONNECT_REDIRECT -> AUTH ticket -> accepted-socket WSAIoctl context/records -> one-shot CLAIM -> outbound records -> SSH receipt, with independent physical network observations and negative controls. All gates must be validated before loading; no source-only/native-build PASS may substitute.

**G2 = OPEN/NO-GO. Release = NO-GO.**

Primary contracts:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-flags
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/ne-fwpsu-fwps_fields_ale_auth_connect_v4
