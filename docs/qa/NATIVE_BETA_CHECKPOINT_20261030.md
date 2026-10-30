# FlowBridge — внутренний beta-чекпойнт 2026-10-30

Статус: **подтверждённая нативная сборка и локальный SOCKS5; полноценный
системный перехват Windows/macOS ещё НЕ принят**. Не публиковать как
окончательную замену Proxifier.

## Provenance and exact-head evidence

- Базовый `main` до интеграции: `b5971a2e185283851173504e79a96812430b7178`.
- [PR #29](https://github.com/i-shutov/flowbridge/pull/29), проверенный исходный
  SHA: `a38fd84effd7efa19b0091f7aebc4319a531e215`.
- Squash merge в `main`: `068b9aeea75533868a0e910ef5670493b88d8d91`.
- [Native + Rust CI #41005277502](https://github.com/i-shutov/flowbridge/actions/runs/41005277502):
  **SUCCESS, 5/5**: `windows-application`, `macos-application`,
  `rust (ubuntu-24.04)`, `rust (windows-2025)`, `rust (macos-15)`.
- [Native DNS CI #41005277446](https://github.com/i-shutov/flowbridge/actions/runs/41005277446):
  **SUCCESS, 3/3**: Windows, macOS, Ubuntu.
- Previous related verified stages: PR #25 genuine two-process Linux OpenSSH
  routing, PR #27 fault-injection recovery, PR #28 handle-attested FFI.

GitHub Actions artifacts (from the **exact PR head**, with limited 14-day
retention; artifacts are not a signed/public release):

| Artifact | Evidence |
| --- | --- |
| `FlowBridge-windows-x64` | real unsigned Windows x64 installer |
| `FlowBridge-windows-verification` | Windows native GUI, install/upgrade/uninstall and dependencies |
| `FlowBridge-macos-universal-local` | local-development universal macOS `.pkg` |
| `FlowBridge-macos-verification` | macOS package install/launch/upgrade |
| `FlowBridge-real-SSH-verification` | disposable Linux `sshd`, 128 held channels, pool failover, admission/recovery and process-resource measurements |
| `FlowBridge-native-session-*` | native user-mode routing, isolation and ownership QA |
| `FlowBridge-wfp-wire-fixture-*` | cross-platform mock protocol/wire QA, **not** installed kernel interception |
| `FlowBridge-exact-source` | source archive and SHA-256 checksums |

## Delivered vertical: multi-process managed SSH desktop

- Windows compact Win32 connection page: persisted **1–4 worker** selector,
  independent unelevated OpenSSH supervisors on base local port + 2×index;
  selected SSH executable, start/stop, actual child/PID statuses, ready count,
  aggregate admission cap 128, counters, worker failures and privacy-sanitized
  diagnostic JSON. The optional privileged WFP helper does not launch SSH
  or receive SSH key material. All attested OpenSSH executable paths are
  excluded from transparent application capture to prevent routing loops.
- macOS SwiftUI: saved **1–4 worker** selector, independent supervisors on a
  serial worker queue, read-only published handle snapshots, monitored
  readiness and truthful stop failure. Multiple workers are enabled **only
  for explicit local SOCKS5**; transparent Network Extension mode refuses
  more than one worker until system-specific native validation.
- Both GUIs use `fb_engine_sync_owned_ssh_pool_json` with already registered
  supervisor IDs. Rust checks that the handles are live and unique, derives
  each endpoint and readiness from genuine supervisor PID/state, and rejects
  invalid updates without changing the current pool.
- A failed worker never causes **DIRECT** fallback. Existing TCP streams
  belonging to surviving workers remain pinned; a dead worker's streams
  cannot migrate or replay. Windows single-worker mode retains bounded 30 s
  new-flow grace for SSH reconnect. Multi-worker all-unready fails closed.

## Mandatory gates before declaring a *full transparent* beta

1. **Windows WFP:** approved/signature-validated driver installed and loaded
   on an authorized disposable VM; [WFP real VM acceptance](WFP_REAL_VM_ACCEPTANCE.md)
   must produce real IPv4 and IPv6 selected-application redirect evidence,
   nonselected bypass, no DIRECT on negative SOCKS response, and cleanup on
   normal/abrupt exit. Hosted CI builds only the user-mode helper and fixtures.
2. **Native Windows OpenSSH exhaustion:** reproduce/characterize the user's
   `nchannels 251/252`, `accept: Too many open files` on the selected actual
   `ssh.exe`, with 64/128/192/256/512 attempted-flow tiers and recorded
   process/descriptor evidence. [QA guide](REAL_OPENSSH_CAPACITY.md). Linux
   success is not Windows FD-table evidence. Keep [Issue #7](https://github.com/i-shutov/flowbridge/issues/7)
   open.
3. **Apple system activation:** approved Team ID, entitlements and code
   signing for the real Network Extension on Macs, with TCP/DNS interception
   and uninstall/disable acceptance. Local development package and unsigned
   Xcode build are insufficient.
4. **Release reliability/privacy:** signed app installer/upgrade/uninstall,
   per-application DNS (including IPv6 and DoH/DoT/QUIC scope), Windows real
   DPI matrix, external clients of managed SOCKS ports, user authority
   boundaries, prolonged soak, and explicit confirmation of no unintended
   traffic leak. No automatic transport replay or full kill switch yet.

## Operator usage — only accepted local SOCKS path

- On Windows, install `FlowBridge-0.2.0-windows-x64-setup.exe` from
  `FlowBridge-windows-x64` artifact; macOS uses the *local* `.pkg` artifact.
  These packages are unsigned/development artifacts: use a nonproduction
  workstation/test account and verify the artifact provenance.
- Select managed SSH, enter server/user and key or agent (pre-enroll the
  actual host key); choose 1–4 processes. Keep FlowBridge listener
  `127.0.0.1:1081` separate from SSH `-D 1080/1082/1084/1086`.
- A client that explicitly supports SOCKS5 can use
  `socks5h://127.0.0.1:1081` so hostname resolution is performed upstream;
  a client that already resolved its destination locally cannot be retroactively
  protected by this setting. No unsupported transparent-capture guarantees.
- For real VM evidence use only the isolated fixture scripts documented
  above, not a production SSH server/credentials.
