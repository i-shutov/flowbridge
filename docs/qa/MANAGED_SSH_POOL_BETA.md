# FlowBridge internal beta — independent managed OpenSSH worker pool

Prepared: 2026-10-29. **This is new-flow routing, not TCP session resumption.**

## Design and guarantees

The Rust explicit SOCKS runtime can now select **1–4 independently started,
real local OpenSSH `-D` processes**. The owner GUI or service starts and
monitors each child separately; the runtime never launches SSH by merely
receiving a JSON pool configuration. OpenSSH's existing settings enforce
`ControlMaster=no` and `ControlPath=none`, so distinct local SOCKS ports
cannot silently collapse into a shared underlying SSH master connection.

The first worker must match a configured, prevalidated, **single-hop SOCKS5**
proxy in the active profile. Every worker endpoint is a unique literal
127.0.0.1 / ::1 loopback socket. Mapped IPv4-in-IPv6 aliases are normalized to
prevent duplicate listeners. Remote addresses, domain names, 0.0.0.0 and
duplicate endpoints are rejected; a pool of more than four workers is rejected.
Validation is atomic: malformed updates leave the previous routing policy.

For every new proxied flow:

1. Read the current worker readiness snapshots (the owner supplies status
   from its actual OpenSSH supervisors, not from an unauthenticated client).
2. Choose a ready worker with free established-flow/opening permits; alternate
   among equally available workers with an atomic per-engine cursor.
3. Reserve that worker's global shared loopback admission budget, including
   bounded opening and queue; never bypass capacity for a different engine.
4. Pin the flow to the chosen worker's SOCKS endpoint. The connection snapshot
   includes `worker_port` when a managed pool worker was selected.
5. If the selected worker becomes unavailable before connection establishment,
   fail SOCKS5 without using DIRECT. Once connected, retain the original
   worker for the flow's lifetime: **no transfer, no TCP replay**.
6. An all-unready pool responds with SOCKS failure immediately. This differs
   from the legacy single-SSH gate, which retains its bounded 30s reconnect
   grace; existing single-worker installations are unaffected.

Per-worker maximum accepted flows multiplied by worker count must be **no
greater than `aggregate_max_flows`**. The combined ceiling is a checked
configuration invariant, not a claim that adding SSH processes increases the
machine's network, descriptor, or remote-server capacity. User-selected
external clients of worker SOCKS ports can bypass FlowBridge admission and
must be excluded or independently accounted for in production acceptance.

## C ABI interface

The already-owned engine is configured with:

```c
char *fb_engine_set_upstream_pool_json(uint64_t engine_id,
                                       const char *pool_json);
```

Example pool JSON (two actual local SSH subprocesses and an **aggregate of
128 flows**, each with 64 maximum concurrent flows):

```json
{
  "primary": {"host": "127.0.0.1", "port": 1080},
  "workers": [
    {"endpoint": {"host": "127.0.0.1", "port": 1080}, "ready": true},
    {"endpoint": {"host": "127.0.0.1", "port": 1082}, "ready": true}
  ],
  "limits": {
    "max_flows": 64,
    "max_opening": 16,
    "max_queued": 32,
    "wait_timeout_ms": 500
  },
  "aggregate_max_flows": 128
}
```

Call again on watchdog readiness changes. The historic
`fb_engine_set_upstream_gate_json` restores the single-child mode. No
networking operation is performed by the pool-configuration call itself.
For the actual incremental CI pool test, the primary's preexisting
128-flow `Budget` is reused: both workers are configured with equal
128-flow limits and a declared aggregate cap of 256.

Observability is intentionally bounded and per-worker: snapshot
`managed_pool.ready_workers`, `aggregate_max_flows`, and
`workers[].{endpoint,ready,admission}` include only local proxy endpoints
and shared admission counts, not SSH private keys, server passwords or
raw OpenSSH stderr. Explicit SOCKS mode does not invent source process IDs,
AI application names or per-app fairness identity.

## Executable acceptance evidence

Rust unit/FFI tests cover duplicate/remote endpoint rejection, schema
strictness, aggregate overcommit, fail-closed all-down, atomic update,
admission pinning, and two-member selection.

The first iteration of `tests/ssh_real_integration.py` now additionally
runs `tests/real_ssh_pool_integration.py` against its disposable GitHub
Ubuntu `sshd`, using two separate, authenticated OpenSSH child PIDs:

- 16 held binary-echoed channels across both independently owned SSH
  processes, with in-memory engine connection metadata confirming which
  worker owns each channel;
- terminate **only the secondary** SSH process and mark it unready; bytes
  on established primary-worker streams must remain correct;
- 12 more connections must use the surviving worker; if both are marked
  unready, new SOCKS clients must fail with no DIRECT fallback;
- wait for the dead worker to restart under its own supervisor, prove the
  first PID stayed unchanged, re-enable it, verify a new binary flow;
- close/remove the secondary process and restore legacy single-worker gate
  for the remaining 19 real SSH lifecycle regressions.

The test report is uploaded as
`build/verification/ssh/iteration-01/real-ssh-pool.json` within
`FlowBridge-real-SSH-verification`. No private-key files are included in
this report. A green Rust unit test by itself is not proof of multiple real
OpenSSH processes; use the report's `real_openssh_processes: 2`,
distinct-child PID flag and pass/fail assertions.

## Windows native desktop integration

The separate Windows GUI beta work adds a persistent 1–4 worker count, with
the default remaining one for existing desktop settings. Windows uses actual
independent, unelevated `fb_ssh_create_json` supervisors on base SOCKS port
+ 2 × worker index. It updates per-worker readiness before selecting new
connections, keeps the complete pool under an aggregate 128-flow allowance,
and stops all SSH children after withdrawing engine routing. The compact
connection form shows ready/total workers and worker SOCKS ports. Privacy-safe
diagnostics expose each worker's admission counters without raw backend
paths, credentials, or destination names.

The elevated WFP capture helper, if separately installed/allowed on an
authorized Windows VM, receives **only** the GUI-owned SOCKS listener. All
attested live SSH executable paths are bypassed from application capture.
This native GUI work must separately pass Windows compiled/screenshot QA
before being considered integrated; Rust-only tests do not prove it.

## Remaining release and product integration gates

- Native Windows/macOS GUI control is implemented in the current integration
  candidate, including 1–4 child process creation and lifecycle, saved worker
  count, bounded metrics and supervisor-derived readiness. Exact-head CI and
  real operating-system acceptance must pass before marking it verified.
- Real Windows OpenSSH resource-exhaustion acceptance on a dedicated
  authorized VM, including handle/FD diagnostics at 251/252 channels and
  comparisons of explicitly chosen, trusted SSH binaries.
- Native WFP selected application → pooled SSH end-to-end acceptance with a
  genuinely installed/allowed driver; and signed macOS NE activation.
- Sustained soak, fair scheduling across trusted native identities, external
  clients to managed SOCKS listeners, 10k-channel manual churn, and remote
  DNS leak evidence. No automatic TCP migration or request replay is offered.

These gates remain open until tested with the appropriate operating system
and external prerequisites. Do not claim a public release from a green
simulated or hosted user-mode integration alone.

## Integration candidate — 2026-10-30

The native GUI implementations were unified on post-#28 `main` rather than
merging divergent feature branches: Windows ported its compact worker selector,
process supervision, bypass of owned OpenSSH backend executables and Win32 GUI
smoke tests; macOS ported its serial worker queue, worker-status polling,
settings persistence and explicit-SOCKS-only pool. SwiftUI now exposes a 1–4
worker selector. Transparent macOS Network Extension mode rejects 2–4 workers
until separate native multiplexing validation is complete.

Both platforms now call the *owned-supervisor* C API
`fb_engine_sync_owned_ssh_pool_json`. No GUI field can manufacture a healthy
worker or substitute a guessed local SOCKS endpoint: Rust derives the endpoint,
actual PID and readiness from registered, live supervisor handles. A missing,
duplicated or destroyed handle rejects the update atomically. The legacy
single-worker gate retains 30-second bounded reconnect grace on Windows;
multi-worker all-down fails closed. No active TCP stream is replayed or migrated.

**Acceptance remains evidence-driven:** the code must pass exact-head Rust,
Clippy, native Windows x64 GUI/installer, macOS ARM64/Intel and native DNS
workflows. Hosted user-mode builds do not constitute a Windows signed/installed
WFP-driver test, real Windows ssh.exe 251/252-channel saturation test, authorized
macOS Network Extension activation test, or long-duration per-app transparent
capture. Issue #7 remains open until actual Windows resource-load QA is run.
