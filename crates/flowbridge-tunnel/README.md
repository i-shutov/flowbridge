# Managed OpenSSH forwarding

`Supervisor` owns an OpenSSH `ssh -D` child and a restart watchdog. The native UI
uses this process directly; it does not open a terminal or invoke a command shell.
A separate FlowBridge Engine supplies the stable application-facing SOCKS entry.
Existing TCP sessions cannot survive the loss of their SSH transport; the Engine
readiness gate can wait for recovery before opening new matching proxy routes.

## Authentication and profile

Only enrolled public keys and the existing SSH agent are supported. Encrypted
keys need an agent that can unlock them. Passwords, private-key contents, host-key
acceptance overrides, and arbitrary SSH arguments are absent from the schema.
Host keys must already be enrolled in the selected known-hosts file or the
platform's default OpenSSH known-hosts files. A missing or changed host key stops
retries and reports that the fingerprint must first be verified through a trusted
channel and enrolled. Authentication rejection similarly produces an actionable
failed state.

OpenSSH runs with `-F none`, so host aliases and forwarding, shell, proxy-command,
backgrounding, and other settings from user/system SSH configuration are not
inherited. The host field must contain the actual host/IP. The managed arguments
include `-N -T -n -a -x`, a literal loopback `-D` bind, `BatchMode=yes`,
`StrictHostKeyChecking=yes`, `ExitOnForwardFailure=yes`, public-key-only
authentication, one connection attempt per child, and configured server-alive
settings. `known_hosts_file` values receive OpenSSH configuration-language quoting
in addition to argument separation; paths with spaces work. Quotes and controls
in paths are rejected. Windows known-hosts paths use forward slashes internally.

```json
{
  "host": "server.example",
  "user": "alice",
  "port": 22,
  "local_port": 1080,
  "identity_file": null,
  "known_hosts_file": null,
  "compression": false,
  "server_alive_interval_secs": 15,
  "server_alive_count_max": 3,
  "connect_timeout_secs": 10,
  "health_check_interval_ms": 1000,
  "health_check_timeout_ms": 1000,
  "startup_timeout_ms": 15000,
  "restart_initial_delay_ms": 1000,
  "restart_max_delay_ms": 30000,
  "max_restarts": 0
}
```

Only `host` and `user` need to be supplied. Other fields have the defaults above;
unknown fields are rejected. `max_restarts=0` means unlimited watchdog retries.
Backoff doubles to the configured maximum and resets after 30 seconds of stable
readiness. Explicit Start resets attempt/restart counters.

## States, health, and cleanup

Start returns after launching supervision, usually in `starting`. A `ready` state
requires both a live owned child and a valid no-authentication SOCKS5 greeting on
the configured loopback port. It verifies the local forwarding service; it does
not test a remote Internet destination. OpenSSH's encrypted server-alive messages
detect SSH transport loss. Failure moves to `reconnecting` with a bounded delay;
permanent key/authentication failures, missing OpenSSH, an occupied initial port,
or the configured retry limit move to `failed`.

Stop cancels health checks and backoff, kills only the owned child, waits to reap
it, and prevents further restarts. It never kills by process name or kills a
process merely because it holds the configured port. Health I/O uses short
socket deadlines and checks cancellation between attempts. Captured diagnostics
are bounded to 32 lines of 2 KiB, with a separate 256-entry event queue. Snapshot
also reports attempt count, cumulative restarts, PID, last error, and retry delay.

Windows children have no console window and are assigned to an owned process job
with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; failure to establish job containment
fails the launch. Normal stop/destroy reaps the child on every supported platform.
**On macOS and other Unix platforms, abrupt death of the parent process can leave
OpenSSH running.** There is no claim of parent-crash cleanup on those platforms;
`status.parent_exit_cleanup` reports `explicit_stop_only` (Windows reports
`windows_job_object`). The native application must call Stop/Destroy on normal
exit.

The OpenSSH options and their semantics follow the primary manuals:
https://man.openbsd.org/ssh and https://man.openbsd.org/ssh_config.

## Tests

Tests launch the Rust test executable as a deterministic fake child and use only
local mock SOCKS listeners. They cover readiness, owned-child exit and failed
SOCKS recovery, startup deadline, backoff/retry limits, stop during backoff, reaping,
occupied-port preservation, strict configuration, permanent authentication/host-key
errors, and bounded stderr. They use no external SSH server or credentials.
