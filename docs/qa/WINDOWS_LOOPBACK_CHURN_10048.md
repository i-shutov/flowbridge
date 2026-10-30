# Windows loopback 10048 — strict hosted SSH capacity probe

## Observed evidence (30 October 2026)

[Real Windows OpenSSH run 41027933355](https://github.com/i-shutov/flowbridge/actions/runs/41027933355)
held **128 real authenticated OpenSSH channels** with correct bytes, refused
**1152** excess requests through the admission budget, and drained all 128.
During the mandatory **10,000** connection churn, the probe failed after
**636** successful cycles, with `WinError 10048` from the test client's
`socket.create_connection(('127.0.0.1', ingress_port))`. The concurrent
hosted Windows snapshot reported **3922 TIME_WAIT** entries. The selected
system OpenSSH process was still `ready`, had its original PID, and a
separate direct echo probe passed. This is **not evidence** that the user's
Windows OpenSSH internal 251–252-channel failure has been reproduced or fixed.

Windows Winsock labels 10048 `WSAEADDRINUSE`: local address/port already
used, potentially while a socket is closing. Relevant vendor documentation:
[Microsoft Windows sockets codes](https://learn.microsoft.com/windows/win32/winsock/windows-sockets-error-codes-2)
and [TCP port exhaustion troubleshooting](https://learn.microsoft.com/troubleshoot/windows-client/networking/tcp-ip-port-exhaustion-troubleshooting).

## Precise repair to the *test client*, not the transport

- The disposable Windows loopback connector now explicitly binds a fresh
  socket to `127.0.0.1:0`, then connects to the existing **same** engine
  ingress port. No extra SSH child, proxy listener or target is introduced.
- Only `WSAEADDRINUSE=10048` is retried, at most **six** times with bounded
  delays. Each failed socket is closed. Timeouts, resets, SSH failures, SOCKS
  rejections and invalid responses remain immediate failures.
- The audited JSON adds `loopback_socket_dialer`: logical TCP connects,
  address-collision retries, and exhausted retries. The entire churn rejects
  more than ~1% repeated address collisions, and still requires **all 10,000
  actual byte-verified SSH sessions** with half-close; one failed channel
  fails the CI job.
- Independent negative unit tests assert no retry on a non-10048 failure,
  fail-after-budget, cleanup and normal non-Windows behaviour. These run
  **before** the Windows integration acceptance.

## Follow-up: 10k passed; bare OpenSSH ceiling is observable

[Exact-head follow-up run 41034072928](https://github.com/i-shutov/flowbridge/actions/runs/41034072928)
proved that the explicit-bind test correction works: **128 actual concurrent
authenticated channels**, **1,152 overload rejections**, **10,000/10,000**
binary payload and half-close SSH churn sessions, **0 Winsock 10048 retries**,
zero failed churn, and a functioning **four-process owned SSH pool**.
Selected system client `OpenSSH_for_Windows_9.5p2` retained its PID.
Its OS HANDLE count changed **166 → 292 held → 162 after recovery**, without
using OS HANDLE counts to infer internal OpenSSH FD slots. The entire workflow
remained **red** for a different, final *bare backend* probe.

That final independent raw-SSH test requested tiers up to 512 and
`min_held=128`. With an isolated external SSH process (no FlowBridge
admission gate), one **new** SOCKS CONNECT candidate reset before its initial
echo, and its subprocess aborted. The server log reported
`pipe(notify_pipe) failed Too many open files` and
`wait_until_can_do_something: ppoll: Not enough space` near the failure.
These are server-side resource messages in the **isolated fixture**. They
suggest an authentic Windows OpenSSH descriptor/resource limitation but
do **not** measure the Windows system client's internal FD table or establish
an exact 251/252 limit.

The follow-up probe logic now records new-candidate CONNECT/initial-echo
transport failure as `failed_new` and its stage/type, closes that candidate,
then continues to assert binary integrity for **all existing** verified
streams. A failure before the **minimum 128** still fails. Any loss of an
established stream, byte corruption, child death, failure of recovery
connections, or leak still fails the entire acceptance. Three negative
regressions guard these distinctions.

**No performance waiver:** a successful capacity probe describes observed
safe baseline and observed saturation, not a claim that 512 simultaneous
channels are safe. A 128-per-OpenSSH managed FlowBridge admission limit remains
the reviewed conservative policy until dedicated Win10/11 evidence says
otherwise.

## Safety and release boundaries

No modification of Windows ephemeral-port range, `TcpTimedWaitDelay`, DNS,
system services, firewall, signing policy, SSH host-key checking or production
socket code. No `SO_REUSEADDR` socket bypass. This change is a test harness
correction, **not** a throughput optimization and **not** a waiver for
Windows load acceptance. The hosted Windows Server 2025 exercise, even when
green, does not substitute for real Windows 10/11 WFP+SSH, process identity,
native DNS leakage, dedicated DPI/GUI, or signed macOS Network Extension
release evidence. See [Issue #7](https://github.com/i-shutov/flowbridge/issues/7).
