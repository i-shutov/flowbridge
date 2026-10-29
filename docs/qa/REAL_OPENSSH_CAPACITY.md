# FlowBridge — live OpenSSH capacity and overload acceptance

2026-10-29. Applies to the **real local OpenSSH process** authenticated to a
disposable `sshd` on a GitHub-hosted Linux runner, not a mock SOCKS endpoint.
SSH host/client keys are ephemeral, stored in a temporary directory and **not
uploaded**; no external DNS, internet destination or user server is used.

## Why this test

Issue [#7](https://github.com/i-shutov/flowbridge/issues/7) recorded a genuine
Windows OpenSSH `ssh -D` failure near 251–252 channels with
`accept: Too many open files`. The observed channel count is not an OS FD
measurement. The previously existing shared admission tests exercised 4 held
mock-SOCKS connections and bursts of 64/128/192/256/512 synthetic attempts.
This addition targets a **live SSH transport** with comparable pressure and
bounded, honest diagnostics; it is not a claim to have reproduced a Windows FD
limit.

## Default CI acceptance

One of the 20 independent disposable-sshd integration iterations invokes
`tests/real_ssh_capacity.py` *after* actual key authentication, strict
`known_hosts` enrollment, native ABI streaming and remote DNS-query tests:

1. Configure the exact same **per-SSH process budget** across both the
   explicit SOCKS runtime and native ABI sessions:
   `max_flows=128`, `max_opening=16`, `max_queued=64`,
   `wait_timeout_ms=500`. The default budget is a **conservative policy**,
   not a discovered backend descriptor limit.
2. Open and **hold 128 real OpenSSH dynamic-forward channels** to the isolated
   local TCP echo service. The client passes `localhost` as SOCKS
   `ATYP=DOMAINNAME`; FlowBridge does not resolve the destination locally.
   Assert 128 actual occupied admission permits and zero ongoing opens.
3. While retaining these channels, send an additional 64, 128, 192, 256 and
   512 new requests in independent concurrent batches. All new requests
   must fail with SOCKS5 general failure, not DIRECT. Preserve the original
   OpenSSH PID and the 128 established streams; exchange binary payload on
   representative previously established channels after every burst.
4. Confirm rejection counters, max queued/opening limits and stable SSH PID.
   Gracefully half-close all 128 held channels and require every admission
   semaphore to return to zero.
5. Open/echo/half-close another 200 **fresh authenticated SSH channels** in
   bounded 32-way concurrency. Assert no reconnection, and zero active,
   opening, and queued permits afterward.
6. Continue the existing real SSH regression: kill the owned child, verify
   watchdog restart and new/pending connections; explicit Stop must prevent
   restart, and an unenrolled host key must fail permanently.

Evidence appears under
`build/verification/ssh/iteration-01/real-ssh-capacity.json`, inside the
`FlowBridge-real-SSH-verification` workflow artifact.
The report records commit, backend **version only** (local absolute path is
not disclosed), original process PID, attempted/rejected counts, total
elapsed time and peak/final admission counters. Do not upload private SSH keys
or full `known_hosts` in test artifacts.

## Extended 10,000-channel churn

The same workflow supports manual **Run workflow → ssh_churn=10000** for
a more expensive one-off test of 10,000 **sequentially recyclable** channels
with at most 32 simultaneous opens. This exercises churn, not 10,000
simultaneous SSH channels. The default pull-request CI runs 200 churn requests
to keep feedback fast. The Python fixture refuses `ssh_churn > 10000`.

The test remains limited to the disposable GitHub-hosted Ubuntu runner. It
does not test Windows `ssh.exe`'s `MAX_FDS` implementation, competing external
clients using `ssh -D`, independent worker pools, fairness across trusted
process identities, 24-hour process memory trends, Windows handle tables,
system DNS leaks, or WFP/Apple NE. Those remain separate acceptance gates.

## Windows-specific remaining required evidence

Run a separately authorized, isolated **native Windows OpenSSH** load at
64/128/192/256/512 total attempted connections, collect exact `ssh.exe`
path and `-V` version, observe channel counts and
`accept: Too many open files`, compare Git-for-Windows OpenSSH if explicitly
selected, and measure **actual OS process socket/handle usage** without
equating it to the internal FD table. If the chosen backend has a lower
working ceiling, reduce its per-worker cap with reserve; do not blindly
change OS or server limits. Repeat Stop/restart/recovery and confirm that
all old TCP sessions are treated as interrupted, never replayed.
