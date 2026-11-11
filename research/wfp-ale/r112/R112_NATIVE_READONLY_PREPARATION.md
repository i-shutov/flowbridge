# R112: read-only native Windows build readiness and 32-bit action validation

Scope: `i-shutov/flowbridge` ONLY, branch
`research/windows-wfp-ale-attribution-20261107`. This file does not authorize
WFP filters, callout/driver loading, service or firewall changes, CI/runner,
VNC/SYSTEM rescue, any network or paid operation. No code in this checkpoint
performs such actions.

## New negative result: an UNPUBLISHED diagnostic draft was incorrect

The prior, **unpublished** R112 draft tested `FWPM_FILTER0.action.type == 3`
(AUTH) and `== 5` (REDIRECT). Those are only the low action ordinals.
Full official `FWP_ACTION_TYPE` values include flags:

* `FWP_ACTION_CALLOUT_TERMINATING = 0x4000 | 0x1000 | 3 = 0x5003`
* `FWP_ACTION_CALLOUT_UNKNOWN = 0x4000 | 5 = 0x4005`

An uncorrected draft would fail to recognize the valid R19 policy on
all four ALE layers. Its prior synthetic tests used the same incorrect
3/5 assumption and therefore failed to detect it. The corrected inspector
compares the exact 32-bit `action.kind` and intended callout GUID,
condition field keys, condition value types and TCP6, and cross-family
AppId equivalence before assigning an owned baseline. Invalid/unknown
cases return `UNKNOWN`; nothing can return `SAFE`, packet proof or G2 PASS.

These action constants match **existing R99** checked-in Rust source
(`ACTION_TYPES=[0x5003,0x5003,0x4005,0x4005]`), the R19 installation's
`FWP_ACTION_CALLOUT_{TERMINATING,UNKNOWN}` from `policy_windows.rs`, and
Microsoft's action enum documentation.

## Offline reproducibility

* `python3 r112_action_flags_negative.py`: 9 Python unit tests and a
  full 33,696-case deterministic policy-shape matrix.
* `node r112_action_flags_independent.mjs`: separately implemented Node
  oracle over the same explicit integer constants, with the complete
  decision stream hashed and compared to the Python matrix.
* The original unpublished R112 model had 6,240 cases but abstracted
  `action` as a 0..4 code, so it could not detect the 3/5 bug.
* `R112_WINDOWS_NATIVE_READONLY_CHECK.ps1` is a prepared, **not executed**
  Windows PowerShell 5.1 script. It uses no toolchain installation and
  no remote calls. It fails if `rustc.exe` or an x64 Windows host is absent.
  Default behavior only asks rustc to typecheck the exact source and emit
  metadata; `-RunUnitTests` links/runs synthetic Rust tests;
  `-RunReadOnlyBfe -RunUnitTests` separately opts in to a read-only BFE
  management snapshot. No positive result is kernel-origin proof.

The current Linux executor has no Rust toolchain and no Windows execution
capability. Native compilation, Rust unit test execution, Windows SDK ABI
verification and BFE API execution are therefore **NOT TESTED**. A test
matrix or PowerShell script must never be reported as Windows PASS.

## Required on-host evidence before accepting Windows checks

Windows edition/build; source Git blob SHA-1; source SHA-256; rustc version,
Windows target, Windows SDK header path (if installed); metadata compile exit
code; synthetic test executable SHA-256 and log; optional BFE read-only JSONL,
exit code, inspector executable SHA-256; explicit statement that snapshots
cannot prove `classifyFn` invocation, live traffic, no-DIRECT or fail-closed
policy between samples.

## Official references

- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_action0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_condition0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilterenum0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltercreateenumhandle0

## Kernel-origin trust chain / NO-GO

`EPROCESS` origin reference + kernel creation epoch/start key and canonical
image-section file identity -> ALE CONNECT_REDIRECT and AUTH_CONNECT for
IPv4/IPv6 -> unforgeable flow/ticket binding -> same accepted SOCKET and
WinSock redirect records -> CLAIM -> attested SSH channel / revocation.

Unresolved: process death/PID reuse, repeated 5-tuple, sibling DIRECT,
DNS/UDP/QUIC, explicit local binds, BFE/driver/SSH loss, reauthorization,
and runtime callout arbitration. These require separate authorized native
proof. No user-mode correlated PID/timestamp/5-tuple can substitute.

**No main/beta/release/PR56/runner/services/networks/security/automations
changes are part of this work.**
