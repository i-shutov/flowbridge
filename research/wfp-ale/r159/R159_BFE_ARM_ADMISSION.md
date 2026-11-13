# R159 — source-level closure of BFE/AppId/ARM sequencing mismatch

Date: 2026-11-13. Repo: i-shutov/flowbridge. Exclusive research branch:
research/windows-wfp-ale-attribution-20261107. Parent at authoring:
071599f10bc4299b9313f2040e3b84125c4cb42b (R158).

## Actual implementation changes

1. kernel-r19/policy_plan.rs: new Plan::arm_matches compares the full canonical
   WFP AppId bytes INCLUDING trailing UTF-16 NUL AND both listener ports.
   Unit test checks equal case, mismatched target, swapped ports, and truncated blob.
2. kernel-r19/broker_windows.rs: Device::arm now accepts &Plan and refuses
   mismatch before emitting any ARM ioctl. The ARM wire still carries the
   kernel-trimmed AppId bytes; the BFE plan keeps its full blob.
3. kernel-r19/broker.rs: approved laboratory policy activation (including
   four-family/type filter readback via policy_plan::install) precedes ARM.
   A failed activation cannot mark the kernel route armed through this broker.
   The unprotected non-policy research path still permits ARM and MUST NOT be
   described as transparent no-DIRECT mode.

R158 documented a conditional BFE filter A / ARM target B mismatch, not a
witnessed real process misconfiguration. Prior normal broker construction
already used the same SelectedImage. This patch makes that dependency
explicit and prevents accidental internal divergence or a permissive future
caller, but CANNOT bind an arbitrary privileged device IOCTL to actual BFE
filter state in kernel or authenticate original ALE packet owners.

## Critical negative and lifetime boundaries

- Window between BFE filter installation and ARM can cause selected traffic
  to be BLOCKED by unconfigured R19 callout. That behavior is proposed, not
  natively measured, and must be accepted before a signed-driver trial.
- R19 policy_windows.rs retains FWPM_SESSION_FLAG_DYNAMIC and flags=0.
  If the owning process/session dies, those filters vanish. Neither source
  ordering nor user-mode equality creates a persistent OS kill switch.
- Actual effective arbitration, action rights, native kernel classify,
  selected UDP/QUIC/DNS, original-vs-current AppId, IP compartments,
  kernel process epoch/endpoint, accepted socket WFP records/CLAIM/SSH,
  process-death race, 5-tuple/PID ABA, BFE/restart loss remain NOT ACCEPTED.
- A process with separate privileged device access can submit ARM without
  going through the typed broker. This source gate is not a kernel ACL proof.
- No WFP filter, driver, service, network adapter, firewall, DNS, Windows
  security or CI runner was installed or modified. No production release merge.

## Reproducible test

On an exact research checkout:

    python3 -B research/wfp-ale/r159/r159_source_gate.py
    python3 -B research/wfp-ale/r159/r159_source_gate.py --source-gate
    rustc --edition=2021 --test research/wfp-ale/kernel-r19/policy_plan.rs -o r159-policy-tests
    ./r159-policy-tests

The Python gate checks exact source Git blobs, readback-before-ARM source
order, selected AppId/port binding, and rejects source/decision mutants.
The pure Rust test includes the new arm_match negative. Native Rust/Windows
execution NOT RUN in this executor; do not equate source gates with WFP PASS.

## Next decisive native work (separate permission required)

Run on disposable signed-driver Windows 10 and 11 with a preverified
independent VNC/SYSTEM console, snapshot and rollback. Instrument effective
rule hits/rights and BFE readbacks before and after ARM. Verify mismatching
AppId cannot produce DIRECT or a false protected success and legitimate
selected v4/v6 TCP still reaches accepted-socket redirect records /
single-use CLAIM / SSH. Simulate broker, BFE and SSH failure under external
packet observation, plus UDP/QUIC/DNS and nonselected sibling controls.

Overall status: SOURCE HARDENED / NATIVE NO-GO / RELEASE NO-GO.

Primary references:
https://learn.microsoft.com/en-us/windows/win32/fwp/basic-operation
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
