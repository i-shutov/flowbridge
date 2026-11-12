# FlowBridge WFP/ALE R150 — preselection-before-birth decision

Date: 2026-11-13. **Research only** in `research/windows-wfp-ale-attribution-20261107`.
Input HEAD: `4f9c6268bcf424aed4f7a73829cd9ae40451307c` (R149).
Observed main: `5b5afc2feeda2195f302380e615ba003d4906e09`.

## New architectural trade-off (model, not a kernel fix)

R19 records all eligible OS process births in a non-evicting global 256-entry
`Ledger`; unrelated process churn or PID reuse can poison the selected route.
This R150 experiment evaluates a deliberately different **candidate**:
preconfigure one opaque selected identity, retain only matching *birth-time*
identities, bind model tickets to generation + PID + creation epoch + start key
+ process token + endpoint, and release selected-owner records after a matching
exit while invalidating outstanding tickets. No production R19 code was changed.

Two constraints were reproduced:

1. **Unrelated churn:** after 1 selected process and 1,000 unrelated
   birth/death pairs, R19's model is globally lost while the preselected-only
   candidate still has one live owner. This is conditional model behavior.
2. **Late selection:** a process born *before* identity configuration was not
   captured by a selected-only observer. Configuring a selected AppId later
   does **not** supply a birth-time kernel reference, epoch or prior ALE owner.
   Without a separate proven kernel-origin acquisition path, admitting it
   would be a retrospective PID/image join, **NO-GO**.

This creates a product decision: configure selection **before launching** the
selected executable (explicit restart for already-running targets), or retain
a global bootstrap observation architecture with its limits, or independently
prove another lawful same-classify kernel reference mechanism. A Windows API
might enable another design; R150 is NOT a claim of platform impossibility.

The candidate explicitly rejects stale tokens after process death, admits
reused PID only under a fresh synthetic epoch/generation, and does not mistake
reused 5-tuples for the same ticket. Same-basename sibling with a different
opaque ID stays outside selected scope. A selected-only capacity overflow,
live PID collision, or mismatched exit reference cannot be called release
PASS; independent WFP egress enforcement remains unproven. Importantly this
candidate does **not** fix the R148 4096-endpoint tombstone limit.

## Source pins and executable checks

Officially fetched exact R19 Git blobs, with independently checked source
markers:

- `kernel-r19/kernel/src/ledger.rs`:
  `b88c4c9237c4c118517978fc454f5048f522aa7f`.
- `kernel-r19/kernel/src/lib.rs`:
  `53f5ce6faa0f9f591974287f38ea890cafeb0dd2`.
- `kernel-r19/kernel/src/redirect.rs`:
  `a093f049d162987981a957aac90db1014bc6ff09`.

On Linux, CPython 3.13.5 normal and `-O`, and an independently authored
Node.js 22.16.0 implementation each generated **2,022 matching synthetic
trace rows**, SHA-256:

`f7584ef7aaf3840df499d36eb3c1563648c1e9323968a7f0c71ca57bb277679a`

The experiment includes unrelated churn, selected exit and PID reuse, old
ticket rejection, 5-tuple reuse, late configuration rejection, sibling image,
selected owner cap, mismatched exit reference and fail-closed collision.

Execution here used **`--model-only`**, because the exact R19 source checkout
is not mounted in the isolated Linux executor. Without that explicit flag the
Python source gate failed with nonzero exit in both normal and `-O` modes,
rather than claiming source-pin PASS. Source Git blobs were verified remotely.
**Rust compiler, Windows, native WFP and kernel code were NOT executed.**

Reproduce from the exact branch checkout:

```sh
python -B research/wfp-ale/r150/r150_preselection_negative.py
python -O -B research/wfp-ale/r150/r150_preselection_negative.py
node research/wfp-ale/r150/r150_independent.mjs
```

## Trust boundary and next deciding experiment

Microsoft's `PsSetCreateProcessNotifyRoutineEx` and
`PS_CREATE_NOTIFY_INFO` document birth/exit callbacks, process FileObject,
and qualified `FileOpenNameAvailable`; `PsGetProcessCreateTimeQuadPart`
gives an epoch for a referenced `PEPROCESS`. User-mode
`FwpmGetAppIdFromFileName0` returns an **opaque** AppId; equal lowercased
file-path bytes are not a universal identity proof. Preserve
`PsGetProcessStartKey` and reference lifetime; do not infer them later from
a numeric PID. Documentation:

- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_ps_create_notify_info
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetprocesscreatetimequadpart
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0

Required but unproven physical chain:
referenced process/FileObject + PID/epoch/start-key/canonical EXE
→ actual `ALE_CONNECT_REDIRECT_V4/V6` and `ALE_AUTH_CONNECT_V4/V6`,
original/current AppId and filter hit → `FWPS_CONNECT_REQUEST0`
redirect context/records → actual accepted socket with
`SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS` →
one-shot CLAIM → `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS`
on physical outbound SSH socket *before* connect → independently enforced
DIRECT blocking across BFE, broker, driver and SSH loss.

**Next allowed experiment:** source-gated R149+R150 execution on exact checkout,
plus unprivileged read-only Windows comparison of
`FwpmGetAppIdFromFileName0` result and eligible selected-process image
identity. No kernel experiment or WFP filter change permitted without owner
authorization and rescue/rollback gates.

Remaining **NO-GO**: process origin, ALE reauthorization, IPv4/IPv6
compartments, PID/endpoint/5-tuple reuse, sibling DIRECT, DNS/UDP/QUIC,
WFP/BFE/SSH continuity, PacketBound/G2, leak-free. No change to main, beta,
PR #56, driver, filters, services, firewall, security, network, runners,
automations or other repositories. No historical G1 promotion.
