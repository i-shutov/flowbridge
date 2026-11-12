# FlowBridge R144 — R143 rehashed nested-boolean acceptance (offline validator)

Date: 2026-11-12. Research branch ONLY: `research/windows-wfp-ale-attribution-20261107`.
Baseline research SHA: `cc2ae5940076de8ddb27a3ad8d3c09046ba30bc3`; preflight main: `5b5afc2feeda2195f302380e615ba003d4906e09`.

## Confirmed falsification

The R143 blueprint validator checked `boot_handoff` and `state_machine` using
Python dictionary `==`. In Python, `False == 0` and `True == 1`;
therefore a JSON integer could silently replace a proof-related JSON boolean
while preserving dictionary equality. The self-hash only certifies the modified
document's bytes; an adversary can recompute it. The original R143 source
validation for the pinned R141 input is NOT the vulnerable code path: the
vulnerability concerns later independently supplied compiled blueprint objects.

Exactly three rehashed examples evade the old nested-object comparison:
- `boot_handoff.persistent_flag_combined: false -> 0`
- `state_machine.ready_observations_proven: false -> 0`
- `state_machine.state_names_are_model_only: true -> 1`

This is a deterministic JSON contract-type bypass, NOT proof of installed
filters, altered WFP classification, packet leakage or fail-closed continuity.

## Fix and verification

In `r143/r143_policy_compiler.py`, replace both nested equality checks by the
existing recursive `same_typed()` helper. Add three exact mutation/rehashed
tests to `r143/test_r143.py`; add `r144_compiled_blueprint_negative.py` (eight
mutants using the actual R143 compiled blueprint) and `r144_independent_oracle.mjs`
(independent semantic oracle). Correct normal behavior and default blueprint
digest should remain unchanged: only malformed later inputs are rejected.

Independent local OFFLINE reproductions prior to publication:
- Python 3.13: 8/8 cases, old comparison false accepts 3, strict false accepts 0.
- Node 22: 8/8 cases, same vector results.
- The new R144 repo-backed Python suite, changed R143 74-test suite and Windows
  PowerShell/native tests require execution on an exact checkout for acceptance;
  do not count them as run based solely on syntactic review.

## WFP and trust boundary

Microsoft's official layer-condition matrix lists
`FWPM_CONDITION_ALE_ORIGINAL_APP_ID` at `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4/V6`
and `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` from Windows 8 onward. This validates
a layer-condition design possibility, NOT an installed, effective or arbitrated
policy. Reference:
https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer

Other official contracts to retain:
- Dynamic/persistent WFP object lifetime: https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
- ALE reauthorization: https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- Callout absent, terminating action: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscalloutregister0
- WFP filter arbitration: https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration

Still NO-GO: kernel-origin process/creation epoch/canonical EXE provenance;
AUTH_CONNECT/CONNECT_REDIRECT association; redirect context/records to the
accepted socket, one-use CLAIM to actual SSH socket; original/current AppId
with PID and 5-tuple reuse; IPv4/IPv6 compartments; reauthorization, sibling
DIRECT, DNS/UDP/QUIC, WFP/BFE/SSH loss. No PacketBound/G2 PASS or leak-free claim.

## Next discriminating experiment

On exact research SHA checkout run:
`python -B -m unittest discover -s research/wfp-ale/r143 -p 'test_r143.py' -v`,
`python -B research/wfp-ale/r144/r144_compiled_blueprint_negative.py`,
`node research/wfp-ale/r144/r144_independent_oracle.mjs`,
and repeat the Python suite under `python -O`. Save stdout/stderr,
exit codes and SHA-256 of source and results. No driver, filter, service,
network change, Windows beta integration, PR #56 or main operations.
