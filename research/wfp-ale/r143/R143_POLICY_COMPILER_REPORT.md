# FlowBridge R143 — Deterministic non-installable policy blueprint compiler

Date: 2026-11-12. Project: `i-shutov/flowbridge`.
Only branch: `research/windows-wfp-ale-attribution-20261107`.
Baseline: `bc75fc1691986715a5f87d3e67c8bb501483eb3b` (includes R142 descriptor hardening). `main` remained `5b5afc2feeda2195f302380e615ba003d4906e09` at preflight.

## Decision

**R143 pure offline compiler PASS; release NO-GO.** This is explicitly not an installer,
a Windows service, a WFP filter policy, a signed driver, a firewall rule or a network
interception proof. Do not promote simulated states to physical observations.

## Input and authenticity

The compiler requires the exact R141 design-only descriptor document, pinned by
SHA256 `28c86cdaabeae107ca9ddfb95097622d940eee2ea454cf04edb781d52bb3c289`
and Git blob `b9c1e5f2c7ffed691d613fa2f8927d7fd8582fc6`.
The document is already in the repository at
`research/wfp-ale/r141/R141_DESIGN_ONLY_DESCRIPTORS.json`.
R142 separately hardened `r141_descriptors.py` (Git blob
`af2d14c2d6c7738d3ad80cc776a0dd7479056a1e`) against scope swaps and
Python `-O` validator bypass. R143 adds a separate strict structural validator
and relies on the immutable R141 JSON, so it neither reverts nor edits R142.

Inputs with duplicate keys, excess size, BOM, NaN, reordered/swapped WFP layer
identity, protocol swap, raw AppId, GUID, unexplained evidence promotion, added
keys, changed native-proof flags or incorrect boolean types are rejected.
The comparison is recursive and type-aware: Python `False == 0` never grants a
schema bypass. A mutation of the pinned source JSON itself fails its SHA check.

## Output schema

`R143_BLUEPRINT.json` is an immutable canonical *design-only* compilation:

- Eight symbolic dependency nodes: provider, sublayer, IPv4/IPv6 TCP callouts,
  and four IPv4/IPv6 TCP/UDP selected-original-AppId filter candidates.
- Forward dependency ordering, plus a reverse **design** rollback ordering.
  Neither sequence is executable or contains SDK API commands.
- No real GUIDs, raw selected AppId, real filter flags, provider service name,
  WFP mutation instructions, installer, signer, driver, registry or network call.
- Explicit `PERMIT_IF_CALLOUT_UNREGISTERED=false` everywhere applicable.
- Distinct `SEPARATE_BOOT_DESIGN` candidate, never combined with persistent flag.
- `native_wfp_executed=false`, `no_direct_proved=false`, `release_accepted=false`
  and `bfe_outage_continuity_proved=false` are immutable acceptance boundaries.
- Self-hashed canonical JSON. The blueprint validator separately checks the
  allowed node graph, action, protocol, family, identity, source and state fields,
  even if a modified JSON's fingerprint was recomputed.

### State machine (strictly simulated)

`BLOCKING_BASELINE → RECOVERY → VERIFIED_REDIRECT_READY → REVOKING` describes
only proposed design phases. The name **VERIFIED_REDIRECT_READY is simulation-only**;
it never asserts a real WFP permission or a blocked packet. A transition from
RECOVERY to that synthetic phase requires **all 11 illustrative observation bits**.

On `BFE_LOSS`, every phase moves to `RECOVERY` with
`continuity_unknown=true` and `actual_enforcement_proved=false`. On broker,
SSH, driver, policy-object, action-rights or reauthorization provenance loss,
the conceptual model enters REVOKING. `REVOKE_COMPLETE` is *not* evidence of a
protective baseline; the model refuses to claim BLOCKING_BASELINE until an
independent baseline observation is explicitly supplied, and even then its
result carries `actual_enforcement_proved=false` because all inputs are synthetic.

No setting of the eleven booleans, nor any possible transition, yields
`release_accepted=true`. No use of a late PID/tuple, selected-original AppId alone,
localhost exception, persisted object readback or unregistered-callout fallback is
accepted as real socket-binding authority.

## Actual local acceptance

- Python `unittest`: **71/71 PASS** (normal execution, full log captured).
- Python `-O` negative control rejects a forged action despite disabled asserts.
- Independent Node oracle agrees with Python on **2048/2048** bit combinations.
  Only one all-ones bitmask is a *simulated* ready candidate; native acceptance=0.
- Deterministic blueprint SHA256:
  `f1f08d056e88010fee2cf9bc4f47ea6e3dfc2af22231117a98bffda62f605ebb`.
- Independent 2048-row matrix SHA256:
  `36217fa663c9e2454ade494bae3554e81dbf55310added36d8ec3f1c25c81e54`.
- This local executor **did not execute Windows WFP APIs, drivers, sockets or BFE**.
  No native Windows results or external traffic observations are claimed.

## Remaining release blockers

1. R140 ACTION_WRITE guard source update received an owner-reported static
   Windows PASS; it has **not** been executed in a native WFP classify callback.
2. Dynamic R19 policy still does not supply durable runtime enforcement. A
   persistent stored object is not proof of activity or continuity on BFE loss.
3. Exact native ALE original process identity, process creation epoch,
   original/current AppId, redirected *accepted socket* WFP records/context,
   one-use kernel CLAIM and original-record-tagged SSH must be tested end-to-end.
4. Arbitration and non-hard-block exceptions must not open sibling DIRECT or
   break legitimate redirect. IPv4/IPv6, UDP/QUIC, DNS, reauthorization,
   PID/5-tuple reuse and BFE/SSH failure require independent packet evidence.
5. Before any actual policy installation: signed driver, disposable VM,
   separate console/VNC rescue, tested rollback and explicit owner authorization.

## Next permitted block

R144: independent adversarial review of the blueprint output and a **read-only**
Windows metadata/preflight inventory, not filter installation. Transforming this
JSON to `FWPM_FILTER0` or using it to change any WFP object is prohibited by design.

## Official documentation

- WFP object lifetime: https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
- WFP boot→BFE handoff: https://learn.microsoft.com/en-us/windows/win32/fwp/basic-operation
- Filter persistent/boot flags: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
- ALE reauthorization: https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- WFP filter arbitration: https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
