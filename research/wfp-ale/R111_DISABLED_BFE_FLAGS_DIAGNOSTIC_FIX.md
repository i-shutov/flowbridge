# FlowBridge WFP/ALE R111 — DISABLED filters invalidate weight-only arbitration diagnostics

2026-11-11. Independent clean-room architecture research **only** in `i-shutov/flowbridge`, branch `research/windows-wfp-ale-attribution-20261107`. Not beta, PR #56, release, PacketBound/G2, G1 transfer, leak-free or no-DIRECT acceptance. No drivers, callout/filter installation, BFE writes, network tests, Windows changes, runner, services or automations.

## Immutable inputs

- Research parent `ba39c8668847139bd495ff2674e3677784a4dff8` (R110); `main` `5b5afc2feeda2195f302380e615ba003d4906e09`.
- Exact baseline `research/wfp-ale/r103/r103_readonly_arbitration_inventory.rs`, Git blob `d2880bfa829c2fbe280929ed6de8832295ede8d9`. New source is updated only at that path.
- Its only BFE operations are read-only engine open, filter snapshot enumeration, enum destroy, memory free and engine close. It cannot evaluate actual callout execution, ACL-hidden policies, continuous enforcement or packet routing.

## Concrete R110 source finding

R110 compared `FWPM_FILTER0.effectiveWeight` against all visible filters in the same ALE layer/sublayer, but neither rejected `FWPM_FILTER_FLAG_DISABLED` on its **owned reference** nor excluded that flag from **foreign arbitration candidates**. Microsoft documents `FWPM_FILTER_FLAG_DISABLED` as a flag returned by BFE for disabled filters; the fact that the filter is visible does not mean it participates in classification. The retrieved flag is `0x20` and `FWPM_FILTER_FLAG_INDEXED` is `0x40` in official SDK definitions.

**Conditional counterexample:** BFE returns an owned rule with the correct GUID, ALE layer, sublayer and original `FWP_EMPTY` weight but `flags=0x20`. R110 accepts its effective weight as a valid reference. The fixed diagnostic rejects it as `UNKNOWN` at `baseline_flags_unverified`. Likewise, a visible foreign filter with `flags=0x20` and higher numeric weight is no longer classified as a current arbitration competitor; it is counted separately in `visible_disabled`.

### Exact corrective predicate

- Owned baseline accepts `flags=0` and BFE-added `INDEXED=0x40`; any other unexpected bit is unverified. In particular `DISABLED`, `PERMIT_IF_CALLOUT_UNREGISTERED`, context/action changes and unknown bits are not promoted to a trustworthy baseline.
- Foreign disabled filter may still be visible, but is omitted from active weight comparisons. Keep a separate diagnostic count. A foreign filter with unknown flags and without `DISABLED` remains a conservative candidate if higher/equal weight.
- Missing/ACL-hidden owned filter, parse failure, over-budget enumeration, and BFE errors continue returning `UNKNOWN`. No status `SAFE` or kernel proof is introduced.
- The improvement does not solve possible invisible filters or arbitration in other sublayers. An enum snapshot is not a physical packet observation.

## Independent executed negative tests

- Python `r111_filter_flags_negative.py`: 17/17 tests PASS, including two **effective weakened-policy witnesses**, source-surface guards and absence of driver/network writes.
- Independent Node `r111_independent_oracle.mjs`: exact agreement over 1,344 modeled combinations (4 ALE rules × 2 baseline-visibility choices × 8 owned flag variants × 7 foreign flag variants × 3 relative weights).
- Previous weight-only model reports 448 candidate combinations. New predicate reports 80: **368 old candidate labels are not justified by the new filter-state preconditions.** This is a *diagnostic-model* count, not 368 real Windows failures.
- 672 states have no visible owned reference, 504 have unexpected owned flags, and 48 have disabled foreign filters with a valid visible owned reference.
- Full ordered decision stream SHA-256: `e3a04e67be3d3c52498cd253882aa457665e8551d2f7a96cefb75509df7b1997`.
- The Rust source adds a unit test, but no `rustc`/`cargo` or Windows runtime is available in this executor. Native Rust compilation, SDK ABI and BFE runtime behavior are **NOT RUN**.

## Trust boundary and decision

This is **GO only for the repaired read-only diagnostic predicate**, not a new WFP capture functionality or native acceptance. `FWPM_FILTER0.flags/effectiveWeight` are management-plane observations, not authenticated kernel-origin attribution. The original process object, PID+creation epoch+canonical EXE/AppId, V4/V6 CONNECT_REDIRECT → AUTH_CONNECT, one-time ticket, actual accepted socket/CLAIM, physical SSH egress, reauthorization, process death/PID reuse, reused 5-tuple, sibling DIRECT, UDP/DNS/QUIC and WFP/SSH loss remain separate **NO-GO** obligations.

**Next decisive experiment:** compile the exact modified Rust Git blob on a permitted Windows x86_64 machine and perform read-only BFE enumeration. Capture Windows build, Rust compiler/SDK versions, binary SHA-256, per-filter flags/weights, JSON/exit code and ACL errors. Do not install or load a kernel driver, BFE filter or callout. No runner, network configuration or Windows security setting changes.

## Official references

- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilterenum0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltercreateenumhandle0
- SDK constants: `FWPM_FILTER_FLAG_DISABLED=0x00000020`, `FWPM_FILTER_FLAG_INDEXED=0x00000040` (Microsoft Windows SDK `fwpmtypes.h`).
