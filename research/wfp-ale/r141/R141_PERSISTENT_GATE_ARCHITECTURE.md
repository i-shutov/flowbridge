# FlowBridge R141 — persistent WFP enforcement: architecture and deployment preflight (NOT an installer)

**Date:** 2026-11-12. **Scope:** `i-shutov/flowbridge`, branch `research/windows-wfp-ale-attribution-20261107`. **Status: RELEASE NO-GO.** No BFE mutation, driver load, sockets, firewall settings, service changes, runners or unrelated branches.

## Accepted R140 observation and source pins

The owner provided the Windows PowerShell 5.1 console output: syntax PASS, five immutable Git-source blobs checked, `R140_STATIC_ACTION_GUARD_PASS_RELEASE_NO_GO`, diagnostic exit `3`. The R140 harness documents this as a conditional **user-mode Rust test/source** PASS and remaining RELEASE NO-GO; the original `R140_EVIDENCE.json` and `evidence-only.zip` have **not** been uploaded to this conversation. This report records owner-reported evidence, not an independently rehashed executable or native callout exercise.

Relevant unchanged source:

- `research/wfp-ale/kernel-r19/policy_windows.rs` — Git blob `acf60334320d970f58af3349ee75fbaa59826602`: `FWPM_SESSION_FLAG_DYNAMIC`, filter `flags=0`, two exact-AppId TCP `ALE_CONNECT_REDIRECT` callouts and two `ALE_AUTH_CONNECT` callouts for v4/v6, no persistent baseline; no IPv4/IPv6 UDP enforcement.
- `research/wfp-ale/kernel-r19/policy_plan.rs` — Git blob `c8ab344551f1adfc20fd0019c4606cf3ca3c81c4`: transactional install/readback around dynamic-scoped rules.
- `kernel/src/action_rights.rs` — Git blob `c6a4a107255cc5ecca82266481935c93467a01ed`, source-contract correction in R140, **not native driver proven**.

## Decisive architectural distinction

**Stored object ≠ enabled object ≠ effective, continuous enforcement.** A persistent filter can be stored across the close of its management session and across BFE restart; it can still be disabled by provider startup state, subject to arbitration or not executing in some service-loss interval. Enumerating by GUID proves presence in a management store only. For the protected **selected executable**, no no-DIRECT result can be inferred from readback alone.

Microsoft distinguishes:

| Lifetime | Session owner exits | BFE stops after initial startup | Before first BFE initialization |
| --- | --- | --- | --- |
| Dynamic | Deleted | Not retained | Not active |
| Static | Can remain until BFE stops | Gone | Not active |
| Persistent | Stored | Stored; **effective enforcement while BFE down NOT established** | Not yet active |
| Boot-time | Not dependent on user session before BFE | Does **not** automatically reappear for an arbitrary runtime BFE crash | Initial TCP/IP boot filter |

A filter cannot combine BOOTTIME and PERSISTENT in the same FWPM_FILTER0 flags. A documented boot→first-BFE handoff of boot-time and persistent policy is *not* proof of arbitrary BFE runtime stop/restart continuity.

Microsoft's `FWPM_PROVIDER_FLAG_DISABLED` describes filters disabled at BFE startup if the provider lacks a serviceName or the service is not automatic. Callout registration is another distinct state: by default, a filter referencing a callout added but **not** registered is treated as BLOCK; `FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED` explicitly changes that to PERMIT. **The default BLOCK is conditional on the filter actually being active and matching the flow.** Never use that default as an end-to-end guarantee of no DIRECT.

## Security trap: hard persistent BLOCK can break the intended redirect

The current R19 AUTH filter matches `FWPM_CONDITION_ALE_ORIGINAL_APP_ID`. According to Microsoft this retains the originating app across redirects. A naive **persistent hard BLOCK** for that same original AppId can still match an authorized redirected flow, causing legitimate selected traffic to fail. It is not enough to create an allow rule for `127.0.0.1:port`, a PID, an EXE basename or an authenticated local SOCKS endpoint. A WFP filter from an unrelated provider may also change arbitration. No exception using such coarse attributes is approved.

A viable design must first prove a **scoped, kernel-origin-authenticated exception** on the same classify request/redirect state, with both original and current AppId interpreted correctly and the correct `FWPS_RIGHT_ACTION_WRITE` behavior. It must preserve the original process epoch/start key, accepted-socket-bound WFP redirect context/records, terminal CLAIM, and outbound SSH socket ownership. Only the native kernel path can establish those facts; this Python/Node blueprint cannot.

## R141 output: a gate for proposals, never an installer

`r141_preflight.py` exposes a typed design dossier with 21 blockers. It rejects:

- Dynamic or static-only policy for the target lifetime; partial persistence of only the filter without provider/sublayer/callout lifecycle.
- Missing provider auto-start/activation evidence, or `PERMIT_IF_CALLOUT_UNREGISTERED` on a security-critical block path.
- Missing selected IPv4/IPv6 TCP and UDP scope, indirect DNS resolver attribution, or original/curr AppId separation.
- Any hard selected-app BLOCK with no native-proven exception, or any path/PID/localhost/port-only exception.
- Missing arbitration review, runtime BFE stop/restart, boot transition, independent rescue/rollback or accepted socket→SSH test plans.

Even with a fully populated *proposal* dossier, it returns only `DOSSIER_READY_FOR_INDEPENDENT_LAB_REVIEW_ONLY`. It cannot return release PASS, claim OS enforcement, or write a WFP filter. No self-reported boolean in a dossier substitutes for signed, independently inspected native evidence.

`r141_lifetime_oracle.py` and `r141_lifetime_independent.mjs` independently test **192** illustrative lifetime/status combinations. Every row explicitly ends with `effective_proof=0`. Callout-registration flags are for a **callout-type filter candidate**; they are not applicable to a static FWP_ACTION_BLOCK. These cases are documentation-based design constraints, not observed network events or probabilities. A state `configured` means *plausibly configured for inspection*, not definitely enabled or blocking traffic.

## Release-oriented plan and hard gates

1. **Architecture review (R141):** freeze original/current AppId semantics at ALE_AUTH_CONNECT for IPv4/IPv6, define persistent provider/sublayer/callout/filter GUID ownership, provider serviceName/auto-start behavior, hard/soft arbitration and callout-unregistered fallback. Describe a provable exception that does not rely on client-provided context or a late TCP-table PID join. Review against `FWPM_FILTER0`/`FWPM_PROVIDER0`/WFP arbitration docs.
2. **Offline compiler and state-machine implementation (next):** a non-mutating descriptor builder with explicit `owner` and rollback metadata, no global wildcard and no `PERMIT_IF_CALLOUT_UNREGISTERED`. Track phases `BLOCKING_BASELINE → VERIFIED_REDIRECT_READY → REVOKING → RECOVERY`. Output descriptors only; no Add/Delete API yet. Couple this with a threat model for app-origin DNS from SYSTEM and UDP/QUIC.
3. **Disposable signed-driver lab, only after separate authorization:** independent administrative console, snapshot, VNC/SYSTEM rescue and tested rollback. Install only own provider/sublayer/callouts/filters with transactions; verify all persistent flags, provider service state, registration and filter readback. Prove actual hit/count/classify with exact selected-executable traffic; readback alone is insufficient.
4. **Native failure matrix:** broker crash, service kill, BFE process termination/restart, reboot and boot→BFE transition, driver unregister, SSH loss, selected and non-selected same-basename siblings, IPv4/IPv6 TCP and UDP/QUIC, system DNS, reused PID and reused 5-tuple, other firewalls/filters and uninstallation. Capture external observer/pkt trace before declaring no DIRECT. Failed or not run = NO-GO.
5. **Acceptance/release:** only with physical packet/connection evidence, reversible deployment, independent review and no false positive on authorized SSH redirect. No old G1 result automatically transfers to G2.

**Explicitly prohibited here:** converting existing dynamic session to persistent in place, adding broad hard BLOCK or PERMIT on your Windows host, stopping BFE, installing drivers, changing Windows security/Defender/Firewall, breaking SSH/RDP access, or inventing successful native evidence. No network experiment was performed in R141.

### Official references

- WFP object lifetime: https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
- Persistent/boot flags and unregistered-callout policy: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
- Provider disabled/serviceName: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_provider0
- Filter arbitration: https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration
- WFP boot→BFE transition: https://learn.microsoft.com/en-us/windows/win32/fwp/basic-operation
- Original AppId condition: https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-
- ALE reauthorization: https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
