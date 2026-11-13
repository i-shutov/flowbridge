# R162 — ALE reauthorization of an admitted selected flow is not continuity-safe

Date: 2026-11-13. Independent R&D only, not beta/PR #56. Parent: `80093a73174b400bedb58f8d75cb7596ab7a918c`; main read-only: `5b5afc2feeda2195f302380e615ba003d4906e09`.

## Conditional source-level NO-GO

R19 `kernel/src/redirect.rs::auth_check` explicitly rejects `FWP_CONDITION_FLAG_IS_REAUTHORIZE` (0x00000004) and `FWP_CONDITION_FLAG_HONORING_POLICY_AUTHORIZE` (0x02000000), before `Book::attest`. With `FWPS_RIGHT_ACTION_WRITE`, `auth_classify` invokes `guarded_block` and returns `FWP_ACTION_BLOCK`; without that right, only a preceding PERMIT is vetoable and CONTINUE/BLOCK are preserved. Separately, `Book::attest` has a one-shot `auth_seen` flag: simply removing the reauthorize-flag rejection is insufficient.

Microsoft documents that ALE reauthorization may follow policy changes, changed arrival interface or pending operations. Thus **if** a selected TCP flow is reclassified by these filters and ACTION_WRITE is present, this implementation blocks it rather than maintaining a previously accepted relay. This is a continuity/availability limitation, not observed disconnection, packet leakage, or proof that an external policy update will necessarily reach this filter. The model does not assume full reauth metadata or an outbound packet direction.

## Source pins and tests

| R19 source | Git blob SHA |
|---|---|
| kernel/src/redirect.rs | a093f049d162987981a957aac90db1014bc6ff09 |
| kernel/src/lib.rs | 53f5ce6faa0f9f591974287f38ea890cafeb0dd2 |
| kernel/src/handoff.rs | e1d17217db50362ba9c4efc83af820b6beb094cf |
| policy_windows.rs | acf60334320d970f58af3349ee75fbaa59826602 |

Files under `research/wfp-ale/kernel-r19/`. Their Git tree SHA pins were checked from the exact parent. No full local checkout, so **positive** source-gate not executed.

Run `python3 -B research/wfp-ale/r162/r162_reauth.py --test`, similarly under `-O` and `-OO`, plus `node research/wfp-ale/r162/r162_reauth.mjs`. If exact checkout exists, run `python3 -B research/wfp-ale/r162/r162_reauth.py --source-gate .`. Deterministic narrowly scoped Python model and independent Node.js oracle: 768 modeled combinations, zero mismatches; Python 10/10 each mode. Outcomes: BLOCK 186, BLOCK_VETO 64, PRESERVE_CONTINUE 64, PRESERVE_BLOCK 64, NOT_INVOKED 384, PERMIT_ONCE 6. Deliberately drifted source-gate and deliberately modified Python model were both rejected in isolated checks. Local full matrix SHA-256: `1674d416804843da02d33a25d3824a0ea92e6bc7fa89a4338e45de0f901508bd`. No native WFP/driver/Rust tests.

Official docs: https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization ; https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts-asynchronously ; https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection .

## Trust boundary and next decisive experiment

Not proved: real PEPROCESS / PID+creation epoch / canonical EXE and AppId → redirect and AUTH v4/v6 classification with compartment and endpoint identity → accepted socket redirect context/records → unique CLAIM → physical SSH socket with SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS → authenticated SSH and fail-closed DIRECT exclusion. Existing tests are a **code-contract** falsifier, not kernel-origin proof. Other NO-GO: endpoint ABA/5-tuple reuse, sibling DIRECT, DNS/UDP/QUIC, WFP/BFE/SSH loss, generation rollover. Next authorized experiment: source-pinned driverless read-only Rust trace interpreter, modeling initial AUTH → CLAIM → re-AUTH and identity/generation barriers; independently check against these executable negative traces. Native classify requires separate owner-approved driver/VNC/SYSTEM rescue/rollback gates. No protected branches, services, networking or automations changed.
