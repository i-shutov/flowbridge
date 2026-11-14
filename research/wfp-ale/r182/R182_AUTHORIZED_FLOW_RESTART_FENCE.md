# R182 — Retained AuthorizedFlow needs a native join and a restart fence (conditional NO-GO)

Date: 2026-11-14. INDEPENDENT Windows WFP/ALE R&D; target ref `research/windows-wfp-ale-attribution-20261107`, **not** beta / PR #56. Source baseline: research HEAD `9753b039d86e712ba0b97690476392f8b43ca56a`, tree `02ed05ba594b71d0fb8e4ba8590da784c9365f44`; read-only main HEAD `5b5afc2feeda2195f302380e615ba003d4906e09`.

## Hypothesis tested

R181 showed the current one-shot FBR3 `Book` cannot attest an ALE reauthorization after CLAIM. A separate retained `AuthorizedFlow` would be necessary. R182 models a **strict, explicitly hypothetical** authority with transaction ID, a native per-flow join, original AppId, PID + creation epoch + canonical EXE, endpoint + generation, IPv4/IPv6 family + compartment, original tuple, durable Witness ACK, completed CLAIM, establishment, owner liveness, broker/BFE/SSH epochs and revocation. A model-supplied `kernel_join_attested` MUST NOT be confused with actual `FWPS_METADATA_FIELD_FLOW_HANDLE` or WFP redirect records: *no such exact native join has been demonstrated*.

A reauthorization may have `FWP_EMPTY` fields and the reverse packet direction. Under a trusted, separately preserved flow binding, those facts must not *alone* invalidate the correct flow. Without such proof, a tuple/AppId cache cannot distinguish the selected flow from a reused PID/endpoint/5-tuple, physical proxy socket or changed compartment.

A second, executable test addresses recovery: **persisted grant+ACK+CLAIM bytes do not prove no unjournalled revocation occurred before worker death**. A process crash without a revoke and a crash after a volatile in-memory revoke have byte-for-byte identical journal images. A policy that reloads those records as an active authorization can permit the revoked flow. A strict recovery that advances the broker/kernel session epoch and denies ALL old-session grants avoids this *modelled* resurrection, but does not prove live WFP blocking or a rollback-safe kernel epoch.

## Exact source gates (frozen at baseline)

- `research/wfp-ale/kernel-r19/kernel/src/redirect.rs` blob `a093f049d162987981a957aac90db1014bc6ff09`: `auth_check` rejects all `IS_REAUTHORIZE`; `Book::attest` is the only native authorization association in this R19 code path.
- `research/wfp-ale/kernel-r19/kernel/src/handoff.rs` blob `e1d17217db50362ba9c4efc83af820b6beb094cf`: `Book::take` consumes slot; no retained post-CLAIM authority, transaction-linked Witness receipt or separate flow certificate.
- `research/wfp-ale/kernel-r19/kernel/src/lib.rs` blob `53f5ce6faa0f9f591974287f38ea890cafeb0dd2`: no callout `flowDeleteFn`, `FWPS_METADATA_FIELD_FLOW_HANDLE` retained binding or Witness ACK-gated CLAIM.
- `research/wfp-ale/kernel-r19/policy_windows.rs` blob `acf60334320d970f58af3349ee75fbaa59826602`: terminating selected-original-AppId TCP AUTH_CONNECT V4/V6 rules; not scoped to reauthorization reason or original-vs-proxy classifications.

## Real executed tests (user-mode ONLY)

Commands from this directory:

```sh
python -m unittest -v test_r182.py
python -O -m unittest -q test_r182.py
python -OO -m unittest -q test_r182.py
python r182_authorized_flow_negative.py > python.jsonl
node r182_independent_oracle.mjs > node.jsonl
cmp python.jsonl node.jsonl
python r182_crash_journal.py > crash_results.jsonl
```

- Python unittest **7/7** in each of 3 modes; 5,760 deterministic rows; independent Node.js **5,760/5,760 identical**; canonical matrix SHA-256 `8b50f19e50e0a5a24ce108d21ebbd979497f8524500496637ccc335a9a0e539a`.
- Strict hypothetical permits **32** best-case reauthorization rows, with known kernel proof *injected as a model premise*. A deliberately unsafe tuple/AppId cache permits **1,792**, of which **1,760** are false permits relative to the strict oracle. These are NOT real Windows frequencies.
- Actual subprocess `os._exit(61)` process deaths after `fsync` writes; seven journal outcomes (pre-ACK, post-CLAIM, volatile revoke, durable revoke, exact duplicate, conflicting duplicate, truncated record). Process crash test result SHA-256 `42979e008548dc0ec1e7ead353fd7c23505de0061801fe14dfabf3c3bf7bdbf9`.
- The `post_claim` and `unobserved_revoke` byte streams both SHA-256 `e7c0008c958266cc5e6bcaf5c933cc2f67939fc09b6ab5351f2cff3c19817f4b`: naïve restore says allow in both; epoch-fenced restore says deny in both. Corrupt/torn frames fail closed. Model checks exact-vs-conflicting duplicate receipts.
- Independent sensitivity: deleting the `kernel_join_attested` guard makes a forged flow-token example permit when its expected decision is deny. Mutation was detected.
- `fsync` is a real process-crash exercise but **NOT power-loss durability proof** (no disk flush/fail-stop hardware testing, no kernel driver). Python and Node negative tests do not test Windows classify delivery, trusted flow-token provenance, actual SSH egress, packet behavior or physical leak prevention.

## Required native trust chain; unproved items

1. At process creation, retain referenced `PEPROCESS` and canonical image `FileObject` (`PsSetCreateProcessNotifyRoutineEx`, `PsGetProcessCreateTimeQuadPart`, `PsGetProcessStartKey`, object references), not later PID lookup.
2. In `ALE_CONNECT_REDIRECT_V4/V6`, bind WFP AppId and original destination to that retained process and native transport endpoint/generation/compartment; account for `FwpsQueryConnectionRedirectState0` and IPv4/IPv6.
3. On `ALE_AUTH_CONNECT_V4/V6`, distinguish initial / UWP policy-honor / reauthorization / physical proxy; use typed documented flags, `REAUTHORIZE_REASON`, fields' `FWP_EMPTY` and metadata presence checks, with a kernel-owned transaction ID connecting to the original classification. `FwpsPendOperation0`/`FwpsCompleteOperation0` require private pending state; not a general reauthorization cure.
4. Identify established flow using a **documented, actually delivered** native binding. `FWPS_METADATA_FIELD_FLOW_HANDLE` availability is conditional. `FwpsFlowAssociateContext0` needs a registered `flowDeleteFn`; a flow handle or five-tuple alone is not the authorization credential. `AuthorizedFlow` must survive CLAIM only as long as the native flow does, and be removed/revoked on endpoint closure, owner death, policy loss and session changes.
5. Bind accepted-socket `SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT` to the same transaction and process authority, enforce an exclusive durable Witness ACK, then a one-use CLAIM and recorded `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` before physical SSH. Prove withholding first byte until all gates hold, including BFE/SSH loss.
6. Explicitly account for sibling DIRECT, loopback proxy recursion, DNS/UDP/QUIC, re-used five-tuple, compartments, and IPv4/IPv6 policy coverage. None is certified here.

**Decision:** conditional model-level GO for *feasibility of a retained certificate predicate* given trusted native inputs; conditional architectural **NO-GO for recovering persisted AuthorizedFlow without a fresh authenticated kernel/BFE/session fence**, and unconditional overall **WFP/ALE NO-GO** pending native provenance and runtime proof. No PacketBound/G2 PASS, no no-DIRECT or leak-free guarantee, no transfer of G1 `dd1ab3c`.

## Next decisive, permitted experiment

A read-only Windows user-mode Rust probe, WITHOUT installing drivers or filters, must first inventory the exact runtime availability and scope of flow/endpoint metadata, WFP policy and original-AppId flags via supported APIs and verify that source-level assumptions are not contradictory. Any actual ALE hook / driver experiment requires separate owner authorization and all driver/VNC/SYSTEM rescue/rollback gates. Before that, implement offline Rust `AuthorizedFlow` simulator with process-crash/restart fencing; do not call an uncompiled Rust file an executed proof. Native missing-flow-join indistinguishability and BFE/SSH failure remain NO-GO.

Official Microsoft sources:
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts-asynchronously
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_incoming_metadata_values0_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsflowassociatecontext0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpspendoperation0

Scope: no `main`/release/beta/PR #56 mutation; no runners/CI, driver/callout/NDISRD/WFP filter/service/Defender/SecureBoot/MemoryIntegrity/firewall/UFW/network/VNC/signing/paid ops; no ProxiFyre, PR40, vendor binary or C++ payload.
