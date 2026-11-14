# R189 — BFE commit does not establish an ALE reauthorization barrier

Scope: independent FlowBridge WFP/ALE research only; no driver, kernel callout, filters, services, firewall or network operations. **NO-GO** for a no-DIRECT, PacketBound/G2 or kernel-origin proof.

## Source and exact trust boundary

Research parent: 175710f4827c06a0131ab2da1eb3968532bd00bc; main read-only: 5b5afc2feeda2195f302380e615ba003d4906e09.

- R19 policy installer: research/wfp-ale/kernel-r19/policy_windows.rs, blob acf60334320d970f58af3349ee75fbaa59826602. A dynamic BFE session installs four selected-TCP AUTH_CONNECT and CONNECT_REDIRECT filters for IPv4/IPv6, and commits an object transaction.
- R19 policy plan: research/wfp-ale/kernel-r19/policy_plan.rs, blob 0c3d0e88eb9d06f4030131d9533da2d629dbdab0.
- R188 byte-exact AppId diagnostic: research/wfp-ale/r188/main.rs, blob f11fd2227e57a72935d1646ef14b51c6b3cfd51f. Read-only inventory is not kernel-origin proof.
- Management APIs: FwpmTransactionBegin0, FwpmTransactionCommit0, FwpmFilterGetByKey0, FWPM_TXN_READ_ONLY. Their documented success describes BFE object state, not completed reauthorization of all previously permitted ALE flows.
- Kernel layers: FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6 and FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6. Microsoft states that once a policy change is detected, *the first packet traversing a previously authorized affected flow* is selected for reauthorization; it does not document a synchronous per-flow packet barrier at COMMIT return. The reauthorization flag is FWP_CONDITION_FLAG_IS_REAUTHORIZE; packet direction can reverse and fields can be FWP_EMPTY.

## Deterministic negative experiment

The two management observations COMMIT_OK/FILTERS_PRESENT/READ_TXN_COMMIT_OK are equal, while adversarial kernel schedules differ: policy detection can be modeled as pending, or as detected with first packet reauthorized and blocked. This is a *documentation-level counterexample to inferring a fence*, **not a Windows packet capture** or proof that a particular Windows build actually forwards a stale packet.

Offline executable model commit_fence_negative.py enumerates 576 scenarios over v4/v6, TCP/UDP, selected/sibling, previously granted/not, inbound/outbound, in-flight/queued, three reauth phases, stable/BFE/SSH loss. It finds 72 naive COMMIT+readback green labels; 68 of those have modeled stale/unknown potential, and all 72 lack a valid no-DIRECT certificate. UDP/sibling are out of this selected-TCP policy, not proven protected. Loss means unknown, not observed leakage.

Independent JavaScript oracle oracle_independent.mjs checks the same serialized 576 rows and SHA-256. Unit tests run under Python normal/-O/-OO; mutation turning the certificate into True must fail. Rust Windows and BFE runtime are not executed.

## Missing native proof and next decisive experiment

Only a kernel-origin join across process PID + creation epoch + canonical EXE, AppId, compartment, original tuple and redirect context, ALE AUTH/reauthorization, accepted-socket redirect records, durable Witness ACK/CLAIM, actual SSH flow, PID/5-tuple reuse, sibling DIRECT, DNS/UDP/QUIC, IPv4/IPv6, and BFE/SSH loss could support further acceptance. At every link, independent runtime evidence is missing. FwpsFlowAbort0 with FWPS_METADATA_FIELD_FLOW_HANDLE is a *kernel* candidate for revoking identified flows (Windows 8+), but requires driver work forbidden by this track and still does not retroactively prove queued bytes never left.

The next permitted step remains an independent Windows user-mode **read-only** build of the R188 AppId/BFE probe. Its output can be structural evidence only. An enforcement-fence experiment needs a **separate owner decision** and all signed-driver/VNC/SYSTEM rescue/rollback gates; do not conduct it here.

Official Microsoft documentation:
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-stateful-filtering
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactioncommit0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactionbegin0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsflowabort0
