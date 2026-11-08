# R57: Reclassify opt-in and conditional-flow bootstrap NO-GO

Date 2026-11-09. Independent source-only WFP/ALE R&D. Sole allowed branch `research/windows-wfp-ale-attribution-20261107`; neither beta nor PR #56, G2, PacketBound or system no-DIRECT proof.

## Pinned source
Research parent HEAD `6e5cd4ab6e4fded5a730e038a9471793dd355023` (tree `2cd701c2380cbcd0e9c481c36a916c6852f32249`); main `5b5afc2feeda2195f302380e615ba003d4906e09` read-only. Git blobs: `kernel-r19/kernel/src/lib.rs` `0af6d4539673d2894cbaa91af0ea8f3524862a26`; `redirect.rs` `9a07e026134d46ef646d39862bd982cc48bbc5f6`; `handoff.rs` `e1d17217db50362ba9c4efc83af820b6beb094cf`.

Actual `FWPS_CALLOUT1` registration in lib.rs lines 166-173 zero-initializes all four callouts, sets GUID/classify/notify but never sets `flags` or `flowDeleteFn`. The classify callbacks ignore `_flow`, and auth_check blocks all `IS_REAUTHORIZE` cases. Book attestation is single-use.

## Microsoft API distinctions (not a driver proof)
- `FWP_CALLOUT_FLAG_ALLOW_RECLASSIFY = 0x10` is a documented `FWPS_CALLOUT1.flags` opt-in to being called when an **existing socket operation** is reclassified. Current code does not explicitly opt in. This does **not** prove that all ALE policy reauthorization is absent without the flag, or that adding it guarantees dispatch, WFP metadata or kernel-origin ownership.
- `FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW = 0x01` limits callbacks to flows with an **already associated context**; Microsoft describes this option for stream-inspection connections. Blindly enabling it for initial AUTH ticket issuance creates a bootstrap trap: no prior context -> no callback -> cannot issue ticket. It is not a general AUTH_CONNECT identity solution.
- `FwpsFlowAssociateContext0(flowId,layerId,calloutId,flowContext)` is specific to the requested layer+callout, needs a nonzero context and registered flowDeleteFn, and only uses a valid `FWPS_METADATA_FIELD_FLOW_HANDLE`. A flowContext of zero is not evidence of an authenticated flow. There is no automatic join across CONNECT_REDIRECT, AUTH_CONNECT and STREAM.
- `FwpsCompleteOperation0` triggers AUTH_CONNECT reauthorization after pending initial AUTH. A unique pending state must be retained. BFE filters still have to match; fields can be `FWP_EMPTY`. The socket-reclassification opt-in is **not** a universal claim about ALE policy reauthorization.

**Source-level NO-GO:** switching 0x10 and/or 0x01 cannot repair the kernel-origin session/ticket/epoch/EXE join. Even if the callback is delivered, existing auth_check rejects reauthorization. A context-required initial auth callback would risk not being invoked. No physical packet leak was observed.

## Executed negative tests, independent oracle
Offline Python standard-library `unittest`: 15/15 PASS. Independent Node oracle published here agrees with Python on **131,072** hypothetical states (two IP families x four stages x 2^14 assumptions), per-stage counts and SHA256 of all outcome vectors: `223c60437f91ddef68c69835002bc7b96518a3ee6b4fe13acc90c4af0ea533eb`. Hypothetical dispatch candidates initial/socket/completion/policy = 12,288/6,144/12,288/12,288; strict conditional model permits = 24/4/8/8; source reauthorize flag-gate upper bounds = 24/0/0/0; deliberately weakened context-only model permits = 12,288/4,096/8,192/8,192. These counts ASSUME BFE matching and other proof bits: they are **not** Windows-native classifications, flow counts or packets. An unobserved physical process death is observationally indistinguishable until callback delivery. Python source, logs, full report and SHA256 manifest are in the R57 checkpoint; Rust and Windows native execution were not performed.

## Trust chain and next experiment
Must prove same native ALE_CONNECT_REDIRECT_V4/V6 classify AppId+canonical EXE, PID+creation epoch/start key+referenced EPROCESS, endpoint, original IP family/destination, kernel-issued ticket; exact AUTH_CONNECT receipt, pending issuance and completion reason; legitimately associated layer+callout flow context; original accepted-socket `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS`, outbound `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS`, authenticated SSH; termination under process exit/PID reuse/tuple reuse, sibling DIRECT, DNS/UDP/QUIC, IPv4/IPv6 and WFP/SSH loss. Neither packet-level stop nor PacketBound/G2 PASS/no-DIRECT/leak-free is established. Historical G1 dd1ab3c is not transferred.

Next safe decisive experiment R58: read-only inspect whether documented initial AUTH and CLASSIFY_COMPLETION provide any exact shared trusted socket/flow identity under missing `FWP_EMPTY` fields and BFE filter dispatch, without circular context bootstrap. If documentation cannot prove this, keep NO-GO. No kernel driver/filter, runner, VNC, network, security or automation changes.

Official references (2026-11-09):
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_callout1_
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsflowassociatecontext0
https://learn.microsoft.com/en-us/windows/win32/api/fwpsu/nc-fwpsu-fwps_callout_classify_fn1
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/processing-classify-callouts-asynchronously
https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
