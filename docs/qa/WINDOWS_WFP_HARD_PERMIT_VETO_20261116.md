# WIN-01 G2 P0 — WFP CONNECT_REDIRECT hard-permit veto (2026-11-16)

## Observed source defect

At the stacked Windows WFP product head (PR #71, `391316368470f0a9f6fe85eb302d54a6afaeb5f8`), `FbAuthClassify` correctly vetoed a previous hard `FWP_ACTION_PERMIT` when `FWPS_RIGHT_ACTION_WRITE` was absent. However, `FbClassify` at `ALE_CONNECT_REDIRECT_V4/V6` immediately returned on the same no-write-rights condition. That left a prior hard PERMIT in force without the selected connection ever passing the mandatory local redirect.

Microsoft states that a callout can veto a prior hard PERMIT by setting `FWP_ACTION_BLOCK` even when `FWPS_RIGHT_ACTION_WRITE` is absent:
- https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_classify_out0
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration

## Engineering change

`native/windows/wfp/driver/driver.c`: the actual product `FbClassify` now calls the existing terminal `FbBlock(out)` if no-write-rights is combined with `FWP_ACTION_PERMIT`, then returns. An already BLOCKed decision is left BLOCKed. Only when write-rights exist may the normal redirect decision continue. The prior AUTH_CONNECT veto remains unchanged.

`tests/test_windows_wfp_hard_permit_veto.py` audits **both actual product classify functions** and `FbBlock`; six adversarial mutations must be rejected, including missing REDIRECT/AUTH veto, reversed action predicate, missing rights guard, return before veto and non-blocking block-helper. The WFP source workflow runs the tests. This is static source coverage, not a kernel callback test or physical routing acceptance.

## Limits and release gates

- No signed driver is installed, loaded or deployed by this change. No Windows system policy is modified.
- This closes a specific source-level P0 permit-veto gap, **not** native G2. No guarantee is made that a third-party hard PERMIT filter can always be observed by this callout under every installed BFE configuration. The physical filter ordering and no-DIRECT behavior require independent traces on a rollback-ready signed-driver lab.
- Exact accepted socket-object proof through the terminal CLAIM boundary, generation-safe ticket reclamation beyond the 512-record prototype, ALE reauthorization, competing WFP filters, real SSH/redirect-record propagation, DNS/UDP/QUIC containment, dual-stack no-leak and native kill/restore still remain open.
- No merge to main, release tag, 1.0 acceptance or bypass of existing G2 gates follows from hosted tests.

**State:** `WIN-01.source-hard-permit-veto=PATCHED_PENDING_CI`; `WIN-01.native-g2=NO_GO`; `release-1.0=NO_GO`.
