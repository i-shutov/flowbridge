# R146 — ALE_AUTH_CONNECT honoring-policy phase counterexample

Date: 2026-11-12. Research branch only. Baseline 2ba14965bc55ac1eb89e16de138dc5b1824d404e, main 5b5afc2feeda2195f302380e615ba003d4906e09. NO-GO; no driver/BFE/filter/network work.

**Conditional architectural NO-GO:** Microsoft documents FWP_CONDITION_FLAG_IS_HONORING_POLICY_AUTHORIZE (0x02000000) as a first ALE_AUTH_CONNECT phase for redirected Universal Windows apps, carrying pre-redirection destination and followed by effective-destination/proxy classification. R19 filter matches FWPM_CONDITION_ALE_ORIGINAL_APP_ID on v4/v6 ALE_AUTH_CONNECT, but auth_check *unconditionally rejects* 0x02000000 (also 0x00000004 reauthorization), and requires 0x00100000 IS_CONNECTION_REDIRECTED, original destination, endpoint and current loopback. If this filter sees the honoring phase, R19 cannot return PERMIT for it. With FWPS_RIGHT_ACTION_WRITE the guarded callback requests BLOCK; without write rights only a lawful veto of prior PERMIT is possible. This is a source/API contract contradiction, NOT a native traffic denial, bypass or leak measurement. R145's outbound SSH collision is a distinct conditional path.

**Important:** automatically permitting the honoring phase is NOT an approved safe fix. It would require independent kernel proof of the later effective-destination authorization, filter precedence, process identity and fail-closed guarantees.

Sources pinned and independently verified through GitHub: policy_windows.rs acf60334320d970f58af3349ee75fbaa59826602; redirect.rs a093f049d162987981a957aac90db1014bc6ff09; kernel lib.rs 53f5ce6faa0f9f591974287f38ea890cafeb0dd2.

Two separately implemented Python 3.13 / Node 22 offline oracles agree on all 1,024 IPv4/v6 selected, honoring, redirected, reauth, metadata, local, receipt, write-right, prior-permit combinations: 380 BLOCK_CANDIDATE, 512 NOT_SELECTED, 4 PERMIT_CANDIDATE (all effective redirected), 128 PRESERVE_UNPROVEN. 128 selected-honoring plus ACTION_WRITE cells demand BLOCK_CANDIDATE; no honoring permit cells. Matrix SHA-256 f35c117b4159ba1c4f00e49796d9b874f889e8ad78c8182eabdd15ed8e0517b6. No native Windows tests; model explicitly assumes every other identity/ticket condition succeeds.

**Trust boundary:** process-create PEPROCESS/FileObject PID+epoch+start key+canonical EXE -> kernel ALE/AppId/ORIGINAL_APP_ID and phase flag -> per-flow redirect context -> accepted socket WSAIoctl SIO_QUERY_REDIRECT_RECORDS/CONTEXT -> one-shot CLAIM -> outbound SIO_SET_RECORDS -> physical SSH. Correlation is never kernel proof. PID/5-tuple reuse, v4/v6 compartments, reauthorization, sibling DIRECT, DNS/UDP/QUIC, BFE/SSH loss all still NO-GO.

Next decisive evidence: (1) exact checkout Python pin gate and independent Node run, (2) only after separate authorization and all driver/VM/VNC/SYSTEM rescue/rollback gates, observe both Windows AUTH stages, original/current AppIds, target, rights, filter hit, and outcome. No PacketBound/G2, no-DIRECT, leak-free or G1 promotion.

Microsoft primary sources:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-flags
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_incoming_metadata_values0_
- https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_classify_out0
