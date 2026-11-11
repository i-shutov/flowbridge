# R100 — CONNECT_REDIRECT AppId divergence leaves CONTINUE
2026-11-11. Research ONLY; parent d4eaa3adc73594fce1c591b4c2ca3bc71d7e1953. main read-only 5b5afc2feeda2195f302380e615ba003d4906e09.

## Source-level conditional NO-GO
Exact R19 lib.rs Git blob 0af6d4539673d2894cbaa91af0ea8f3524862a26 initializes actionType to FWP_ACTION_CONTINUE when ACTION_WRITE is granted, before invoking redirect::classify. Exact R19 redirect.rs blob 9a07e026134d46ef646d39862bd982cc48bbc5f6 returns immediately when callback ALE AppId differs from armed broker AppId: if appid!=&r.name[..r.len]{return;}. This leaves CONTINUE unchanged. Policy filter type is FWP_ACTION_CALLOUT_UNKNOWN, which Microsoft permits to return CONTINUE, handing off the decision to other filters (it is NOT BLOCK). Whether real Windows supplies divergent identity representations is UNPROVEN.

The separate AUTH_CONNECT callout rejects unredirected traffic if it actually executes, and may therefore stop this branch. Conditional failure chain: selected filter matches, callback is invoked with right to write, normalized/observed AppId differs, redirect CONTINUE; AUTH callback is not invoked (or cannot enforce), and independent policy permits. This is a candidate exposure, NOT observed DIRECT nor a proved leak. R99 management snapshot cannot prove continuous AUTH invocation.

## Independently reproducible negatives
Python control flow and Node.js Boolean-table oracle each test 128 abstract states: selected filter, redirect invoked, ACTION_WRITE right, AppId equality, AUTH callback invocation, downstream permit, broker readiness. Both produce 8 CONTINUE states, 2 conditional potential-DIRECT states, byte-identical canonical matrix SHA-256 cc6905633e2ad748d6735d45843f455e13fbde4870234fb83986b9e1c3f5db3d.
Minimal witness: 1,1,1,0,0,1,1 => CONTINUE, AUTH_NOT_INVOKED, potential_DIRECT. Change AUTH=1 => AUTH_DRIVER_BLOCK, meaning only the local callback decision, NOT end-to-end WFP arbitration. Synthetic state count does NOT measure actual Windows behavior.
Optional Python checkout source guard is defined but was not executed against a full checkout in this cycle. R19 Git blobs above were read through GitHub connector.

## Trust boundary / next decisive proof
Kernel process-create via referenced EPROCESS, PsGetProcessCreateTimeQuadPart and PsGetProcessStartKey -> canonical EXE/AppId -> ALE CONNECT_REDIRECT/AUTH_CONNECT IPv4+IPv6 -> original destination, endpoint and one-shot ticket -> WSAIoctl QUERY redirect records/context on the accepted socket -> terminal CLAIM -> SET redirect records before outbound connect -> authenticated pinned-key SSH. This full causal chain remains NO-GO. PID reuse, repeated 5-tuple, sibling DIRECT, DNS/UDP/QUIC and WFP/SSH loss remain open.

Next authorized READ-ONLY task: build the exact R99 source on Windows x86_64 (if accessible) with SDK ABI validation and capture BFE JSON, exit code, OS build and binary SHA. To discriminate this R100 condition, compare existing trustworthy AppId evidence from broker ARM, FwpmGetAppIdFromFileName0 and kernel ALE callback WITHOUT creating/driving callouts or traffic. Any new driver, WFP filter, traffic or VNC test requires separate gates. Do not equate BFE presence with kernel-origin or no-DIRECT proof.

Microsoft contracts:
https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_action0
https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_classify_out0
https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer
No modifications to main/release/beta/PR56, drivers, services, filters, runner, network, security settings, automations or other repositories.
