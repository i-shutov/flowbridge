# R156 — source-level correction of R155: redirect self-state callback output

Date: 2026-11-13. Repository: i-shutov/flowbridge.
Only authorized branch: research/windows-wfp-ale-attribution-20261107.
Base: 0b9a0d720d68fc160d1a08c089fbf03ce86cd80e (R155).
Main observed read-only: 5b5afc2feeda2195f302380e615ba003d4906e09.
Status: SOURCE-LEVEL CORRECTION + OFFLINE TESTS PASS; native WFP and release NO-GO.

## Material correction to R155

R155 considered redirect.rs::classify in isolation and said the self/previous-self early return preserves the input FWPS_CLASSIFY_OUT0 action. This is incomplete for the actual installed R19 callback. The outer lib.rs::classify **first overwrites actionType with FWP_ACTION_CONTINUE whenever FWPS_RIGHT_ACTION_WRITE is set**, before entering rundown protection and before calling redirect::classify. Only when ACTION_WRITE is absent can an early self-state return preserve the incoming action unchanged. R155 source-level NO-GO must therefore be narrowed; the previous assertion about all writable self-state inputs inheriting arbitrary actions is contradicted by the full call graph.

At the actual R19 redirect filter, action type is FWP_ACTION_CALLOUT_UNKNOWN. On the selected, configured, valid self/previous-self path with write permission, the returned action is explicitly CONTINUE from the wrapper (rights retain ACTION_WRITE); no additional redirect attempt is made. This matches Microsoft's documented permit/continue choice for REDIRECTED_BY_SELF. PREVIOUSLY_REDIRECTED_BY_SELF still requires separate AUTH enforcement. This is **not** proof that WFP calls this filter, that another filter permits or blocks, or that no DIRECT traffic exits.

With no ACTION_WRITE, the wrapper cannot replace actionType. The self/previous-self early return then preserves incoming action and rights; the true WFP input and arbitration remain unknown. In other paths guarded_block may veto only an incoming PERMIT without write permission, but cannot convert an unmodifiable CONTINUE to BLOCK. Errors with ACTION_WRITE cause BLOCK and clear that right. The early AppId mismatch path also returns CONTINUE on writable input, so enforcement still depends on coverage of the independent ALE_AUTH_CONNECT rules.

## Source pins (GitHub connector, exact R155 HEAD)

- research/wfp-ale/kernel-r19/kernel/src/lib.rs = 53f5ce6faa0f9f591974287f38ea890cafeb0dd2 (outer wrapper, guarded_block)
- research/wfp-ale/kernel-r19/kernel/src/redirect.rs = a093f049d162987981a957aac90db1014bc6ff09 (inner self return, error paths)
- research/wfp-ale/kernel-r19/kernel/src/action_rights.rs = c6a4a107255cc5ecca82266481935c93467a01ed (rights/veto decision)
- research/wfp-ale/kernel-r19/policy_windows.rs = acf60334320d970f58af3349ee75fbaa59826602 (UNKNOWN redirect filter versus TERMINATING AUTH)

Exact source hashes and decisive markers were inspected through the GitHub connector, independently from the numerical test model. The Python source gate can verify full local blobs when executed against an exact checkout; no full checkout was available in the execution container, so local tests used --model-only and **are not labelled local source-pinned**.

Official Microsoft API documentation:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nc-fwpsk-fwps_callout_classify_fn0
- https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration

## Tests executed

- R155 original: 11/11 tests PASS, each of normal, -O, -OO. This confirms the original *isolated callback model* is reproducible, not end-to-end correct.
- R156 full callback composition: 16/16 tests PASS, each of normal, -O, -OO.
- R156 independent Node.js implementation: 224/224 matrix rows, zero disagreement with Python. Test dimensions: IPv4/IPv6, SELF/PREVIOUS_SELF, incoming PERMIT/BLOCK/CONTINUE/NONE, WRITE right absent/present, seven branch paths.
- Result categories: 32 OUTER_CONTINUE, 80 BLOCK_WITH_WRITE, 20 VETO_PERMIT_NO_WRITE, 92 PRESERVED_NO_WRITE. R155's self-return model produces a different action in **12 of its original 32 synthetic rows**, all in the writable half. Four other writable rows already began at CONTINUE.
- Matrix SHA-256: cb05f79b8587c56b01e0e285b4264294fdf29e9635f726297854e2898499d933.
- Source drift negative test: rejected. Unspecified source-root / missing source never constitutes proof.
- No Rust compiler, Windows kernel classify, WFP filters, driver, socket traffic or system configuration invoked in this cycle.

Run from repository root, after checkout of exact research commit:

    python -B research/wfp-ale/r156/r156_callback_composition.py --source-root research/wfp-ale/kernel-r19
    python -O -B research/wfp-ale/r156/r156_callback_composition.py --source-root research/wfp-ale/kernel-r19
    python -B research/wfp-ale/r156/test_r156.py
    python -O -B research/wfp-ale/r156/test_r156.py
    python -OO -B research/wfp-ale/r156/test_r156.py
    node research/wfp-ale/r156/r156_independent.mjs

The source-root argument requires those four blobs exactly. It never loads any driver or WFP filter.

## Trust boundary and decisive next experiment

Kernel source and documentation -> theoretical callback action under assumed input -> **STOP**: no observed WFP callback reachability, no actual input rights/flags, no provider/weight arbitration, and no native no-DIRECT claim. Subsequent required link: referenced process & FileObject, PID/creation epoch/start key and canonical WFP AppId -> ALE_CONNECT_REDIRECT_V4/V6 and ALE_AUTH_CONNECT_V4/V6 with typed endpoint/compartment -> FWPS_CONNECT_REQUEST0 context -> accepted socket SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT -> one-use CLAIM -> SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS before physical proxy connect -> authenticated SSH. Tests must cover PID reuse, same 5-tuple, sibling DIRECT, IPv4/v6, DNS/UDP/QUIC and WFP/BFE/SSH outages.

Next authorized step: run local exact source-pinned negative suite on a fully checked-out R156 commit, with independent Node result comparison. Native classify-out tracing is forbidden until separately approved driver, VNC/SYSTEM rescue and rollback gates. No main/release, beta, PR56, runner, service, network, security, driver, filter, other repo or automation changed. PacketBound/G2 PASS, leak-free, no-DIRECT and historical G1 are not claimed.
