# R135 — ALE action-rights contract counterexample and R129 qualification

Recorded 2026-11-12; only research/windows-wfp-ale-attribution-20261107 in i-shutov/flowbridge.
Baseline SHA 9137fc19d3f79fef32841bcbc0fa9d87bc61a746; main read-only SHA 5b5afc2feeda2195f302380e615ba003d4906e09.

Pinned exact Git blobs in R19:
- kernel/src/lib.rs: 0af6d4539673d2894cbaa91af0ea8f3524862a26
- kernel/src/redirect.rs: 9a07e026134d46ef646d39862bd982cc48bbc5f6

## Conditional source-level contract NO-GO

Microsoft FWPS_CLASSIFY_OUT0 says actionType may be written with FWPS_RIGHT_ACTION_WRITE.
Without that right, a write to FWP_ACTION_BLOCK is permitted only to veto a preceding
higher-weight FWP_ACTION_PERMIT. Source: https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_classify_out0

R19 redirect.rs::block unconditionally assigns FWP_ACTION_BLOCK and clears action-write.
redirect::classify invokes it when incoming_write==0. auth_classify invokes it when
FWPS_RIGHT_ACTION_WRITE==0. lib.rs::classify and auth_callback write BLOCK without checking
the previous action or right on STOP / failed rundown acquisition.
Therefore if WFP invokes these paths without action-write and with prior BLOCK/CONTINUE/NONE,
these writes are outside the documented veto exception. No claim is made these inputs
actually occurred on the Windows host; WFP classify was NOT executed.

## Correct R129 direct-callback assumption

lib.rs::classify first assigns FWP_ACTION_CONTINUE when ACTION_WRITE is available.
Therefore redirect::classify's early return on REDIRECTED_BY_SELF / PREVIOUSLY_REDIRECTED_BY_SELF
does NOT leave the outgoing action uninitialized in this authorized path. R129's
direct-callback negative model must be qualified by the real wrapper behavior.
When ACTION_WRITE is absent, redirect::classify blocks before reaching the self-state
test; the conditional veto rule applies instead. Not a leak observation.

## Independently reproducible negative model

r135_rights_oracle.py and r135_independent.mjs independently enumerate four
hypothetical incoming actions across redirect_self, redirect_no_write,
auth_no_write, callback_stop, with applicable rights bits.
Executed locally: 12/12 Python unittest PASS; both models agree on 24/24
synthetic cases, of which 12 are conditional disallowed writes.
Exact ASCII matrix SHA256: 9e1f244d647e0b471515b3b7096e93a94524ca9016d92efaee8d1fc567e376be.
Nine source-shape checks against the two pinned Git blobs were separately
performed through fresh read-only GitHub fetches. No native Windows/PowerShell/Rust
test was run here. Python --check-sources <repo-root> is prepared for a real checkout.

The matrix is a WFP API contract counterexample, NOT a kernel proof, packet
capture, or evidence that all its hypothetical classifications occur.

## Trust boundary and next decision

Kernel-original PID/epoch/start key/executable/AppId -> real redirect and auth
classify -> redirect records/socket -> one-use claim -> SSH remains unproven.
PID reuse, 5-tuple reuse, process death, reauthorization, sibling DIRECT,
IPv4/IPv6 compartments, DNS/UDP/QUIC and WFP/BFE/SSH-loss continue NO-GO.

Next permitted step: exact-source R135 source-contract test on a checkout and
R134 read-only own-image native observation on authorized Windows 10 Pro x64,
preserving raw JSONL, stderr, binary SHA256 and exit codes. To resolve real WFP
rights/action sequences would need separately authorized kernel lab with full
driver/VNC/SYSTEM rescue/rollback gates; not authorized here.
No mutation of main/beta/PR56/runner/service/firewall/Defender/SecureBoot/
MemoryIntegrity/network/automations and no kernel/filter/callout operations.
No PacketBound/G2 PASS, no leak-free or no-DIRECT claim; no historical G1 transfer.
