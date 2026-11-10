# R85 — conditional FWPS_RIGHT_ACTION_WRITE contract gap

2026-11-10. Only i-shutov/flowbridge branch research/windows-wfp-ale-attribution-20261107. Independent WFP/ALE R&D, NOT beta, PR #56, PacketBound/G2 PASS, leak-free/no-DIRECT, or transfer of historic G1 (dd1ab3c).

Pinned source: research HEAD 5bd948ecd33010c90edf77ecc1fc7e190b4bbceb; main read-only HEAD 5b5afc2feeda2195f302380e615ba003d4906e09.
Pinned Git blobs: kernel-r19/kernel/src/lib.rs 0af6d4539673d2894cbaa91af0ea8f3524862a26; kernel-r19/kernel/src/redirect.rs 9a07e026134d46ef646d39862bd982cc48bbc5f6; kernel-r19/policy_windows.rs acf60334320d970f58af3349ee75fbaa59826602.

## Finding and strict boundary
R19 redirect.rs block(out) unconditionally assigns FWP_ACTION_BLOCK and clears FWPS_RIGHT_ACTION_WRITE. auth_classify calls block when action write right is missing; redirect classify calls block on missing right. R19 kernel/src/lib.rs kernel STOP/rundown callback branches also unconditionally set BLOCK without testing incoming actionType.

Microsoft FWPS_CLASSIFY_OUT0 says a callout without FWPS_RIGHT_ACTION_WRITE should not write actionType EXCEPT to veto a higher-weight previously returned FWP_ACTION_PERMIT. Therefore, a no-right invocation with previous BLOCK, CONTINUE or NONE has no documented authority for the current unconditional assignment. Source does not assert the necessary prior-PERMIT precondition.

THIS IS CONDITIONAL, NOT A DEMONSTRATED WINDOWS FAILURE: there is no evidence WFP can actually present no-right + non-PERMIT to these particular callback/filter paths. If WFP guarantees only prior PERMIT, the explicit BLOCK veto is documented. No claims of traffic leak, BSOD, exploitability or kernel-origin attribution follow from synthetic cases. Do not patch or load the driver without separate owner gates.

## Independent offline negative tests
r85_rights_negative.py: 4/4 Python PASS. Independent Node r85_rights_independent.mjs: all 64 ordered scenarios agree with Python; SHA256 cf11bcc17c7e58b909ddace264cf1e6c5807c1e989601119ba0829a363d48b3b; 24 synthetic CONTRACT_GAP and 40 DOCUMENTED. Axes: four unconditional-BLOCK code paths, IPv4/IPv6, action-write 0/1, prior PERMIT/BLOCK/CONTINUE/NONE. These are pure models, not WFP callbacks, native Windows/packet observations, or proof of scenario reachability. rustc/cargo and Windows runtime absent; Rust not compiled.

## Unchanged architectural NO-GO
CONNECT_REDIRECT_V4/V6 -> PROCESS_ID with kernel-referenced process epoch/start key/canonical original EXE + FWPS original/current AppId and queried redirect state -> AUTH_CONNECT_V4/V6 provenance/destination -> endpoint generation and one-use ticket -> accepted SOCKET with SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT -> DeviceIoControl(CLAIM) -> SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS on outbound TCP SSH socket -> authenticated SSH -> independent sibling-DIRECT denial remains UNPROVEN. CLAIM does not carry a kernel-authenticated accepted socket. Reused PID/5-tuple, process death, IPv6 compartments, UDP DNS/QUIC/ICMP, TCP-only R19 rules, WFP/BFE/SSH loss and dynamic-session teardown remain NO-GO.

## Next decisive experiment
Compile/run exact R83 published Rust source on separately authorized Windows x86_64 user-mode environment for negative WinSock ABI/error baseline only. For this rights condition, only source/official-document review is permitted now: determine if missing action write right always implies a prior PERMIT at these exact layers/action types. A live classify callback experiment requires separate driver/VNC/SYSTEM rescue/rollback approval and is currently FORBIDDEN. No physical PASS from a model.

Official contracts checked 2026-11-10:
https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_classify_out0
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nc-fwpsk-fwps_callout_classify_fn0
https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_action0
https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection

No main/release/beta/PR #56, CI/runner, service, firewall/UFW/Defender/SecureBoot/MemoryIntegrity, network, other repo, driver/callout/filter/NDISRD/VNC, vendor binary/AGPL/closed PR40/C++ WFP payload, payment, or automation mutation.
