# R196: Dynamic BFE-session lifetime limits the R190 read-only experiment

Date 2026-11-15. Independent WFP/ALE research only, research/windows-wfp-ale-attribution-20261107. Initial research HEAD 893dcfdf6a8144f671241e3175c473ec21898eba; main read-only 5b5afc2feeda2195f302380e615ba003d4906e09.

## Material experiment-admission finding

The unchanged R19 policy_windows.rs blob acf60334320d970f58af3349ee75fbaa59826602 sets session.flags=FWPM_SESSION_FLAG_DYNAMIC in Engine::open, then adds a sublayer, 4 BFE callouts, 4 BFE filters with FwpmSubLayerAdd0/FwpmCalloutAdd0/FwpmFilterAdd0. Its Installed owner holds the engine session alive. Microsoft explicitly states that all objects added via a dynamic WFP session are removed when that session terminates.

The unchanged R190 main.rs blob 775762e773ad2b2577d83a9976ef068df708f3e4 requires exact GUID matches for that sublayer, all 4 registered callouts, and all 4 filters, plus exact layer/action/TCP/AppId. Therefore, on a clean host where there is no active R19 session and no exact-key artifacts, R190 cannot return STRUCTURE_OBSERVED_NOT_PROOF. No absent object should be misreported as a failure of WFP or as a security proof. R190 does NOT activate those objects.

Current owner constraints prohibit starting/installing kernel callouts/drivers or WFP filters, so the frequently proposed R190 clean-host BFE inventory is NOT a decisive *positive* R19 structure experiment within this scope. This is a conditional TEST-ADMISSION NO-GO, not a new runtime WFP failure. We have not inspected an actual host and cannot assert whether any exact R19 objects presently exist there. Even a visible match cannot prove dynamic-session ownership, callback reachability, process identity or physical no-DIRECT.

## Evidence and tests

Exact GitHub source blobs fetched at the initial HEAD. Independent full-source JS review passed 12/12 source/negative assertions including two mutation guards. Published Python and independent Node executables each passed 16/16 checks on bounded local reduced-source fixtures; full-checkout execution is NOT CLAIMED because the executor has no GitHub DNS and no Windows/Rust environment. The scripts require a full checkout to independently validate the actual R19 and R190 files. Synthetic eligibility states are not Windows observations.

Microsoft references:
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0
- https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0

## Decision and next decisive experiment

Within permission: build unchanged R190 user-mode read-only Rust on an approved Windows 10 Pro x64 host with reproducible Cargo dependency pinning; record OS/rustc/source/lock/binary SHA256. A read-only BFE scan is a negative baseline if R19 objects are absent; log exact APIs and ACL/errors, do not install anything to make the test positive. To observe actual registered R19 callouts/filters requires a separately admitted and already running environment, or a distinct owner decision with all driver/VNC/SYSTEM rescue/rollback gates. Do not run kernel tests in this track.

Kernel-origin PEPROCESS/creation-epoch/canonical EXE, native ALE_CONNECT_REDIRECT/AUTH_CONNECT, accepted-socket WSAIoctl redirect records/context, one-use CLAIM and physical SSH remain unproven as one chain. IPv4/v6, PID/5-tuple reuse, process death, sibling DIRECT, DNS/UDP/QUIC, reauthorization and WFP/SSH loss remain NO-GO. No PacketBound/G2 PASS, no-DIRECT/leak-free or historical dd1ab3c G1 transfer.

Only this research branch is in scope. No main/release/beta/PR #56, drivers, WFP activation, services, firewall, security settings, network, runner, automation, paid action or other repo change.
