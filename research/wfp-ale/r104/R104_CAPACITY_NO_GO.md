# R104 — global process-create capacity: source-level availability NO-GO

2026-11-11; **only** research/windows-wfp-ale-attribution-20261107. Parent 62951e0a2d92ea42ab34fc5eb3a6fdd95523e51c; main 5b5afc2feeda2195f302380e615ba003d4906e09. NOT beta/PR56, not native PacketBound/G2, no-DIRECT, leak-free or historical G1 dd1ab3c.

## Reproducible source-level result
- \`kernel-r19/kernel/src/lib.rs\` Git blob \`0af6d4539673d2894cbaa91af0ea8f3524862a26\`: the callback registered through \`PsSetCreateProcessNotifyRoutineEx\` calls \`Ledger::born\` for *every usable successful process-create event*, not just the selected EXE; it registers before broker ARM. Conditions such as missing full filename can skip an event, so this is a threshold in **accepted notifications**, not a wall-clock or total-process-count prediction.
- \`kernel-r19/kernel/src/ledger.rs\` Git blob \`b88c4c9237c4c118517978fc454f5048f522aa7f\`: \`MAX_OWNERS=256\`, no reuse of dead slots, \`born\` on a 257th distinct PID sets \`lost=true\` permanently. Any later \`lookup\` / \`observe\` fails. PID reuse triggers the same latch independently.
- \`kernel-r19/kernel/src/redirect.rs\` Git blob \`9a07e026134d46ef646d39862bd982cc48bbc5f6\`: \`ready\` depends on live broker lookup; after ledger loss this gate fails. This is source-level availability failure for an otherwise live selected stream, **not a demonstrated Windows callback, packet, DIRECT or leak**. Other redirect callback CONTINUE paths retain R100's separate NO-GO.

## Executed evidence
- Independent Python dictionary model and Node array model on local executor: 52 synthetic traces each (v4/v6, selected early/late, dead-owner churn, unrelated 257th process, PID reuse), 16 terminal LOST, identical SHA-256 \`5974b31d3a79c93b6dc82b7e3ef459844fa01c54f39b6edbd34fd6077230f356\`. Node model is available in the local R104 archive; the Python model is also committed.
- New \`r104_exact_ledger_negative.rs\` imports the **actual** Ledger Rust module and tests three boundary cases. \`rustc\` is unavailable in the executor; **do not claim Rust tests were run**. Run explicitly in any permitted user-mode Rust environment: \`rustc --edition=2021 --test research/wfp-ale/r104/r104_exact_ledger_negative.rs -o r104-ledger-test && ./r104-ledger-test\`. No drivers, kernel, sockets or WFP calls.
- The existing Ledger already has an isolated cap test; R104 independently verifies that **unrelated** globally notified processes exhaust a generation ledger intended to authorize selected traffic. This may be an intentional safety latch, but it is not viable for extended normal Windows process churn without an explicit design change.

## Trust boundary / next decisive experiment
Candidate chain remains: kernel process notify + referenced EPROCESS/file + creation epoch/start key + canonical EXE, same-event ALE CONNECT_REDIRECT/AUTH_CONNECT v4/v6 and exact AppId, origin-bound endpoint/redirect context, accepted socket WSAIoctl records, one-use CLAIM, pinned SSH; no PID/5-tuple or ETW-time substitution. Also open: post-CLAIM process death, sibling DIRECT, DNS/UDP/QUIC, repeated tuples, WFP/BFE/SSH loss and IPv6.

Next: compile exact-source Rust *user-mode* tests, then design a selected-only bounded registry with explicit unknown preexisting-process fail-closed policy, safe reference lifetime, PID reuse handling and no unproved kernel-origin attribution. No driver/callout/NDISRD/WFP filter, runner, VNC, network, firewall/Defender/SecureBoot/MemoryIntegrity or other repository/automation actions.

Microsoft: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex ; https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pcreate_process_notify_routine_ex ; https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection ; https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking .
