# R205 — R203 offline collector branch-HEAD admission blocker

Date: 2026-11-16. Scope: **research/windows-wfp-ale-attribution-20261107** only.

Source anchor: \`7631a5904189ba90949259909d4f317f06e2584d\`.
Before R205, the research HEAD was \`42cd076110815b2c3e7163f4c708e997d7122b2e\`; \`main\` was \`5b5afc2feeda2195f302380e615ba003d4906e09\`.

## Reproduced preflight blocker

The standalone R203v4 offline PowerShell collector accepts only its source anchor or **a single direct descendant editing only r203/**. The published R204 consists of **two** linear child commits:
\`3b6531d9d93fc09e6033c7fc3954da6c63a143e5\`, then \`42cd076110815b2c3e7163f4c708e997d7122b2e\`. Both edit only the same three r204 files. Thus R203v4 stops at \`Unexpected research ancestry\` on the current research branch before running any Rust test or optional BFE readback.

The repaired offline R203v5 checkpoint has a new PowerShell per-commit ancestry gate: exact branch; source-anchor merge-base; every post-anchor commit has exactly one parent and a nonempty diff; all changed paths on every commit must remain in the **explicit tooling allowlist** (\`r203/\`, \`r204/\`, \`r205/\`). Crucially, the existing fixed Git blob locks for R199/R201/R202 and hash-verified off-checkout source snapshots remain mandatory; the R199 frozen manifest is still compiled \`--offline --locked\`. No kernel source may be modified and later reverted to bypass the per-commit check.

The full repaired collector and existing R203v4 validators are in the independent offline R203v5/R205 ZIP handoff, not in this commit. The two scripts committed here are independent, **synthetic negative-test oracles**, not the collector or native Windows evidence.

## Executed checks and limitations

Run \`python r205_lineage_negative.py\` and \`node r205_lineage_oracle.mjs\`. Each passes **11/11** deterministic cases, including current two-R204 commit chain, altered pinned source, changed-then-reverted kernel path, diverged ancestry, merge, unexpected path and missing diff. Earlier R203v4 dual-validator fixtures remain 25/25 PASS. These fixtures do **not** execute the PowerShell collector, Rust, Windows BFE or kernel classify. Native Windows gate execution is still unverified.

## Architecture — still NO-GO

Required chain: \`PsSetCreateProcessNotifyRoutineEx\` plus referenced EPROCESS/FileObject, process epoch/start key/canonical EXE/opaque AppId -> \`FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6\` and \`FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6\` with exact endpoint and original-destination metadata -> \`WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT)\` on the actual accepted socket -> terminal \`DeviceIoControl(CLAIM)\` -> \`WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS)\` on the outbound physical SSH socket.

No native proof for PID reuse/death, repeated 5-tuple/endpoint, sibling DIRECT, DNS/UDP/QUIC, IPv6 compartments, reauthorization or WFP/SSH loss. R199 is non-atomic management readback, not classify proof. Dynamic BFE session objects disappear on session owner termination. Redirect records are opaque and do not by themselves prove an original-destination identity on an unrelated SSH transport.

The next authorized experiment is execution of R203v5 offline Rust R201/R202 tests (14/8) on admitted Windows 10 Pro x64; optional passive R199 BFE readback with exact API/OS/compiler/binary hashes and independent R203v4/R204 validation. **No drivers, WFP filters, callouts, network changes, services, security changes, NDISRD, VNC or paid operations**. No mutation to main/release, beta or PR #56, runners or automations. No PacketBound/G2 PASS, no-DIRECT or leak-free promise.

Microsoft: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection , https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking , https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0 .
