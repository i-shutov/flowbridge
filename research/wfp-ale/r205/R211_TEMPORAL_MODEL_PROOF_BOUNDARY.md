# R211 — temporal proof boundary of R201 selective ledger (executable negatives)

2026-11-17. Research branch only. This is **not** a new R19 driver defect, native Windows evidence, PacketBound/G2 PASS, no-DIRECT or leak-free proof. R201 deliberately has a time-free user-mode value-model API; its synthetically accepted CLAIM therefore cannot certify R19's time-sensitive kernel CLAIM.

Pinned source blobs: R201 selective_ledger.rs `bc4c02daf2f09609cfa11b595d842e5ad2608625`; R19 handoff.rs `e1d17217db50362ba9c4efc83af820b6beb094cf`; R19 redirect.rs `a093f049d162987981a957aac90db1014bc6ff09`.

Actual R19 contract: `handoff::Book::take(context, now)` checks issuance age <= `TTL=100_000_000` in 100-ns ticks and rejects time rollback; `redirect::ready(now)` demands last broker PING age <= `LEASE=30_000_000`. By contrast `r201::SelectiveLedger::claim(id, endpoint)` has no clock argument, so synthetic issuance/attestation/CLAIM may succeed with ticket age > TTL, heartbeat age > LEASE, or a reversed clock. **This only demonstrates R201's known abstraction boundary**, not any ability of R19 to admit the flow: R19 checks independently.

Executable artifacts (all pure offline): `python3 research/wfp-ale/r205/r211_temporal_negative.py --source` and `node research/wfp-ale/r205/r211_temporal_oracle.mjs --source`. Python: six named differential scenarios, including IPv4/IPv6, TTL boundary, expired TTL, stale lease, clock reversal, explicit health/process exit and PID/endpoint/UDP controls. JS: 20 independent truth-table assertions, TTL/lease/rollback mutation sensitivity plus eight separate pinned-source guards. A PASS on the negative scenarios means R201 is **not** adequate to prove temporal admission, not that WFP failed.

The pinned source hashes and ten Python structural guards were independently checked through GitHub. Offline Python 6/6, JS 20/20, Python compile and JS syntax tests actually ran. Rust compiler and approved Windows host were unavailable: no Rust, PowerShell 5.1, BFE, kernel classify, WFP filter, driver or SSH native execution. Only `r205/` files are added, preserving R203v7's existing per-commit path allowlist and every pinned R199/R201/R202/R19 source blob.

Next decisive authorized experiment: execute pinned R201/R202 and R203v7 on approved Windows 10 Pro x64; optional passive R199 BFE snapshot only if approved. A trustworthy kernel-origin attribution/CLAIM/physical SSH join still needs separate owner-controlled driver/VNC/SYSTEM rescue and rollback gates, and must cover process death/PID reuse, endpoint closure, AUTH reauthorization, recycled 5-tuples, sibling DIRECT, IPv4/IPv6/compartments, DNS/UDP/QUIC and WFP/SSH loss.

Microsoft API contracts: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection ; https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization ; https://learn.microsoft.com/en-us/windows-hardware/drivers/network/ale-endpoint-lifetime-management
