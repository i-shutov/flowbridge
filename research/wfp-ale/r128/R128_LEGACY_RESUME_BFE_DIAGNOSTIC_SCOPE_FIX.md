# R128 — R113 exact-blob resume wrapper must not execute stale BFE diagnostics

2026-11-12. Strictly `i-shutov/flowbridge` research branch `research/windows-wfp-ale-attribution-20261107`. Not beta, PR #56, historical G1, PacketBound/G2 PASS, no-DIRECT or leak-free.

**Source pins before change:** research HEAD `75e12c285488e324abc6ac2f192827be52e838b4`, read-only main `5b5afc2feeda2195f302380e615ba003d4906e09`. R115 resume script Git blob `7c91ae5fc4d645b1dea49bd1e2439d3e146cdc8a`.

## New functional evidence-integrity blocker

The R115 R113 resume script, newly published at the research HEAD, deliberately exports **old R113** checkout `e24f3c2d866e9374e8873ecdab325dd7b06049ee`, inspector Git blob `49506ca07145c18947a0845f2a1a63b3de1f54ec` and harness Git blob `6cab4c1e8aee20506bb3ba9ae17cf348ec19b7df`. Its *default* previously enabled `-RunReadOnlyBfe`. Those binaries/validation rules predate R114, R123 and R124 hardening; the old snapshot can be an **incomplete/misclassified read-only BFE diagnosis**, even while accurately pinned to Git.

Specifically: the R113 Rust inspector decides candidate only from higher/equal same-sublayer weights; R123 also considers lower-weight competitors for `ALE_CONNECT_REDIRECT`, where `FWP_ACTION_CALLOUT_UNKNOWN` may return `FWP_ACTION_CONTINUE`. The R113 PowerShell JSONL parser accepts broad .NET `[ValueType]` counters and does not test `visible_filters` cardinality; R114 tightened both. A synthetic lower-only redirect candidate is classified old 4/new 3; a synthetic impossible count (`visible_higher=1`, `visible_filters=4`) is accepted old 3, rejected new 2. **No actual BFE filter conflict or packet leak was observed.** Old exit 4 was already UNKNOWN, never GO.

## Minimal remediation

Keep the R115 exact Git object pins, isolated extraction, compile and synthetic Rust ABI tests unchanged. The R115 PowerShell wrapper now never adds `-RunReadOnlyBfe`, including its default execution; it fails on an unexpected diagnostic exit 3/4 instead. `-CompileOnly` remains metadata only; default becomes metadata + synthetic tests, no BFE. `-SkipReadOnlyBfe` remains a harmless backwards-compatible switch. For a read-only BFE inventory, separately run the exact *current* R124 harness/inspector (R114/R123 fixes), never use this old pinned resume for it.

## Independent deterministic negative tests

`python3 research/wfp-ale/r128/r128_legacy_snapshot_negative.py` — **6/6 tests PASS**. `node research/wfp-ale/r128/r128_legacy_snapshot_independent.mjs` — **160/160 matching** scenarios across four rules, four counter buckets, five values and two declared visible-filter counts. Ordered canonical matrix SHA256: `20cd16d5de1d43823bc3c98445eb29b7e3d0b36db61954056edecde037c87c33`. Verdict pairs `(old,new)` counts: `(2,2)=32; (3,2)=40; (3,3)=8; (4,2)=40; (4,3)=2; (4,4)=38`. Models assume the matching terminal status/exit for their respective inspector; they do not manufacture real BFE evidence. No native Rust, PowerShell 5.1 or WFP classify execution occurred.

## Trust boundary and decisive next step

Official contracts: `FwpmEngineOpen0` → `FwpmFilterCreateEnumHandle0` → `FwpmFilterEnum0` (ACL-limited read-only snapshot, NOT classify proof); `FWP_ACTION_CALLOUT_UNKNOWN` and `FWP_ACTION_CONTINUE`. Kernel-origin trust still demands `FWPS_METADATA_FIELD_PROCESS_ID` at `ALE_CONNECT_REDIRECT_V4/V6` plus referenced process, epoch/start key and canonical EXE; `FwpsQueryConnectionRedirectState0`, `FWPS_CONNECT_REQUEST0`; initial/re-authorization `ALE_AUTH_CONNECT_V4/V6`; accepted socket `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT)`; kernel one-use CLAIM; outbound `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS`; and SSH peer verification with sibling DIRECT protection. These links remain **NO-GO**, including IPv4/IPv6, compartments, PID/5-tuple reuse, process exit, DNS/UDP/QUIC, reauthorization and WFP/BFE/SSH loss.

**Next permitted experiment:** on an already-authorized Windows 10 Pro x64 host with Rust + SDK preinstalled, execute exact R113 resume *compile only*, then its default synthetic tests, preserving Git blob SHA, executable SHA256, stdout, exit codes. For BFE inventory use only current R124 exact-source harness separately and verify JSONL cardinality/booleans independently. Neither proves packet-bound nor no-DIRECT. A kernel/driver/classify experiment still requires separate owner approval and all VNC/SYSTEM rescue/rollback gates.

Microsoft: https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_action0 ; https://learn.microsoft.com/en-us/windows/win32/api/fwpstypes/ns-fwpstypes-fwps_classify_out0 ; https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilterenum0 ; https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking

**Isolation:** no changes to main/release, beta branch, PR #56, runners, services, firewall/UFW, Defender/SecureBoot/MemoryIntegrity, network, other repos, automations, driver/callout/WFP filters/NDISRD, VNC, signed-driver or paid work. No ProxiFyre AGPL, closed PR40, vendor binaries or C++ WFP payload.
