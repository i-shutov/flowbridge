# R188 — selected-AppId substitution false positive in R187 read-only BFE inventory

Date: 2026-11-14. Only `i-shutov/flowbridge`, branch `research/windows-wfp-ale-attribution-20261107`; research parent `9bb71765cf19f066738908988c13a2bcfd8e5864`, main read-only `5b5afc2feeda2195f302380e615ba003d4906e09`. Not beta, PR #56, release, PacketBound/G2 or leak-free.

## Concrete source-level defect

`research/wfp-ale/r187/src/main.rs`, blob `d6f80a83ab1f8d99ce1c7259f8133350e083fee2`, checks that each read-back BFE filter condition has the expected AppId field/type and a non-null, even-sized blob of 4..514 bytes. It never compares the blob *contents* to the selected executable's AppId. Consequently, a coherent R19-shaped policy targeting a **different executable with an equal-sized AppId** returns `STRUCTURE_OBSERVED_NOT_PROOF`. That result is a **misleading selected-scope observation** only, not a real allow/deny decision. The R99 predecessor had an exact AppId comparison; R187 regressed that stronger condition.

## Reproducible negative tests

`python3 research/wfp-ale/r188/r188_negative.py` and `node research/wfp-ale/r188/r188_independent.mjs`. Both independently construct two different equal-length synthetic UTF-16LE AppIds and enumerate 512 combinations of selected path (2), four-filter structural shape mask (16), and actual AppId equality mask (16). R187's shape-only gate accepts 32; 30 have at least one wrong selected AppId. Byte-exact selected-scope gate accepts 2; false positives 0. Matrix canonical SHA-256 `09b7cbbe73486d76050c4d6e8261ba9038e5e56981ec97940290e3705443d413`. Python normal, `-O`, `-OO` and independent Node all agree; deletion of the Rust equality check is detected by a source mutation guard. These are deterministic source/abstract-model negative tests, **not native WFP** observations or packet leak metrics.

## Clean-room Rust candidate (NOT native-compiled)

`main.rs` derives a *filename-based* AppId with documented `FwpmGetAppIdFromFileName0`, frees it using `FwpmFreeMemory0`, keeps `FwpmTransactionBegin0(FWPM_TXN_READ_ONLY)` and compares each of the four `FWPM_FILTER0` AppId condition blobs byte-for-byte to the selected value. The input is exactly one absolute local drive path (not UNC). Any difference, null, bad size, access error or BFE/RPC error returns `NO_ATTESTATION/UNKNOWN`; success remains `STRUCTURE_OBSERVED_NOT_PROOF` only. Source uses `windows-sys=0.61.2`; it has not been compiled or executed on Windows because this environment has neither Rust nor an authorized Windows host. Do not claim native pass. This source does not install or manipulate drivers, WFP filters, services, sockets, firewall, security settings or runners.

This closes only the **AppId byte-identity check in a management-plane inventory model**. The file path may refer to a non-running or replaced executable; exact AppId agreement is not a proof of kernel-origin PID+creation epoch+canonical EXE, process lifetime, or classification. No `Fwps*` driver/kernel callouts are used. R187 and older artifacts are preserved unchanged.

## Native trust boundary and next decisive experiment

For end-to-end transparent interception, kernel-issued owned process provenance (`PsLookupProcessByProcessId`, `PsGetProcessCreateTimeQuadPart`/`PsGetProcessStartKey`), ALE `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6` original tuple/AppId/compartment, the `FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6` classification and reauthorization, `FwpsQueryConnectionRedirectState0`/redirect context, `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS)` on accepted sockets and `WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS)` on outbound socket, immutable ticket/Witness/ACK/CLAIM, and verified SSH path must form one trust chain. PID/5-tuple reuse, process death, sibling DIRECT, DNS/UDP/QUIC, IPv4/v6, WFP/BFE/SSH loss and gap-free filter ownership remain NO-GO. BFE inventory, even byte-exact and read-transactional, cannot prove continuous enforcement or a no-DIRECT property.

Next permitted experiment: **independent Windows 10 Pro x64 compilation** of this exact read-only Rust file with a previously authorized toolchain, then compare read-only R187 vs R188 output for two distinct equal-length EXE paths using only management API reads. Record OS build, source/blob SHA, rustc/cargo versions, binary SHA-256, exit codes and JSON. No driver, filter, kernel, VNC/SYSTEM or network experiment without explicit owner decision and rescue/rollback gates.

Official contracts (reviewed 2026-11-14):
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_condition0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactionbegin0
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfreememory0
- https://docs.rs/windows-sys/0.61.2/windows_sys/Win32/NetworkManagement/WindowsFilteringPlatform/fn.FwpmGetAppIdFromFileName0.html

No protected refs, runners, services, network settings, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, VNC, signed driver, AGPL ProxiFyre, vendor binaries, closed PR40, automation or other repositories were changed.
