# R160 — BFE session loss cannot be closed by a kernel PING watchdog

2026-11-13. Research-only R&D; no Windows/driver execution. Exact four R159 Git blob pins are embedded in r160_repo.py. Parent inspected: d0b1048063870e606b221713aadb45689f372dac; subsequent R159 CI line-ending correction did not modify any of these four blobs.

## Source finding

R159 fixes local AppId/port admission and orders BFE dynamic-session readback before ARM. However, broker.rs's heartbeat checks ONLY Device::command(PING), not BFE objects; policy_windows.rs uses FWPM_SESSION_FLAG_DYNAMIC and reads back the four filters only at initial setup. Kernel redirect::ready() proves broker lease, not that the WFP management session/filters still exist. When an owned dynamic WFP session ends, the filters are deleted (documented). A historical successful readback cannot imply live interception.

Sources: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0 and https://learn.microsoft.com/en-us/windows/win32/fwp/object-management .

Furthermore, BFE filter-change subscriptions (FwpmFilterSubscribeChanges0) are asynchronous and explicitly **unreliable**. Detection and immediate STOP cannot restore a filter that already vanished or enforce absence of DIRECT packets. Source: https://learn.microsoft.com/en-us/windows/win32/fwp/change-notifications .

## Executed negative checks

Bounded event-state model for initial readback+ARM, then session loss/restart, PING, an optimistic instant probe/STOP, IPv4/IPv6 selected TCP, SSH loss and broker death. 8 events, all lengths 0–4: **4,681** traces. Python normal/-O 7/7 tests each. Independent Node.js oracle 4,681/4,681 aggregate comparisons, 0 differences. Conditional observations: 634 traces with selected IPv4 uncovered by *R19-owned* filters, 634 with IPv6; 388 include uncovered selected attempts while broker remains unrevoked. These are **model trace counts, not packet leak observations or probabilities**. Another 586 end with filters missing and broker still unrevoked.

Minimal traces: BFE_SESSION_LOST → HEARTBEAT gives kernel PING success with BFE policy absent; BFE_SESSION_LOST → PROBE → SELECTED_V4 remains outside these filters even with immediate STOP. On session restart, dynamic objects are not automatically recreated.

Reproduce in this exact branch checkout:
python3 -B research/wfp-ale/r160/r160_repo.py --source-gate
python3 -B research/wfp-ale/r160/r160_repo.py --test
python3 -O -B research/wfp-ale/r160/r160_repo.py --test
node research/wfp-ale/r160/r160_repo.mjs

The local model and independent JS tests were executed; exact four Git blobs and source shape were also checked directly through GitHub. The local --source-gate needs the exact checkout and was **not** executed in the limited offline container.

## Trust and next proof

FwpmGetAppIdFromFileName0 (selected canonical EXE) → PsSetCreateProcessNotifyRoutineEx / PsGetProcessCreateTimeQuadPart / PsGetProcessStartKey (PID+epoch) → ALE_CONNECT_REDIRECT/AUTH_CONNECT v4/v6 (endpoint, compartment, original AppId) → SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS (accepted socket) → one-use CLAIM → SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS (physical SSH). Each link still needs a native provenance witness. PID reuse, endpoint ABA, repeated 5-tuple, sibling DIRECT, DNS/UDP/QUIC, BFE/SSH loss remain NO-GO.

Next allowed read-only user-mode Rust experiment on authorized Windows: capture FwpmFilterGetByKey0/FwpmCalloutGetByKey0 timestamps, actual AppId/ports, and independently timestamped passive observation. Do not induce BFE failure. A readback or notification is observability, not a no-DIRECT barrier. Any driver, callout, filter insertion, network, system rescue or cost activity needs separate owner decision and gates. No PacketBound/G2 PASS, leak-free, beta or release claim.
