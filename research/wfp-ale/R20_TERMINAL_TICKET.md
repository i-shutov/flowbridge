# R20 — final admission receipt failure must permanently retire its ticket

Date: 2026-11-07. Scope: only `research/windows-wfp-ale-attribution-20261107`; independent pure-model work. Read-only main at start: `5b5afc2feeda2195f302380e615ba003d4906e09`. Research parent read at start: `d22e87ff0c3549e8ccb519cc0a50e64e6dcf1a6d`.

## New counterexample: terminal receipt followed by forged improvement

In `trust_contract.rs` R16, `TrustGate::decide` inserted a ticket in `consumed` **only after** all acceptance checks succeeded. For a real admission attempt, the following is an invalid second chance:

1. A purported selected TCP IPv4/IPv6 connection presents an in-session ticket and a missing `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` result, wrong accepted-socket record, changed process epoch, or a source other than an owned kernel redirect. The first call returns `RejectOwnedIngress`.
2. The *same* ticket is resubmitted with all trusted fields set to true. Previous R16 code returns `RouteOnOwnedProxySocket` because the first rejected attempt never entered `consumed`.
3. An accepted-socket receipt can therefore be represented as first incomplete and then complete *after* the supposedly terminal admission boundary. A boolean model cannot authenticate either submission, but permitting such an upgrade is weaker even as a synthetic contract.

A separate Python `ResearchGate.accept` already retired a classified ticket *before* its final checks. Rust and Python models were inconsistent.

## R20 rule and exact scope

Once transport is selected TCP, AppId equals the exact selected byte string, and a nonzero ticket matches this session, `decide` **reserves/retire-once** the ticket before evaluating source, process identity or any accepted-socket receipt flags. A replay after a rejected terminal admission is rejected. Rejected events outside selected AppId, from a different session, or without a ticket do not consume a selected ticket. Capacity is still bounded to 4096 without eviction.

**Boundary:** `WSAIoctl` with a zero-size buffer may return `ERROR_INSUFFICIENT_BUFFER` during preliminary size negotiation; that is not a final admission attempt and must be resolved before calling `decide`. Never model an arbitrary read-size probe as a terminal failure. Once an admission decision is attempted with a claimed receipt, failed evidence is terminal. A new attempt requires a genuinely new owned ticket and proof, **not** reuse of an old numeric endpoint, PID or 5-tuple. A malicious or unrelated caller must not have direct access to the real authority to retire tickets; `Source` and booleans are still untrusted without a native origin adapter.

## Executed checks and limitations

- Inspected exact GitHub Rust source `trust_contract.rs`, old blob `438b46977a73b7bd67a312cbe20806cfbffa434d`; old insertion was after `accepted.*` validation.
- Independently executed `python /mnt/data/flowbridge_r20_audit.py -v` using a separately implemented Python state oracle: 3 PASS, 1 SKIP (no local Rust checkout); 14 / 14 old-contract upgrade counterexamples across IPv4/IPv6 and seven missing/forged evidence dimensions, and 14 / 14 corrected-contract denials. Independent source-order guard against exact fetched GitHub Rust text completed before commit.
- Added three pure Rust regression methods in the actual `trust_contract.rs`. **NOT COMPILED OR EXECUTED** here: there is no `rustc` in this isolated executor. The Python oracle does not prove equivalence to executable Rust.
- Published `test_r20_terminal_ticket.py` includes its own oracle and static source-order guard for a future local full checkout. No CI/runner, driver, filter, VNC, firewall, network or system change was made.

Offline regression without operating-system modification:

```sh
python3 research/wfp-ale/test_r20_terminal_ticket.py
rustc --edition=2021 --test research/wfp-ale/trust_contract.rs -o /tmp/flowbridge-r20-tests
/tmp/flowbridge-r20-tests
```

## Windows trust chain and NO-GO

| Link | Documented Windows interface | Evidence limitation |
| --- | --- | --- |
| Selection and EXE identity | `FwpmGetAppIdFromFileName0`, `FWPS_FIELD_ALE_CONNECT_REDIRECT_*_ALE_APP_ID`; referenced `EPROCESS`, creation epoch | Full canonical file object versus AppId aliasing unresolved; same original PID/epoch must be acquired in the native classify, not a retrospective numeric PID lookup |
| Classification & authorization | `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6`, `FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6`, `FWP_CONDITION_FLAG_IS_REAUTHORIZE`, WFP metadata validity bits | Endpoint or repeated 5-tuple is not a proven lifetime identity; reauthorization can be inbound and some fields `FWP_EMPTY` |
| Receipt | `FWPS_CONNECT_REQUEST0.localRedirectContext`, `FwpsQueryConnectionRedirectState0`, `SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS` / `_CONTEXT` on **actual accepted socket** | No real redirect-bound authenticated capture in FlowBridge; query failure is not a proof of absence |
| Outbound | `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` before outbound connect; UDP requires `WSARecvMsg/WSASendMsg` record ancillary data | TCP-only model cannot claim UDP, QUIC, DNS, or per-frame ownership |
| DIRECT and outage | Separate kernel ALE_AUTH_CONNECT policy and verified filter persistence | An ingress-level denial cannot prove system-wide sibling DIRECT prevention, fail-closed or WFP/SSH crash safety |

Microsoft references:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
- https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-context
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization
- https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer

**G2/PacketBound, kernel-origin process ownership, no-DIRECT and leak-free remain NO-GO.** The previously built R19 observer is not used, changed, signed, installed or run under the current authorization. Historical G1 cannot be transferred. The next decisive permissible experiment is compilation and execution of all R20/R16 Rust tests on a *local non-runner* toolchain, followed by a read-only native WFP/AppId probe if such an environment is already lawfully accessible. Redirect enforcement tests still require separate driver/VNC/SYSTEM rescue and rollback gates.
