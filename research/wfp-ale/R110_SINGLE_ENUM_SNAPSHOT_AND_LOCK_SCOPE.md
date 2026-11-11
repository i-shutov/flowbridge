# R110 — Avoid a long BFE management lock and mixed-snapshot arbitration inference

Date: 2026-11-11. Scope: `i-shutov/flowbridge`, branch **only** `research/windows-wfp-ale-attribution-20261107`. Independent read-only/user-mode research, **not** beta, PR #56, signed-driver work, G2/PacketBound, native WFP acceptance, or no-DIRECT/leak-free certification.

## Source-pinned finding

- Research HEAD before this change: `9d0d8453ce25d8b68b70576c1518d732ee7471a1`.
- `main`: `5b5afc2feeda2195f302380e615ba003d4906e09` (read only).
- Exact original `research/wfp-ale/r103/r103_readonly_arbitration_inventory.rs` blob: `de0900259cc4ab44dd1decfe69782bb3ed54edd4`. Its executable code was sourced from the R103 checkpoint and verified with `git hash-object` against this Git blob SHA.

R103 opened `FWPM_TXN_READ_ONLY`, fetched four FlowBridge baselines with `FwpmFilterGetByKey0`, and then enumerated all visible filters with pages of 128 entries, **without committing the transaction until after the entire enumeration**. With `MAX_VISIBLE = 131072`, as many as **1024 full data pages plus an exhaustion check** could be processed under the explicit management transaction. Microsoft documents transaction lock acquisition, a default 15-second lock-acquisition wait, and a **one-hour maximum user-mode transaction lock ownership**. We have **not** observed BFE delays or asserted that all other operations are necessarily blocked for that hour; the source contains a real, avoidable long explicit lock scope.

Microsoft also specifies that `FwpmFilterEnum0` enumerates a **snapshot taken when its enumeration handle was created** and returns only the objects visible to the caller under BFE ACL. An explicit long transaction is not needed to compare filter weights taken from this *one* enumeration snapshot.

## Concrete source-only user-mode correction

- Remove the BFE explicit `FwpmTransactionBegin0`/`Commit0`/`Abort0` and separate `FwpmFilterGetByKey0` baseline retrieval from this **R103 diagnostic tool only**.
- Create **one** `FwpmFilterCreateEnumHandle0` snapshot and use `FwpmFilterEnum0` to read both the four expected FlowBridge filters and all visible same-layer/sublayer competing filters. Compare effective weights only after completing enumeration.
- Refuse a diagnostic result if any of the four baseline filters is absent, hidden by ACL, malformed, duplicated, or has no valid `FWP_UINT64` effective weight. Validate the owned filter's exact layer, sublayer, original `FWP_EMPTY` weight type, and expected key.
- Keep the existing `MAX_VISIBLE=131072` memory/entry budget, `PAGE=128` pagination, `FwpmFreeMemory0` ownership handling and mandatory `FwpmFilterDestroyEnumHandle0` success.
- Continue returning only `VISIBLE_ARBITRATION_CANDIDATE`, `UNKNOWN_NO_VISIBLE_CANDIDATE`, or `UNKNOWN` on error, **never a `SAFE` or enforcement proof**. JSON now records `single_enum_snapshot=true`. ACL-hidden filters may exist and are never treated as absent.
- The tool uses only BFE management **read** APIs; it does not install, activate, change, subscribe to, or delete drivers, callouts, filters, services, or network connections.

Caveat: enumeration is still synchronous and may impose some read load; there is **no documented wall-clock completion guarantee**. Removing the explicit long transaction is a reduction in risk, not proof of zero BFE impact. An enum-handle snapshot only describes visible management objects at one instant; it does not attest runtime `classifyFn`, packet behavior, process/flow identity or persistence over time.

## Deterministic executed negative evidence

Local `python3 r110_single_snapshot_negative.py`: **13/13 unittest PASS** and zero failures. Independent `node r110_independent_oracle.mjs`: same **896** synthetic cases, exact same full decision stream SHA-256: `ca58f481a8b3e7c84291cc186b64638b114bdbc9880b5b8c1e600be34485d152`.

- **224** cases: baseline not visible at enumeration; new model must remain `UNKNOWN`.
- **68** cases: the earlier two-time read can falsely report a competing filter not present with higher/equal weight in the coherent later snapshot.
- **68** cases: the earlier two-time read can miss a competitor that exists with higher/equal weight in the coherent later snapshot.
- This is an **information consistency counterexample**. It is not evidence of actual malicious BFE modifications or Windows packet leaks.
- Static source guards confirm the edited Rust source no longer invokes the explicit transaction or separate `GetByKey0`, still uses one enumerator and exactly four owned filter identities, retains ACL/budget fail-closed handling, and contains no WFP policy mutation APIs.
- **Rust compilation NOT RUN:** no `rustc/cargo` in the available local executor. **Windows native execution NOT RUN**, and no driver or WFP filters were installed or started.

## Exact trust boundary: unchanged

`FwpmFilterEnum0` => **ACL-limited filter snapshot**, NOT `ALE_CONNECT_REDIRECT`/`ALE_AUTH_CONNECT` source identity. `FwpmGetAppIdFromFileName0` and `FWPM_CONDITION_ALE_{ORIGINAL_}APP_ID` give pathname-derived selection, not a lifetime-authenticated original process object. Kernel-origin process/reference and `PsGetProcessCreateTimeQuadPart`/`PsGetProcessStartKey` are distinct native requirements. `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT)` must be applied to the **actual accepted socket**. `Book::take` consumes a ticket, but no kernel-attested socket join has been demonstrated; `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` on an upstream SSH socket does not by itself prove packet or owner affinity. Reauthorization, PID and 5-tuple reuse, process death, sibling DIRECT, UDP/DNS/QUIC, IPv4/v6 egress, WFP/SSH loss, physical no-DIRECT and PacketBound/G2 remain **NO-GO**. Historic G1 dd1ab3c is not promoted.

## Next decisive authorized experiment

Compile the **exact revised Git blob** as Windows x86_64 user-mode, compare its ABI with installed Microsoft Windows SDK, then run only the read-only inventory on a separately authorized Windows host and capture toolchain, OS build, binary SHA-256, JSON, exit code and permissions. **Do not create driver/callout, install WFP filters, mutate infrastructure, run a runner or conduct a VNC/network test.** A successful snapshot is still not native kernel-origin proof.

## Official Microsoft documentation

- `FwpmFilterEnum0` snapshot/pagination/ownership: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilterenum0
- Object management: transaction lock timeouts and lifetime: https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
- `FwpmTransactionBegin0` read-only lock mode: https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmtransactionbegin0
- BFE ACL-limited filter enumeration: https://learn.microsoft.com/en-us/windows/win32/fwp/access-control
- Redirect tracking: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
