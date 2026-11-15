# Windows-first FlowBridge 1.0 — WFP/ALE kernel-origin process incarnation, first product block

**Date:** 2026-11-15. **Architecture:** user explicitly authorized proceeding with Windows WFP/ALE development and testing. This supersedes the former NDISRD-only *product development* constraint, but does not waive signing, user-machine safety, native acceptance, independent no-DIRECT, rollback or release approval.

**Status:** SOURCE/WDK/USERMODE QA IN PROGRESS, **G2 NO-GO**. Original pinned explicit SOCKS beta, `main`, installed NDISRD, user Win10/Win11 and all other products unchanged.

## 1. Source-level P0 defects to address

The earlier `native/windows/wfp/driver/driver.c` ALE_CONNECT_REDIRECT implementation has a trusted WFP-provided PID and AppId at classification, but its redirect context `v2` includes **no process creation epoch**, start key or transport endpoint handle. A PID reused after another process exits is not bound to a process incarnation.

Two additional unprotected paths in the old selected-app callout were:

- With dynamic BFE selected filters still present but `gEnabled==FALSE` (driver disable/owner-close race), the classify method returned soft `FWP_ACTION_PERMIT` and could let the selected connection go DIRECT.
- `FWPS_CONNECTION_REDIRECTED_BY_OTHER`, or a previous foreign local redirect in `FWPS_CONNECT_REQUEST0`, previously returned `PERMIT` rather than preventing an unverified route. A different redirection provider's destination is NOT our pinned original endpoint.

Microsoft's WFP connect-redirection and reauthorization guidance distinguishes initial, self, previous-self and foreign redirection, and requires applying a writable `FWPS_CONNECT_REQUEST0` even when unchanged.

## 2. Production changes

- `native/windows/wfp/process_epoch.h`: fixed nonpaged / spinlock-owned process-incarnation table, 512 buckets × 8 ways; PID, creation time (100ns), Windows process start key, opaque process-object token (never dereferenced or sent to user mode). Duplicate live PID, invalid identity, hash overflow and wrong exit callback poison the entire table **fail-closed**. Preexisting selected EXEs without kernel create callback are not silently backfilled from IP Helper or ETW; operators must relaunch them after the newly signed backend is initialized.
- The real WDK driver registers `PsSetCreateProcessNotifyRoutineEx` at startup; calls `PsGetProcessCreateTimeQuadPart` and `PsGetProcessStartKey` in OS process-create/exit callbacks, and unregisters the callback at unload. The linker marks the .sys image `/INTEGRITYCHECK`; this is an image property, NOT a signature, not code-integrity acceptance and not authorization to load it.
- The real ALE_CONNECT_REDIRECT classify method reads the cached OS process origin under its kernel spinlock, requires OS `transportEndpointHandle`, and copies all three fields into the immutable per-socket **v3** redirect context. Missing/poisoned kernel record → `BLOCK`; never substitute PID+tuple snapshots.
- WFP device control ABI raised from **2 to 3**; older driver/GUI helper combinations refuse to interoperate. The accepted-socket Win32 `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` reader validates the v3 length, PID/creation/start-key/transport endpoint and remaining canonical byte fields before any routing.
- **Rust FFI fail-open fix:** the actual `crates/flowbridge-ffi/src/lib.rs`
  WFP entrypoint previously permitted a selected redirected connection to
  choose a profile `DIRECT` route if the application-specific rule did not
  match. With non-empty OS WFP redirect records, a protected connection
  must now resolve to **Proxy/Chain with at least one hop**; missing rule,
  `DIRECT`, `BLOCK` or an empty route aborts **before** stream reservation
  and creation of any outbound socket. An explicit SOCKS connection
  without WFP records keeps its existing independent DIRECT policy.
  Rust unit tests and two independent source mutations guard the boundary.
- Existing selected flow `gEnabled==FALSE` and foreign redirector scenarios now **block**. Self/previous-self redirection is still returned to WFP to avoid recursion; actual authorization at `ALE_AUTH_CONNECT` remains the separate outstanding P0. On configuration, a lost/unregistered process-notify ledger produces `STATUS_DEVICE_NOT_READY`.

## 3. Tests and exact acceptance boundaries

- `tests/windows_wfp_epoch_v3.cpp` compiles and exercises the **actual C source** of the bounded ledger on native x64 MSVC. Scenarios: OS-create/exit, same-PID new-epoch reincarnation, duplicate PID poisoning, stale exit rejection, malformed/zero birth and start key refusal, eight-way bucket exhaustion, plus compile-time v3 kernel/user layout.
- `tests/test_windows_wfp_epoch_source.py` checks integration into the actual driver/Win32 accepted-socket reader and seven reintroduced source regressions: disabled selected flow becoming PERMIT, foreign redirector PERMIT, PID-only identity, stale poisoned ledger configuration, reader accepting no birth epoch, v2 ABI and poisoned-table admission.
- `.github/workflows/windows-wfp-epoch-v3.yml` runs MSVC tests on `windows-2025` without loading a driver. The existing `.github/workflows/windows-driver.yml` additionally builds the actual WDK `.sys` **unsigned, never installed or loaded**; general Rust/native workflows must remain green for Windows, Linux and macOS.

**Critical P0 not yet closed:** genuine native `ALE_AUTH_CONNECT_V4/V6` callback and reauthorization, competing BFE filters/hard permits, accepted socket one-shot kernel receipt/redirect record, physical outbound SSH, signer/driver deployment and **separate Win10 Pro 22H2 + Win11 Pro** selected/unselected dual-stack no-DIRECT/DNS/UDP/QUIC checks. WFP `ALE_ORIGINAL_APP_ID` may propagate selected AppId to the physical proxy SSH socket and cause a self-block; research R198 documents this conditional collision. A native signed lab must distinguish this behavior; do not bypass by broker PID alone.

**No owner machine intervention:** do not change SecureBoot/BCD/testsigning, Defender, BFE/firewall or installed drivers, and do not load unsigned .sys even on general GitHub runners. True native kernel tests require an approved disposable VM snapshot, signing, VNC/SYSTEM rescue, and independent egress observer. Approval to *develop/test the architecture* does not assert those prerequisites are met.

## 4. Microsoft evidence

- [PsGetProcessCreateTimeQuadPart](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetprocesscreatetimequadpart)
- [PsGetProcessStartKey](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetprocessstartkey)
- [PsSetCreateProcessNotifyRoutineEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [WFP connect redirect](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection)
- [WFP reauthorization](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization)

**Release truth:** Windows `WIN-01/G2` remains `NOT_ACCEPTED` until kernel-origin process+epoch+endpoint, actual AUTH, proxy redirect records and physical no-DIRECT all pass independently on owner-approved signed Win10/Win11 lab. Existing macOS code remains reusable; the portable Rust policy and FFI must not import WFP/Win32 struct layouts.
