# R200 — unrelated process births exhaust the R19 owner ledger

Date: 2026-11-15. Research only, not beta, PR #56, driver QA, G2 or PacketBound acceptance.

## Source-level functional NO-GO (not Windows runtime proof)

R19 registers `PsSetCreateProcessNotifyRoutineEx(Some(process_event),0)`, which Microsoft documents as a system-wide process creation/exit callback. The valid-create path in `kernel/src/lib.rs` sends each accepted process to `STATE.born(owner)` **without filtering by selected EXE/AppId**. `kernel/src/ledger.rs` has `MAX_OWNERS=256` append-only slots. The **257th distinct accepted valid process-create event** causes `born()` to set `lost=true` and return `Denied::Full`, even if all those processes are unrelated to FlowBridge. `died()` marks owners dead but never reclaims slots; `lookup()` returns `None` globally after loss. `kernel/src/redirect.rs::ready()` requires a live broker lookup and calls `lose()` on failure.

Result: unrelated processes, including short-lived ones, can permanently revoke the laboratory routing lease during that driver lifetime. This is a **fail-closed availability blocker**, not proof of DIRECT leakage. It does not mean the 257th Windows launch necessarily trips the latch: malformed/unsupported create callbacks can be skipped. Registration does not retroactively observe processes already running.

An existing `ledger.rs::owner_cap_no_eviction` unit test covers the local table bound. R200 adds the missing **cross-module** assertion: unrelated process births feed that bound and its loss disables selected/broker routing.

## Exact source inputs (Git blobs)

- `research/wfp-ale/kernel-r19/kernel/src/lib.rs`: `53f5ce6faa0f9f591974287f38ea890cafeb0dd2` — global process notification and unconditional `born`.
- `research/wfp-ale/kernel-r19/kernel/src/ledger.rs`: `b88c4c9237c4c118517978fc454f5048f522aa7f` — 256 fixed slots, global lost latch, no recovery on exit.
- `research/wfp-ale/kernel-r19/kernel/src/redirect.rs`: `a093f049d162987981a957aac90db1014bc6ff09` — `ready()` checks owner lookup and fails closed.

Microsoft: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex

## Deterministic negative tests (no driver, Windows APIs or network)

Run from `research/wfp-ale/r200` inside a complete checkout:

```sh
python3 negative_owner_budget.py
node source_bound.mjs
```

The independent Python model exercises **5/5 PASS** scenarios: a selected process lost on the 257th unrelated valid birth; dead unrelated processes still consuming slots; 256 unrelated births blocking later selected registration; irrecoverable lost state; exact capacity boundary. The independent JavaScript source oracle verifies **8/8 PASS** cross-module predicates against the pinned real R19 Rust sources. Both were verified on 2026-11-15 (Python executed locally; JS equivalent eight predicates executed against GitHub file content). They do not establish native Windows process-count distribution, Rust ABI or WFP classify.

Raising the capacity or evicting entries is **not** an accepted fix: PID reuse, referenced EPROCESS/FileObject lifetime, creation epoch, WFP origin AppId, endpoint reuse and fail-closed properties need a separately verified design. Selective accounting also needs a demonstrated configuration/identity lifecycle; not implemented here.

## Next deciding work

Independently design/test a **pure Rust, user-mode, no-driver** selective bounded ownership ledger; negative cases must include unrelated valid births, process death, reused PID, 5-tuple/endpoint reuse and loss. Independently, the previously approved read-only R199 Windows 10 Pro baseline remains `cargo build --offline --locked --release` followed by passive BFE reads and exact OS build/toolchain/API/ACL/hash evidence; this does not validate the R200 kernel lifecycle. No driver/VNC/SYSTEM rescue/rollback gate is implicitly granted.

The complete origin chain EPROCESS/FileObject + PID/create epoch/canonical EXE/AppId → ALE REDIRECT/AUTH v4/v6 → accepted-socket context/records → one-use CLAIM → physical SSH remains **NO-GO**. Sibling DIRECT, IPv4/IPv6 compartments, DNS/UDP/QUIC, reauthorization, SSH/WFP loss, R88 conditional SSH self-block and actual no-DIRECT/leak-free guarantees remain unresolved.
