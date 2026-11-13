# R164 — Global process-churn poisons the R19 broker ledger (source-level NO-GO)

2026-11-13. Independent WFP/ALE R&D only. **Not beta, not PR #56, not G2/PacketBound acceptance.**

Source-verified research parent: `597188af1a37cce5ead31b5637f3dba32ff917fd`; main at study: `5b5afc2feeda2195f302380e615ba003d4906e09`.

## Cross-subsystem finding

The driver registers `PsSetCreateProcessNotifyRoutineEx` for **all** valid process-creation notifications, not only the selected AppId or broker. `kernel/src/lib.rs::process_event` calls `STATE.born(owner)` for every event meeting its image/object constraints. `kernel/src/ledger.rs` has `MAX_OWNERS=256`, increments `used` for each accepted distinct PID, and never decrements it on process exit. The 257th accepted distinct birth sets `Ledger.lost=true` irreversibly. `Ledger::lookup` then rejects *every* owner, including the still-live broker. `redirect.rs::ready()` sees the missing broker, invokes `lose()`, disarms the route and calls `Book::kill()`. Subsequent PING cannot recover in that driver instance; R161 explains the independently terminal ARM/Book lifecycle.

**Counterexample:** after recording broker and selected process (two slots), 254 valid unrelated births leave the ledger full but alive. The 255th unrelated valid birth makes its ledger permanently lost. The selected process and broker can both still be running; even immediate termination of all the unrelated processes does not recover capacity. With the BFE rules otherwise unchanged, the next `ready()`/PING fails. This is deterministic source-level **availability** loss, NOT demonstrated Windows packet loss or DIRECT leakage. The trigger counts **accepted valid process notifications**, not arbitrary OS process starts: `FileOpenNameAvailable`, file object, path length and status checks exclude some creation events.

Source Git blobs independently checked against the exact research HEAD:
- `kernel/src/ledger.rs`: `b88c4c9237c4c118517978fc454f5048f522aa7f`
- `kernel/src/lib.rs`: `53f5ce6faa0f9f591974287f38ea890cafeb0dd2`
- `kernel/src/redirect.rs`: `a093f049d162987981a957aac90db1014bc6ff09`

Paths above are relative to `research/wfp-ale/kernel-r19/`.

## Deterministic independent checks

A separate checkpoint contains the complete Python and independent Node.js trace models: **1,566 paired scenario outputs matched** (261 counts × 3 exit strategies × 2 selected-process states), zero divergences; Python unit tests **8/8** in each of normal, `-O`, `-OO`. The source-token/three-Git-blob gate was verified separately through GitHub; a *full local checkout source gate* was **not** run. No native Rust, Windows, kernel, WFP, driver or network operations were executed. Minimal independent threshold reproducers, both executed successfully:

```python
for immediate_exits in (False, True):
    count, poisoned = 2, False  # broker + selected already accepted
    for unrelated in range(255):
        if count == 256: poisoned = True
        elif not poisoned: count += 1
        # EXIT only clears live flag; it does not decrement count.
    assert count == 256 and poisoned
    assert not (not poisoned)  # Ledger::lookup refuses even the live broker
```

```javascript
for (const immediateExits of [false, true]) {
  let used = 2, lost = false;
  for (let unrelated = 0; unrelated < 255; unrelated++) {
    if (used === 256) lost = true;
    else if (!lost) used++;
    // Died never decrements used.
  }
  if (used !== 256 || !lost) throw Error("owner-cap proof failed");
}
```

## Trust boundary and next decision

`PS_CREATE_NOTIFY_INFO` + referenced `PEPROCESS`/file object + `PsGetProcessCreateTimeQuadPart`/`PsGetProcessStartKey` provide birth-origin evidence, but global all-process bookkeeping means unrelated activity can invalidate the selected flow. Never silently evict old owner entries to restore availability: PID reuse, endpoint ABA and in-flight AUTH/CLAIM require an independent proof. Next permitted experiment: source-pin all three exact files on a clean checkout; run read-only user-mode process churn accounting (no driver installation, WFP filters or live system changes). Decide an explicit and independently verified selected-AppId admission/retirement contract before any future kernel trial.

Full flow remains **NO-GO**: canonical `FwpmGetAppIdFromFileName0` ↔ PEPROCESS birth/epoch ↔ ALE CONNECT_REDIRECT/AUTH_CONNECT IPv4/IPv6 and compartment ↔ accepted socket redirect records/context ↔ one-shot CLAIM ↔ physical SSH egress; sibling DIRECT, DNS/UDP, endpoint and 5-tuple reuse, reauthorization, BFE/SSH loss remain unproven. PacketBound/G2 PASS and leak-free are not claimed.

Microsoft: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_ps_create_notify_info
