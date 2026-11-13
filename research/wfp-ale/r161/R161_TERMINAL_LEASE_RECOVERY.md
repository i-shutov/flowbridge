# R161 — terminal ARM lease prevents in-place recovery
Date: 2026-11-13. Research branch only: research/windows-wfp-ale-attribution-20261107.
Based on exact source at parent 1282e9686c2086a76190c16de00bc52dc9e4c240 (R160).
No driver, WFP filters, service, network, firewall, runner or system configuration touched.

## Source-level architectural finding
* kernel/src/redirect.rs: ARM rejects when r.configured is already true. First success sets both r.configured=true and r.armed=true.
* redirect::lose() sets r.armed=false and Book::kill(), but never clears r.configured. STOP, broker process death, expired/failed ready() call lose().
* kernel/src/handoff.rs: Book::kill sets lost=true; Book::initialize refuses to replace an already initialized session. No supported reset method exists.
* Consequently, in the **same loaded R19 instance**, ARM -> STOP -> ARM, ARM -> broker process death/restart -> ARM, and ARM -> lease-timeout check -> ARM are irrevocable failures. Recreating BFE dynamic-session filters afterward does not restore the kernel lease.
* A hypothetical edit that only clears configured is also inadequate: Book is still permanently lost, and the existing ARM ioctl does not independently check Book health. A false-positive ARM success followed by failed ready/PING would be possible under that incomplete edit. This is a mutation hypothesis, not observed Windows behavior.

This is an availability/recovery architecture NO-GO, not proof of a packet leak or a Windows WFP classification outcome. R160's BFE/PING blindness remains separate: while BFE filters are absent, kernel PING can still succeed. Both problems must be resolved before claiming automatic fail-safe recovery.

## Reproducible model and limitations
Python r161_recovery.py and independent Node.js r161_recovery.mjs enumerate all 8-event traces of length 0 through 5: 37,449. Python normal, -O, -OO: 8/8 tests in each mode. Independent Node oracle: 37,449/37,449 aggregate comparisons, zero differences.
Matrix:
- traces=37449
- terminal=8733
- rejected_rearm=2349
- reinstalled_terminal=1359
- bfe_missing_ping_ok=590
- configured_and_not_armed=8733
These are synthetic model trace counts, **not** real packet measurements, leak probabilities or native callout proof.
SHA-256 of matrix.json: 7485bec5d2afb8af0cacbc75ace547593608a57a91c4be6b2f20434239d199cd.

The model pins five existing source Git blobs and has a fail-closed --source-gate that checks their exact Git object SHAs and source transitions. Their SHAs were independently fetched through GitHub. A full local checkout and Rust compiler were unavailable, so --source-gate and native Rust/Windows WFP execution were NOT run in this cycle. Do not re-label the Python/Node model as kernel proof.

Reproduce on exact checkout:
    python3 -B research/wfp-ale/r161/r161_recovery.py --source-gate
    python3 -B research/wfp-ale/r161/r161_recovery.py --test
    python3 -O -B research/wfp-ale/r161/r161_recovery.py --test
    python3 -OO -B research/wfp-ale/r161/r161_recovery.py --test
    node research/wfp-ale/r161/r161_recovery.mjs

## Trust chain still not accepted
FwpmGetAppIdFromFileName0 (selected canonical EXE bytes) -> PsSetCreateProcessNotifyRoutineEx / PsGetProcessCreateTimeQuadPart / PsGetProcessStartKey (referenced PEPROCESS+epoch) -> ALE_CONNECT_REDIRECT / ALE_AUTH_CONNECT v4/v6 (original AppId, endpoint, compartment) -> accepted socket SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS -> one-use CLAIM -> physical SSH socket SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS -> authenticated SSH.

Every transition needs native provenance evidence. R19's 4 BFE rules are TCP-scoped and DYNAMIC. Endpoint/PID ABA, re-used 5-tuple, selected process death, sibling DIRECT, DNS/UDP/QUIC, IPv4/IPv6 compartments, reauthorization and BFE/SSH loss remain NO-GO. PacketBound/G2 PASS, no-DIRECT and leak-free are NOT claimed.

Next permitted experiment: exact pinned-source gate and a read-only user-mode Rust witness for existing FwpmFilterGetByKey0/FwpmCalloutGetByKey0, without driver or policy alteration. Any driver lifecycle, callout, WFP filter, VNC/SYSTEM or paid step requires fresh owner authorization and rescue/rollback gates. A future restart protocol must explicitly solve Book generation and outstanding AUTH/CLAIM endpoint-ABA before attempting code changes.

Official docs:
https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0
https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltergetbykey0
