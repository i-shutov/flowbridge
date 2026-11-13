# FlowBridge R154 — compartment provenance not bound by R19 handoff

Date: 2026-11-13. Research ONLY: research/windows-wfp-ale-attribution-20261107.
Pinned research base: 44856e929a111d10d526bd0cedff4688cd9d7f4e.
Observed main: 5b5afc2feeda2195f302380e615ba003d4906e09.
NOT beta; NOT PR56; no native WFP PASS.

## Confirmed static limitation

R19 kernel/src/handoff.rs defines Origin using pid, epoch, key, numeric endpoint
and owner generation, but NOT compartment. Context serialization and
Book::attest do not carry or compare compartment. In
kernel/src/redirect.rs::classify and auth_check the documented
FWPS_FIELD_ALE_CONNECT_REDIRECT_V4/V6_COMPARTMENT_ID and
FWPS_FIELD_ALE_AUTH_CONNECT_V4/V6_COMPARTMENT_ID are not read.
This means R19 cannot separately prove compartment equality between native
CONNECT_REDIRECT and AUTH_CONNECT using its handoff fields alone.

It does NOT establish that Windows can recycle or alias an endpoint handle
between compartments; nor does it show a bypass, packet leak or DIRECT route.
Actual WFP guarantees for handle uniqueness/lifetime and callback timing could
provide additional protections not established in this R&D.

Source pins verified from the exact research revision:
- kernel-r19/kernel/src/handoff.rs e1d17217db50362ba9c4efc83af820b6beb094cf
- kernel-r19/kernel/src/redirect.rs a093f049d162987981a957aac90db1014bc6ff09
- kernel-r19/policy_windows.rs acf60334320d970f58af3349ee75fbaa59826602

## Microsoft documentation (Windows 10 version 1703+ compartment fields)

- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_connect_redirect_v4_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_connect_redirect_v6_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v4_
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v6_
- https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization

If the architecture requires compartment-specific binding, use actual typed WFP
values from both native classifications, reject absent/unknown fields, bind to
an issuance-specific context, and verify with same-flow independent evidence.
Never promote ETW/PID, socket table or reused 5-tuple correlation to kernel proof.

## Executed negative tests (offline only)

Python 3.13.5 normal, -O, -OO and independent Node.js 22.16.0 each
enumerated 192 hypothetical states across v4/v6, process liveness, process
epoch, numeric endpoint, same/different/missing compartment, AppId and
ACTION_WRITE. Exact output agreement; 0 mismatches.
Four states with matching existing R19 projection but mismatched/absent
compartment are conditional counterexamples; two states match all model
requirements; other 186 states reject for a separate missing requirement.
6/6 Python regression tests PASS in normal and -O.
192-row matrix SHA256:
36b6b973731c403261889ff439539777ed564456f243b4d21a674e2725bef275.

IMPORTANT: Tests ran with explicit --model-only; full source-pinned local checkout
and native Rust/Windows/WFP were NOT run. SHA sources were independently
checked through GitHub. The --source-root path refuses missing or altered
blobs. The test is a source-grounded conditional projection, not execution of
R19 kernel classify and not an observed Windows race.

Reproduce from the exact repository checkout:

    python -B research/wfp-ale/r154/r154_compartment_negative.py --source-root research/wfp-ale/kernel-r19
    python -O -B research/wfp-ale/r154/r154_compartment_negative.py --source-root research/wfp-ale/kernel-r19
    node research/wfp-ale/r154/r154_independent.mjs
    python -B research/wfp-ale/r154/test_r154.py

## Remaining trust chain and decision

Kernel-origin process reference/creation epoch/start key/canonical EXE +
opaque WFP AppId -> ALE_CONNECT_REDIRECT_V4/V6 and AUTH_CONNECT_V4/V6 with
actual WFP compartment, endpoint, rights and reauth metadata ->
FWPS_CONNECT_REQUEST0 -> redirected accepted-socket
WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT/RECORDS) ->
terminal CLAIM -> physical SSH socket
SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS before connect -> externally observed
enforcement against sibling DIRECT, DNS/UDP/QUIC and WFP/BFE/SSH loss.

R19 multi-compartment provenance: NOT PROVED / NO-GO.
PacketBound/G2, no-DIRECT and leak-free: NOT PROVED.
Next permitted experiment: source-pinned negative suite on exact checkout
and read-only inspection of existing WFP filter definitions. No kernel
observation is authorized without separate owner driver/rescue/rollback gates.
No driver, filter, service, network, firewall, system safety, runner, automation,
main/release, beta, PR56 or other repository changed.
