# R94 — unregistered callout false-positive in read-only BFE inventory

Date: 2026-11-10. Scope ONLY: i-shutov/flowbridge, branch research/windows-wfp-ale-attribution-20261107. Architecture R&D, not beta, not PR #56, not release/PacketBound/G2/no-DIRECT/leak-free acceptance.

## Exact baseline / verified source hypothesis

Research parent: a0ea696007b1527e612996918966c8012f9bcbf4. Read-only main: 5b5afc2feeda2195f302380e615ba003d4906e09.
Original R93 Rust inventory blob: bf3580bbc8aa0d68ffd0041755ab244f008ef5dd. Original R19 policy_windows.rs blob: acf60334320d970f58af3349ee75fbaa59826602.

R93 checked four R19 BFE filter and four management callout GUIDs, but exit 0 did NOT require kernel registration: it merely printed callout flags. Therefore all eight management objects could match shape while every kernel callout is unregistered and R93 would have returned success. R19's installation path explicitly checks FWPM_CALLOUT_FLAG_REGISTERED, so R93's diagnostic was weaker than its underlying policy.

The Windows SDK defines FWPM_CALLOUT_FLAG_REGISTERED = 0x00040000 (fwpmtypes.h); Microsoft's FWPM_CALLOUT0 documentation says this query-only bit indicates current kernel registration. Microsoft's FwpsCalloutRegister0 documentation says filters invoking an unregistered callout with FWP_ACTION_CALLOUT_TERMINATING or FWP_ACTION_CALLOUT_UNKNOWN are treated as BLOCK (unless specific filter flags change behaviour). R19's four filter flags were zero. This is an availability/diagnostic false-positive, NOT proof of physical traffic handling, DIRECT escape or kernel-origin identity.

## Implemented correction

Research-only change to research/wfp-ale/r93/r93_readonly_policy_inventory.rs; the existing five read-only Fwpm* FFI calls remain the entire native API surface. No WFP mutation or network socket is introduced.

For each callout, successful GetByKey, non-null returned pointer and (flags & 0x00040000) != 0 are now required to set kernel_registered. The JSON has independent inventory_shape_complete, registered_snapshot_complete and snapshot_gate_complete fields. Exit 0 requires both shape and registration for all four callouts. Missing, failed or unregistered observations return exit 3; unrelated flag bits do not mask a registration. One Rust unit test is added. These are point-in-time, non-atomic observations and are NOT an enforcement barrier.

## Deterministic independent negative proof

Two separately implemented specifications, Python and Node, enumerate 256 object-presence masks x 16 shape masks x 16 registration masks = 65,536 rows.
Legacy shape-only gate: 16 synthetic positives, including 15 with one or more missing registrations.
Repaired shape+registration gate: exactly 1 synthetic positive; the other 65,535 fail closed.
Canonical ordered matrix SHA-256: ecac7e55eeeeebeefbe95f9a15beea9fc4e2a3ec3a7ead7ae40e60f302902f61.

The two specifications were independently executed in a local scratch environment with matching SHA-256. The source-guard test was initially exercised against a representative snippet, NOT an exact checked-out Git source; exact published-file test execution and Windows native compilation remain pending. The amended Rust text and Git blobs must be checked after branch publication. Thus these are deterministic logic tests, not native BFE proof.

Commands from complete checkout:
python3 research/wfp-ale/r94/r94_registered_gate_negative.py
node research/wfp-ale/r94/r94_independent_oracle.mjs
On an already-authorized Windows x86_64 host with pre-existing Rust toolchain, compile the exact updated r93 Rust source and run its tests, then perform read-only BFE inventory with OS build, caller identity/permissions, binary SHA-256, JSON/exit status. No driver/filter, install or privileged system change is authorized.

## Trust boundary / next experiment

A registered bit cannot certify the registered classifyFn's identity or behaviour, the filter action/conditions, active redirect path, atomic continuity or system-wide DIRECT denial. Full NO-GO: canonical EXE/AppId and PID+creation epoch from the same kernel ALE_CONNECT_REDIRECT v4/v6 event; original endpoint/scope; AUTH_CONNECT provenance/rights; WSAIoctl SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT on the actual accepted socket; one-shot CLAIM; SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS before physical authenticated SSH connect; process death/PID reuse; re-used five-tuple; source bound sockets; sibling DIRECT; UDP/DNS/QUIC; IPv4/IPv6; WFP/BFE/SSH loss. R87-R92 also remain open.

Official documentation:
https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_callout0
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscalloutregister0
https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
SDK macro check ONLY: https://github.com/tpn/winsdk-10/blob/master/Include/10.0.10240.0/shared/fwpmtypes.idl

No main/release/beta/PR #56, runner, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, networks, other repositories, automation schedules/state, controller, kernel driver/callout, WFP filters, NDISRD, VNC, signed driver, ProxiFyre AGPL, closed PR40, vendor binaries, C++ payload or paid operations are touched.
