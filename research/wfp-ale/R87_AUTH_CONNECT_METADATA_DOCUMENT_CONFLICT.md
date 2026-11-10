# R87 — ALE_AUTH_CONNECT metadata contract conflict (conditional evidence gate)

2026-11-10. Scope: `i-shutov/flowbridge` **research/windows-wfp-ale-attribution-20261107 only**. Independent architectural research; not beta, PR #56, PacketBound/G2 PASS, leak-free, or transfer of historical G1 at dd1ab3c.

## Source pins and exact baseline

At research start: `24d64cc8c5784fb3b54155345656f2739730b16b`; `main` `5b5afc2feeda2195f302380e615ba003d4906e09`.
R19 Rust source `research/wfp-ale/kernel-r19/kernel/src/redirect.rs`: Git blob `9a07e026134d46ef646d39862bd982cc48bbc5f6`.
R19 BFE policy `research/wfp-ale/kernel-r19/policy_windows.rs`: Git blob `acf60334320d970f58af3349ee75fbaa59826602`.
R86 source-rights investigation: `research/wfp-ale/R86_VETO_PROVENANCE_ORACLE_CORRECTION.md`.

The actual R19 `auth_check` serves **both** `FWPS_LAYER_ALE_AUTH_CONNECT_V4` and `V6` and demands, simultaneously:

- `FWPS_METADATA_FIELD_PROCESS_ID`
- `FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE`
- `FWPS_METADATA_FIELD_LOCAL_REDIRECT_TARGET_PID`
- `FWPS_METADATA_FIELD_ORIGINAL_DESTINATION`

The hard guard `m.currentMetadataValues & needed != needed` returns `false` if **either** of the last two bits is missing. A later check requires a non-null `m.originalDestination`, and `m.localRedirectTargetPID` is checked against the broker PID. `auth_classify` blocks on an unsuccessful `auth_check`.

## Two official Microsoft contracts are inconsistent, not proof of runtime absence

- Microsoft, [Metadata fields at each filtering layer](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer) (page last updated 2021-12-15): the `ALE_AUTH_CONNECT_V4/V6` row includes PROCESS_ID and TRANSPORT_ENDPOINT_HANDLE **but lists neither** LOCAL_REDIRECT_TARGET_PID nor ORIGINAL_DESTINATION. Its introduction describes the table as the *possible* fields by layer.
- Microsoft, [Using Bind or Connect Redirection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection) (last updated 2024-09-27), specifically instructs ALE_AUTH_CONNECT redirection callouts to inspect **both** LOCAL_REDIRECT_TARGET_PID and ORIGINAL_DESTINATION for redirected indications (lines 197–203). This is a more specific affirmative assertion than the generic inventory. The same paragraph contains an apparent `..._TARGET_ID` naming typo; the actual field in the other sentence and metadata identifier list is `..._TARGET_PID`.
- [Metadata field identifiers](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-field-identifiers) defines both fields, but definition of a bit is **not** proof of its presence on a given callback or Windows build.
- [FWPS_FIELDS_ALE_AUTH_CONNECT_V4](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ne-fwpsk-fwps_fields_ale_auth_connect_v4_) separately documents original AppId since Windows 8; this is an incoming value, **not** a substitute for the two missing metadata items in the generic list.

**Conclusion:** a source + documentation **inconsistency and a test prerequisite** are confirmed. It would be incorrect to infer that Windows never supplies these fields, because Microsoft explicitly documents the opposite in the specialized redirection guide. It is equally incorrect to declare their availability natively proven. This is a **conditional evidence gate**, not a demonstrated R19 bug, not a leak, and not a new positive WFP proof.

## Deterministic negative audit and independent verification

`r87/r87_metadata_negative.py` reads the R19 Rust source and checks its field conjunction against a pinned transcription of the generic AUTH_CONNECT metadata row and the two redirection-guide fields. Independent `r87/r87_metadata_independent.mjs` parses the same Rust declaration separately.

Local offline execution: Python **4/4 PASS**; Node independent result agrees on four required fields, exactly two fields absent from the generic row, and full coverage when the redirect-specific guide is included. Common canonical SHA-256 `05aa001a1064774548ede910885c4ace51b6651db40185649ae7acf0abe8fd99`. Local smoke execution used a narrowly extracted source fixture; **the full published Git blob was separately parsed through the GitHub connector** and yielded the identical field set and guard. No claim that a local fixture is the full source. Running tests from a full repository checkout uses the real source automatically.

The tests are documentation/source contract checks only: no driver loading, WFP filters/callouts, network, Windows execution, or physical packet observation.

## Decision, trust chain, and next decisive experiment

Existing **NO-GO** for original kernel process/epoch/AppId → ALE redirect → AUTH_CONNECT attest → real accepted SOCKET WFP context/records → one-shot CLAIM → SSH, along with PID/endpoint/5-tuple reuse, sibling DIRECT, DNS/UDP/QUIC, IPv4/IPv6 coverage and WFP/BFE/SSH loss, remains in force. A correctly scoped `FwpmGetAppIdFromFileName0` / `FWPM_CONDITION_ALE_APP_ID` filter does not attest a canonical EXE. `FWPS_METADATA_FIELD_PROCESS_ID` plus a process-create reference, `PsGetProcessCreateTimeQuadPart`/start key, and trusted endpoint generation would be necessary; `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/CONTEXT)` must operate on the actual accepted socket; `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` must be carried to the outbound proxy socket. No receipt-to-accepted-socket cryptographic proof exists.

**Next experiment permitted without driver:** native compile/read-only WinSock negative baseline on separately authorized Windows x86_64 for exact R83 Rust blob. **Actual R87 metadata-availability proof** would require inspecting kernel classify indications on both IP families and OS builds, and is **not authorized**: any WFP callback/filter/driver test needs separate owner decision with driver/VNC/SYSTEM rescue and rollback gates. Until then, preserve conditional evidence gate and do not certify positive AUTH or PacketBound.

No changes to `main`/release/beta branch/PR #56, runners, services, firewall/UFW, Defender/SecureBoot/MemoryIntegrity, networks, other repos, automations, paid services; no ProxiFyre AGPL, PR40, vendor binary, C++ WFP payload, or signed-driver work.
