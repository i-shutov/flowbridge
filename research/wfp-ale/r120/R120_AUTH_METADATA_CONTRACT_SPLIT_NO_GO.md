# R120 — AUTH_CONNECT metadata-contract split: conditional FAIL-CLOSED, native NO-GO

Date: 2026-11-12. Scope ONLY `research/windows-wfp-ale-attribution-20261107` in `i-shutov/flowbridge`. Parent research HEAD `2267ac532bb8ac8ad62e02ee647a1f9c8ea5e188`; read-only main `5b5afc2feeda2195f302380e615ba003d4906e09`. Independent R&D, NOT beta, PR #56, release, PacketBound/G2 PASS, leak-free or historical G1.

## Material Microsoft documentation disagreement

The official [Metadata fields at each filtering layer](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-fields-at-each-filtering-layer) (last updated 2021-12-15) lists `FWPS_METADATA_FIELD_PROCESS_ID` and `FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE` for `FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6`, but NOT `FWPS_METADATA_FIELD_LOCAL_REDIRECT_TARGET_PID` or `FWPS_METADATA_FIELD_ORIGINAL_DESTINATION`. The per-layer table describes *possible* fields and notes conditional availability.

However [Using Bind or Connect Redirection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection) (last updated 2024-09-27), "Handling Connect Redirection from Multiple Callouts", explicitly instructs a redirect callout at AUTH_CONNECT to inspect both latter metadata fields when `FWP_CONDITION_FLAG_IS_CONNECTION_REDIRECTED` is set. That page also uses the apparent typo `FWPS_METADATA_FIELD_LOCAL_REDIRECT_TARGET_ID` once, whereas its other references and the [Metadata field identifiers](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/metadata-field-identifiers) use `..._PID`.

These documents are inconsistent if the first table is read as an exhaustive layer contract. **This does NOT prove the fields are absent on actual Windows, nor that Windows failed.** A native valid-bit observation is missing; management-plane BFE enumeration cannot settle it. R108 previously recorded the basic gap; R120 pins the conflicting authoritative clauses and makes the consequence executable.

## Frozen R19 source condition and evidence

`research/wfp-ale/kernel-r19/kernel/src/redirect.rs` Git blob SHA-1: `9a07e026134d46ef646d39862bd982cc48bbc5f6`, unchanged. `auth_check` at AUTH_CONNECT v4/v6 requires ALL FOUR currentMetadataValues flags:
`PROCESS_ID` + `TRANSPORT_ENDPOINT_HANDLE` + `LOCAL_REDIRECT_TARGET_PID` + `ORIGINAL_DESTINATION`. It also requires a non-null `originalDestination`; false returns fail-closed BLOCK via `auth_classify`. The selected original AppId, TCP/6, redirect flag, no reauthorization, live broker lease, same-process PID+epoch and one-time kernel ticket are separate gates. Ten static source predicates were verified against the pinned Git blob (10/10 PASS), not against a live callback.

The 2021 table's *listed subset* among these four fields is mask `0b0011`. All four required bits have mask `0b1111`. If only the table-listed subset were ever available, a legitimate redirected selected TCP AUTH callback would fail. The 2024 redirection guidance allows a contrary runtime outcome. **Native applicability remains UNKNOWN**, not categorical BLOCK or PASS.

## Independent runnable negative witnesses, no driver

- `r120_metadata_contract_negative.py`, independent Python predicate and 4096 ordered cases.
- `r120_metadata_independent.mjs`, independent Node.js Set-based model, same 4096 ordered cases.
- Axes: v4/v6; all 16 subsets of four metadata flags; redirected/reauthorization; live lease; matching ticket; same process epoch; selected opaque original AppId; TCP/UDP.
- Conditional synthetic branch permits 2, rejects 4094; table-only mask permits ZERO. Neither conditional permit is a native Windows PASS.
- Independently matching ordered matrix SHA-256: `a6efa1073d7eab9af53456dd0f63f4ee85b7fc8930c541b692ad484c3b43901d`; result objects semantically equal.
- Run: `python3 research/wfp-ale/r120/r120_metadata_contract_negative.py` and `node research/wfp-ale/r120/r120_metadata_independent.mjs`.

These are source-contract negative tests and cross-language oracle verification, NOT Rust compilation or WFP observation.

## Exact trust boundary and GO/NO-GO

Required design: `FwpmGetAppIdFromFileName0` and opaque `FWPM_CONDITION_ALE_APP_ID` selected image → same kernel `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4/V6` classification with valid `FWPS_METADATA_FIELD_PROCESS_ID`, referenced `EPROCESS` and safe IRQL/creation epoch (`PsLookupProcessByProcessId`, `PsGetProcessCreateTimeQuadPart`), canonical EXE, original v4/v6 destination → `FwpsQueryConnectionRedirectState0` and owned `FWPS_CONNECT_REQUEST0`/redirect context → actual accepted socket `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS/_CONTEXT)` → verified one-use receipt and process epoch → outbound socket `WSAIoctl(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS)` *before connect* → independent `FWPS_LAYER_ALE_AUTH_CONNECT_V4/V6` enforcement including reauthorization and sibling DIRECT. Never substitute retrospective PID, 5-tuple, timestamp, ETW or IP Helper correlation.

Native classification for metadata validity is **NO-GO**; so are process death/PID reuse, repeated 5-tuple, sibling DIRECT, both IP families, DNS/UDP/QUIC, lost WFP/BFE/SSH, kernel ownership, record-to-socket provenance and no-DIRECT/leak-free. R120 makes no PacketBound/G2 claim.

**Next decisive experiment, NOT authorized by this R&D:** only after owner's driver/signing/VNC/SYSTEM rescue/rollback gates on a disposable Windows x64 VM, capture `FWPS_INCOMING_METADATA_VALUES0.currentMetadataValues` at a genuine selected initial AUTH_CONNECT v4/v6 callout, record the two disputed values (if valid), layer, redirect flag, owner PID+creation epoch, socket/record outcome. Already permitted user-mode Rust compile/read-only BFE inventory is an ABI/management diagnostic and cannot replace this. No driver or WFP experiment performed.

Do not touch main/release, integration/windows-rust-capture-agent-20261031, PR #56, runners, services, firewall/UFW, Defender, SecureBoot, MemoryIntegrity, network, other repos, schedules/automations, controller. No drivers/callouts/NDISRD/filters/VNC, ProxiFyre AGPL, closed PR40, vendor binaries, C++ WFP payload, signed-driver activity, or paid operations. Only expected-SHA/force=false research ref updates.
