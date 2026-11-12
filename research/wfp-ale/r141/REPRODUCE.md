# Reproduce R141 (offline only)

Requirements: Python 3.11+ and Node 18+; no admin rights, WDK, BFE, Rust compiler, sockets or VPN changes.

```shell
python research/wfp-ale/r141/test_r141.py
python research/wfp-ale/r141/r141_preflight.py
python research/wfp-ale/r141/r141_descriptors.py
python research/wfp-ale/r141/r141_lifetime_oracle.py
node research/wfp-ale/r141/r141_lifetime_independent.mjs
```

Expected Python unittest `36 tests, OK`; independent matrix `192` rows, SHA-256 `5b99f8a5d2147bb8f54704dbeec81fb89dbe30a684b19376236d1abe5651f4bf`.

No test is evidence of WFP runtime filtering. `R141_DESIGN_ONLY_DESCRIPTORS.json` is intentionally non-installable; it lacks selected AppId, concrete GUIDs, proven exception and permission to call management APIs. `R140_OWNER_RESULT.json` is a provenance-labeled *console excerpt*, not original host evidence bytes.

See `R141_PERSISTENT_GATE_ARCHITECTURE.md` for acceptance, source boundaries and staged authorization. `main` and any installed Windows filters remain untouched.
