# FlowBridge 0.3.0-beta.2 — independent owner Win10 A3 V4 archive review

**Reviewed 2026-11-16.** Owner-original 7.0 MB V4 ZIP was supplied directly to the conversation, not inferred from a local C:\ path. Offline audit status: **`EVIDENCE_INTEGRITY_AND_CROSS_SOURCE_CONSISTENCY_PASS`**. This verifies the integrity/coherence of submitted original QA evidence, **not** independently rerunning GUI/SSH or cryptographically attesting the physical host.

## Source, artifact, and independent evidence hashes

| Provenance | SHA / immutable ID |
| --- | --- |
| Final source commit | `86583a1a0487b9d383c0122b24558e620bde5b9c` |
| Source tree | `9f92e9e9e87725d127505c8ac415f37e42a8d148` |
| [Full candidate CI](https://github.com/i-shutov/flowbridge/actions/runs/43883696169) | **attempt 2: SUCCESS, 11/11 jobs** |
| [Official verified candidate artifact #14238314845](https://github.com/i-shutov/flowbridge/actions/runs/43883696169/artifacts/14238314845) | outer ZIP SHA256 `8ab897935e48f02bf7e3524db36b6601985184c6e151af505c209f414c8ddfb8` |
| Frozen beta.2 candidate inner kit | SHA256 `9980c786ceea82d2609b0229eca87b7f3ba044dc742466fedfa5e3b08e7585ae` |
| Windows installer | SHA256 `0699bed4acaa1b9df9b63c658808b08fd65b5953cacdaaddb7a13953389e19f4` |
| Final GUI EXE | SHA256 `0cf1749e7531659b1f5a42433818ecf31fe517d6815d11faeca6e04f9821325e` |
| FFI DLL | SHA256 `23b62d54a89feea53331f3ac68fe7c3d348ca99ed72d816f3dcfbc94ef3fd2b4` |
| Original owner V4 submitted ZIP | SHA256 **`23844631907f96063f0b13db73a835b92c386a4be3ed13a174c484c3139606e2`** |
| Independent audit verdict JSON | SHA256 `88086df63281c54a9bb3f23d6620ce33fa49eaef09d8b1334847e7be1b6abbda` |
| Independent auditor Markdown report | SHA256 `02c75c757bf2975c6cacf2e73a4160bb31325e4a5bf5421631501cb9519bb287` |
| Private independent audit bundle (user handoff) | SHA256 `485703093d1bed89de32960d47012c65a041a34d042c1efc42855c2af8e88606` |

## Independent checks of supplied bytes

- Outer ZIP: **CRC PASS**, no duplicate/traversal/symlink unsafe paths. **101 ZIP entries = 100/100 original manifest files with exact matching sizes/SHA + 1 manifest**; zero missing or extra.
- Embedded original V3 ZIP: full source SHA256 matched original `8cf08b80a6d3e4d595cd2b33cf43eb6628cecf61e1c1940295d7d13de16883c6`, its inner **41/41** file sizes/SHA verified, CRC PASS.
- Nested official Windows GitHub Actions ZIP SHA256 `1cb5ceef10609f5921ea376a496819ece5915b8fe55e281862f1fdc356362b90` agrees with separate public Actions artifact. The actual installer and **13/13 binary/manifests payload** hashes/lengths verified in that inner ZIP.
- Native Win10 `lifecycle/native-acceptance.json`: **six lifecycle phases PASS on exact final source/installer**, `owner_native=true` based on operator-provided metadata, `a3_a4_full_acceptance=false`. All 5 QA BMP SHA matched JSON.
- **17 original GUI PNGs** independently decoded; action-specific screenshot metadata and 980×680 / 1366×768 (plus 1180×760) dimensions match. Original action log, HWND/PID/control metadata and PowerShell script source are present. Manual visual audit observed Ready, Failed, Reconnecting, Journal, Save/Apply/Cancel; compact SSH status appears as one line at 980×680, the long top error banner ellipsizes intentionally and full text appears in event journal. Screenshots/redacted identity fields are **not committed to public GitHub**.
- Actual `ssh/gui-echo.json` and `ssh/ffi-result.json` match final DLL/GUI SHA; SOCKS5 `ATYP=DOMAINNAME` for `localhost`, exact binary up/down `0001027F80FEFF410042`, both EOF, FFI Stop and zero listeners reported. Four negatives all reported `SOCKS_REPLY_1` with no local DIRECT target accepted. GUI all-down `0501...` after **30,011 ms**, target did not accept bypass. These are original test-harness observations, **not independent re-execution**.
- `restore-checks.json` / `cleanup.json`: owner-script recorded all pre/post beta/stable SHA, ACL, timestamps, attributes and file count matches, registry export identical, no leftovers. Reviewer did not directly interrogate owner's host.
- **Whole candidate CI** rechecked independently: initial attempt 1 failed on a canceled macOS packaging runner; after targeted retry the unchanged source commit **attempt 2 completed SUCCESS (11/11)**, resulting unified signed? **NO:** Windows installer unsigned, Mac package ad-hoc. This resolves the earlier V4 report's historical `whole_ci: NOT_GREEN` snapshot, not other acceptance gates.

## Exact exit boundaries

| Gate | Decision |
| --- | --- |
| A3 V4 *original archive and executed scenario evidence* | **EVIDENCE_REVIEW_PASS_WITH_GAPS** |
| A3 Win10 tested GUI/SSH subset | **ORIGINAL_EVIDENCE_CONSISTENT_PASS**, subject to independent native host attestation limits |
| A3 full acceptance / beta.2 released | **FALSE / NO_GO**. User/QA omitted the final beta.2 **invalid private-key path** negative case; it passed only on original beta.1 V3. Need either execute on final beta.2 or explicitly document reviewed scope exclusion |
| Separate Win11 owner-native | **NOT_RUN** |
| A5 project-specific `LICENSE`, independent security/legal/native review | **OPEN** |
| A6 independent release approval / A7 publication | **OPEN / NOT_RELEASED** |
| Raw OpenSSH 512 held | **NOT_PROVED**. Earlier failed at ~244, another only met 128 minimum with peak 246. No universal backend ceiling inferred |
| Windows-first 1.0 WFP/ALE G2, selected app physical no-DIRECT and DNS/UDP leak proofs | **NO_GO; outside beta A3** |

**Important:** The exact official candidate kit currently has `A3_owner_windows=NOT_RUN` because the CI system does not ingest owner-original private V4. This separate reviewer checkpoint records the later uploaded user evidence; it does not mutate or forge GitHub's original candidate index.

**Private deliverables:** self-contained offline stdlib read-only auditor `verify_v4.py`, verdict JSON, detailed MD, private GUI contact sheet. Only these sanitized SHA references are written to the public repo; do not upload original 100-file V4 ZIP or screenshots.

**Next:** one small final beta.2 invalid-key-path negative (or explicit documented QA scope decision), independent A3 sign-off, separate Win11, license/legal A5, A6 review and explicit owner A7 GO. Do NOT reopen already passing 100-file integrity checks, and do NOT install WFP/NDISRD or change DNS/Defender/firewall in beta.
