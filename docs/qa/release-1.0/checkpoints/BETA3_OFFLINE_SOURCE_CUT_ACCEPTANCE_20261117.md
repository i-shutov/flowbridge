# FlowBridge — beta.3 private-local SOURCE CUT accepted in CI (NOT installer/release)

**Date:** 17 November 2026. Owner policy: **proprietary / internal-only / Win10 Pro 22H2 x64 ONLY**. Windows 11/macOS release QA deferred, not passed. The GitHub repository remains public pending owner's planned Private switch; **do not create a new proprietary binary artifact on the public CI runner**.

## Immutable product and CI provenance

- Original **beta.2** source `86583a1a0487b9d383c0122b24558e620bde5b9c`, installer SHA256 `0699bed4acaa1b9df9b63c658808b08fd65b5953cacdaaddb7a13953389e19f4`, candidate [11/11 original CI](https://github.com/i-shutov/flowbridge/actions/runs/43883696169) and owner Win10 V4+V5 original evidence: unchanged, valid only for original beta.2, **privacy/trust P1 not fixed in this EXE**.
- Selected **security source** for new local beta.3: `44e3ba988ac5a9f7cf2d25b16d46c432ff3d8c38`, stacked [raw SSH stderr privacy #84](https://github.com/i-shutov/flowbridge/pull/84) and [Microsoft-signed OpenSSH launcher #88](https://github.com/i-shutov/flowbridge/pull/88).
- **Same source** [targeted Rust/Linux/Windows + Win32/FFI CI #44076875289](https://github.com/i-shutov/flowbridge/actions/runs/44076875289): 3/3 SUCCESS. [Full rust-and-native CI #44076875466](https://github.com/i-shutov/flowbridge/actions/runs/44076875466) **attempt 2 SUCCESS 5/5** after targeted rerun of only the canceled macOS Rust job, unchanged source bytes; original [Windows real OpenSSH #44076875435](https://github.com/i-shutov/flowbridge/actions/runs/44076875435) managed and raw jobs both SUCCESS. This does **not** prove raw 512 guaranteed on every host, nor physical WFP/G2.
- New [Draft PR #89](https://github.com/i-shutov/flowbridge/pull/89), QA-source commit **`cb3b257d6628adea2b3f1585e46875d074c18b3a`**, [test-only CI #44088189435](https://github.com/i-shutov/flowbridge/actions/runs/44088189435) **SUCCESS 2/2 on Ubuntu 24.04 and hosted Windows 2025**.

## Exactly what the new beta.3 stage CI proves

1. The **FULL actual security source** `44e3...` is checked out separately from the release-governance QA tool; wrong source SHA or dirty source fails closed. 5 adversarial/mutation fixtures on version contract, cargo package set, archive traversal/symlinks, no-remote Git and unsupported OS requests succeed on both platforms.
2. Source is archived under a new independent **LOCAL-only standalone Git repository with NO remotes**, no accidental push route to public origin; exactly nine version contract carrier files are rewritten. `Cargo.toml` now has `0.3.0-beta.3`, exactly seven own-code path packages in `Cargo.lock` are `0.3.0-beta.3`, third-party versions/checksums retained, platform installer names `...beta.3...`, Windows file version `0.3.0.3`, Mac bundle version `3.0.3`. Beta user profile namespaces retained, license not silently changed or made open source. All internal `release_approved` flags stay `false`.
3. **Original `tools/explicit_beta_metadata.py::check_versions`** validates the new standalone commit, not just a synthetic fixture.
4. **`cargo check --locked --workspace` and `cargo test --locked -p flowbridge-tunnel --lib -- --test-threads=2`** execute against that **new locally versioned beta.3** on both GitHub Windows and Linux, and PASS. No new driver or global network changes.
5. **NO Windows NSIS installer was produced**, no new private executable was uploaded in Actions, no user Win10 GUI/SSH re-acceptance and no A5/A6/A7 security/publisher GO. Tests run under temporary directories removed by CI, not host production targets.

## How an authorized local Codex can take the next step

Use [`tools/stage_internal_beta3.py`](https://github.com/i-shutov/flowbridge/blob/qa/internal-beta3-offline-cutter-20261117/tools/stage_internal_beta3.py) from **a separate QA tooling checkout** and [full runbook](https://github.com/i-shutov/flowbridge/blob/qa/internal-beta3-offline-cutter-20261117/docs/qa/release-1.0/checkpoints/BETA3_OFFLINE_PRIVATE_STAGE_20261117.md). `--source` **must** be a clean local product checkout whose SHA is exactly `44e3ba988ac5a9f7cf2d25b16d46c432ff3d8c38`, **not** the QA tooling branch.

With a NEW output folder (never reuse):

```powershell
python "$qa\tools\stage_internal_beta3.py" --source $src --out-dir "$privateDestination"
# Only after a separate owner-approved QA build decision, on real Win10 Pro 22H2 x64:
# python "$qa\tools\stage_internal_beta3.py" --source $src --out-dir "$anotherNewPrivateDestination" --build-windows
```

This locally opted-in builder invokes the existing **`build-explicit-beta.py`** (Rust locked FFI/CLI, native CMake explicit-only, NSIS) and checks SHA/source/driver-free manifest. It emits the local candidate and a checkpoint but does **not** install it or upload anything. If NSIS/Rust/MSVC or Win10 environment are missing, it stops without claiming a release.

## Precise remaining blockers (NO-GO)

- [Owner-controlled repository privacy #83](https://github.com/i-shutov/flowbridge/issues/83) still OPEN, existing public Git clones/artifacts cannot be retracted; no private binary uploaded.
- New **actual** native Windows 10 x64 installer beta.3 is **not built**; therefore there is NO new installer SHA, no new exact owner GUI/SSH + host-key/invalid-key, Stop, ACL/registry/upgrade/uninstall original evidence, no independent reviewer signoff. Old beta.2 A3 cannot be promoted.
- On actual owner Win10, signed SSH path/Authenticator and ESU Year2 patch state read-only checks remain NOT_RUN. Win10 security updates matter for internal pilot. [Codex read-only preflight handoff](https://github.com/i-shutov/flowbridge/blob/qa/win10-internal-security-inventory-20261117/docs/qa/release-1.0/checkpoints/WIN10_A5_A6_READONLY_SECURITY_PREFLIGHT_CODEX_20261117.md).
- A5 third-party/native SDK rights, A6 formal native Win32/SSH security/privacy, A7 **explicit internal deployment GO** not granted. Public Release/tag forbidden, current code still proprietary; no MIT/Apache license grant. Windows 1.0 full WFP/G2 signed kernel socket authority/physical no-DIRECT/DNS/UDP remains **NO-GO**, unaffected by SSH-only beta QA.

**Truth flags:** `beta3_private_source_cut_ci_pass=true`, `beta3_cargo_locked_compiles=true`, `beta3_installer_built=false`, `beta3_owner_win10_a3_accepted=false`, `a5_a6_a7_go=false`, `wfp_g2_accepted=false`. No release published.
