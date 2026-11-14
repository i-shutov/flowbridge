# FlowBridge 0.3.0-beta.1 — independent A5 frozen artifact audit

Date: 2026-11-14. **Independent QA / legal A5 decision remains OPEN.**
No new binaries, no rebuild, no user machine operations, no native driver,
no installer execution, no automatic release. This work is staged on its
own Draft PR based on main; it does not alter frozen product PR #59.

## Why this gate matters

The candidate produced by run 43407093536 is already pinned to source
f5ecd48d8f81c594f755a55e7969b57d20903020 and 11/11 hosted PASS.
The distribution includes CycloneDX SBOM and dependency notices, but prior
validation was made by the same release assembler that produced the package.
A5 needs a **separate implementation** that reads original archived bytes,
not metadata invented by an auditor or an unpinned rebuild.

## Reproducible input

GitHub Actions artifact:
https://github.com/i-shutov/flowbridge/actions/runs/43407093536/artifacts/14028139291

The workflow uses actions/download-artifact, identifying original run and
artifact NAME independently of this source branch, then checks the inner
candidate ZIP SHA256:

    4b51d4136878476b48946361ce1635cb6d630e62b50ca82c73df28a5902ed8b8

Windows installer SHA256:

    74ff309d2e8ae115083bed9c5d4f233fd02dc841a8084a22912f3430c1e4b504

macOS pkg SHA256:

    7eb645e227442ba5a2d12bc1b9c5853212baf8a3d28e7215640f0e3e2ec0453c

No files from user profiles, private SSH keys, networking traces or
signing material are downloaded or included in the published JSON.

## Actual independent tests

tools/a5_beta_frozen_artifact_audit.py:

- Requires the exact source SHA, workflow/run number, candidate version,
  original inner kit SHA, declared ZIP entries and SHA256SUMS.
- Fails on ZIP traversal, duplicate paths/case aliases, symlink entries,
  extra/missing/modified files, forged owner/native acceptance flags,
  mutated original installers or metadata.
- Reads the original git source LICENSE from its source archive; if the
  source no longer states that the FlowBridge-specific license is
  unselected, the gate refuses to guess or approve a new license.
- Independently cross-checks both embedded SBOMs, counts (Windows 71,
  macOS 37), dependency refs, distinct BOM components, production source
  pins, full third-party notice hashes, license inventories and build
  metadata. Reports declared copyleft-family expressions for further
  human review, **without guessing actual obligations**.
- Does not claim exact linked binary contents, runtime OS/SDK license
  review, known vulnerability status, native code-signature approval,
  independent legal conclusion or publisher release readiness.

The unit suite builds synthetic adversarial archives to test rejection
paths. Fake fixture packages are **never** compared to genuine expected
installer hashes outside a patched local unittest scope.

Run:

    python -m unittest discover -s tests -p test_a5_beta_frozen_artifact_audit.py -v

When the original artifact ZIP and source archive have been downloaded:

    python tools/a5_beta_frozen_artifact_audit.py \
      --original-artifact-dir build/frozen-artifact \
      --report build/a5/a5-verdict.json

## Verdict contract and next external decisions

Even a successful original-byte audit returns only:

    TECHNICAL_A5_INVENTORY_PASS_LEGAL_AND_NATIVE_REVIEW_OPEN

It MUST preserve:
project_license_selected=false,
independent_license_review_passed=false,
native_sdk_runtime_distribution_review_passed=false,
security_vulnerability_audit_passed=false,
a5_accepted=false, release_accepted=false.

A5 closure still requires an explicit choice of license for FlowBridge's
own code, an independent review of license obligations across native
Windows C++/NSIS, Apple SDK/frameworks and Rust dependencies, code-signing
distribution decisions, security/vulnerability analysis and approval
of publication limitations. A3 Win10/11 and A4 Apple Silicon/Intel native
owner QA on the **same frozen package** also remain OPEN.

Publication A7 or version 1.0 remain NO-GO without independent A6
and subsequent owner GO. Do not create a release tag from this PR.
