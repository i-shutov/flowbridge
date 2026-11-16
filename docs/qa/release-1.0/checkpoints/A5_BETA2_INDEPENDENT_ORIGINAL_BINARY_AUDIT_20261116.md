# A5 — independent beta.2 original-binary inventory audit

**Status before CI:** QA tools authored and pinned to one **immutable original Actions artifact**. Review is deliberately divided into a **technical provenance/SBOM gate** that may become PASS and a **legal/native/security gate** that remains OPEN.

## Exact retained candidate

- [PR #76](https://github.com/i-shutov/flowbridge/pull/76) `0.3.0-beta.2` source `86583a1a0487b9d383c0122b24558e620bde5b9c`.
- Original verified [11/11 successful workflow attempt 2](https://github.com/i-shutov/flowbridge/actions/runs/43883696169), artifact [#14238314845](https://github.com/i-shutov/flowbridge/actions/runs/43883696169/artifacts/14238314845).
- **Inner kit SHA256:** `9980c786ceea82d2609b0229eca87b7f3ba044dc742466fedfa5e3b08e7585ae`. `FlowBridge-0.3.0-beta.2-candidate-86583a1a0487.zip`.
- **Windows installer:** `0699bed4acaa1b9df9b63c658808b08fd65b5953cacdaaddb7a13953389e19f4`.
- **macOS package:** `0b69658f053c2c5a95a1f456769a527aea91465bef5b194ebddbe71b4cdc815b`.

## Exactly what the independent script verifies

The original-byte Python stdlib-only tool `tools/a5_beta2_original_artifact_audit.py` reads the original kit and original accompanying source ZIP, **without installing or executing any binary**. It checks pinned source/run/version/installer hashes, ZIP path+traversal/casefold duplicate/symlink/size protections, exactly 21 declared content files plus index and SHA256SUMS, all file hashes and sizes, build metadata, Windows and Mac BOM structure, all component references and dependency graph edges, hashed notices, license-file inventory, and advertised unsigned/non-native-security limitations.

Source LICENSE **explicitly does not select a license for FlowBridge-specific code**. SBOM identifies 71 Windows and 37 Mac production/build components, with Rust dual-permissive and a Unicode license among other expressions; an inventory is *not* a binary-linkage legal determination, a security/vulnerability scan, or a native SDK runtime distribution determination. The audit must preserve those omissions and return `TECHNICAL_A5_INVENTORY_PASS_LEGAL_AND_NATIVE_REVIEW_OPEN` when valid.

The script is a beta.2-pinned adaptation of the previously accepted [PR #62 original beta.1 auditor](https://github.com/i-shutov/flowbridge/pull/62), with independent original beta.2 source/kit/package hashes. It does not modify beta.2 binaries or `main`. Its negative-control regression suite must still pass on Linux and Windows.

## Next mandatory decisions (not automatically waived)

1. **Owner license decision**: select project-specific distribution license (or explicitly define a proprietary end-user distribution agreement) before public distribution; retained notices must satisfy applicable dependencies and included tools. Do **not** simply tag the source while LICENSE says no distribution license has been selected.
2. Independent legal/native runtime review (toolchain and SDK redistributables, NSIS notices, copyright attribution, runtime link mode); separate dependency vulnerability review. Neither is proven by a CycloneDX file's existence.
3. Independent A6 final package and native A3/Win11 evidence, A7 explicit release approval; signed publisher release still absent. The original Windows owner V4 evidence was separately [reviewed 100/100](https://github.com/i-shutov/flowbridge/blob/docs/release-win10-vm910136-20261110/docs/qa/release-1.0/checkpoints/BETA2_OWNER_WIN10_A3_V4_INDEPENDENT_REVIEW_20261116.md), but one invalid private-key-path negative on final beta.2 remains.
4. Windows 1.0 WFP/ALE signed driver, native socket attribution, fail-closed, DNS/UDP, Win10/Win11 24h soak remain **NO-GO** independent of A5.

This branch is an **independent reviewer tool**, not a release branch or a replacement candidate. A5/legal/release flags remain false regardless of technical PASS.
