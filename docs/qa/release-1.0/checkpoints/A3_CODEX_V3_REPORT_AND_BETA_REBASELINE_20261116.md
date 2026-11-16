# A3 CodeX V3 first functional results and beta candidate decision — 2026-11-16

**Source:** user-pasted Codex V3 report. **Original evidence ZIP not supplied to this review**; claims below are marked `OWNER_FORWARDED_CODEX_REPORT`, not independent tester acceptance.

## Observations as reported by local Win10 Codex

- Fix developed in **local-only** branch `codex/a3-ssh-status-layout`, source commit `7ac6ef0ef5d4fb61e275e8a6c9f222893b7dd341`; QA GUI test ran executable with SHA beginning `82c308…483d`. After a comment-only commit and rebuild the reported new EXE SHA began `30f855…550b`; **the latter EXE was NOT executed**.
- Original frozen GUI has the observed layout defect: `native/windows/main.cpp::showSsh` assembles a multiline SSH summary containing last error, worker/resource details and backend paths. Codex states it limited headline to one line and moved diagnostics to event log; reported Ready/Failure/980×680 GUI visual pass **only for earlier QA executable**.
- Managed SSH/real loopback via original frozen DLL FFI: actual C ABI process, SOCKS echo, half-close/EOF both directions and Stop reported PASS. Negative unavailable-SSH and all-down reported; SOCKS failure `01` observed after **30.012 s** recovery window, no direct local echo accepted in that test. Wrong key path reports generic publickey rejection. Other matrices may have been run, but **only the assertions in submitted report are credited**.
- Original 4 profile files, ACL, attributes, timestamps and registry reported restored; no lingering child/test processes. Evidence archive reported at a **local Windows path only**, filename `A3-Codex-V3-20261116T044227Z.zip`, SHA256 `8cf08b80a6d3e4d595cd2b33cf43eb6628cecf61e1c1940295d7d13de16883c6`, 41 contained files hash-manifest reportedly valid.
- **Independent check now:** connected public GitHub returned `404 Branch not found` for `codex/a3-ssh-status-layout`, and `422 No commit found` for `7ac6ef0ef5d4fb61e275e8a6c9f222893b7dd341`. No remote PR/CI can yet review it; the C:\\ local evidence path is not accessible from GitHub review.

## Release implications

1. **Do not retroactively alter original frozen `0.3.0-beta.1` identity**. Exact old candidate source `f5ecd48d8f81c594f755a55e7969b57d20903020` and kit ZIP SHA256 `4b51d4136878476b48946361ce1635cb6d630e62b50ca82c73df28a5902ed8b8` retain original 6/6 automation and original GUI layout defect. Its A3 full GUI acceptance remains `false`.
2. A **new, uniquely versioned Windows beta candidate**, e.g. `0.3.0-beta.2` if a version bump is approved in release pipeline, is required to consume any GUI fix. Every source, installer, binary, JSON, artifact, SHA/CI run must identify the new exact candidate; no claim that the old A3 kit tested the new binaries.
3. Codex should push the private local branch to `i-shutov/flowbridge` after checking the remote, working tree, and diff provenance; open **Draft PR** based on the appropriate original beta source (or a newly cut beta-next branch) and isolate only GUI fix + regression tests, no WFP/driver changes.
4. Run real native GUI, Ready/Failure at 980×680 and target 1366×768, keyboard navigation/Save/Cancel/reload, and exact installer/payload/SSH/SOCKS5h/host-key/all-down/Stop against **the same final newly built EXE**; only then accept GUI. CI/WS can be parallel but not substitute for executed final bytes. Independent report must audit exact-head source→binary→kit mappings.
5. Obtain original V3 evidence archive for SHA verification (owner upload or secure private transport) and sanitized report; avoid raw secrets or private paths in public GitHub. Preserve originals, don't rewrite.
6. Full 1.0 Windows WFP/ALE G2 and physical no-DIRECT/DNS/Win11 gates remain OPEN; this A3 beta GUI fix cannot satisfy them.

**Current verdict:** `A3_SSH_REPORTED_PASS_INDEPENDENT_REVIEW_OPEN`, `A3_GUI_FROZEN_KNOWN_DEFECT`, `NEW_CANDIDATE_EXACT_BINARY_NOT_TESTED`, `A3_FULL_ACCEPTED=false`, `RELEASE_APPROVED=false`. Further work should begin with *publish source and evidence provenance* and *retest exact new artifact*, not requesting the owner to click GUI.

## Codex next task

See [A3_CODEX_V4_FINAL_CANDIDATE_HANDOFF_20261116.md](A3_CODEX_V4_FINAL_CANDIDATE_HANDOFF_20261116.md).
