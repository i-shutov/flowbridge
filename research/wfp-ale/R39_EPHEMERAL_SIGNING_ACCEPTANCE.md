# R39-DEV: verified ephemeral x64 SYS+CAT test-signing rehearsal

Date 2026-11-08. Branch `feat/r39-win11-dev-lab-20261108`;
draft PR [#57](https://github.com/i-shutov/flowbridge/pull/57).
No user Windows Server, no local user Windows host or production policy changed.

## Verified execution (not an implementation plan)

- [GitHub Actions 42477876753](https://github.com/i-shutov/flowbridge/actions/runs/42477876753),
  exact source `54328b8e13da7fadea1f2d284835793995d1a437`:
  **completed SUCCESS** on disposable GitHub-hosted Windows 2025.
- Downloaded original no-load candidate from [Actions 42465140005](https://github.com/i-shutov/flowbridge/actions/runs/42465140005).
  Original unsigned SYS SHA256 `c613fd1d98a9a4e22d6551f07143c7821263df2732c3e25bae2543b1ca7d4c00`;
  INF `29b62d0272436d62098d2514a6586db171261faaa58c9ac31a271518f3c5fbdd`;
  broker `295bc4b74c42e95f3f94d7576bfba7a4e1aeee4e2ba52dc2c84f007d703ac2bb`.
  All matched before the temporary certificate existed.
- Microsoft SignTool embedded an ephemeral self-signed TEST signature
  in a separate staged SYS. `Inf2Cat.exe` from **official pinned
  Microsoft.Windows.WDK.x86 10.0.26100.6584** created an x64 Win11
  25H2 catalog `FlowBridgeG2R38.cat` and SignTool signed it.
- The signer of BOTH staged SYS and CAT matched the temporary CurrentUser
  code-signing cert `24DA7EC937F41D91BAFADEB425A3738B67C90BFA`;
  no key was exported. Executable PE section bytes matched the original
  unsigned SYS, independently compared by `compare_pe_sections_r38.py`.
- Signed temporary SYS SHA256 `98e02e08e2faad2565556e8271fab510912abb739ec8e56fa784595c1ca34023`;
  signed CAT SHA256 `9c2791cdbf443908e5b91e7080f2d25ed5a8c63c7fa0be253cc458bfc77037a7`.
  These bytes were **not uploaded or retained as a user-installable package**.
- After signing, the test certificate was removed from CurrentUser/My;
  the same thumbprint was not present in read-only checks of user/machine
  Root or TrustedPublisher stores. This does **not** independently prove
  the OS purged any underlying cryptographic key-container remnants, but
  the ephemeral runner is destroyed after its job.
- One-byte mutation of a copy of the original SYS was denied BEFORE
  signing/Inf2Cat, and no forged affirmative evidence was emitted.
- The exact original Actions ZIP artifact **13616315987**, SHA256
  `eac0a39628dba100f23155c561a4c836e324c32bbb8e96e5cea2028242dd8dd8`,
  was downloaded independently, passed ZIP CRC and contained exactly
  `signing-rehearsal-report.json` and `independent-qa.json`.
  Machine-readable attestation: `R39_EPHEMERAL_SIGNING_VERIFIED.json`.

## Precise remaining gates

This **does not** mean the self-signed binary is Microsoft-accepted or
loadable under normal Windows code integrity. The temporary certificate
is not trusted by a later Windows 11 guest and the signed bits were not
distributed. No real Windows 11 x64 guest was installed, no test-signed
driver loaded, no WFP/ALE classify was executed, and no physical packet
leak test occurred.

For a real test, use an isolated, disposable **Windows 11 x64** guest with
independently verified VM recovery, SYSTEM rescue, egress monitor,
guest-only TESTSIGNING and a *new* guest-controlled test certificate.
The R39 original unsigned SYS remains the pinned source, but the
actual guest test-signed SYS/CAT must be freshly hashed and admitted.
Post-CLAIM owner-exit R41/R42 stays an explicit native negative control.

`g2_pass=false`, `native_e2e=false`, `release_accepted=false`.
No signing secret or key is stored in the repository, ZIP or ChatGPT.
