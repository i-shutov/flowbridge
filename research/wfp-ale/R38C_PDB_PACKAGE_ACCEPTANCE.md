# R38C — verified PDB-inclusive attestation candidate; native R39 still gated

Date: 2026-11-08. All changes remain in research/windows-wfp-ale-attribution-20261107.

## Executed real Windows acceptance of unsigned package

- Build commit: `85a4b0602aa8f0c0a2c7b68c535172028bd1073f`.
- [Windows Actions #42459583528](https://github.com/i-shutov/flowbridge/actions/runs/42459583528): 3/3 SUCCESS. The kernel was compiled but NEVER LOADED; BFE filters never activated.
- Original build artifact ID 13608359384, SHA256 74dfcaab1741c179bde6d15da2e06ec37ea813269c89c6a59d9fcc8d43a32748.
- Independent download, ZIP CRC, 29/29 exact-source SHA256 + Git blob checks PASS.
- Driver 207872 bytes: SHA256 1167b3cb84c3ca3b920ae36d8a4f0ba57d2ba58a13bac7d0fe8eaf2e863e5dd1.
- Release MSVC PDB 1110016 bytes: SHA256 4d413cc3079d9c1e21a378d95b3d2fac5df0ad17988c7f48e29ee79a63b4fd31.
- Independent parsing of PE CodeView RSDS and PDB MSF7 info stream confirmed exact PDB GUID and age match the driver.
- Broker SHA256 3646f938f1187a2b71751510d16bf41a775ae588e1e0c52c9fa595ffcaffeaf4; 39 broker regressions PASS.
- Original unchanged INF SHA256 29b62d0272436d62098d2514a6586db171261faaa58c9ac31a271518f3c5fbdd: Microsoft InfVerif /w PASS and /u PASS from [run #42458944899](https://github.com/i-shutov/flowbridge/actions/runs/42458944899), exact INF bytes separately pinned.
- New unsigned CAB: 259262 bytes, SHA256 ee9e070816767a40c55ccdc1ce055251b6d7c61657180d49e8ade9f4e89c07dd.
- CAB has precisely three entries: .sys, .inf, matching .pdb; Windows Expand re-extracted each and checked member SHA256. Independent CAB directory parser verified names and sizes.

## Real causal build blockers resolved, with failures retained

First PDB build #42459279129 compiled Rust with debug info but the script searched only Cargo release output; the PE's RSDS pointed to a PDB not archived at the expected path. The build correctly failed without shipping an incomplete CAB.

Fix `85a4b060`: force exact absolute MSVC linker `/PDB:` output into artifact directory. Subsequent #42459583528 PASS; no fake/unrelated PDB accepted.

## External R38 signature/host admission (NOT YET DONE)

- Package is UNSIGNED. Never load/submit as a signed driver. No actual Microsoft Partner Center upload, approved EV publisher or returned Microsoft signed .sys/.cat.
- The 2026 Microsoft attestation route is for Windows 10+ Desktop testing audiences; it requires Hardware Developer Program enrollment and EV-backed publisher. Retail Windows Update distribution requires HLK certification, not attestation.
- Publisher must EV-sign the CAB and submit under its own account. Do NOT send EV private keys into CI or ChatGPT; provide only the Microsoft-returned signed package and public verification metadata.
- Reverify returned signed .sys/.cat on the **actual** Windows desktop via SignTool /kp; compare loadable PE section bytes against pinned unsigned .sys and preserve new signed SHA.
- Independent VNC, SYSTEM rescue, full rollback and independent egress observation must be live-verified for the exact target before any driver or BFE filter installation.
- R39 first selected unmodified EXE → actual ALE_CONNECT_REDIRECT → AUTH one-shot ticket → accepted WFP context/records → outbound tagged physical SSH socket → pinned host key and user authentication → exact remote response must all be seen on ONE REAL FLOW.
- G2, NDISRD PacketBound, physical system no-DIRECT and release remain NO-GO pending those actual tests.

Machine-readable source: `research/wfp-ale/R38C_VERIFIED_UNSIGNED_PDB_PACKAGE.json`.

References:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation
- https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings
- https://learn.microsoft.com/en-us/windows-hardware/drivers/develop/validating-windows-drivers
- https://learn.microsoft.com/en-us/windows-hardware/drivers/develop/creating-a-primitive-driver
