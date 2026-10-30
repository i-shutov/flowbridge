# FlowBridge WFP: Microsoft signing and reproducible GitHub input

**Scope:** driver-signing preparation, not kernel runtime acceptance. A successful windows-wfp-driver workflow produces an **UNSIGNED** Windows WDK build and a byte-verified **UNSIGNED** CAB candidate. It does not install a driver, create a signing key, submit a Microsoft hardware certification package, or change code-integrity policy.

## Verified build inputs and outputs

- The pinned WDK/SDK build uses SignMode=Off. See .github/workflows/windows-driver.yml and native/windows/wfp/driver/FlowBridgeWfp.vcxproj.
- The generated WDK directory contains FlowBridgeWfp.sys, FlowBridgeWfp.inf, flowbridgewfp.cat; the linker additionally generates FlowBridgeWfp.pdb. Inf2Cat produces the catalog but it is **not Microsoft signed**.
- tools/wfp_signing_package.py validates the expected inputs, the INF service/catalog references, the PE header and the PDB. It stages exactly four files into one driver subdirectory, generates an unsigned CAB with Windows MakeCab, extracts that CAB and checks each file SHA-256.
- wfp-signing-input.json contains the exact checked-out source SHA, all four input hashes and sizes, the CAB hash, and a deliberately NOT_VERIFIED signature status. A green result means **only** that unsigned submission input was prepared byte-for-byte.
- The existing unsigned development build and WDK logs remain separate artifacts. No keys or Partner Center credentials are added to GitHub.

The CAB is suitable for **evaluating a desktop attestation testing submission** once it is signed and approved by the authorized publisher. It is **not** an HLK .hlkx submission, a production-signed driver, or a driver that can be loaded on Windows Server 2025. A MakeCab success does not guarantee Microsoft accepts a submission.

## Signing routes — October 2026

| Intended usage | Correct route | Remaining dependencies |
|---|---|---|
| Windows 10/11 development testing | Microsoft **attestation for testing** or approved preproduction signing | Publisher EV certificate, Microsoft Hardware Developer Program enrollment, authorized submission and installed signed output |
| Windows Server 2025 or production driver including Windows Server | **HLK/WHCP certification plus Microsoft signing** | HLK machine/test results, .hlkx submission, Partner Center approval and returned signed package |
| Private disposable VM with preproduction signing | Trust provisioned expressly for this VM | Microsoft preproduction service and compatible controlled provisioning, no change to unrelated machines |

Attestation only supports desktop versions and is now restricted to testing use. It does **not** make a driver Windows Certified or eligible for Server 2025. An EV certificate on its own merely authorizes publisher submissions; it is **not** a valid substitute for a Microsoft kernel-mode signature. Cross-signing is obsolete for new production drivers.

## Security and ownership boundary

1. **Public GitHub Actions:** WDK compile + unsigned CAB preparation + negative tests + hash manifest. Job permission is contents: read. There is no EV private key, PFX, hardware token, Partner Center secret, identity token grant, Microsoft submission or kernel driver install on a hosted runner.
2. **Publisher-controlled environment:** obtain/manage an EV code-signing certificate using an approved protected key/HSM and enroll a valid organization in the Windows Hardware Developer Program. Never upload private keys, PFX files, passwords or API tokens to public artifacts or PR runners.
3. **Microsoft Hardware Dev Center:** upload the correctly publisher-signed CAB for an eligible desktop **testing attestation** submission, or HLK .hlkx evidence for production/Windows Server. The Hardware Dashboard API can automate submissions only after enrollment and Microsoft Entra authorization. It cannot issue a publisher identity or bypass Microsoft signing.
4. **Microsoft-returned driver:** check the actual signed catalog and signature chain in an isolated authorized Windows environment with the full WDK SignTool. Typical commands from the driver package directory:

       signtool verify /kp /v /c FlowBridgeWfp.cat FlowBridgeWfp.sys
       signtool verify /pa /v /c FlowBridgeWfp.cat FlowBridgeWfp.inf

   Preserve actual signing publisher/chain, SignTool exit codes, Microsoft submission ID, operating-system signature acceptance and loaded-driver evidence. A locally trusted test signature does not satisfy the Windows Server HLK release gate.
5. **Independent WFP runtime acceptance:** only after approval, install the allowed driver on an authorized VM and run .github/workflows/windows-wfp-runtime-vm.yml; require real IPv4/IPv6 redirects, fail-closed routing, correct executable scope, and normal/abrupt stop cleanup. Compilation, signing and actual native acceptance are three distinct gates.

**Important provenance distinction:** Microsoft can replace the catalog and embedded driver signature. Do not require the returned signed .sys SHA-256 to equal the unsigned .sys SHA-256. Link the source SHA and CAB hash to the actual Partner Center submission ID, returned signed files, certificate and target-OS evidence.

## What the project owner must provide to complete signing

- Legal publisher identity and EV code-signing certificate, plus enrollment/authorization in Microsoft Partner Center (or confirmation that these already exist).
- An authorized isolated Windows desktop/Server test or HLK VM. GitHub-hosted Server 2025 cannot replace full HLK/WHCP validation.
- Explicit choice of desktop-only internal attestation testing versus Windows Server production certification.

No release 1.0, WFP driver-ready, Windows Server signature-ready or native acceptance status may be claimed from the unsigned preparation workflow.

## Microsoft references

- [Driver signing options and Windows Server restrictions](https://learn.microsoft.com/windows-hardware/drivers/dashboard/driver-signing-offerings)
- [Attestation signing](https://learn.microsoft.com/windows-hardware/drivers/dashboard/code-signing-attestation)
- [Hardware Developer Program registration](https://learn.microsoft.com/windows-hardware/drivers/dashboard/hardware-program-register)
- [Hardware Dashboard API](https://learn.microsoft.com/windows-hardware/drivers/dashboard/dashboard-api)
- [SignTool verification](https://learn.microsoft.com/windows-hardware/drivers/install/verifying-the-release-signature)
