# R38C — verified Microsoft InfVerif PASS; matching PDB required before signing

Date: 2026-11-08. Research branch only. main and beta PR #56 unchanged.

## Genuine Windows InfVerif execution

One-shot Windows-2025 Actions run: https://github.com/i-shutov/flowbridge/actions/runs/42458944899
Exact prior unsigned source commit: ecc66afe63ab0c1e65274da7dd95f7026140d782.
GitHub source artifact: 13606839479 from Actions 42454895627.
Driver SHA256: 74626c2e6d07d51a15b0886f81e9aa1460731875eeb1f293d0d378077486861c.
INF SHA256: 29b62d0272436d62098d2514a6586db171261faaa58c9ac31a271518f3c5fbdd.
CAB SHA256: 047b8158c9d8a1a61734ff5101f3b50a3cb4d4336a9376a0c8bd694a92cc0687.
All three SHA256 checked against the original artifacts.
Microsoft WDK InfVerif /w: PASS. InfVerif /u: PASS. Zero reported findings.
InfVerif output artifact ID 13608404587; GitHub ZIP SHA256 5a201e3cb5f69d56ed24773e25a1cd110d2a1fe52c423958d71bbf2ed276f380.
Original ZIP independently SHA/CRC-verified; contents result.json, infverif-u.txt, infverif-w.txt.
No driver signed, loaded or installed. No BFE filters or services changed. G2 PASS=false.

## Missing symbols addressed in actual build/package source

Microsoft attestation CAB guidance requests kernel .pdb debug symbols for automatic crash analysis.
Previous CAB included only .sys and .inf. New source builds exact MSVC release with debug=full and /DEBUG:FULL.
Build fails closed unless exactly one kernel release PDB is present and larger than 1 KiB.
Windows CAB contains exact .sys, .inf and .pdb; each re-extracted member is SHA256-checked.
Manifest records PDB hash and size. No generated fake symbols or user-mode test PDB allowed.
This changes the original .sys binary, so new hashes must be pinned after CI.
The INF file itself is unchanged; its InfVerif result remains grounded to its exact byte hash.

## External approval conditions

Attestation signing in current Microsoft guidance is for Windows 10+ Desktop testing audiences.
EV code-signing certificate and Hardware Developer Program are prerequisites; no EV private key is uploaded to CI.
Partner Center submission, Microsoft-returned signed .sys/.cat, SignTool /kp on the actual desktop,
fresh independent VNC and SYSTEM rescue, rollback, native kernel redirect and physical no-DIRECT are NOT done.
Do not sign, load, or install the unsigned candidate. g2_pass=false, release_accepted=false.

References:
https://learn.microsoft.com/en-us/windows-hardware/drivers/develop/validating-windows-drivers
https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation
https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings
