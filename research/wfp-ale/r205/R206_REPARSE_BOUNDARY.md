# R206 — negative proof of the R203v5 evidence-path boundary

Pinned start: research HEAD \`6f2e3a4ff75f66c8c03753881d033207cd6382c0\`, main \`5b5afc2feeda2195f302380e615ba003d4906e09\`. This R206 finding affects the **offline R203v5 PowerShell collector**, not the WFP driver, kernel classification or packet handling.

R203v5 checked EvidenceDir outside RepoRoot using lexical \`Path.GetFullPath\` + case-insensitive prefix. This is not final filesystem-object containment: an outside directory alias can point into an empty checkout subdirectory. Windows NTFS junctions/symlinks are reparse points. The old collector would admit the lexically external path and subsequently write copied sources and results through it, violating its no-checkout-write prerequisite. No such Windows write was performed.

Executable independent Python and Node oracles each ran **5/5 PASS** on actual temporary POSIX symlinks: ordinary external, direct internal, alias at evidence leaf, alias in evidence ancestor, and linked repo root. This proves the lexical containment error class, **not** the exact native Windows failure or its repair. These scripts stay in the existing permitted \`r205/\` tooling prefix so R203v5's strict HEAD lineage allowlist is not expanded.

**Offline candidate R203v6** adds \`Assert-NoReparseAncestry\` to reject any reparse point in both the root and evidence path ancestries using \`System.IO.File.GetAttributes\` and \`FileAttributes.ReparsePoint\`, twice before writes. Its complete collector and stronger 8/8 + 8/8 negative suite are in a separate offline checkpoint. That collector is **not** committed or Windows-executed. This is fail-closed hygiene, not an atomic filesystem sandbox; malicious concurrent alias replacement and alternate drive mappings are not closed.

Independently rerun prior R203 evidence dual-validator fixtures: 25/25 PASS; R205 Python/Node ancestor oracles: 11/11 each. Native PowerShell/Rust/BFE/kernel tests **not run**. No changes to drivers, filters, services, network, security, protected branches, beta, PR #56, runners or automations.

**Architecture remains NO-GO:** EPROCESS/FileObject/process epoch/start key/canonical EXE → ALE IPv4/IPv6 original AppId/endpoint/redirect metadata → accepted-socket redirect context/records → terminal CLAIM → physical SSH has no native end-to-end classify proof. PID death/reuse, 5-tuple reuse, sibling DIRECT, DNS/UDP/QUIC, reauthorization and WFP/SSH loss are unresolved. R199 BFE inventory does not prove classify; redirect records do not alone attest a particular SSH connection. No PacketBound/G2 PASS, no-DIRECT or leak-free claims.

Next *authorized* experiment: native Win10 Pro x64 **read-only refusal test** for NTFS junction/symlink before creating EvidenceDir; then 14/8 pinned Rust R201/R202 tests; optional passive R199 readback subject to read permission. Independent validators must still accept no kernel proof.

Official: https://learn.microsoft.com/en-us/dotnet/api/system.io.fileattributes ; https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection ; https://learn.microsoft.com/en-us/windows/win32/winsock/sio-set-wfp-connection-redirect-records .
