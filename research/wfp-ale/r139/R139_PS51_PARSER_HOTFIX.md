# R139 PowerShell 5.1 source-gate hotfix — 2026-11-12

Scope: only research/windows-wfp-ale-attribution-20261107 in i-shutov/flowbridge.

## Owner report and diagnosis

Owner downloaded the original R139 PowerShell source gate, verified SHA256
d7545306aad0e85da565bc679c98037aa51797f9b13d36558076f39fd7efe43b,
and its Windows Parser.ParseFile returned errors before script execution.

Static byte review identifies ONE surplus right parenthesis on EACH of original
lines 79 and 80. They surround nested Contains-InOrder calls for the trusted
SSH and SOCKS record-before-connect checks. There are two opening delimiters
but three closing delimiters on each line (quoted Rust fragments excluded).
This is a script authoring error, not evidence of Windows/WFP misconfiguration.

## Exact minimal change

Original: FlowBridge-R139-SourceGate.ps1 (9073 bytes, preserved).
Fixed: FlowBridge-R139-SourceGate-PS51-v2.ps1 (9071 bytes).

Original SHA256:
d7545306aad0e85da565bc679c98037aa51797f9b13d36558076f39fd7efe43b

Corrected SHA256:
2b66655e819d7a1218103527e141ab0eed1fb641539fdf416b5052945ae32c0d

Only two closing parentheses are deleted. No source pin, WFP rights contract,
dynamic-policy contract, SDK signature, evidence/reporting, or safety boundary
was weakened or removed.

## Reproducible local checks

- Seven delimiter regression tests passed; the old script is rejected and
  the corrected source has balanced nested delimiters, comments and strings.
- All 26 existing R139 Python tests passed with the corrected file.
- Independent Python and Node models remain semantically equal for all 2048
  synthetic paths, digest
  b96761c1db4c04d8e3485730b6c2c385cf6968af17eedc4edad4a39f7da9eb96.

IMPORTANT: This Linux environment cannot run Windows PowerShell 5.1. Its AST
parser and v2 runtime have NOT BEEN EXECUTED here. The lexical checker is a
regression test, not a replacement for Parser.ParseFile.

## Owner's next native gate

Download the NEW file from the repair commit, verify exact SHA256, and call
System.Management.Automation.Language.Parser.ParseFile locally.
If errors remain, print all error line/column/message and STOP without executing.
If zero errors, execute v2. The expected diagnostic status, provided the
source contracts still match, is R139_SOURCE_RECEIPT_VALIDATED_RELEASE_NO_GO
with deliberate exit code 3. Exit 2 is an unavailable/source mismatch result.

The read-only tool downloads four pinned Git blobs and optionally reads an
installed Windows SDK header. It never creates sockets, calls BFE, changes WFP
policy, installs drivers or modifies the Windows environment.

Architecture boundaries remain open: ACTION_WRITE/veto contract, loss of
dynamic WFP filters, kernel-origin ALE identity, actual accepted socket-to-SSH
chain, packet-bound G2 and no-DIRECT/leak-proof claims. No release acceptance.

Only this research branch may be updated, with expected prior SHA and force=false.
