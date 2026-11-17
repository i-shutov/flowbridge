# FlowBridge Win10 — P1 signed OpenSSH origin at runtime

**Source-only remediation on top of [privacy PR #84](https://github.com/i-shutov/flowbridge/pull/84). Date 2026-11-17. Status `CI_PENDING`.**

## Exact old product boundary

Frozen `0.3.0-beta.2` source `86583a1a0487b9d383c0122b24558e620bde5b9c`, installer SHA256 `0699bed4acaa1b9df9b63c658808b08fd65b5953cacdaaddb7a13953389e19f4`: **unchanged and NOT fixed**. Original owner Win10 V4 100/100, V5 26/26 accepted for old functionality, not transferable as new privacy/security QA.

## Runtime threat and implementation

Original Windows backend resolution searched arbitrary entries of user-influenced `PATH` for `ssh.exe` if no explicit `ssh_executable` was selected; for an explicit `*.exe`, `-V OpenSSH_` was the only check before execution. A malicious local binary can fake that response, so this must not be a trust boundary.

- On Windows only, default `ssh.exe` now resolves **only** from the actual kernel-provided `GetSystemDirectoryW()/OpenSSH/ssh.exe`, never from `PATH`, `WINDIR` or the current directory. An explicitly configured portable client is still allowed if full local absolute path, Microsoft-signed and trusted. No change to macOS/POSIX backend discovery.
- Before **either** OpenSSH `-V` probe or the real SSH child, runtime canonicalizes the path, rejects reparse-point components, opens the exact binary with `FILE_SHARE_READ` only (write/delete sharing denied), and holds this handle across the signature probe **and `CreateProcess`**. This blocks ordinary replace/delete between checking and launch. Fails closed on verifier or path failure.
- Signature check uses **Windows PowerShell from kernel-derived System32**, static literal command, process-environment supplied path and `-LiteralPath`, `Get-AuthenticodeSignature` Status `Valid` plus Microsoft Corporation signer subject. No dynamic PowerShell interpolation, no leaking path into process logs, output disabled. A bounded 12s deadline prevents stalling the SSH supervisor. System PowerShell/certificate trust store remain part of the Windows OS trust boundary. The file guard prevents ordinary file modification during verification; this is **not** a proof against kernel-level tampering or malicious privileged administrators.
- The same runtime proof is required for the additional SSH process used for remote POSIX DNS discovery. Failure does not fall back to arbitrary `PATH`.
- Synthetic custom test launchers are isolated from production signer checks and never credited as a signed backend. Windows tests verify unsigned test binary refusal *before* running its `-V`, relative/non-executable rejection, and signed Microsoft system `ssh.exe` acceptance if installed.
- Rest of explicit fail-closed gates, verified host-key requirements, managed 128 baseline, no 512 raw promise, original GitHub CI/WDK separations stay intact.

## Residual gates

This source-level implementation still requires **actual Windows CI**, independent review of Windows trust assumptions (revocation, signer chain, portability, ACLs, reparse points, process creation/race behaviour) and native Windows 10 original GUI/SSH tests on the exact **new uniquely versioned candidate**. The `Get-AuthenticodeSignature` built-in status and Microsoft signer check are not equivalent to independent code signing audit of every installer or OS file. The read-only owner Win10 ESU / actual selected SSH file proof is still pending.

**Do not distribute any new package or publish public GitHub Release.** Project closed/internal-only; repository currently Public until owner action [#83](https://github.com/i-shutov/flowbridge/issues/83). [P1 #86](https://github.com/i-shutov/flowbridge/issues/86) requires independent runtime trust acceptance. [P1 #85](https://github.com/i-shutov/flowbridge/issues/85) privacy suppression is a separate source patch on which this stacks. New beta.3 source/installer SHA and Win10 V6 original private evidence must be newly accepted; A5/A6 formal internal security and A7 owner GO remain `false`. WFP/G2 Windows 1.0 still `NO_GO`.
