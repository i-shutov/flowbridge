# R8 — unblock native AppId measurement without weakening acceptance

Date: 2026-11-07. Research branch only: `research/windows-wfp-ale-attribution-20261107`.
Initial source: `aec64d6e48550a751cbb09cdc7f45dbdbe167a49`. A concurrent R7 commit advanced
HEAD to `f7656d1dd5d9feace5a21ac69955088b590ffb46`; its changes were read and preserved.
The AppId harness blob remained `4fee7e02221797251dabc86820e62e3833c5b9aa` on both revisions.
Main was `5b5afc2feeda2195f302380e615ba003d4906e09`. No beta/PR #56 changes.

## Functional change: two explicit measurement scopes

R6 unconditionally compiled Rust before making its first Windows API read. That combined
an unavailable compiler and an unavailable Windows executor into one apparent blocker.

`python appid_native_matrix.py --native-only` now selects a real Windows user-mode
`FwpmGetAppIdFromFileName0` measurement using Python's standard-library ctypes, without
calling rustc, netsh or any other subprocess. It measures identical files, same-basename
copies in different paths and the available hardlink/symlink/case aliases. Copied EXEs
are never executed. Temporary files are cleaned on success and failure; optional alias
failures remain SKIP. This narrower path requires Windows x64 and 64-bit Python >=3.10,
not a Rust toolchain, installed driver, callout, BFE filter, or network connection.

The original default mode STILL requires the Rust probe. Compiler failure does NOT
fall back to native-only. A single-reader result explicitly reports:

- `evidence_level=native_api_only`;
- `rust_probe_built_and_executed=false`, `rust_pairwise_crosscheck_complete=false`;
- `independent_native_acceptance=false`, `release_accepted=false`;
- all kernel-owner, PacketBound and physical no-DIRECT proof flags remain false.

`--selftest` reports only `offline_preflight`. An incomplete native attempt preserves
successful API-read counts but never reports a completed experiment. Rust comparison is
honestly labelled `equality_and_lengths_only`: the existing Rust output does not return
its AppId bytes, so R6's description of exact cross-implementation byte comparison was
not supported. This is not a replacement for independent native acceptance.

The native reader uses an explicit UINT32 blob size, bounded pointers, mandatory
FwpmFreeMemory0 cleanup, a System32-only DLL search and OS GetSystemDirectoryW lookup.
UNC/device/relative/ADS paths and ambiguous spellings are rejected before file inspection;
non-local temporary roots are rejected before creating fixtures. This lexical check is
NOT attestation of reparse targets, executable signatures, or canonical file objects.
Only known error codes are emitted; arbitrary exception text and raw AppIds are excluded.

## Executed validation and limits

On this session's Linux / Python 3.13.5: 32/32 unit and CLI tests PASS (the unchanged nine
R6 regressions plus 23 new tests). Mock Win32 ABI/lifetime tests are labelled as mocks,
not Windows measurements. Four deliberate unsafe mutants were detected: restoring the
Rust dependency in native-only, falsely accepting Rust cross-check, dropping same-file
consistency and omitting the native memory free. Syntax checks PASS.

Actual invocation of `--native-only` on this executor returned exit 2,
`no_windows_native_executor`, zero native reads and all acceptance flags false.
No Windows API measurement, Rust compilation, independent reviewer sign-off or native
release acceptance occurred. Test execution is not a G2 proof.

The available GitHub connection exposes repository writes and Actions reads but no
workflow_dispatch action. Local gh, credentials, Rust and a Windows runtime are absent.
An attempt to obtain the official Rust installer could not resolve the download host;
no toolchain was installed and no network/security configuration was changed. Neither
push/issue/rerun dispatch workarounds, paid browser execution, new credentials nor new
agents were used. Code permission is not Windows execution capability.

## Next exact operation and release boundary

On an already-authorized Windows x64 executor with Python, from this source directory:

```powershell
py -3 appid_native_matrix.py --native-only > appid-result.json
```

Check process exit status and the source fingerprints in JSON. This will establish
AppId behavior only, not the owner of an intercepted connection. The unchanged full
Rust cross-check is a separate subsequent command without `--native-only`.

The missing capability is executing this command on Windows, not additional permission
from the owner to perform the no-driver experiment. No unsafe kernel trial is implied.
WFP/ALE and NDISRD retain separate trust boundaries; G2 remains OPEN/NO-GO. Historical
G1 remains bound only to dd1ab3c. Owner-approved explicit SOCKS-only beta must use its
own acceptance gates and must not acquire R6/R8 as an unrelated new release prerequisite.
This research update neither approves nor modifies that beta.

Primary API references:
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0
- https://learn.microsoft.com/en-us/windows/win32/api/fwptypes/ns-fwptypes-fwp_byte_blob
- https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectoryw
- https://docs.python.org/3/library/ctypes.html
