# R12 — actual Windows WFP AppId + handle-path identity experiment (2026-11-07)

## Provenance and isolation

Branch: `research/windows-wfp-ale-attribution-20261107` only. The research-only
commit `c6a1884a4300121f91dbb14c9f9eb9c64de944c3` added a **single-use**
push-triggered workflow `.github/workflows/research-wfp-appid-native.yml`
restricted both by exact branch and by edits to that workflow file itself.
The workflow used an isolated **GitHub-hosted standard `windows-2025`** machine,
not the owner's self-hosted runner. It did not change an existing runner,
repository default branch, beta/PR #56, services, WFP filters, firewall,
Defender, driver, SecureBoot, UFW, network configuration, or automation schedules.
Its WFP API calls are read-only; the temporary `where.exe` copies and aliases
are local fixtures that are removed before a successful report.

| Item | Verified |
|---|---|
| Actual Actions run | 42362494488, event=push, status=completed, conclusion=success |
| Windows job | 128373613085, appid-path-witness, conclusion=success |
| Research commit executed | `c6a1884a4300121f91dbb14c9f9eb9c64de944c3` |
| Artifact ID | 13569289892, `research-wfp-appid-path-r12-42362494488` |
| GitHub-signed artifact SHA256 | `6565405ee70224c74611e3d186be7ee873361aeab22d3b3f2629b65f1b4aaf9a` |
| Source Git blob | `2132bf55cedc062739a5b8b96200a17352fa2898` |
| Windows checkout source SHA256 | `15b3b9335b5cc289ff0c440a59221495486c97b8514e85c1369cafb988700469` |
| Source fingerprint nuance | Windows checkout converts LF to CRLF; exact transformed SHA256 matches live report |

The GitHub artifact is preserved in this branch as
`fixtures/r12-native-windows.zip` (539 bytes; only sanitized `native-result.json`).
`verify_native_r12.py` independently verifies the exact outer digest, ZIP CRC,
original Git blob, Windows checkout newline transformation, every observed
boolean, five-case completeness, false release/PacketBound flags, and absence
of additional sensitive fields. Nine independent adversarial regression tests
ran locally: **9/9 PASS**. The earlier R10 offline preflight also passed
**68/68** on Python 3.13.5. This does not replace independent Windows
kernel acceptance.

## Measured Windows AppId behavior (real `FwpmGetAppIdFromFileName0`)

| Controlled source and alias | Supplied-path AppId equal? |
|---|---|
| Same path read twice | YES |
| Identical EXE bytes, same basename, *different directories* | **NO** |
| Hardlink to the same NTFS file under a second name | **NO** |
| Directory symlink to the same executable | YES |
| Same path with changed case | YES |

For **each** case, AppId obtained from the caller-supplied pathname was
**different** from AppId obtained by `FwpmGetAppIdFromFileName0` on the
`GetFinalPathNameByHandleW(VOLUME_NAME_DOS)` pathname. Both returned
nonempty UTF-16LE device path-shaped blobs, but only the latter matched the
read-only `GetFinalPathNameByHandleW(VOLUME_NAME_NT)` pathname (with casefolding).
No raw process path, NT device path, AppId, identifiers, IP, or credentials
were printed or stored. All optional alias tests were exercised; skips={};
`temporary_files_removed=true`.

These are *observations on the Windows-2025 runner*, not universally proved
semantics for all filesystems, reparse points, Windows 10/11, signed executables
or file-inode identity. In particular, hardlink inequality shows that **AppId
must not be treated as immutable physical-file identity**. Symlink and case
results are bounded to the tested directory names. The exact source of the
input-vs-handle path mismatch remains unproven (e.g. DOS/NT namespace or
path-spelling transformation), but the mismatch itself is now reproducible on
native Windows and has concrete negative controls.

## Trust-boundary consequence / remaining NO-GO

The historical hosted Windows CI also found a handle-derived AppId whose
representation matched recorded WFP exact-filter events but the input
pathname representation did not. That old report contained marginal counters,
not authenticated per-event tuples. R12 adds an independent native AppId/path
measurement, but does **not** observe an ALE_CONNECT_REDIRECT classify callout,
record a referenced EPROCESS generation/creation epoch, bind a canonical EXE
to the originating socket, query redirect records from a real accepted proxy
socket, or block sibling DIRECT/DNS/UDP under WFP/SSH failure.

A future allowed WFP transparent architecture must use **exact opaque
kernel-origin ALE_APP_ID in the same classify** and must separately prove
correct PID+creation epoch+file object, redirect context and accepted socket
linkage; it cannot infer this chain from a DOS path, 5-tuple, historical
CLASSIFY_DROP aggregate, hardlink, timestamp, or packet buffer. G2 and NDISRD
PacketBound remain **OPEN / NO-GO**. `release_accepted=false`, no-DIRECT not
proved. Historical G1 applies only to `dd1ab3c`.

## Next decisive read-only measurement (if necessary)

Discriminate the cause of DOS/NT path mismatches using local-only redacted
structural comparisons (device volume and directory component shape, not raw
names) and repeat on Windows 10/11. Do **not** add a WFP driver/callout or
filter to explain a read-only API path identity difference. A native
connection-to-process proof requires a separate authorized and fully gated
kernel experiment; AppId measurement is not that proof. SOCKS-only beta
proceeds with its own independent release gate, without an R12 prerequisite.

Windows source APIs:
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew
- https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-
