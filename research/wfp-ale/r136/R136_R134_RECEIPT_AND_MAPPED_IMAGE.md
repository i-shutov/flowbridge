# R136 — verify received R134 native evidence; stage main image-section observation

Recorded 2026-11-12. Repository: `i-shutov/flowbridge`, strictly
`research/windows-wfp-ale-attribution-20261107`. **No beta, release, PR56, G2 or PacketBound work**.
Research parent at start: `4d5c1ad6eaf3cc9849391c9d67762c13330b11de`
(R135 action-rights model); read-only main: `5b5afc2feeda2195f302380e615ba003d4906e09`.
R135 remains intact. Exact parent/current SHA is rechecked before any non-force ref movement.

## 1. Received R134 acceptance — complete

Owner ZIP `evidence-only(2).zip` SHA256:
`79cdb99f14c550982b8477bc3c69ee88bde21b167ce850a97ef065c93165ea4e`.
18 distinct basename-only members; ZIP CRC PASS; no nonempty stderr files; source Git
blob `06825134c15d609abbf9f2b2f72248fdffe85f60` and SHA256
`863da6390116e4806dea135311120c121e0760eeed29891c0548828ba1ce8f25`
match the exact source in published R134 checkpoint. Three reported stage exit codes zero.
18 individually listed Rust test names exactly match 18 PASS records. The
256-state native matrix was independently reconstructed byte-for-byte;
SHA256 `bae850d1de8c78c1acbf4aee36fb1a1a67a54c6b72c7c6e09677c774442385ec`;
Node and Python oracles coincide. The JSONL file is byte-identical to stdout.
The 5 native JSON rows were **independently parsed**, raw fields recomputed and
`observations_mask=255` verified, not trusted from the reported summary.

Observed on the owner-reported **Windows 10 Pro x64 19045 / rustc 1.91.0**:
- Both held, read-only file handles refer to the same (volume serial, 128-bit ID).
- File IDs were stable across repeated filename-to-AppId queries.
- Four AppId blobs are nonempty and byte-identical, including repeated queries.
- Native Win32 process names remain stable; both handles' final native names match
  the process-reported native name.
- Native probe exit=0, `SELF_IMAGE_FILE_APPID_OBSERVED_NOT_ALE_PROOF`.

`validate_r134_archive.py` validates the original ZIP **in-memory only**; no
extraction, loading libraries or executing anything from the user archive. The
sanitized `R134_RECEIVED_ACCEPTANCE.json` deliberately contains neither user
path/PID/volume/file ID/AppId raw data nor executable binaries. Their SHA256s
are merely **reported** because EXE bytes were not in the received archive.
Host timestamps are log metadata, not provenance/authenticity.
`r134_acceptance.py` 31/31 re-run from previous pinned checkpoint. R134's
Windows native PASS is a narrow observation; it does not carry forward to R136.

## 2. R136 discriminating hypothesis

R134 proved two **reopened path handles** refer to the same file and that the
filename-derived WFP AppId matches. It did **not** inspect the EXE image mapping
inside the process's address space. This is a real trust-boundary distinction:
`FILE_ID_INFO` on a reopened file is not `FILE_ID_INFO` on the underlying process
image section. R136 adds one read-only observation that actually addresses the
*image mapping* without changing Windows state.

1. `GetModuleHandleW(NULL)` obtains the calling process's EXE module base. Do not
   free/decrement this borrowed module handle.
2. `VirtualQuery(module_base)` must report MEM_COMMIT and `MEM_IMAGE`
   (`MEMORY_BASIC_INFORMATION.Type=0x1000000`) with matching AllocationBase.
3. `K32GetMappedFileNameW(GetCurrentProcess(), module_base, ...)` reports the
   device-form filename of the memory-mapped file at that address. Repeat before
   and after the held-file observation.
4. `QueryFullProcessImageNameW` gives Win32 and native process-reported names before
   and after. Reopen **only this own EXE** on a fixed local drive for GENERIC_READ,
   FILE_SHARE_READ, OPEN_EXISTING; obtain NT and DOS names from the same file
   handle and its 128-bit FILE_ID_INFO before/after.
5. Query WFP AppId four times from the original Win32 image name and handle-final
   DOS name; compare **opaque bytes**. All allocations freed; file handle closed.
   The 65,536-byte AppId limit is a memory budget, not a Windows ABI limit.

This distinguishes named file agreement from an actual `MEM_IMAGE` address. The
process-reported and memory-mapped native paths might differ because of aliases,
reparse points, rename/replace races, file-name normalization, or loader details.
A mismatch returns diagnostic exit 3, not a fabricated identity link. No race or
rename is intentionally provoked in this read-only experiment.

### Explicit non-proofs, even if every check succeeds

- `GetMappedFileNameW` yields **a name, not an open handle to the image section's
  underlying file object**. A mapped-path match plus a reopened file's FILE_ID
  does **not** prove those objects have the same kernel file ID. No identity binding
  against a malicious namespace/alias substitution is established.
- `VirtualQuery(MEM_IMAGE)` proves the examined region is a view of an image
  section, **not** that the section came from the reopened file or that its
  original path is immutable. Copy-on-write also does not change the MEM_IMAGE
  classification documented by Microsoft.
- There is no atomic snapshot spanning GetMappedFileName, path lookup, file ID,
  and AppId. Image provenance cannot be elevated from these user-mode reads to
  a historical ALE classify/endpoint owner, nor to PID/creation epoch, socket
  receipt, redirect record, unique CLAIM, selected sibling DIRECT, IPv4/IPv6
  proof, DNS/UDP/QUIC or SSH/WFP loss. No G1 transfer/no-DIRECT/leak-free claim.

## 3. Correctly scoped implementation and tests

`r136_mapped_self_image.rs` is dependency-free Rust. No code paths for arbitrary
process ID/filename, filtering, driver install, network, filesystem mutation,
process creation or service changes. Windows x64 FFI APIs: GetCurrentProcess,
GetCurrentProcessId, GetModuleHandleW, GetModuleFileNameW,
QueryFullProcessImageNameW, K32GetMappedFileNameW, VirtualQuery, GetDriveTypeW,
CreateFileW, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
CloseHandle, GetLastError, FwpmGetAppIdFromFileName0, FwpmFreeMemory0.
`MEMORY_BASIC_INFORMATION` x64 C layout is checked independently at 48 bytes,
Type offset 40; FILE_ID_INFO 24 bytes, id offset 8.

Four JSONL records: `self`, `mapping`, `file`, `summary`, with all proof flags
**false**. Mask bits 0..6: MEM_IMAGE+committed+base, stable mapped name, mapped name
matches process-native, mapped name matches held-file-native, stable nonzero ID,
nonempty/stable same AppId from two names, stable process Win32 name. Bit 7 is
`GetModuleFileNameW` exact string agreement and is **diagnostic only**.
Exit 0 = `MAPPED_IMAGE_NAME_CONCORDANT_NOT_SECTION_FILE_ID_PROOF`;
exit 3 = `MAPPING_OBSERVATION_MISMATCH_NO_PROOF`;
exit 2 = `QUERY_ERROR` (exact stage/status preserved).

`r136_oracle.py` and `r136_independent.mjs`: independent pure models, 256 states,
exactly 2 core-consistent states, matching matrix SHA256
`bae850d1de8c78c1acbf4aee36fb1a1a67a54c6b72c7c6e09677c774442385ec`.
`r136_acceptance.py`: **34/34 local Python tests PASS**, with mutated raw fields,
proof-flag tests, FFI API surface, Rust/PowerShell guard, SOURCE SHA pins, ctypes
layout and independent Node-vs-Python matrix. The Rust source contains 21 tests.
`validate_r136_receipt.py` will independently check a future ZIP's raw four
records, matrix, 21 tests, provenance and false proof flags.

**NOT EXECUTED:** R136 native Rust compile, 21 Rust tests, PowerShell runtime,
actual K32GetMappedFileNameW and VirtualQuery on Windows. This executor has
Python/Node, but no rustc/pwsh. The script's `--contract-matrix` and native path
remain unverified until owner supplies a new genuine Windows ZIP.

## 4. Exact Windows handoff

On an owner-controlled Windows 10 Pro x64 system with **existing** MSVC Rust,
run published `FlowBridge-R136-SelfMappedImage.ps1` with explicit
`-RunSelfMappedImage`. Default runs synthetic compile/tests and matrix only;
`-CompileOnly` stops after metadata. The script gets one immutable Git blob,
verifies its Git SHA1 and SHA256 before compiling, checks the 21 test results,
recomputes the full decision from raw JSON, writes logs and creates
`evidence-only.zip`. Process-local PATH is restored. If unsupported/denied,
report the exact error; do not change security, policy or installation.

## 5. Primary API documentation

- https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlew
- https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmappedfilenamew
- https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualquery
- https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0

No driver/callout/filter or R19 build/run, NDISRD, ProxiFyre AGPL, PR40, PR56,
main/beta, CI/runner, services/firewall/Defender/SecureBoot/MemoryIntegrity,
network-settings/automations, VNC/rescue or paid actions were touched.
