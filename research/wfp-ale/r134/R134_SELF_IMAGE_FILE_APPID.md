# R134 — received R133 acceptance and self-image file/AppId observations

Recorded 2026-11-12. Scope: i-shutov/flowbridge ONLY,
research/windows-wfp-ale-attribution-20261107. Baseline research commit:
ef99f30c9d5f1a32b189621c3c7b020bba201cb6. Base tree:
2e9f65ac0ad367e08bc02f6077e77051760dc251.
Main observed read-only: 5b5afc2feeda2195f302380e615ba003d4906e09.
Only new r134 files. No R19 implementation or other branch changed.

## Received R133 evidence

The current owner-uploaded evidence-only(1).zip SHA256 is
`a9a21abfa8edfe5de60d24deaa85fb72654b366cfcf71bf720c863d003d0b348`.
18 unique basename-only members, all CRCs valid, no nonempty stderr. The 16 unique
listed Rust tests equal the 16 passed tests. Metadata/tests/probe exits are zero.
The raw stdout and JSONL observations are byte-identical. The 60-case gate matrix
was regenerated and compared byte-for-byte, and the Node oracle independently
reproduced SHA256 `9c7a1ee3052a06be99b03e0475b2cc00a08da565aa221bee4d5166649f0126dd`.
The prior 28 Python checks were rerun. Source pins in the report match R133.

Both owned children were NOT_SIGNALED/259 while waiting, then signaled after normal
exit. The first final code is 23 and the second final code is 259. Both retained
handles agree on PID/creation time before and after, as checked by R133. This
confirms the documented exit-code-only liveness trap on this reported host, not a
new Windows defect. No PID reuse was provoked or observed. Windows 10 Pro 19045
and Rust 1.91.0 MSVC x64 are recorded by the harness.

R133_RECEIVED_ACCEPTANCE.json contains sanitized per-case facts and member hashes.
The original archive, raw image names/local paths and PIDs are NOT published.
Executables were not included; their digests remain owner-reported, not independently
rehashed. Host clock timestamps are not used as provenance. validate_r133_archive.py
reproduces the checks without ZIP extraction or executing any ZIP member; it uses
hash-pinned R133 validation dependencies already present in this branch.

## Next native question, not another larger synthetic matrix

Can the current helper's process-reported image name, two simultaneously held file
handles, and repeated filename-derived WFP AppIds be observed consistently?

The standalone clean-room Rust program queries ONLY itself, with no caller-supplied
PID or executable path. It obtains Win32/native image names from GetCurrentProcess
and QueryFullProcessImageNameW. Plain or extended drive paths are restricted to a
fixed local drive; UNC, ADS, relative names and mapped remote drive roots are rejected.
Only the verified extended disk prefix is removed; no casefolding, trimming or
Unicode rewriting is performed.

It opens the own reported image path with CreateFileW(GENERIC_READ,
FILE_SHARE_READ, OPEN_EXISTING), never requests write/delete access, then obtains
GetFinalPathNameByHandleW(DOS/native). It opens a second read handle using the final
DOS name. The two handles stay open while four FwpmGetAppIdFromFileName0 calls read
original-name / final-name / original-name / final-name AppIds. It measures
FILE_ID_INFO before and after (GetFileInformationByHandleEx, class 18), and rereads
its process names. Both file handles are explicitly closed before printing output.
Failure paths release successful file/blob allocations through RAII.

The FILE_ID_INFO pair is the volume serial number plus 128-bit file ID, not an
integer PID, basename or content hash. Zero file IDs remain unknown, never positive.
Unsupported filesystems/API failures are emitted with stage and raw DWORD; no
64-bit fallback or privilege change. FILE_ID_INFO repr(C) is 24 bytes / align 8.
Names are preserved as UTF-16-unit hex and 64-bit volume IDs as hex to avoid loss.
AppId stays opaque bytes: the probe does NOT assume UTF-16, strip NUL, decode it
into a path or silently truncate a blob. The 65,536-byte cap is a resource bound,
not a documented AppId size limit.

Direct API surface: GetCurrentProcess, GetCurrentProcessId,
QueryFullProcessImageNameW, GetDriveTypeW, CreateFileW,
GetFileInformationByHandleEx, GetFinalPathNameByHandleW, CloseHandle, GetLastError,
FwpmGetAppIdFromFileName0 and FwpmFreeMemory0. No policy enumeration, transaction,
subscription, driver/callout/filter install, process enumeration, child process,
socket, registry write, file content write, alias/hardlink/reparse creation.
The WFP AppId helper itself is called; this is NOT a claim of zero Windows internal
RPC activity. No explicit network connection is made by the probe. Source retrieval
by the PowerShell harness is separate and uses the immutable repository blob.

## Decision and evidence boundaries

Five JSON records: self-process, file 0, file 1, four opaque AppIds, summary.
Core bits 0..6 record usable IDs, same file identity, unchanged IDs, nonempty AppIds,
repeatable AppIds, equal AppIds across names, and unchanged self-process names.
Bit 7 records exact native-name equality but does not act as file identity authority.
All core bits required: exit 0, SELF_IMAGE_FILE_APPID_OBSERVED_NOT_ALE_PROOF.
A genuine observation discrepancy: exit 3, OBSERVATION_MISMATCH_NO_PROOF.
API/shape/cleanup failure: exit 2, QUERY_ERROR. Full outputs remain in evidence.
The PowerShell validator independently recomputes comparisons from raw fields;
it does not accept a self-declared observations_mask or positive summary alone.

Even all equal observations do NOT bind a file handle opened by name to the mapped
image section of a process or to a historical original ALE classify. They do not
prove file contents/signature, publisher identity, path stability, namespace safety,
hardlink/reparse correctness, arbitrary binary compatibility or long-lived file-ID
uniqueness. Parent-directory/reparse changes between path lookups are NOT prevented
or tested; equal before/after identities are NOT an atomic transaction with AppId
queries. Read-sharing pins are temporary observations, not a global security fix.
The experiment intentionally does not execute a namespace mutation or racing writer.

## Executed checks vs prepared checks

Executed locally: 31/31 Python tests, including independent ctypes layout model,
source SHA/Git pins, exact 18 Rust-test count, fixed read-only API surface, JSON type/
cardinality/identity/proof-boundary mutants, source corruption and seven weakened
gate counterexamples. Independent Node oracle matches Python across 256 gate states:
SHA256 `bae850d1de8c78c1acbf4aee36fb1a1a67a54c6b72c7c6e09677c774442385ec`.
These synthetic states test the observation decision only, not actual WFP outputs.

NOT RUN here: Rust compilation, the 18 Rust tests, PowerShell 5.1 parse/runtime,
FILE_ID_INFO or new native AppId queries. This Linux executor lacks rustc/cargo/pwsh;
no installation, CI or remote host was used. Old R133 native PASS does not transfer.
No junior-model/subagent execution is claimed; bounded tasks are provided separately.

## Next decisive experiment

Run the exact published FlowBridge-R134-SelfImage.ps1 with -RunSelfImageProbe on
the already approved Windows host. Existing Rust only. Default mode is synthetic;
-CompileOnly stops after Windows-gated metadata. The script gets one immutable
source blob, verifies SHA1+SHA256 without checkout conversion, then compiles/tests,
checks the Rust matrix bytes, runs the opt-in probe and packages logs only.
Process-local PATH is restored. A 120s child timeout may stop only the directly
owned compiler/probe child. No changes to system settings or external processes.

Return evidence-only.zip. A read failure must not be repaired by enabling drivers,
changing ACLs/security settings or adding WFP filters. Diagnose its exact stage/code.

Open chain: kernel-original process reference -> PID/epoch/start key/canonical EXE
and ALE AppId -> CONNECT_REDIRECT/AUTH_CONNECT -> actual accepted SOCKET context/
records -> one-use CLAIM -> SSH egress. Process death callback delay/PID reuse,
reused 5-tuple, sibling DIRECT, IPv4/IPv6 native attribution, DNS/UDP/QUIC and WFP/
SSH loss remain unproven. No G1 transfer, PacketBound/G2, no-DIRECT or leak-free claim.

## Official contracts checked (not C++ payload reuse)

- https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information

Main/release/beta/PR56, runner/services/firewall/security/networks/automations,
NDISRD/VNC/signing, ProxiFyre/PR40/vendor/C++ payload, paid actions untouched.
Git publication requires exact expected HEAD and force=false; conflicts stop writes.
