# R138 — accepted negative R137 result; process-instance binding with same-image siblings

Recorded 2026-11-12. Repository i-shutov/flowbridge ONLY; branch
research/windows-wfp-ale-attribution-20261107. Baseline HEAD:
1aa0f69f500f360c82b9eaad2ac2f0c28bc70190; base tree:
6454a54c0b0ef77c50518fd33e5fead2ef976904. Main read-only observed:
5b5afc2feeda2195f302380e615ba003d4906e09.
Only new r138 files. No R19 implementation change, main/release/beta/PR56 changes,
runner/services/firewall/security/network configuration or automation actions.

## R137 evidence: the proposed absent-name counterexample did NOT occur

Received evidence-only(3).zip SHA256:
c860fe51ed61ddccec3c3c1be959247406a3c67ea08a0a1f66fbdcb5550358a8.
All 18 unique expected members and CRCs checked. The 18 listed Rust tests equal
18 successful test lines; metadata and unit-test exits are zero. The 256-line
contract matrix equals the freshly regenerated pinned Python oracle, independently
confirmed by Node. Source pins match the published R137 blobs.

Raw native result: missing_before=true, missing_after=true, own AppId stable,
negative outcomes stable; both missing-name helper calls return DWORD 2
(ERROR_FILE_NOT_FOUND), no AppId allocation for that name, own AppId length 252.
Summary: ABSENT_PATH_APPID_REJECTED_NOT_ORIGIN_PROOF, mask 15, diagnostic exit 4.
The original JSONL and captured stdout are byte-identical.

This is a completed, useful negative experiment, NOT a compiler/BFE fault and NOT
an absent-file success. The hypothesis that this tested missing pathname could
produce an AppId was NOT CONFIRMED on this host. Do not generalize two calls to
all Windows builds, all filesystems/names or an authentication property of AppId.
Successful filename lookup still does not certify a live process or a connection.

One compiler diagnostic is present: an unused INVALID_FILE_ATTRIBUTES constant
in the unit-test build (dead_code), followed by the compiler warning count. It is
preserved in the acceptance manifest; stderr is NOT falsely reported as empty.
No source patch is needed to reinterpret diagnostic exit 4 as successful execution.
No binary files were supplied: recorded executable hashes remain owner-reported.
No trust is assigned to the host wall clock, which is not remotely attested.
R137_RECEIVED_ACCEPTANCE.json publishes only sanitized facts and member hashes,
not local paths, raw archive, PIDs or image names. validate_r137_archive.py bounds
ZIP size, reads without extracting/executing, and pins prior validation modules.

## Next decisive question

For two concurrently alive instances of the same own EXE, will filename-derived
AppId remain identical while process identities differ? After A exits, can the
same path still yield the AppId while B stays alive, WITHOUT admitting B as A?

AppId represents an executable path, not necessarily an instance. An application
policy may correctly select both instances. The negative control concerns a
process-specific receipt/lease, not a requirement that WFP's path filter split PIDs.
Neither helper creates a network socket. This is not a sibling DIRECT traffic test.

## Native experiment (prepared, not run here)

The new clean-room Rust executable spawns exactly two helpers from current_exe:
A (normal self-exit 23) and B (normal self-exit 29). Both wait on their own stdin
pipes. The parent retains their original Child handles BEFORE opening secondary,
non-inheritable query handles using only the Child.id() values. Rights are exactly
PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE (0x00101000).
No arbitrary PID, EXE path, privilege or target can be supplied to the probe.

For each observation it brackets GetProcessId/GetProcessTimes/GetExitCodeProcess
with zero-time WaitForSingleObject reads and requires primary/secondary agreement.
Creation times are raw 64-bit hex, not floats. Different PIDs are required while
both are alive; equal creation timestamps are permitted. No monotonic-clock or
PID-reuse assumption is used, and undefined live-process exit FILETIME is ignored.

While both wait, their Win32 image names are queried and checked as local fixed
DOS paths. FwpmGetAppIdFromFileName0 reads the two filename-derived AppIds. Then A
is released to exit; the retained handles show A exited while B remains alive.
The helper is called again for A's STORED filename and B's freshly queried name.
There is intentionally no image-name query on the terminated A. B then exits.
Handles are explicitly closed before observations are written to stdout.

Required outcome: equal observed image names and four nonempty, byte-identical
AppIds, distinct live PIDs, stable held process identities, and a still-live B after
A's termination. A test-only instance gate uses exact selected PID/creation time,
unsignaled held-handle readings, STILL_ACTIVE code and equal AppId. Its decisions
are A-before=true, B-before=false, A-after=false, B-after=false (mask 1). A deliberately
weak AppId-only comparison yields mask 15. This gate is a local observation rule,
not a production authorization function or a retrofit of the kernel adapter.

There are seven raw JSON records: five process observations, one with names and
four opaque AppIds, and a summary. The PowerShell harness independently recomputes
both masks from the raw identities/state/AppIds; it does not trust the summary.
No file content, image section, publisher, signature or actual socket is certified.
Observations are not atomic and cannot prove indefinite liveness after a read.

## Safety/resource boundary

Direct imports: OpenProcess, CloseHandle, GetProcessId, GetProcessTimes,
QueryFullProcessImageNameW, GetDriveTypeW, WaitForSingleObject,
GetExitCodeProcess, GetLastError, FwpmGetAppIdFromFileName0, FwpmFreeMemory0.
No kernel callbacks/callouts/filters are compiled, installed or run. No BFE inventory,
policy transaction, socket, process injection/enumeration or foreign process target.
AppId is copied as bounded opaque bytes and freed through its documented allocator.
Helpers self-exit on release, EOF or a 45-second local deadline; parent waits are
bounded at 10 seconds. Rust never calls TerminateProcess/kill. The PowerShell
supervisor can stop only its own direct compiler/probe child on a 120-second timeout.
PATH is changed only within the script process and restored. No tools are installed.
The only download is one exact Git blob from this repository, unless OfflineSource
is supplied. SHA1 and SHA256 are both checked before writing exact bytes for rustc.

## Checks actually executed

R137 recheck: 28/28 Python tests plus the independent Node oracle, then native-archive
validation described above. R138: 42/42 Python tests, including malformed/forged JSON,
source pins, lifecycle order, same-time/different-PID identities, unknown wait values,
byte corruption, ABI size model, API scope and output-boundary checks.
Independent Node and Python implementations agree on all 480 raw-input decisions.
SHA256: 8185ca0c6b8a1dbd968ab3be9a3b0fa105bbc16f9ca0b4b8271f8a1de3d16695.
Exactly one synthetic state qualifies under the full gate; AppId-only would select
240. These are model controls, not measured Windows vulnerabilities or probabilities.

Prepared but NOT RUN in this executor: 20 Rust unit tests, Rust compilation,
PowerShell 5.1 parsing/runtime and the new two-helper experiment. rustc/cargo/pwsh
are absent locally. No installation, Windows connection or CI workaround attempted.
Do not transfer the R133/R134/R137 native acceptance to new R138 code.
No subagent was run; connector discovery offered no callable small-model executor.
Separate deterministic programs are not separate model reviewers.

## Native handoff and next decision

The owner runs the pinned FlowBridge-R138-SiblingBinding.ps1 with
-RunOwnSiblingProbe on the already used Windows host. Default is synthetic only;
CompileOnly stops at metadata. Expected, not yet observed:
20/20, 480-case Rust matrix match, SAME_APPID_DISTINCT_PROCESSES_NOT_ALE_PROOF, exit 0.
Return evidence-only.zip; preserve mismatches with their exact domain/stage/code.
Do not elevate privileges or change policy/security settings to force a pass.

After this composition, more AppId/name equivalence tests alone will not close the
connection-origin gap. The deciding higher-level evidence must bind the original
process identity to the actual native classify and accepted socket, not a later
process query. R138 does not execute that experiment or authorize a kernel lab.

Unproven chain: kernel-original process reference -> PID/creation epoch/start key /
canonical EXE/ALE AppId -> CONNECT_REDIRECT/AUTH_CONNECT -> redirected accepted
SOCKET context/records -> one-use CLAIM -> SSH. Process death callback latency,
PID/5-tuple reuse, sibling DIRECT, IPv4/IPv6 network attribution, DNS/UDP/QUIC and
WFP/SSH loss remain NO-GO. No PacketBound/G2, no-DIRECT/leak-free or dd1ab3c G1 transfer.

## Official contracts reviewed

- https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0
- https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-
- https://learn.microsoft.com/en-us/windows/win32/procthread/process-handles-and-identifiers
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess
- https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject

Publication: only this research branch, expected current SHA, force=false; STOP
and reread on conflict. No paid operations or ProxiFyre/PR40/vendor/C++ payload.
