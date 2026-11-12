# R133 — accepted R132 bytes; next: own-child process-handle lifetime

Recorded 2026-11-12. Repo i-shutov/flowbridge ONLY; branch
research/windows-wfp-ale-attribution-20261107. Base research commit
7e6e1bd2cf6a83fee394c99912b7a43a2efc70fb; main read-only observed
5b5afc2feeda2195f302380e615ba003d4906e09. No beta/release/PR56, driver,
filter, service, runner, firewall, network/security-setting or automation changes.

## R132 received evidence — not merely a console assertion

The owner uploaded evidence-only.zip. Its SHA256 is
`df95397efe52b85c45331f26fcc0d68cca256e5d84c7d9a139b4348a3335913b`.
All 15 member CRCs pass. The 64 unique test names agree between listing and
successful execution, with no ignored/filtered tests. Five reported source pins
match the R132 published pins. Metadata/link/tests/campaign exit codes are zero.
The 1,476,000-byte campaign log contains 36,000 traces / 216,000 event steps.
It is byte-identical to a freshly regenerated Python oracle, not just to a copied
hash literal. A separate Node implementation independently yields the same digest:
`c2af3f996ec4c52620c973f0fb34dc4ead470e94f6805edeb9a8d49fcf278e37`.
R132's 18 local Python checks were rerun successfully. 4,944 synthetic claims and
13,536 synthetic AUTH successes agree with the oracle. These are NOT network events.

The archive identifies Windows 10 Pro / 10.0.19045 and rustc 1.91.0 MSVC x64.
Binary digests are recorded in the owner's JSON, but the binaries are NOT in the
archive and have NOT been independently rehashed. Host wall-clock timestamps are
not attested and are not used as causal/provenance authority. Member hashes and a
sanitized acceptance record are retained in R132_RECEIVED_ACCEPTANCE.json.
The original archive and raw local paths are not copied into the public repository.
validate_r132_archive.py reproduces the bounded archive checks without execution.

Accepted scope: the exact-source synthetic R132 experiment ran successfully on
the owner's host and its returned trace bytes match both independent oracles.
This is not remote attestation, actual kernel scheduling, WFP enforcement, PID
reuse testing or evidence of packet ownership. Existing R19 modules are unchanged.

## Why the next experiment is different

Do not produce another larger synthetic permutation table or repeat absent BFE
queries. R133 instead reads real process identity/time/name from handles of two
OWN helper children created from the freshly compiled executable. Their controlled
self-exit values are 23 and 259. No foreign target PID/path can be supplied.
No process rights are changed; no injection, process termination API or privileges.

For each child the parent retains the handle returned through std::process::Child,
then opens a SECOND non-inheritable handle with exactly 0x00101000:
SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION. The secondary OpenProcess PID is
obtained from that same owned Child while the original handle remains held.
This is not a retrospective join from a TCP table, event timestamp or arbitrary PID.

Query sequence while the child is waiting on its private stdin pipe:
WaitForSingleObject(0), GetProcessId, GetProcessTimes, QueryFullProcessImageNameW
(Win32 and native forms), GetExitCodeProcess, WaitForSingleObject(0). Identity/time/
name observations must agree between both handles. Then the parent releases one
byte, the child exits normally, and the parent waits with a finite bound. It reads
PID, creation/exit FILETIME and exit code again through the SAME retained handles.
The parent does NOT query image names after termination: no undocumented success
assumption about unloaded image data is required. Neither does it require exit
UTC time >= creation UTC time; FILETIME is not a monotonic clock.

GetProcessTimes' exit-time output is undefined while the process is running; it
is deliberately unused until the process object is signaled. Raw 64-bit FILETIME
values are emitted as 16-digit hex strings to avoid JSON floating-point loss.
Image names are emitted as lossless UTF-16-unit hex, not promoted to canonical
file identity, content/signature trust, image-section identity or original AppId.

The deliberate exit-259 negative control addresses a documented contract trap:
GetExitCodeProcess == STILL_ACTIVE alone does NOT prove liveness. The helper
terminates with that same application code; WaitForSingleObject must still show
a signaled process. This is a test of the observation rule, not a new Windows bug.
PID reuse is not forced or claimed. Separate reads are not an atomic snapshot.

## Runtime, FFI and delivery scope

Only direct imports: OpenProcess, CloseHandle, GetProcessId, GetProcessTimes,
QueryFullProcessImageNameW, GetExitCodeProcess, WaitForSingleObject, GetLastError.
Small FILETIME repr(C) only (size 8, alignment 4); no EPROCESS or WFP structs.
Child creation and an anonymous stdin pipe use std, not any external binary.
Both helper processes are this exact compiled executable. They self-exit on EOF,
release, or their own 30-second deadline. Parent waits are finite. No socket, BFE,
callout, driver, filter, foreign process enumeration or network test is present.
The PowerShell supervisor can terminate only its directly owned compiler/probe
child on its 120-second timeout; helper EOF/deadline cleanup needs no kill by PID.

Default script mode builds and runs 16 pure Rust tests plus a 60-case wait/exit
matrix. Only explicit -RunOwnChildProbe executes the two helper-process cases.
The script downloads one pinned Rust blob (or reads exact -OfflineSource bytes),
checks Git SHA1 and SHA256, and does no checkout or installation. PATH is modified
only in its own process and restored. A fresh temp directory stores all artifacts.
It validates JSON row order, integer/bool types, exact phases, retained PID/epoch,
wait/exit values, raw names, summary and false proof flags. Raw stdout/stderr and
source/executable digests go into R133_EVIDENCE.json and evidence-only.zip.

## Actual execution status and independent checks

Performed locally: 28/28 Python source/JSON/negative tests; separate Node oracle
agrees with Python on 60 wait/exit combinations. Expected matrix SHA256:
`9c7a1ee3052a06be99b03e0475b2cc00a08da565aa221bee4d5166649f0126dd`.
Fixtures include changed epoch, changed PID, string booleans, wrong wait result,
wrong terminal code, embedded NUL, misleading proof flags and 64-bit time loss.
The source and script are clean-room Rust + documented Microsoft APIs.

NOT RUN here: R133 Rust compilation/unit tests, Windows PowerShell parsing/runtime,
and native own-child probe. This Linux executor has no Rust/PowerShell toolchain;
no toolchain was installed. R132 native PASS does not transfer to R133. The user
must supply the new native output before any R133 runtime acceptance is recorded.
Small-model local review tasks are in LOCAL_REVIEW_TASKS.md; none dispatched.

## Next deciding observation / unchanged trust boundary

Execute the exact published script with -RunOwnChildProbe on the same already
approved Windows host. Required output: two alive/exited row pairs and summary
OWN_CHILD_HANDLE_LIFETIME_PASS_NOT_NETWORK_PROOF, then collect evidence-only.zip.
Read/API errors remain failures with the exact stage and DWORD; do not change
security settings or retry with elevated rights to turn a failure into a pass.

Even a successful run only validates own-child user-mode handle observations.
It cannot certify original kernel process reference -> PID/creation epoch/start
key/canonical EXE/AppId -> ALE CONNECT_REDIRECT/AUTH_CONNECT -> redirected accepted
SOCKET context/records -> CLAIM -> authenticated SSH egress. PID reuse and callback
latency, IPv4/IPv6, reused 5-tuple, sibling DIRECT, DNS/UDP/QUIC and WFP/SSH loss
remain unproven. No PacketBound/G2 PASS, no-DIRECT/leak-free, or G1 dd1ab3c transfer.

## Primary contracts checked

- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew
- https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
- https://learn.microsoft.com/en-us/windows/win32/procthread/terminating-a-process
- https://doc.rust-lang.org/std/process/fn.exit.html

Git mutation: this branch only, expected-current SHA, force=false; STOP on conflict.
