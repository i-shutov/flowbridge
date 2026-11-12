# R137 — native negative control for filename-derived AppId (read-only, no-driver)

Date recorded: 2026-11-12.

This experiment was initially prepared as R136, but the branch advanced concurrently
to a distinct R136 mapped-image experiment. No previous Git ref was overwritten;
the source and harness were renumbered to R137, repinned, and retested.
 Repository: `i-shutov/flowbridge`. Allowed branch ONLY:
`research/windows-wfp-ale-attribution-20261107`.

## Actual newly received R134 evidence

The owner supplied `/mnt/data/evidence-only(2).zip` from the approved Windows 10 Pro 19045 host.
SHA-256: `79cdb99f14c550982b8477bc3c69ee88bde21b167ce850a97ef065c93165ea4e`.

- All 18 ZIP entries have unique flat names and valid CRC. All `*.stderr.txt` are empty.
- Exactly 18 Rust tests were listed and 18 passed; metadata, unit tests and native probe exited 0.
- All 256 Rust contract-matrix rows match the newly regenerated Python oracle;
  independent Node agrees on SHA-256
  `bae850d1de8c78c1acbf4aee36fb1a1a67a54c6b72c7c6e09677c774442385ec`.
- Native five JSONL rows revalidate to observation mask 255; both held file handles
  have the same volume/FileID, with stable readbacks. The four returned AppId blobs
  are byte-identical (248 bytes including trailing UTF-16 NUL).
- Decoding the returned AppId *for this observation only* matches the lower-case
  native NT image path from `QueryFullProcessImageNameW`, with the NUL terminator.
  This is consistent with documented `FWPM_CONDITION_ALE_APP_ID` path semantics,
  **not** evidence of an image-section object bound to an original ALE connection.
- The uploaded evidence did NOT include test/probe binaries, so their reported
  SHA256 values cannot be independently recomputed from binary files. Source pins,
  raw PID, FileID, local file paths and raw AppIds were deliberately omitted from
  the sanitized public JSON except aggregate pass/fail, source hashes and lengths.
- `R134_RECEIVED_ACCEPTANCE.json` is a deterministic sanitized attestation of
  archive parsing; it is NOT a remote attestation or a replacement for kernel proof.

## Why this question matters

`FwpmGetAppIdFromFileName0` accepts a **filename** and returns `FWP_BYTE_BLOB`.
Microsoft defines `FWPM_CONDITION_ALE_APP_ID` as a lower-case fully qualified device
path, not a file identity (volume ID+file ID), signed binary identity, or retained
kernel process reference. An R134 positive therefore cannot prove that the named
file is still present or the right historical image section was executed.

R137 asks one sharper empirical question: can this Windows host obtain an AppId
for a sibling `.exe` **whose filename is verified absent immediately before and
immediately after the request**? No assumption is made about the answer.

The clean-room Rust program derives its own EXE path through
`QueryFullProcessImageNameW(GetCurrentProcess(), 0)`. The target is constructed
only under that parent on a fixed local drive, with a PID and wall-clock suffix
used for **uniqueness only, never provenance or chronology**. Up to eight candidate
names may be checked, but no file is created or modified. `GetFileAttributesW` must
return `INVALID_FILE_ATTRIBUTES` with `ERROR_FILE_NOT_FOUND` (2), not an ACL error,
for the chosen candidate. An error other than exact 2 fails closed as a probe error.

After confirming the *existing* EXE's own AppId twice, the program invokes
`FwpmGetAppIdFromFileName0` twice on that absent-name string, then checks absence
again. Returned nonempty blobs are copied as opaque bytes and released by
`FwpmFreeMemory0`; only result codes, lengths, repeatability and boolean
comparisons are emitted. The filename and raw AppId are NOT printed. No broad
BFE management enumeration, WFP transaction, subscription or write is used.
No socket, other process handle, driver/filter/callout, service or security setting
is touched. Rust compiler/harness only writes its own fresh temp directory.

## Interpretation, with both possible outcomes

- `ABSENT_PATH_APPID_ACCEPTED_NOT_ORIGIN_PROOF` (exit **0**): both calls returned
  stable, nonempty AppId for a name still absent according to the two attribute
  checks, and it differed from the existing EXE's AppId. This is an important
  counterexample: *the filename helper can return a label without confirming a
  present file under this observed situation*. **It is NOT a flow/origin GO.**
- `ABSENT_PATH_APPID_REJECTED_NOT_ORIGIN_PROOF` (exit **4**): both calls returned
  the same error DWORD; absence remained confirmed. This characterizes *this*
  Windows implementation and does not prove the inverse proposition for aliases,
  TOCTOU, process replacement or real ALE traffic.
- `NOT_STABLE_OR_NOT_CONFIRMED_ABSENT` / `AMBIGUOUS_APPID_EQUAL_TO_OWN_IMAGE`
  (exit **3**): inconclusive, never upgraded.
- `QUERY_ERROR` / native preparation error (exit **2**): preserve API stage/error.

All JSON statuses declare `kernel_origin_proof=false`,
`image_section_identity_proof=false`, `no_direct_proof=false`, and
`atomic_snapshot=false`. A file could appear and disappear *between* the
attribute checks: this experiment does NOT rule out such a race. Nor does it
prove file creation is impossible by others. The source itself does not create files.

## Reproducible checks, independent vs native

`r137_missing_path_appid.rs` includes **18 pure Rust unit tests** and a deterministic
256-row `--contract-matrix` that does not call Windows APIs. The separately
implemented Python and Node oracles agree on all 256 outcomes, SHA-256:
`a42dbe4fe12b36fd15b525dc0d659058c49aad3c77e3066305ad8529c5a65367`.
Distribution: 4 accepted-negative-name candidate states (exit 0), 8 rejected
states (exit 4), 244 inconclusive (exit 3). Synthetic distribution is NOT a
Windows failure or AppId rate. 28/28 local Python source/protocol/negative tests
PASS. The R134 upload was independently read and sanitized as described above.

**NOT RUN by this executor**: Rust compile/link/18 tests, PowerShell 5.1 parser,
`GetFileAttributesW`, or native `FwpmGetAppIdFromFileName0` on an absent file.
The source file and script are ready for the owner's authorized Windows host.
No kernel or WFP install is needed.

## Delivery

The published `FlowBridge-R137-MissingAppId.ps1` obtains one immutable Git blob
of the new Rust source and checks both Git SHA1 and SHA256 before compilation.
Default run compiles/tests only; `-RunReadOnlyMissingName` explicitly adds the
read-only negative-path native probe. The harness validates the two-record JSONL
schema, API codes, length/type limits, all six observation flags, recomputes the
mask and requires the exact matching diagnostic exit. It retains separate
stdout/stderr and SHA256 binary hashes, then saves evidence-only.zip. A failure
never silently rewrites the independent oracle. No network use except downloading
pinned public source; the probe binary does not open sockets.

## Bounded junior-model tasks (not dispatched)

A: Microsoft FFI audit of the eight allowlisted imported functions and owned
FWP_BYTE_BLOB lifecycle; confirm GetFileAttributesW error-code interpretation.
B: adversarial JSON/decision-protocol review, including 256-state oracle and
malformed native results; do not edit expected results to force PASS.
C: on the owner-approved Windows host, PowerShell parse, default synthetic run,
then **only when owner deliberately invokes the opt-in flag**, read-only negative
probe. Return exact evidence SHA and native codes. No Git writes delegated.

No callable junior-model executor exists here; **none was launched**.

## Remaining architectural NO-GO and primary Microsoft contracts

This does not prove `kernel process reference -> PID+creation epoch+start key+
canonical EXE+AppId -> ALE AUTH_CONNECT/CONNECT_REDIRECT (IPv4/IPv6) -> real
accepted SOCKET/redirect records -> one-use CLAIM -> SSH`.
Process death/PID/5-tuple reuse, reauthorization, sibling DIRECT, DNS/UDP/QUIC,
WFP/SSH loss and continuous filtering remain NO-GO. The independent R135
`FWPS_RIGHT_ACTION_WRITE` veto issue is also not solved by a filename helper.
No PacketBound/G2 PASS, leak-free assertion or G1 dd1ab3c carryover.

Official references:
- https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0
- https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-
- https://learn.microsoft.com/en-us/windows/desktop/api/fileapi/nf-fileapi-getfileattributesw
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew

Change scope: only new `research/wfp-ale/r137` files in the single research branch.
No R19 implementation, main/release/beta/PR56, runner/CI, services,
firewall/UFW, security options, networks, automations, NDISRD, VNC, drivers,
filters/callouts, paid operations, ProxiFyre/PR40/vendor/C++ payload touched.
Git mutation uses exact current expected SHA and `force=false`, STOP on conflict.
