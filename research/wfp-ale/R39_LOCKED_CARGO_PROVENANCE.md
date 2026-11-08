# R39 — exact Cargo dependency closure for unsigned driver/SSH broker

Date: 2026-11-08. Research branch only.

## Original independently audited provenance

Original source commit `2086cbaa860671cb3fa13524751fddf3f301e926`;
real Windows no-driver-load CI [run 42463556304](https://github.com/i-shutov/flowbridge/actions/runs/42463556304).
Original artifact ID `13610587594`, ZIP digest
`ab18b9b4bc5fe889ecefaf063cfec9cafed394a81aefc250fab7092d7a3397db`.

The two original archive members were independently byte-reviewed and SHA-256
checked. Read-only Windows export CI [run 42464797927](https://github.com/i-shutov/flowbridge/actions/runs/42464797927) checked the same hashes a
second time on GitHub's Windows runner before text transport.

- `kernel/Cargo.lock`: SHA256 `a5a740f75007652de912d934499dadc7fe6ebbf14dbeccd0ec4ba748dd3af2c0`, 5,931 bytes, 27 packages.
- `broker-package/Cargo.lock`: SHA256 `5b0d34550f2a1449447552b74470960e3d9d18f31b5499dc2c1450446f53d2e6`, 45,558 bytes, 185 packages (including trusted SSH path dependency).

## Corrected reproducibility contract

Both `Cargo.lock` sources are now tracked IN the research repository.
`locks_r39.py` runs **before** the build/source snapshot and rejects any
missing/changed lockfile, version, package count or missing registry checksum.
`package_r24.py` records both exact lock bytes in the 34-file (previously
30-file) SHA256/Git-blob source manifest. `build-kernel.ps1` no longer calls
`cargo generate-lockfile`: it compiles with `cargo build --locked --release`
using these exact dependency closures and retains the originals in the
artifact. No automated signing or driver installation occurs.

This pins dependency package choices and package checksums; it does NOT
guarantee byte-for-byte equal PE/PDB output across different linker/SDK/compiler
versions, no-toolchain drift or a signed kernel artifact. Signed submission must
still re-attest the exact newly compiled `.sys/.inf/.pdb` and source hashes.

## Native R39 external gates remain

Microsoft-signed driver and catalog approved for the exact *Desktop target*,
current independent VNC and SYSTEM rescue, real rollback, physical egress
observer, actual same-flow ALE/AUTH/socket claim and authenticated SSH proof
are still missing. Windows Server 2025 runner is compile-only. No system
protection or test-signing changes. `g2_pass=false`, `release_accepted=false`.

Do not use R38C driver/PDB/CAB hash values for a later locked rebuild.

## Executed final exact-lock Windows CI and negative checkout RCA

- Initial raw lockfile checkout test **correctly failed closed** on Windows
  [run 42464949781](https://github.com/i-shutov/flowbridge/actions/runs/42464949781):
  GitHub blobs were byte-identical to original source, but Windows checkout
  converted LF into CRLF, changing SHA-256. A second pre-fix run
  [42465024496](https://github.com/i-shutov/flowbridge/actions/runs/42465024496)
  also failed before driver staging. **Neither failing run is silently rerun/promoted.**
- Fixed by enforcing `text eol=lf` for both tracked Cargo.lock files
  in root `.gitattributes` and by adding that path to the Windows CI trigger.
- [Final Windows run 42465140005](https://github.com/i-shutov/flowbridge/actions/runs/42465140005),
  source `c2829e87da59e16f06b631af683aee4101ff6621`: **3/3 jobs SUCCESS**.
  5/5 Cargo mutation/absence tests, 11/11 kernel ledger, 7/7 AUTH,
  19/19 handoff, 44/44 actual broker and 9/9 signing-stage source
  regressions PASS. Signed-driver or kernel runtime test was not performed.
- Exact final original Actions artifact ID `13611128671`,
  independent ZIP CRC + source SHA256/Git blob, PDB/CodeView GUID+age and
  41 CAB MSZIP blocks verified. Artifact SHA256
  `b297b1a8ebd11d3fef9f5150f95a8ddfc54208a0bf0c0c7b2fad5479db051fc4`.
- Final `.sys` SHA256 `c613fd1d98a9a4e22d6551f07143c7821263df2732c3e25bae2543b1ca7d4c00`.
  PDB `743beeac0e206b015d8ec970a9a1199bf2353b113d34cc1b05b1cc5b73c31579`.
  Broker `295bc4b74c42e95f3f94d7576bfba7a4e1aeee4e2ba52dc2c84f007d703ac2bb`.
  Unsigned CAB `bad0786ec048c33915d425bab40cb20a50f2a21f6107c3fc28d1d165c1c3b0c2`.
  INF unchanged SHA256 `29b62d0272436d62098d2514a6586db171261faaa58c9ac31a271518f3c5fbdd`.
  The unchanged INF was independently Microsoft WDK InfVerif /w, /u PASS
  in earlier run 42458944899; **no fresh InfVerif claimed** here.
- Machine-readable `R39_VERIFIED_LOCKED_WINDOWS_CANDIDATE.json` records
  `signed=false`, `kernel_loaded=false`, `native_g2_pass=false`.
  No closed R41 post-CLAIM owner-exit proof is inferred from this build.

For Microsoft signing use **only** the exact current unsigned candidate
and the exact independent receipt; the old R38C and pre-lock R39 hashes
identify different builds. A signed-returned `.sys/.cat` still requires
current target-specific signature and Windows desktop validation plus
independently exercised VNC/SYSTEM rescue, rollback and physical egress.
