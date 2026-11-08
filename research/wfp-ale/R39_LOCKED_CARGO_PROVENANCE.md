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
`package_r24.py` records both exact lock bytes in the 32-file (previously
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
