# R38 — actual unsigned attestation CAB; reproducible source, signing still external

Date: 2026-11-08. Scope: `research/windows-wfp-ale-attribution-20261107` only. No changes to main, beta, PR #56, local runners, firewall, VNC, services, Windows protections or production filters.

## Concrete executed milestone

Exact checkout `ecc66afe63ab0c1e65274da7dd95f7026140d782` ran on GitHub-hosted Windows 2025:

- [Actions #42454895627](https://github.com/i-shutov/flowbridge/actions/runs/42454895627): **3 jobs SUCCESS**, including no-load x64 Rust kernel, Windows broker, standalone Rust SSH tests and separate real isolated OpenSSH transport.
- The Windows job created `signing-r38/FlowBridgeG2R38.cab` with `MakeCab`, re-extracted with `Expand`, checked SHA256 of both members, and confirmed the source `.sys` is **unsigned**. Seven additional INF/staging/PE/preflight regression methods **7/7 PASS**.
- Original artifact ID 13606839479, GitHub SHA256 `2ab92364a4f580dc3284d5d98a83d2fffe5f0785e12e051101e8c589a4950046`, independently downloaded, original CRC valid.
- Independent verifier recomputed hashes on kernel and broker, source-manifest SHA for **29/29 files**, CAB header (MSCF, one folder, two files), and original CAB SHA; no interpreter loaded any driver.
- The **unsigned .sys**: 207872 bytes, SHA256 `74626c2e6d07d51a15b0886f81e9aa1460731875eeb1f293d0d378077486861c`.
- The **Windows broker**: SHA256 `c0d584be879e55dc88a541e6e5644d970ac9819588e7b220e96fab2f6d200247`.
- The **unsigned CAB**: 21731 bytes, SHA256 `047b8158c9d8a1a61734ff5101f3b50a3cb4d4336a9376a0c8bd694a92cc0687`.
- The **INF**: SHA256 `29b62d0272436d62098d2514a6586db171261faaa58c9ac31a271518f3c5fbdd`.

Evidence is machine-readable in `R38_VERIFIED_UNSIGNED_ARTIFACT.json`. The signed-driver preflight script, compare-PE helper and source of the signing candidate are kept in `kernel-r19/signing-r38/`. The driver and broker are NOT an accepted native redirect pair yet.

## What *doesn't* follow from the green CI

No Microsoft Partner Center submission, EV-backed CAB signature, returned Microsoft-signed .sys/.cat, InfVerif independent approval, VNC or independent SYSTEM rescue, host rollback demonstration, driver installation/load, actual ALE callbacks, WFP policy commit, physical traffic capture or G2 acceptance has occurred. The unsigned CAB MUST NOT be installed. **The existing Microsoft attestation route for testing is documented as Windows 10+ Desktop, not a waiver to load the unsigned artifact on Server 2025**. Test-signing, SecureBoot off, HVCI off, Defender off or cross-signing workarounds were neither done nor recommended.

The **correct next R38 external gate** is a registered EV publisher and Partner Center Hardware Dev Center acceptance of the actual INF/CAB; an approved signed package then must be returned and independently verified on the exact target using `signtool verify /kp /c` plus same PE section bytes and SHA source provenance. Validate INF with official tooling first; `INFVerif` was not available/proved in this CI and `infverif_independent_completed=false`.

The read-only `preflight_r38.ps1` always exits nonzero and never sets host admission even when `Signtool /kp` passes, because current VNC, independent SYSTEM rescue, rollback and physical egress observation are separate **operator-observed** requirements. No program can truthfully claim a working VNC recovery merely by reading a local JSON field.

## R38A lease-revocation source correction

Just before the package, active authenticated SSH workers were updated to observe a sticky Tokio watch revocation signal at each handshake and the live `copy_bidirectional` stage. Source `0860bd2fc069259f4019ef17686a15d8b0c845f7`: two distinct completed Actions **#42454491815 2/2 PASS** and **#42454491799 3/3 PASS**, including isolated real OpenSSH and Windows no-load backend. The first prior R38A attempt failed because its CLI harness still supplied five arguments to the six-argument relay; the fix retained a real sender through the lab test. That failed run was preserved, not re-run. User-mode cancellation is not a system-wide kill switch; already-buffered bytes and crash-loss need R39 physical proof.

## R39 (gated) native acceptance

Only after R38's signature/host gates: one unmodified EXE launched after callbacks register, same-flow PID/epoch/AppId and ALE_CONNECT_REDIRECT ticket, actual ALE_AUTH_CONNECT receipt, accepted-socket context/records and terminal CLAIM, WFP records SET on *the physical SSH socket before connect*, pinned SSH host/user/channel proof and exact target bytes returned. Then independent negative controls (sibling/direct loopback, PID/endpoint reuse, R35 tombstones, R36 current/original AppId, SSH/PING/BFE loss, IPv4/IPv6, DNS/UDP/QUIC and physical DIRECT) before G2 can be considered PASS.

No driver load was performed in this task. `g2_pass=false`, `release_accepted=false`. Main/beta remain separate.

Official Microsoft sources:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation
- https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings
- https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs
- https://learn.microsoft.com/en-us/windows-hardware/drivers/develop/creating-a-primitive-driver
- https://learn.microsoft.com/en-us/windows-hardware/drivers/install/verifying-the-release-signature
