# FlowBridge — feasibility of GitHub-hosted-only engineering and QA (2026-11-05)

**Decision:** GitHub-hosted runners are confirmed usable for routine CI, installer builds, signed NDISRD loading, genuine passive packet reception, WFP runtime enforcement/crash lab and Windows SCM tests. They are **NOT YET sufficient as the sole release-acceptance environment** for FlowBridge G1–G6. Do not disable any self-hosted runner or mutate release policy as a consequence of these tests.

## Proven, exact sources

Original integration PR #56 source **dd1ab3c5644b4000e75e32385d1322c89240f03c**:
- Capture integration [#41996006451](https://github.com/i-shutov/flowbridge/actions/runs/41996006451): 3/3 successful jobs (Ubuntu 24.04, Windows 2025, macOS 15).
- Rust/native applications [#41996006265](https://github.com/i-shutov/flowbridge/actions/runs/41996006265): 5/5 successful jobs, including Windows GUI/installer and macOS package.
- DNS [#41996006549](https://github.com/i-shutov/flowbridge/actions/runs/41996006549): 3/3 successful jobs.
- Windows OpenSSH [#41996006293](https://github.com/i-shutov/flowbridge/actions/runs/41996006293): raw+managed, 2/2 successful jobs.
- **13/13 CI jobs successful, but no production G1–G6 acceptance is implied.**

Isolated GitHub-hosted kernel probes (on disposable windows-2025, never self-hosted):
- Original signed-driver read-only probe [#42008244427](https://github.com/i-shutov/flowbridge/actions/runs/42008244427), verified artifact [#13406191376](https://github.com/i-shutov/flowbridge/actions/runs/42008244427/artifacts/13406191376): Microsoft-signed NDISRD 3.6.2, MSI install exit 0, kernel SCM RUNNING, Rust device opened, ABI 0x06023000, two adapter records, clean MSI uninstall exit 0.
- Combined packet/WFP/SCM probe [#42009498724](https://github.com/i-shutov/flowbridge/actions/runs/42009498724), exact workflow SHA **105180f1e2785122ebd808d8de18ca1e0f7b9789**, verified artifact [#13406217758](https://github.com/i-shutov/flowbridge/actions/runs/42009498724/artifacts/13406217758), archive SHA-256 **f98a5d8c9343830f7ca89aa3e7268a516c236137385fae4ad5af99e854c7e3cf**:
  - Signed NDISRD installed and original Rust `\\.\NDISRD` device/adapter API working; 1 compatible adapter on this ephemeral VM (image-instance variability, not a regression from earlier run's 2).
  - Original Rust NDISRD **LISTEN_ONLY** observes **176 real frames** (105 outgoing / 71 incoming), **0 injected**, loop completed and adapter mode rolled back to 0.
  - Native WFP dynamic app/port policy test PASS.
  - Hosted persistent WFP TCP/UDP IPv4/IPv6 crash-survival canaries PASS (test-specific independent SYSTEM recovery; not product G3).
  - Rust Windows SCM service start/stop/pipe lifecycle PASS.
  - NDISRD device/ABI still functioning after WFP/SCM tests; MSI uninstall exit 0.
  - The report explicitly marks `native_packet_attribution_proved:false`, `G1_full_native_selected_app_accepted:false`, `G6_Win10_11_accepted:false`.
  - **No NDISRD TUNNEL_BOTH / DIVERT / original frame reinjection / real selected EXE -> SOCKS -> managed SSH / full 23-phase native trial was performed.**

## Feasibility matrix

| Activity | Hosted-only disposition | Evidence / limitation |
|---|---|---|
| Rust, Python, DNS, CLI, package unit and integration | PROVED | Existing 13/13 green hosted jobs |
| Windows Win32 GUI build, NSIS installer, ordinary SCM lifecycle | PROVED | Existing CI and new SCM coexistence |
| macOS Swift/Xcode unsigned package and native tests | PROVED | Existing hosted macOS jobs |
| Windows signed NDISRD install, service, ABI, adapters | PROVED | Two independent hosted probes |
| Physical NIC NDISRD *passive* copy-only packet observation | PROVED | 176 packets, 0 reinjection, cleanup |
| WFP dynamic AppId and persistent QA canaries with driver present | PROVED FOR LAB SCOPE | Two real WFP test suites |
| NDISRD TUNNEL_BOTH original-frame divert/reinjection | NOT TESTED | LISTEN_ONLY does not confer interception |
| G1 23-phase native selected EXE -> owned Rust -> SOCKS -> managed OpenSSH -> recovery, 10/10 trials | NOT ACCEPTED | Requires separate controlled origin, exact-SHA, independent rescue/safety preflight and owner authorization |
| G2 true arbitrary EXE packet->PID + creation epoch | NOT ACCEPTED | IP Helper snapshot and passive samples are not packet attribution |
| G3 persistent app-specific fail-closed across agent/driver loss and reboot | NOT ACCEPTED | WFP lab canary is not production protection |
| G4 full DNS/UDP/IPv6/DoH/DoT/QUIC route-or-block / leak negative | NOT ACCEPTED | DNS unit+lab tests are not full selected-app native traffic proof |
| G5 full installed-product interactive desktop, DPI and driver-backed end-to-end | PARTIAL | hosted headless/component tests vs actual interactive user session |
| G6 native Windows 10 22H2 x64 and Windows 11 x64 acceptance | NOT COVERED | Standard Windows hosted images are Windows Server 2022/2025, not these OS targets |
| Power-loss/reboot/rollback on same machine, 24 h uninterrupted soak | NOT COVERED | Hosted VM discarded after job; max single job six hours |
| Stable external egress IP and inbound owner-controlled HTTP origin | NOT PROVIDED BY STANDARD RUNNERS | No stable source IP for external allowlist; owner origin is separate infrastructure |
| Long-lived production server and persistent VNC/SYSTEM rescue | NOT SUITABLE | Ephemeral CI is not a permanent Windows host |

## Recommended architecture and change control

**Can move now in principle:** ordinary pull_request/push CI across Windows/Linux/macOS; package and artifact pipeline; trustworthy on-demand hosted-only signed driver/WFP/SCM lab. Gate driver actions to a trusted workflow and pin vendor MSI SHA-256 and Microsoft signature. Ensure mode 0 and MSI cleanup, no driver installation on untrusted PRs.

**Keep independent until replacement QA is demonstrated:** one disposable external Windows test VM with snapshot/VNC and SYSTEM recovery for full 23-phase G1, long-lived origin, reboot/driver-loss and Win10/Win11 target-OS acceptance. It may be managed and scheduled entirely *through GitHub Actions*, but it is **not GitHub-hosted compute**. No reliance on the owner's current workstation is required for routine engineering.

**No migration action taken:** no configuration changes to existing runner registrations, GitHub repository settings, main, PR #56, private VPS workflow, user's Windows workstation or Wolfram server. All additional source files are isolated on branch `qa/github-hosted-feasibility-20261105`.

## Official platform constraints

- https://docs.github.com/en/actions/how-tos/manage-runners/github-hosted-runners/use-github-hosted-runners
- https://docs.github.com/en/actions/reference/runners/github-hosted-runners
- https://docs.github.com/en/actions/reference/limits
- https://docs.github.com/en/actions/concepts/runners/larger-runners

**Final answer:** Full migration of **routine development and continuous builds** to GitHub-hosted is supported by evidence. Full migration of **all release acceptance tests** to standard GitHub-hosted is **not yet defensible**. A small, isolated target-OS/reboot/recovery native QA lane must remain or be replaced by separately provisioned cloud Windows VMs.
