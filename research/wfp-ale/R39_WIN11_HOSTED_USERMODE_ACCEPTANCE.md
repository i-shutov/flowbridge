# R39-DEV — actual hosted Windows 11 user-mode execution (not driver load)

Date: 2026-11-08. GitHub-hosted **Windows 11 Enterprise ARM64**, build **26200**.
Branch: `feat/r39-win11-dev-lab-20261108` (draft PR #57 to independent research,
**not** main or beta PR #56). Does NOT install any Windows VM on the user's
Windows Server 2025 or workstation.

## Concrete execution

Original R42 clean-room Rust model could not compile because an identifier
started with a digit: `fn 5tuple_collision_is_not_identity()`. This was a
real compiler error in [Actions 42475953796](https://github.com/i-shutov/flowbridge/actions/runs/42475953796),
**not a passing R42 test**. Changed it to valid Rust identifier
`tuple5_collision_is_not_identity` in commit
`8743ad22372b0e930c7b13dd06196d40c43ec2c2`.

The next [real Windows 11 Actions 42476078493](https://github.com/i-shutov/flowbridge/actions/runs/42476078493)
compiled and executed actual-source Rust unit tests:
- R42 per-ticket post-CLAIM owner-liveness *model* **13/13 PASS**;
- kernel handoff wire / book *unit tests* **19/19 PASS**;
- hypothetical WFP trust contract *unit tests* **23/23 PASS**.
Total **55/55** real Rust tests executed. This does not establish
the kernel-to-broker trustworthy origin-exit notification or physical WFP.

Then [Actions 42476290355](https://github.com/i-shutov/flowbridge/actions/runs/42476290355)
SUCCESS, exact test source commit `c6f8bb439cbfc60d6c7169e8c0e9fc2ebfd3c01f`.
It repeated all 55 tests and executed the **actual previously Windows-x64
compiled** FlowBridge broker on Windows 11 ARM64 under OS x64 emulation.
Exact broker source artifact from Actions 42465140005, SHA256
`295bc4b74c42e95f3f94d7576bfba7a4e1aeee4e2ba52dc2c84f007d703ac2bb`.

Two nonprivileged broker modes passed:
- `--reject-unredirected`: ordinary user-mode sockets denied without WFP
  accepted-socket context (no kernel driver loaded).
- `--verify-policy-plan`: native Win32 WFP policy objects constructed and
  inspected in-memory; **no** BFE policy or filters installed.

Original Windows11 artifact ID `13615671245` has SHA256
`6c42bfa5bc89cc421886c0d0edc6de08816092ff354ee247c3e3afa956b9a1bc`.
ZIP CRC was independently verified; contents `environment.json`,
`rust-result.json`, `x64-broker-result.json`, `guest-readonly.json`,
`host-readonly.json`.

## EXACT scope (do not promote)

The available ChatGPT execution container is Linux without `/dev/kvm`,
QEMU/Hyper-V or suitable VM disk. We **did not** provision a persistent
Windows 11 VM there. GitHub supplied an ephemeral hosted Windows 11 ARM64
VM for these results. The Windows 11 ARM64 kernel cannot load the current
**x64** FlowBridge kernel driver. The x64 user-mode compatibility test does
not prove a real ALE_CONNECT_REDIRECT or ALE_AUTH_CONNECT callback, any
`.sys` installation/signature acceptance, no-DIRECT, IPv4/IPv6 physical
traffic, DNS/UDP/QUIC or post-CLAIM process-exit revocation.

Retained machine flags: `kernel_driver_loaded=false`,
`bfe_policy_changed=false`, `native_ale_redirect_executed=false`,
`g2_pass=false`, `release_accepted=false`.

For native x64 callout testing still need a separately authorized x64
Windows 11 VM with test-signing, independently recoverable snapshot/SYSTEM
access, and independent packet observation; this cannot be substituted
by ARM user-mode CI. No user's Windows Server was changed.

No private keys, host protections, VPN, GitHub runners or external machines
were modified by these read-only tests.
