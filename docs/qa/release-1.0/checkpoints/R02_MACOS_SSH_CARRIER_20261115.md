# FlowBridge 1.0 — R02 SSH carrier bypass security checkpoint

Date: 2026-11-15. **CODE AND HOSTED REAL APPLE SIGNATURE PASS; NATIVE NE R02 STILL NO-GO**.

## Engineering delta on actual product

Draft [PR #66](https://github.com/i-shutov/flowbridge/pull/66), stacked on
Draft PR #63, exact source `328768f064994eb2797f128460d78a025e9c6032`.
Neither `main` (`5b5afc2feeda2195f302380e615ba003d4906e09`) nor
original 0.3.0-beta.1 source (`f5ecd48d8f81c594f755a55e7969b57d20903020`)
was changed. No release/tag/merge, no user host or driver operation.

**Source-level root cause:** native `TransparentProxyProvider.handleNewFlow`
previously returned DIRECT (`false`) for *any* flow whose OS-reported signing
identifier matched `/usr/bin/ssh`, even when that flow targeted a different
remote address or port. This broad signing-ID exclusion could supersede
selected Proxy/Block rules. This is a deterministic code defect, **not**
a claim of a physically witnessed leak.

**Product correction:**

- Desktop startup now requires a literal IPv4/IPv6 SSH server and port for
  transparent integrated SSH. Hostnames cannot create a dynamic exemption.
- NativeController carries exact server IP:port and managed SSH ownership
  config. Missing, duplicated, invalid or unauthenticated exclusions fail.
- App and extension now use **one source implementation**
  `native/macos/Shared/SystemSSHCarrierIdentity.swift`, which checks
  actual `/usr/bin/ssh` with Apple Security `anchor apple` and retrieves
  the real signing identifier; the user profile cannot authorize
  arbitrary app IDs as a trusted carrier.
- Source signing ID, canonical IPv4/IPv6 bytes and exact server TCP port
  **must all match** for carrier bypass. Other SSH destinations use
  ordinary policy; unknown signing ID blocks before a DIRECT verdict.
- Existing R02/R06 startup lifecycle and transactional Apply guards from
  PR #63 remain in effect. No WFP/NDISRD changes.

## Verified same-source CI matrix

| CI and authentic evidence | Outcome |
| --- | --- |
| [Provider actual Swift body #43681078817](https://github.com/i-shutov/flowbridge/actions/runs/43681078817) | **1/1 PASS, 32/32 Swift tests, 5 old failures reproduced, 5 mutants rejected** |
| [Original provider artifact #14147893527](https://github.com/i-shutov/flowbridge/actions/runs/43681078817/artifacts/14147893527) | ZIP CRC PASS, SHA256 `c83da88a4da8fecbb57d34c80135011235584af21ddb7e9c4b3777260fa01b5c` |
| [Real Apple Security Intel/ARM #43681078771](https://github.com/i-shutov/flowbridge/actions/runs/43681078771) | **2/2 PASS**, native actual `/usr/bin/ssh` verified on x86_64 and arm64, both return `com.apple.ssh` |
| [Original real signer ARM #14148123414](https://github.com/i-shutov/flowbridge/actions/runs/43681078771/artifacts/14148123414) | CRC PASS, SHA256 `36e325bdce340bec3e2fe250ba8e6dbffc7a8ff86743fc541f87634acec0a1fe` |
| [Original real signer Intel #14147734396](https://github.com/i-shutov/flowbridge/actions/runs/43681078771/artifacts/14147734396) | CRC PASS, SHA256 `2249bdcad278858bbcdbbca4a38ed1a63eced59d3c1ab2685e444ef10a7db23b` |
| [Full native app/Rust #43681078874](https://github.com/i-shutov/flowbridge/actions/runs/43681078874) | **5/5 SUCCESS**, including local app package and actual native Network Extension Apple SDK target compiled unsigned |
| [DNS vertical #43681078758](https://github.com/i-shutov/flowbridge/actions/runs/43681078758) | **3/3 SUCCESS**, no physical DNS interception claim |

All source hashes were taken from the original provider CI report;
all three original ZIPs were downloaded, CRC-tested, and independently
hashed. Test-only Swift shims cover the OS/FFI provider calls; the
Apple signer run executes the **unmodified production verifier code**
with the real Apple Security.framework on both native architectures.
The full application workflow compiles production code against Apple SDK
with signing disabled; no actual extension was installed or activated.

First patch in this block failed focused CI for a too-late unknown-identity
guard and acceptance of an exclusion without an owned managed endpoint.
The next source correction resolved both. The initial full macOS build
also found a missing `sshTransportEndpoint` property in the local SOCKS
NativeController stub. That was corrected and full CI then passed.
Failures were retained in GitHub history; none were re-labelled PASS.

## Still-open trust/physical requirements

1. The **same authentic SSH application signature plus the exact same server
   IP:port does NOT distinguish a second, unrelated `/usr/bin/ssh` process**.
   A kernel/OS-issued process-instance audit token bound to an owned SSH
   supervisor PID/lifetime is a separate acceptance problem.
2. Apple's `NEFlowMetaData.sourceAppAuditToken` is nullable. Its documented
   metadata scope concerns per-app VPN providers and cannot be assumed
   present/authoritative for every transparent-proxy flow. No fallback
   from missing audit evidence to broad DIRECT is permitted.
   Reference: https://developer.apple.com/documentation/networkextension/neflowmetadata/sourceappaudittoken
3. R02 still requires an actually provisioned signed/entitled app
   and system extension, user-approved activation on real Apple Silicon
   and Intel, selected/unselected IPv4/IPv6 and SSH outage tests,
   real DNS/UDP/QUIC/do-not-fallback, Stop/reboot/uninstall, independent
   original packet/egress observation and rollback.
4. R01 Windows G2 retains the unrelated kernel PacketBound witness blocker.
   Research R195 found its legacy WITNESS queue producer disconnected;
   no native signed WFP/NDISRD attribute proof was performed.
5. Owner A3 Win10/11, A4 original pkg manual Mac GUI/real SSH, A5 legal,
   A6 independent reviewer and A7 publication remain separate open gates.

All 19 accepted release gates remain FALSE,
`beta_release_accepted=false`, `version_1_0_accepted=false`.

## Follow-up

Do not elevate the same-IP same-signing-ID exclusion to a process claim.
Next independent security task: determine whether real transparent NE flow
metadata reliably supplies an OS-owned audit token and whether it can
be bound to the existing owned OpenSSH supervisor's process birth epoch.
Use a **signed, approved, isolated native macOS lab** for the physical
evidence; do not install or enable NE on any owner machine without
its prerequisites, rollback and the owner's approval.

Machine-readable original-SHA evidence:
[R02_MACOS_SSH_CARRIER_20261115.json](R02_MACOS_SSH_CARRIER_20261115.json).
