# Windows Rust capture candidate: current G0-G6 matrix

Updated 2026-11-04. **Pre-beta; no release approval.** This summary belongs to its
containing source revision: never transfer historical CI/native PASS to that revision.
The full previous QA journal is preserved, unchanged, in
[RUST_CAPTURE_INTEGRATION_CANDIDATE_2026-11-03_ARCHIVE.md](RUST_CAPTURE_INTEGRATION_CANDIDATE_2026-11-03_ARCHIVE.md).
The current working source/merge and latest CI are recorded in the
[Draft PR #56 top matrix](https://github.com/i-shutov/flowbridge/pull/56), not inferred
from an older paragraph in the historical journal.

| Gate | Current verdict and missing proof |
|---|---|
| G0 provenance | Revised source: hosted CI and new independent ZIP/PE/FFI/NSIS audit **PENDING**, not inherited. Historical input source `1e81a8941faf6d8988e071d768e6134a1f80a564`, merge `a2647c75300e23b79f9fc41eccf47aff41697cbd`, main `5b5afc2feeda2195f302380e615ba003d4906e09`; four hosted workflows green on that historical source only. |
| G1 native recovery | **FAIL / OPEN.** Last authorized manual native run [41842286785](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41842286785): FAIL / 23-of-23 PASS / FAIL on the historical source, not this change. New controlled-origin fixture/harness integration has local checks only. No causal Rust transport fix or 10/10 proof. |
| G2 arbitrary EXE | **OPEN.** No unprepared independent EXE packet-to-PID+creation-epoch proof; IP Helper/known socket is not PacketBound. |
| G3 persistent fail-closed | **OPEN.** Agent-local gate does not survive agent loss; NDISRD mode 0 is DIRECT-capable. Independent app-specific WFP lifecycle still required. |
| G4 protocol containment | **OPEN.** Native selected-app DNS/UDP/IPv6/QUIC/DoH/DoT route-or-block and real dual-stack controls/traces missing. |
| G5 complete Windows product | **OPEN.** [Real panel window smoke 41820391924](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41820391924) is not select-EXE routing or complete installer/service/upgrade/recovery acceptance. |
| G6 Win10 / Win11 | **OPEN.** Candidate-only local Win10 22H2 Codex report, separate Win11 x64 native tests, negative tests, 24h soak and upgrade/rollback/owner approval missing. Server 2025 cannot substitute. |

## Actual engineering change

The release oracle depended on public `example.com:80`. IANA explicitly does not
provide it as a testing endpoint. That is a confirmed test-design defect, not proof
of the source of the two particular EOFs. The accompanying implementation adds a
bounded owner-controlled origin, exact-response normal/half-close controls,
independent server receipt journal and strict pre-native configuration gate to the
existing harness. It preserves all 23 phases, the original request, conservative
TCP ownership checks, signatures, rollback, explicit safety consent and no DIRECT
fallback. No speculative Rust packet/SSH change was made.

[Implementation and rollout contract](G1_CONTROLLED_ORIGIN.md).
[Investigation and evidence](../../insights/2026-11-04-g1-upstream-eof.md).
[Functional plan and blockers](../../plans/windows-release-g0-g6.md).

Local validation: eight tests PASS with real loopback sockets and synthetic SOCKS
faults; Python compilation PASS. This environment did not run Rust builds, actual
OpenSSH, signed NDISRD or Windows acceptance. Required hosted CI remains separate.

## Historical evidence that remains valid only for its exact source

The latest failed native run used protected QA workflow
`0e7e8873b37a0f82f2c7b615e153c105aa1a5539`. Trial 1 failed at
`ssh_restarted_self`; trial 3 at `ssh_restarted_powershell` after two successful
post-restart transactions. Both had full successful SOCKS CONNECT, completed
relay and 57 request / 0 response bytes. Trial 2 completed all 23 phases.
Both failed trials stopped before the unexpected-SSH-death phases.

All three actual native report ZIPs were independently CRC/SHA-256 checked:
trial 1 `2742c92c811b73e5bcae10799efbb59809705f99b87322c28a0678d66bd6973b`,
trial 2 `4376c6a93836ef54ebb33b73c60651e285588fa1470df36f8865ac29028091ab`,
trial 3 `6206528f3ebea3e8edfba6b007d9260dc85b7d9a46ccbcba09c6ee9b59987b9b`.
Their reports retain SYSTEM rescue armed/disarmed, mode-zero rollback, scoped
firewall cleanup, active Defender and healthy post-test network. A good rollback
is not persistent app protection, and one full pass is not stable G1 acceptance.

Historical source managed-SSH baseline: 128 held /1152 denied /10000 byte-and-
half-close verified /4 independent children. Keep it mandatory. Raw backend 512
stability remains **false**. Hosted DNS success is not a leak-free claim.

## Immediate release blockers

The new source needs all four hosted workflows and independent artifact-byte audit.
The separate HTTP origin needs explicit deployment approval/configuration; none was
provisioned here. Only then repin the existing private manual-only workflow, including
the additional allowlisted fixture file and protected local origin context. The
private old ref must not be used as evidence for this source. Authorized dispatch
is possible through official UI/CLI; it is not a reason to change triggers or use
rerun. No native action was dispatched by this change.

Keep `flowbridge-native` and `flowbridge-ui` isolated. Preserve exact-host/VNC,
signed NDISRD, Defender/firewall, independent SYSTEM rescue and verified rollback
for every native run. No main merge, release, vendor redistribution or permission
to weaken host security. Hourly engineering and independent 12-hour review continue
separately. Never ask for personal Win10 acceptance before an actual candidate.
