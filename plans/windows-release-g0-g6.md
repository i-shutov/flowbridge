# Windows release plan: G0-G6

Updated 2026-11-04. Work in Draft PR #56 only. Full Windows product is the development
target; publication and main merge remain owner decisions. This file replaces
repeated status-only loops with explicit outputs and exit criteria.

## Current block: controlled-origin G1 recovery

| Work item | State | Deliverable / exit criterion |
|---|---|---|
| Identify invalid external HTTP oracle | DONE | IANA primary sources + exact historical FAIL/PASS/FAIL in `insights/2026-11-04-g1-upstream-eof.md` |
| Implement bounded origin + no-driver causal controls | IMPLEMENTED, local tests PASS | Peer-scoped server, independent hashed receipts, full SOCKS CONNECT, normal/half-close probes, no DIRECT fallback |
| Integrate strict native origin prerequisite | IMPLEMENTED, native untested | Missing/legacy origin fails before FFI/SSH; identical original and SOCKS destination; all 23 native phases retained |
| Current-source hosted G0 | PENDING for the revised source | All four workflows; independently download/hash candidate ZIP, PE, FFI and unsigned NSIS; record actual merge parents |
| Independent reachable origin deployment | **STOPPED подтверждён** после окна 600 секунд 2026-11-04 17:09:24–17:19:24 UTC; Windows path OPEN | Run `41873379455` SUCCESS; final artifact `13345723726`, ZIP SHA256 `ee7a01e9b3315b102de625aa41bc05c225c22e01975a29fc34e64e7e7023ea0b`, независимо проверены три JSON ≤16 KiB. Final: STOPPED, origin_connections_observed=0, native/Windows-controls/release=false. Private receipts кодом не удаляются; без повторного node-presence probe. Listener не перезапускался; native acceptance NOT RUN |
| Private protected workflow migration | PENDING exact new artifacts | See rollout contract below; never dispatch default main or rerun old source |
| Causal native experiment | NOT RUN | Authorized manual dispatch, all fresh safety gates, preserve every failed phase and independent origin receipt |
| G1 acceptance | OPEN / historical FAIL | Establish causal finding; >=10/10 consecutive full 23-phase native PASS on ONE source/binary set, 0 selected physical DIRECT, fresh SSH children and independent rescue/rollback |

Do not call a controlled-origin fixture fix a proven Rust transport fix. If the
controlled experiment finds a transport defect, implement its smallest demonstrated
Rust correction and rerun exact-source acceptance. If attribution remains ambiguous,
record that boundary and keep G1 open rather than assigning blame to IANA.

### Private workflow migration contract

After fresh hosted CI and independent byte audit, update only the existing
`qa/wfp-signed-ndisrd-coexistence-20261102` branch with expected_sha and force=false.
Repin public source, PR merge, artifact run and independently computed file hashes.
The tooling manifest now has **12 payload files plus manifest.json (13 total)**;
add only `g1_controlled_origin.py` to the exact allowlist. Do not broaden it.
Replace `GetHostAddresses('example.com')` with the literal approved origin from
protected local configuration. Include its `controlled_origin` object in context
and require equality with `target_ipv4`; never override the SOCKS destination.
Fail on missing consent/configuration before artifact hydration or driver action.
The code-level positive controls then run before FFI/SSH/native activation.

Keep workflow_dispatch only, unique `flowbridge-native` scheduling, exact host
identity, current official driver signature, VNC, Defender/firewall, independent
SYSTEM rescue and verified rollback. The interactive `flowbridge-ui` is only for
authorized bounded GUI smoke. The private main workflow is historical and unsafe
as a default; do not run or modify it to obtain an automatic native trigger.

### No repeated analysis-only loop

A cycle must implement an allowed functional block, produce genuinely new causal
evidence, or name the missing external action. Do not repeat the same counters and
call that progress. No speculative PID/ACK/FIN changes, sleeps, HTTP auto-retries,
new native canary categories or CI-only micro-commits. While native is blocked,
substantial safe G2-G5 code integration is allowed, but acceptance gates stay open.

## Following functional blocks

| Gate | Required complete vertical | Unacceptable substitute |
|---|---|---|
| G0 | Fresh source + merge parents + four CI results + independently verified artifact bytes at every revision | Provider digest, historical green SHA, unit tests alone |
| G2 | Unprepared independent EXE through real capture/flow/PID+creation epoch/relay/SSH; sibling DIRECT; churn/restarts | Pre-announced PowerShell socket, IP Helper snapshot called PacketBound |
| G3 | Independent persistent app-specific WFP barrier; SSH/agent/driver loss, mode 0, network change/reboot/rollback; explicit recovery | Agent-local gate, blanket machine block, dynamic permit alone |
| G4 | Native selected-app IPv4/v6 DNS/UDP/DoH/DoT/QUIC route-or-block with positive controls and traces | Hosted DNS success, TEST-NET-only deny, unsupported silently DIRECT |
| G5 | Least-privilege Rust service/IPC/ACL/user SSH/key separation; install -> select EXE -> start -> SSH -> stop -> uninstall; upgrade/recovery | Window smoke, SCM staging, SOCKS-only panel |
| G6 | Candidate-only local Win10 22H2 Codex report AND separate Win11 x64 native signed-driver negatives, 24h soak, upgrade/rollback, owner approval | Server 2025, requested-but-not-received Codex report, release target treated as release permission |

If arbitrary transparent attribution remains unproved, explicitly document that
limitation; a manual SOCKS mode must not be passed off as the complete Windows
protected product. macOS NE remains outside this Windows critical path.

## Continuity and release controls

Hourly developer stays enabled even when blocked; the independent 12-hour reviewer
remains separate. No schedule changes without explicit owner instruction. No main
merge, release publication, bundled vendor/AGPL code or weakened host protections.
Raw backend 512 stability stays false. Preserve the measured managed-SSH baseline
128 held /1152 denied /10000 byte-and-half-close verified /4 independent children.
VPS #3293462 is retained only while needed for a concrete authorized native block;
never delete it autonomously, and report unnecessary continuing cost explicitly.
