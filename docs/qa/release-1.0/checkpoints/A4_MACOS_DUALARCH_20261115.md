# FlowBridge release checkpoint — A4 macOS dual-architecture frozen beta

Date: 2026-11-15. **Hosted Intel + ARM acceptance completed, owner A4 OPEN, 1.0 NO-GO.**

## What was actually achieved in this block

A separate [Draft PR #65](https://github.com/i-shutov/flowbridge/pull/65)
checks the **same original prebuilt binary** on native x86_64 and arm64
macOS. No recompilation, new signing or production merge.

| Check | Actual exact-source result |
| --- | --- |
| Source, inner kit and installer | Source `f5ecd48d8f81`, kit `4b51d413…b8b8`, pkg `7eb645e2…453c` checked on both hosts |
| Apple Silicon `macos-15` | Real original `.pkg` install/payload/app process launch/upgrade/uninstall/stable preservation **6/6 PASS** |
| Intel `macos-15-intel` | Same actual original `.pkg`, six native user-mode lifecycle steps **6/6 PASS** |
| Independent third job | Both platform reports present, actual CPU IDs distinct, same source/manifest/package hashes; **PASS** |
| Negative controls | **9/9 PASS**, including missing Intel, wrong CPU, forged owner status, incomplete lifecycle, false release GO |
| Full workflow | [#43676247783](https://github.com/i-shutov/flowbridge/actions/runs/43676247783) **3/3 SUCCESS** |

Original evidence was downloaded from the three GitHub Actions artifacts;
all original ZIP CRCs, SHA256 and JSON were independently checked.

| Original artifact | ID | ZIP SHA256 |
| --- | --- | --- |
| [Apple Silicon](https://github.com/i-shutov/flowbridge/actions/runs/43676247783/artifacts/14146717484) | 14146717484 | `883d41f46dc40286aee4a768cbe676015b4c475a1d3408f6d4290656d4bfcf45` |
| [Intel](https://github.com/i-shutov/flowbridge/actions/runs/43676247783/artifacts/14145964268) | 14145964268 | `ca3620629845c854cbf1d406fb63b76c4433a91d4bdaf57ec3dda891b26ce5b1` |
| [Independent comparison](https://github.com/i-shutov/flowbridge/actions/runs/43676247783/artifacts/14145529135) | 14145529135 | `ad10b02846dc2532f886e26543d22e38080f074bdcf7e57aa47d6333188dd2db` |

Exact final PR source `3510cb9db7bee3100df81c4bf67911115c47bba6`.
Previous runs and their real failure codes are preserved: the first
failed on an undelimited Bash status variable *after both native 6/6
results*, the next on an invalid synthetic missing-Intel fixture; neither
was a package failure. Both errors were fixed and the full new-SHA
matrix rerun successfully. Do not relabel previous FAIL attempts.

## Strict boundaries still enforced

- ARM64 and Intel jobs use **GitHub-hosted disposable macOS 15**. This
  does not constitute a user-owned Mac run. A4 remains owner `NOT_RUN`.
- GUI launch is a process surviving **four seconds**, not interactive
  keyboard/window testing, actual mouse ergonomics, manual SSH or routing.
- The frozen beta is **explicit SOCKS-only**. There is no system
  Network Extension, signed pkg, per-app interception, physical no-DIRECT
  or DNS/UDP/QUIC protection. macOS R02 remains NO-GO.
- Notarization, publisher signature, independent license/security
  acceptance (A5), independent review (A6) and publication (A7) remain open.
- Windows G2 is architecture-bound. WFP research R195 also reports
  a disconnected legacy WITNESS producer in R19; not native PacketBound.
  No modification of approved owner NDISRD-only production architecture.
- Existing Windows A3 no-Python hosted six-stage pass in PR #64 does not
  count as native Win10/Win11 A3. No release 1.0 GO.

## Next decisive actions

1. **A4 owner:** run the *unchanged* pinned pkg on actual Apple Silicon
   and Intel, preserving original JSON, real managed SSH, GUI/keyboards
   and independent review. Follow frozen [operator protocol](https://github.com/i-shutov/flowbridge/blob/5dd6ca35d975e536cd8901ebd9cae158aef02797/docs/qa/EXPLICIT_BETA_NATIVE_ACCEPTANCE.md).
2. **A3 owner:** run the Python-free QA script from PR #64 on VM-910136,
   then a separate Windows 11 x64. Original BMP/JSON + true OpenSSH host-key.
3. **R02:** signed and entitled NE app/extension, actual activation on
   physical Apple Silicon/Intel, selected/unselected dual-stack SSH
   and independent DNS/UDP/DoH egress/stop/no-DIRECT proof.
4. **R01/G2:** resolve approved Windows connection ownership backend
   with an actual native kernel witness; never infer PID/epoch from
   NDISRD packet bytes or ETW tuple/time guesses.
5. **A5/A6/A7:** choose FlowBridge-specific license, independent legal
   + security review and owner beta release GO before tagging/publication.

Machine-readable exact-SHA register:
[A4_MACOS_DUALARCH_20261115.json](A4_MACOS_DUALARCH_20261115.json).
All 19 full release gate accepted flags remain false.
