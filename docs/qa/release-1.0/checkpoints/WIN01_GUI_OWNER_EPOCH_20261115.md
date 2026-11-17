# WIN-01 / G2 — Windows GUI→elevated helper process-incarnation trust checkpoint

Date: 2026-11-15. **Real code fix + actual Windows hosted CI PASS. Kernel packet-to-process G2 remains NO-GO.**

## Scope and unchanged release boundaries

Draft [PR #67](https://github.com/i-shutov/flowbridge/pull/67) exact code HEAD
`fd8eb07705456528fc2c95b389eac029bab647ce`. GitHub Actions pull-request
test merge `48d49c19ee907523b7ac078933b857a791bf159d` has the **same exact
git tree** `c9efdd04867042a4937b7f6ac573795c9103741a` as the PR HEAD.
Main remains `5b5afc2feeda2195f302380e615ba003d4906e09` and frozen
0.3.0-beta.1 source remains `f5ecd48d8f81c594f755a55e7969b57d20903020`.
No merge, tag, driver loading, firewall, BCD, Defender, owner Windows access
or backend authorization changes were attempted.

**Original product defect:** GUI passed only PID and a stop event to the
elevated Windows capture helper. Listener TCP owner snapshot checked PID+port,
but not process-incarnation creation time. Asynchronous UAC/helper launch
did not bind the alleged GUI owner to an exact OS process lifetime.

**Production repair:** `native/windows/gui_owner_epoch.hpp` uses real
`GetProcessTimes` to read FILETIME birth epoch and `GetProcessId` to bind
a process handle to the PID, and `WaitForSingleObject` to require a still
running owner. `capture_launcher.hpp` passes its own PID+OS FILETIME as
`--gui-owner-epoch` together with stop event and profile SHA-256. The
`FlowBridgeCapture.exe` `GuiLifetime` checks all values on a retained
`OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE)` handle **before**
opening the driver and installing dynamic filters; the handle is held
throughout capture. Missing/bad epoch, wrong owner, already exited owner
and tampered profile deny. Unlike normal process handles, the valid
`GetCurrentProcess()` pseudo-handle equals `(HANDLE)-1`; the initial
mistaken rejection of it was found by real Windows CI and corrected.

## Exact-source hosted validation

| Real original evidence | Result |
| --- | --- |
| [Actual Win32 owner epoch #43692346319](https://github.com/i-shutov/flowbridge/actions/runs/43692346319) | **1/1 SUCCESS**, actual Windows process creation-time/PID/liveness; **3/3 mutants rejected** for PID, epoch and exited owner |
| [Original native owner artifact #14152683736](https://github.com/i-shutov/flowbridge/actions/runs/43692346319/artifacts/14152683736) | SHA256 `02442c77dac0b71cf01813e5bad73945ffa061a30ea1a0ba7c1113bb8bd014a2`, ZIP CRC PASS, 5 entries |
| [Full Rust/native application #43692346177](https://github.com/i-shutov/flowbridge/actions/runs/43692346177) | **5/5 SUCCESS**: Windows app+GUI/NSIS install→upgrade→uninstall; Rust Windows, Linux, macOS and macOS application |
| Compiled installed `FlowBridgeCapture.exe` CLI | **7/7 actual user-mode rejection/normal preflight cases PASS**, SHA256 `d6ff6f53cacd403b833d5431255eb4cba2e8b5c1a2fd61dd0ff9825dc325ba03`, no driver read beyond deliberate `--preflight` and no filter changes |
| [Original Windows installer evidence #14152659335](https://github.com/i-shutov/flowbridge/actions/runs/43692346177/artifacts/14152659335) | ZIP SHA256 `3620e1e41765957eba5822b0f200568d1e9988cb9d8ad3b745f55e7d81c21454`, CRC PASS, 14 entries, 11 positive installer assertions |
| Windows installed GUI screenshots | Five different compact views **964×641** pixels, plus visual rules/full GUI BMP; CRC and source JPEG/BMP bytes verified. Hosted automatic screenshots, NOT independent interactive visual acceptance |
| [Windows real BFE scope #43692346264](https://github.com/i-shutov/flowbridge/actions/runs/43692346264) | **1/1 SUCCESS**, ephemeral real Windows BFE selected-app filtering, **no custom driver loaded**; artifact #14152384949 SHA256 `6d82811484be01a2d1f2b1209728cceda49511fef719bad8b301e2b1a3f6150a` |
| [Windows WDK source build #43692346190](https://github.com/i-shutov/flowbridge/actions/runs/43692346190) | **1/1 SUCCESS**, development/unsigned driver compile only, no signed driver deployment |
| [Native DNS tests #43692346214](https://github.com/i-shutov/flowbridge/actions/runs/43692346214) | **3/3 SUCCESS**, code regression only, no physical DNS containment |

Original downloaded ZIPs were checked independently for CRC, SHA256 and
machine-readable reports. `native-installer-result.json` records
`passed=true` and **11 actual installed product QA checks**. The
`windows-owner-helper/result.json` explicitly reports
`PASS_USERMODE_PROCESS_HANDSHAKE_ONLY`, `g2_packet_origin_proved=false`.
The compiler/tested package is engineering version **0.2.0**, unsigned and
**distinct from** immutable beta v0.3.0-beta.1; do not transfer these
results across source SHA or call them owner-VM acceptance.

Initial CI failures were preserved and not hidden: (1) duplicate Win32
macro compile warning under MSVC `/WX`; (2) real current-process pseudo
handle mistakenly rejected; (3) legacy installer QA called the new helper
without its now-required birth epoch. All three corrections were rerun
on the exact final source SHA, with the original negative tests intact.

## Most important remaining P0

The work only attests the **GUI owner of the local user-mode SOCKS
listener**. It does not authenticate which process emitted an NDISRD
`INTERMEDIATE_BUFFER` packet, or prove a selected EXE's protected network
egress. PID+creation epoch presented by the GUI to UAC is also not
cryptographic authentication of the elevation requestor; it binds the
subsequently opened **process object**, not the origin of user commands.

The **approved NDISRD-only** backend lacks a trusted per-packet kernel
connection ID + original process creation epoch. A separately captured
ETW/IP Helper tuple/time match cannot establish this common kernel
provenance. Issue [#41](https://github.com/i-shutov/flowbridge/issues/41)
requires explicit owner review before any custom signed WFP/ALE product
backend; the research branch is isolated. Do not enable protected mode,
claim no-DIRECT, perform signed driver install/load on user Win10/11
or publish 1.0 based on the GUI-only handshake pass.

**Next WIN-01 gate:** independently verify actual kernel-origin
packet/accepted-connection identity, original endpoint and process epoch
on an explicitly authorized isolated Win10+Win11 lab with rescue/rollback.
Then complete WIN-02 selected-app IPv4/v6 through owned SSH and
WIN-03 independent no-DIRECT pcap/negative failures. Until then
`WIN-01.accepted=false`, `R01.accepted=false`, Windows 1.0 `NO-GO`.

Machine-readable evidence: [WIN01_GUI_OWNER_EPOCH_20261115.json](WIN01_GUI_OWNER_EPOCH_20261115.json).
