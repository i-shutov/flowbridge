## 2026-11-02 — EXACT-CODE integrated Windows security audit + signed-driver native recheck (PASS within narrow scope)

**Pin all evidence to the implementation HEAD, NOT to this documentation-only follow-up commit:** PR #56 `892812bb74d4225759a4d4a957c0d9d1df62e81f`, unchanged main `5b5afc2feeda2195f302380e615ba003d4906e09`, GitHub PR test-merge `717053184d6215d8c6eed92ac38350954fe392bc` (verified parents main + implementation HEAD).

All four exact-source Actions completed **SUCCESS**: [capture #41415306058](https://github.com/i-shutov/flowbridge/actions/runs/41415306058) **3/3**, [Rust/native #41415306106](https://github.com/i-shutov/flowbridge/actions/runs/41415306106) **5/5**, [DNS #41415305980](https://github.com/i-shutov/flowbridge/actions/runs/41415305980) **3/3** (**not** leak-free), [real Windows OpenSSH #41415305991](https://github.com/i-shutov/flowbridge/actions/runs/41415305991) managed **128 real held / 1,152 rejected / 10,000 authenticated byte/half-close verified / four independent supervised processes**. Raw capacity experiment reaches only **246 held** before failure; a green bounded raw characterization job **does NOT** prove stable raw 512.

**Actual Windows Server 2025 hosted candidate product + WFP verified**: the new required Python byte/security audit passes the exact allowlisted five-member Rust candidate, manifest, AMD64 PE32+, installed original Rust GUI → restricted IPC → authenticated OpenSSH/SOCKS, unsigned NSIS installer/fault rollback and **all 33 actual native-host WFP soft-lease checks**, including independently vetoed flow, held TCP revoked after temporary permit process death, persistent selected-AppId deny maintained, independent SYSTEM cleanup. The hosted test **did not activate NDISRD**. Synthetic negative contract tests 11/11; Rust capture unit tests 84/84. Independent audit JSON explicitly sets `actual_driver_divert_tested=false`, `protected_fail_closed=false`, `native_packet_to_pid_proven=false`, `dns_leak_free=false`, and `windows_10_11_accepted=false`.

The Windows hosted CI **computed** SHA-256 for nested five-file candidate ZIP `ac4c0b3c794a76a9cc015643c78023e8f9af99ae68fd7a533b5b696ead2e3f7d`, Rust x64 agent `5493b62129263aa7eb97f544a221890557c3cb6eddc858cb517c8101edf71d0f`, unsigned setup `4efe58976fb8cb3ef96c348480fd69f39a9a81cf01ccb06ed984cdabdec30c32`, manifest `7c212f8a0c48ea39dc73e99dfc994a87645399f390cb27be0af45929518ff7e5`. Outer capture Actions artifact #`13128360077` SHA-256 `9faa84a721bf7d58011e640734be52ab5e05b91e16540f893ade9428b2c41ac8` was **independently downloaded by private VDSina Windows runner** (its Actions log verifies download hash equals GitHub published digest); not a locally downloaded artifact in this documentation work.

**Real separately installed signed NDISRD on VDSina, SAME implementation SHA + GitHub test merge:** private QA branch fast-forward (expected SHA, no force) commit `f0753beabbb3565cf5b55422d1d9e8fcadae4fb9`, private [Actions #41420892324](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41420892324) **SUCCESS**, private [issue #1 evidence](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6573678007). NDISRD kernel signed-driver SHA-256 `8623a9c34531cf73de4286ad518b84af03a331c78959769a1ca38723e3258984` verified; active Defender and all firewall profiles. With original verified agent and two byte-identical copied Rust QA EXE files, three bounded actual signed-driver `LISTEN_BOTH` **copy-only** sessions observed outbound TEST-NET IPv4 UDP canaries while original Rust WFP dynamic AppId rule changed:

| Native phase | Selected QA EXE frames | Sibling QA EXE frames |
|---|---:|---:|
| Positive baseline without WFP rule | 2 | 2 |
| Guard installed/read back; selected AppId + port denied | **0** | **2** |
| WFP guard intentionally terminated, rule removed | 2 | 2 |

Independent local SYSTEM MSI-uninstall rescue was armed **before** the first NDISRD mode change; each of all three sessions was explicitly returned to adapter mode **0** and read back; rescue disarmed only after verified driver/Defender/network health. No raw address, PID, payload, packet identity or credentials saved. Artifact #`13129443479`, published outer SHA-256 `24e51855dad3fd9d8c39c6268f9a8065c74372066cc131e41d68cc43c182d0ca`. The native report was independently **parsed and strictly checked field by field** against the source/test-merge, exact binary hashes, 2/2→0/2→2/2, signer, health, rollback and all negative flags. Scope **PASS** is only WFP-denied selected QA outbound UDP against a genuine signed-driver **LISTEN-only observer**.

**CRITICAL nonclaims.** This is NOT packet→arbitrary PID+creation epoch ownership; WFP/NDISRD general ordering with `TUNNEL_BOTH`/diversion was not tested. No real arbitrary selected-app TCP rewrite→reverse TCP→SOCKS/SSH proof on this HEAD, production protected fail-closed after service/SSH/driver death, DNS/UDP/QUIC/DoH/DoT/IPv6 leak-free, or Windows 10/11 native acceptance. Mode 0 restores normal DIRECT-capable networking, not kill-switch protection. Window Server 2025 VPS is research only. Keep VPS #3293462 for separately rescued real-driver experiments. PR remains draft; main unchanged, no official NDISRD redistribution, no release.

---

## 2026-11-02 — Independent c60448 byte/lease/installed-client audit; new strict CI gate PENDING

**Source explicitly audited as input, not the new documentation/test commit:** PR #56 code
`c60448c8392170e9203afa52ba573c5df0aa2a99`, unchanged main
`5b5afc2feeda2195f302380e615ba003d4906e09`, actual GitHub PR
test-merge `aa753a86b2381a51c9f64845049f953e5550dac0`.
All four **exact previous source** Actions completed SUCCESS:
[capture #41409309315](https://github.com/i-shutov/flowbridge/actions/runs/41409309315)
(Windows Server 2025, macOS, Ubuntu: 3/3),
[Rust/native #41409309292](https://github.com/i-shutov/flowbridge/actions/runs/41409309292)
(5/5), [DNS #41409309296](https://github.com/i-shutov/flowbridge/actions/runs/41409309296)
(3/3; NOT leak-free), and
[real Windows OpenSSH #41409309298](https://github.com/i-shutov/flowbridge/actions/runs/41409309298).
The actual hosted Windows OpenSSH managed log has **128 real held, 1,152 rejected,
10,000 successfully byte/half-close verified with zero churn failures, and four
distinct owned SSH processes** at 15/s; raw 512 characterization reaches only
**246 held**, NOT a 512 stability PASS.

**Critical genuine Windows WFP local-loopback evidence, not NDISRD diversion:**
The hosted Windows job #125158451795 ran the original Rust executable and
real TCP sockets against an AppId-wide persistent IPv4+IPv6 deny plus same-sublayer
dynamic *soft* permit. `windows-wfp-soft-lease-hosted.json` shows **all
33/33 separate strict checks true**: selected receives a bounded temporary
one-port permit, another port stays denied, an independently created BFE sublayer
still vetoes, sibling/Python remain unaffected, an ALREADY ESTABLISHED TCP
selected flow does not deliver after lease-process death, dynamic lease filters
disappear, persistent deny survives both lease- and guard-process death, and
independent SYSTEM recovery restores normal networking. This distinguishes
post-connection revocation from mere blocking of new connections.
The experiment was on **GitHub-hosted Windows Server 2025**, used **no NDISRD**,
and does not prove an actual driver/SSH crash-protected product.
The controls do not disable Defender or global firewall.

**Independently downloaded exact Windows Action artifact #13124852214:**
outer ZIP SHA-256
`15e6bae33f8dc23f8be127882b91d3ef197da966dbad5c3d296dc87709bc345f`
matches GitHub digest; inner five-entry original-Rust allowlisted ZIP SHA-256
`40b75fd04c07fe89401209baf129221b418e638fc0bead929011f8b796c50734`;
source/HEAD and all manifest hashes match, manifest SHA-256
`a4fef8c0225d09c1a36be7c4aa712b269ce5f1397bf5bd373e4f11a20f879fd2`,
Rust x64 agent SHA-256
`96ff2c6b0a990f4e0a963afe10117c1e6bd8068a1e25592fcbdd53c124d61ad6`.
Unsigned user-owned Rust NSIS installer exact SHA-256
`6aa0a09628e3d0bce48b0a45cbf2130eaa8aab0077fb4f808f6231aa49ccfbd5`;
separate installed GUI→IPC→real authenticated OpenSSH/SOCKS, SCM and
fault-injected install/recovery reports are present and true. Managed SSH
artifact #13125945180 ZIP SHA-256
`430929d4910e8a4450d93a9466e055de524976d45cf24439e861ad38edf156d4`;
raw diagnostics artifact #13125365653 SHA-256
`39b364dc05209c2ff7f4da8739f97a14462343427ee2745de8edae4e5913063f`.
All are previous tested-source evidence, not new-HEAD binary provenance.

**New four-file integrated evidence gate in #56, strict CI acceptance PENDING:**
`tools/capture_evidence_audit.py` is a standalone read-only byte inspector
for the exact candidate ZIP, x64 PE, five-member allowlist, exact source
test-merge and PR HEAD, file SHA-256, unsigned NSIS bytes, installed real GUI/
SSH/SOCKS and negative release/security claims. It refuses a missing or false
held-TCP revocation, failed other-sublayer veto, false rollback, tampered
installer, duplicate/traversal/altered ZIP, stale SHA, or bogus release flags.
`tests/test_capture_evidence_audit.py` covers eleven *synthetic negative
contracts only*; these unit tests are never labeled native evidence.
`.github/workflows/capture-integration.yml` now must run those contracts on
all three hosted OSes and run the actual on-disk Windows provenance/lease/
installed-product auditor as a strict end-to-end step. A green prior-source
run is NOT transferred to the newly committed CI gate. Accept this QA block
only after fresh exact-new-HEAD GitHub run, real test-merge and independently
audited new artifact hashes.

**Native and release blockers still OPEN:** the separate paid VDSina native
Windows Server 2025 signed-NDISRD
[LISTEN/WFP TEST-NET canary evidence](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6570697616)
is pinned to older source `0039a528a20a211b1a720c7b482ad70b497ab364`,
not to the above hosted executable. We still lack simultaneous actual NDISRD
TUNNEL_BOTH diversion with gated WFP soft permit and proven driver/SSH crash
ordering, reliable arbitrary packet→PID+creation epoch authority, protected
IPv4/IPv6/DNS/UDP/QUIC/DoH leak containment, native Win10/11 acceptance and
owner-approved release. The signed driver mode 0 means DIRECT-capable normal
networking, NOT protected fail-closed. The paid VPS remains needed for
carefully pre-armed, VNC-recoverable native integration; NEVER deploy the
hosted-only persistent WFP QA canary there unchanged. No main merge or release.

---

## 2026-11-02 — Release blocker: permanent WFP deny vs NDISRD driver capture

**Architecture research / safety-gated experiment, NOT production enablement.** Microsoft WFP filter arbitration first selects the highest-weight match within *one* sublayer; a default **soft permit** can stop a lower-weight persistent block there, while filters in other sublayers still have the right to block. See https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration . The current AppId-wide persistent canary uses high FWP_UINT8-range block weights. A dynamic-session, explicit FWP_UINT64 maximum-weight soft permit in **the same QA sublayer** may temporarily admit traffic while its owning Rust process is alive, and disappear automatically when that BFE session closes/crashes. This could resolve the fundamental conflict that a permanent AppId block otherwise prevents the selected app's packets reaching NDISRD. The mechanism is not assumed working until real Windows tests prove it.

The new **GitHub-hosted Windows Server 2025 ONLY** `wfp-qa-appwide-soft-lease` requires independent SYSTEM rescue, a previously installed and identity-matching IPv4+IPv6 persistent deny, a canonical copied QA executable and one 49152–65534 destination port. It never installs/changes NDISRD, never uses CLEAR_ACTION_RIGHT (hard permit), rejects any stale lease and uses a BFE dynamic session with exact keyed readback. The corresponding end-to-end QA must prove persistent deny → one-port controlled soft permit, nonleased port denied, independent sibling unaffected → kill lease process → persistent deny restored → kill guard → persistent deny remains → independent cleanup and restored sockets, all without declaring protected mode. No vendor/AGPL binary.

**Unclosed release gates:** whether an existing admitted TCP connection survives lease loss, whether WFP other-sublayer blocks retain precedence, actual NDISRD divert visibility while soft permit exists, SSH/NDISRD failure-state ordering, reliable arbitrary packet→PID and Win10/11 native acceptance. Default application behavior remains unchanged. No main merge/release.

## 2026-11-02 — VERIFIED Windows native exact-filter WFP AppId source-canonicalization mismatch (strict RED)

Source code `f0e119623899893ce0e46e8137aef5d38c9a1d86`, GitHub test merge
`17c0e0f4b178d15a919bf2d9002c0292dc2a4a4d`. Actual
[capture CI #41353379715](https://github.com/i-shutov/flowbridge/actions/runs/41353379715)
Windows Server 2025 **FAIL**, deliberately at original strict per-EXE AppId
enforcement after PASS of Rust-only GUI→IPC→Banner First→authenticated
OpenSSH→SOCKS, real PowerShell canaries, NSIS recovery and SCM upgrade.
macOS/Linux capture PASS; [DNS #41353379820](https://github.com/i-shutov/flowbridge/actions/runs/41353379820)
3/3 PASS. No native Win10/11 or protected policy is inferred.

Independently downloaded actual Windows capture artifact #13102532015:
outer Actions ZIP SHA256 **`e911288c9082adfe8c4d9db37bcfa503813519c5e15bfb5699457391ffc4b60c`**,
equals GitHub digest; exactly 19 explicitly enumerated report/package
entries. Nested exactly five-member original Rust candidate ZIP
SHA256 `06e303ef3f1d4215450c120b6ee8492fcbc95b959e0b7f9c54c178a92a015b12`,
sidecar and all manifest hashes match source PR head/merge. Independently
checked all MZ/PE32+ AMD64 (machine 0x8664, magic 0x20b):
agent `bc92f97bbd40bbe87870fc1a1ac14d508ae0292b8a6c301bf72c7f27f47853d7`,
CLI `1063e1bbfa9b49b2c76c7c10c43bb53165f6ea7503ffbd33a38a128f3a2130df`,
panel `edffe805edb89c8b8fdec442f979ccb8a8976e3f28434b274342de68ac4f0d6b`.
Unsigned real NSIS SHA256 `dbd7601c89447fb3c789afdad07585cfdf0d9e5272810f196cc933c93de7cf8c`
matches installer report. No vendor binary, C++/WFP sidecar, secrets or
false protected/release flags.

**Important new actual BFE diagnosis, BOTH 127.0.0.1 and separately
host-owned non-127 IPv4:** for each route the exact transient port-only
filter ID had three CLASSIFY_DROP records, all with structurally valid
UTF-16LE AppIds. The independently computed Python client AppId was an
**exact byte match**, one of three. Two original Rust EXE copies with
different paths were each matched uniquely by executable *basename*,
but neither complete event AppId BLOB matched the ID returned for its
file path by `FwpmGetAppIdFromFileName0`. ASCII case/slash
normalization did not fix the selected copy. The original Rust agent
AppId matched none. This strongly narrows the problem to full-path
canonicalization/volume aliasing of the copied executable, NOT random
unrelated port events or Python identity and NOT merely 127.0.0.1.
Actual AppId-only and AppId+port filters still **did not** deny selected
traffic; port-only blocked all three real clients, followed by successful
process-death recovery. No raw path/PID/ID/packet logged. BFE event
identity is **not** kernel-verified arbitrary packet→PID authority.

**Independent OpenSSH gate on this exact source:**
[CI #41353379737](https://github.com/i-shutov/flowbridge/actions/runs/41353379737)
managed capacity 128 held/1152 denied succeeded, but 10000 churn
**FAILED at 1655 started / 1654 completed**, WinError 10048,
Windows TIME_WAIT 6259. Experimental raw test reached only 246
held and explicitly denies stable 512 even when its characterization
job returns success. Do not transfer prior SHA's managed 10000 PASS to
this SHA or weaken tests.

**No release:** DNS leak-free, selected-app PID attribution, persistent
native protected fail-closed, UDP/IPv6/QUIC, actual Win10/11 and signed
installer remain open. Disposable dynamic WFP filter only; no driver,
firewall, Defender or paid VPS modification. Next lab direction:
compare *live kernel event-observed* native volume path to
file-handle-canonicalized path in memory and prove actual app-specific
denial before choosing a protected rule. WFP/NDISRD ordering on VPS
requires independent rescue and evidence.

## 2026-11-02 — WFP exact-filter cross-process AppId source discrimination (CI PENDING)

At PR #56 source parent `0bcc0106c8e88e5a048d20461edff3c964b541f0`, a strict hosted-Windows WFP test still
observed three actual `CLASSIFY_DROP` events tied to the **exact ephemeral
port-only filter ID**, all with an AppId but none byte-equal to either copied
Rust QA executable. At the same time the AppId-scoped real TCP tests failed
on both loopback and same-host non-127 IPv4; filter readback was exact.
This is a root-cause investigation, not an app-level routing fix.

This coordinated original Rust + real Windows Python QA change now cross-checks
each exact-filter event against FOUR independently obtained BFE executable AppIds:
selected Rust copy, different-path byte-identical Rust copy, original Rust agent
and the actual Python fixture executable. It reports only aggregate equality
counts, UTF-16LE structural validity, case/slash-normalized equality and
executable-basename equality; no raw path, PID, filter ID, packet, user or
stable fingerprint is persisted. The same source-owned guard is tested at
both 127.0.0.1 and independently bound host-owned non-127 local IPv4, with
read-only exact-filter net-event correlation on both routes. The original
real selected-vs-independent-user TCP matrix and port-only negative
control remain strict; a successful event lookup NEVER overrides a failed
application filter test.

Hypothesis discriminators: a Python/agent AppId match suggests the kernel
event belongs to a different executable; a basename-only or ASCII
normalization match suggests image-path canonicalization; no match leaves
kernel identity/driver ordering unresolved. All are **observations**, not
trusted packet-to-process evidence. No BFE audit setting, permanent filter,
host firewall, NDISRD mode, security protection or paid VPS is changed.
**Exact new HEAD CI, test-merge and independently downloaded artifact hashes
are required before this block is accepted.** Native Win10/11,
crash-persistent protected fail-closed, DNS/UDP/IPv6 leak containment, raw
512 OpenSSH stability and release 1.0 remain unproven.

## 2026-11-01 — Exact ephemeral BFE filter-ID / WFP CLASSIFY_DROP causal correlation (CI PENDING)

After exact code SHA \`8f3a5d14d30f9f624680d71b5d1b9af28cd5854f\`, Windows Server
2025 [hosted capture #41348275968](https://github.com/i-shutov/flowbridge/actions/runs/41348275968)
completed *both* real signed PowerShell live canaries, Rust-only installed GUI/
IPC/Banner First/authenticated OpenSSH/SOCKS, NSIS recovery, real SCM upgrade
and 81 Rust unit tests; the Windows job correctly FAILED the existing strict
WFP per-app gate. Actual BFE event enumeration succeeded, and three
port-matched APP_ID_SET events matched NEITHER copied executable's
\`FwpmGetAppIdFromFileName0\` blob, even though a transient port-only filter
blocked all three clients. **Those events were correlated only by TCP port,
not by exact filterId, and cannot yet be claimed as the QA filter's drops.**
This distinction changes the investigation: filter registration/readback
works, BFE condition serialization checks pass, actual enforcement by AppId
still FAILS on 127.0.0.1 and same-host non-127 IPv4.

New coordinated Rust + Python integration QA runs only on a disposable,
20-second **nonpersistent** dynamic BFE guard scoped to the real local QA
listener. The guard emits its ephemeral, BFE-assigned \`filterId\` to an
in-memory parent pipe; it is **never emitted in the report**. Before forcibly
ending the guard, the independent original Rust read-only event probe validates
that the BFE filter is still present under the exact QA sublayer/ALE layer,
then accepts only tagged \`FWPM_NET_EVENT_TYPE_CLASSIFY_DROP\` with exactly that
\`FWPM_NET_EVENT_CLASSIFY_DROP0.filterId\` and the real TCP port. Counters
distinguish actual filter drops with selected/other AppId, unresolved AppId,
missing AppId and other-filter drops. No PID, binary path, raw AppId, filter
identifier, payload or endpoint is serialized. Absent auditing/events is
INCONCLUSIVE, never promoted to PASS; the existing real selected/other/Python
AppId enforcement matrix remains strict and deliberately red unless WFP
actually blocks the selected process. The signed-driver mode, host firewall,
BFE audit options, Windows protections and VDSina VPS are untouched.

**CI / test merge / artifact hashes PENDING for the new source.** No security,
DNS leak-free, native arbitrary packet→PID, crash-persistent fail-closed,
Win10/11 or release 1.0 acceptance. Native WFP-before/after-NDISRD ordering
must be measured separately with rescue-armed provider VNC.

## 2026-11-01 — Signed Windows PowerShell startup/three-phase WFP diagnostic unblocking (CI pending)

PR #56 only. Parent source `27ff9f6e22ea6db35dc9a054779cefdbcdeb37b7`, exact work is an integration-harness
repair, **NOT** application packet-to-PID proof or protected network enforcement.
The verified previous hosted Windows capture job #41341889375 (GitHub test merge
`53d8a317c955a734836c20aabf1b48bb27222585`) completed 81 original Rust
unit tests, real NDISRD ABI read-only, native BFE read-only, Rust SCM install and
binary upgrade, but failed **before** the strict WFP AppId stage: genuine signed
in-box PowerShell did not announce its reserved TCP source port within the old
eight-second startup window. The failed test therefore provided **no new WFP
classification result**. DNS 3/3, Rust/native 5/5 and managed Windows SSH were
separately green on the exact parent; raw 512 remained red.

The coordinated Python QA change shares one strict bounded **20-second** cold
startup reader between both real Microsoft-signed PowerShell canaries. The
first line must be non-empty, the process must still be alive before GO, and
the embedded-script port must be a decimal value within the real TCP port
range. An unreadable pipe, early child exit, timeout, or malformed line remains
a hard failure. Startup never sends GO or TCP itself. All three pre-GO killed,
REJECT, real binary HTTP/half-close scenarios remain mandatory, as do the
unrelated signed OS process and strict WFP BFE readback/event identity trials.
Only sanitized error classes are persisted; no subprocess stderr, encoded
command, process identity, endpoint or secret is captured.

**Acceptance pending exact-head GitHub Actions, its test-merge SHA and Windows
artifact hashes.** The earlier dynamic AppId-only and AppId+TCP filters failed
on real 127.0.0.1 and non-127 same-host routes, notwithstanding a successful
port-only block. Do not declare WFP per-app blocking, NDISRD/WFP ordering,
persistent fail-closed, DNS leak-free, arbitrary packet ownership, Win10/11
acceptance or release from this harness correction. No mode or security
setting changed, no additional PR or main/release change.

## 2026-11-01 — WFP AppId BFE serialization + kernel event identity, strict negative CI

The real Windows Server 2025 test demonstrated the target BFE-derived AppId
matching its own lookup, while AppId-scoped ALE filters did not block TCP on
either loopback or same-host non-127 IPv4. The port-only negative control did
block all three independent processes; neither observation proves per-app
enforcement. **This P0 AppId gate stays FAIL until native enforcement works.**

New original-Rust dual-observability QA is intentionally nonpersistent:
- Immediately after `FwpmFilterAdd0`, `FwpmFilterGetById0` retrieves the
  registered BFE filter and verifies *all* condition GUIDs, values, types,
  equality operators, target AppId BLOB bytes, layer, action, and private
  sublayer. Any mismatch hard-fails before a PASS-like guard-ready message.
  This separates user-mode pointer/serialization defects from actual ALE
  kernel classification; it does not prove kernel AppId matching.
- After a real three-process port-only denial, a bounded read-only
  `FwpmNetEventEnum0` correlates **at most 256** preexisting BFE event
  AppId BLOBs against the two hash-identical, different-path QA executables
  on the unique ephemeral TCP port. The report exposes only counts/booleans
  and no raw event, path, PIDs, addresses, payload or BLOB bytes. If event
  collection was disabled or no matching event is available, it records
  *inconclusive*; it **never** enables global auditing, logging or security
  settings. A BFE event is NOT packet-to-arbitrary-PID authority.
- The same installed-product/GUI/Banner First/real OpenSSH/SCM/NSIS
  integration runs ahead of this strict WFP gate. No app-specific
  authorization or protected-mode claim is made on the strength of BFE
  registration or event readback alone.

**Status when authored: implementation pending exact-source GitHub Actions,
Windows JSON, signed source/test-merge identity and downloaded binary SHA
inspection.** No server driver mode changed, no VDSina workflow launched,
no production persistent WFP rule, no third-party binaries or secrets.
Native arbitrary selected-app routing, crash-persistent fail-closed,
DNS/UDP/IPv6 leak freedom, Windows 10/11 and release remain unaccepted.
Raw SSH 512 stability remains unproved; managed 128/1152/10000/four-child
load remains a separate nonwaived gate.

## 2026-11-01 — STRICT second-route WFP ALE AppId integration, host-owned IPv4 (candidate; CI NOT YET ACCEPTED)

This block extends the **still-failing**, nonpersistent, isolated hosted-Windows WFP QA matrix in the same PR #56. It never changes production routing or grants protected-mode acceptance. The original five loopback AppId/port trials remain hard assertions. A new independent host-owned **non-127 IPv4 local-interface destination** (discovered by local OS address assignment and verified with a local bind, never an Internet test server) exercises an actual Rust TCP client through the same short-lived BFE AppId-only, AppId+TCP+port and port-only negative control. The original Rust client **refuses** a non-local destination: a successful local UDP bind is mandatory before any connect, and that bind emits no datagram. Independent Python and byte-identical different-path Rust executables must remain permitted under scoped AppId rules and denied by the diagnostic port-only rule. Guard force-kill must restore TCP every time.

The redacted JSON will report `local_interface_ipv4_diagnostic` with `available`, `baseline_ok`, `tested`, three explicit native outcomes, and `app_id_scoped_proven`; never reports actual IP, PID or EXE paths. If hosted Windows has no usable non-127 assigned IPv4, reports **not tested** with no product PASS claim; if the route is tested and either AppId trial does not block, the **entire Windows job still FAILS**. The original loopback failures are **never skipped, downgraded or waived**, even if the second route works. The WFP QA step runs **after** the independent installer/GUI/SSH/SCM tests, so a genuine AppId negative can no longer prevent collecting unrelated evidence; its failure still prevents full capture integration PASS.

This is local host delivery, **not an external NIC packet**. Dynamic BFE guards vanish on process crash; no persistent filter, NDISRD mode, firewall/Defender or network configuration changes, nor packet-to-PID authority, DNS leak-free, native Win10/11 or release proof are claimed. Exact-HEAD/test-merge CI and SHA-256 artifact audit needed before interpreting the result.

## 2026-11-01 — Verified real BFE AppId lookup matches QA executable; WFP per-EXE enforcement still FAILS

**Never claim this is a protected-mode pass.** On [exact source PR #56 HEAD `433ad39ffe2ddb6042c54cbcfefc13488709d8f3`](https://github.com/i-shutov/flowbridge/commit/433ad39ffe2ddb6042c54cbcfefc13488709d8f3) / test-merge `1c6b888b1d6258cd4978b84e9555d91dc2f0a67c`, [capture workflow #41335859787](https://github.com/i-shutov/flowbridge/actions/runs/41335859787) executed five **real** bounded Windows Server 2025 dynamic BFE filter experiments. QA matrix is a genuine **FAIL**, faithfully preserved in `windows-wfp-dynamic-lifecycle.json`:
- Read-only `FwpmGetAppIdFromFileName0` from within the running real copied target EXE agrees exactly with the target's own path-derived AppId (**true**); byte-identical EXE at another path (**false**); original Rust agent path (**false**). This rules out the tested self-vs-target user-mode AppId lookup discrepancy, but **does not establish the AppId seen by WFP kernel classification**.
- One ephemeral loopback port-only BFE filter denies selected QA Rust, different-path identical Rust, and Python; all recover after guard is forcibly killed. **Positive real WFP enforcement, not per-EXE**.
- AppId-only and AppId+TCP+port dynamic filters, both with the original Rust agent guard and with a self-guard launched from the selected QA EXE path, all **FAIL to deny** the selected process; other clients remain allowed and every trial recovers. Thus making guard executable match the selected application does **not** repair WFP AppId enforcement on this loopback OS fixture. Do not infer a universal WFP or Windows design limitation until an independently verified non-loopback AppId classification experiment exists.
- Each filter is dynamic/nonpersistent, port-scoped to a disposable local QA test, 20 seconds maximum; no actual NDISRD, firewall, Defender, external traffic or persistent WFP rule modified.

Downloaded actual Actions ZIP [artifact #13095496139](https://github.com/i-shutov/flowbridge/actions/runs/41335859787/artifacts/13095496139) and independently checked **outer SHA-256 `89b4c986216aadfd297f03999d11d0d0ec01bdc87fea5f8202c76b5905244d07`** matches GitHub; nested five-file Rust candidate SHA-256 `c905cc62df27941c8fc92219f32d327deea36150fa5c09f3cb9470f07a9fffd2` matches sidecar. Verified all manifest payload digests and genuine AMD64 PE: agent `ef8e5248d8da0e6d8ea55b7b078400586ab7e06fb4a0b5d2fc90ce62fed5a8f3`, CLI `923fe3c49559d73b47d8d3759c734be8825863fae73fb9eda6110546114f9422`, panel `775bae4e0985d0f764f0d536134db4c109183268d611e1bcc5ece8428718cc6b`. No bundled NDISRD/vendor, ProxiFyre, legacy helper, keys or release approval. All protected/native Win10+11 acceptance booleans FALSE. This full run also revealed strict rustfmt failure (two exact hunks), independently audited via [format patch artifact #13095560660](https://github.com/i-shutov/flowbridge/actions/runs/41335859787/artifacts/13095560660), ZIP SHA-256 `27ed751a756b1c4b4b27c59ad9ebffe88427273e7934d6bf8738597d315b4bb9`. Current follow-up is **only exact rustfmt correction plus QA evidence**, not a workaround or weakened assertion. CI on follow-up SHA must be assessed independently; app-ID enforcement is **still expected to fail** unless the OS behavior changes.

**Critical P0:** prove WFP's *actual* ALE app identity under controlled non-loopback circumstances, then only with independent VNC/SYSTEM rescue measure WFP-vs-signed-NDISRD ordering. Persistent app-scoped fail-closed, arbitrary kernel packet→PID, selected-app DNS/UDP/IPv6 and Windows 10/11 remain OPEN. Keep the strict dynamic app-ID negative test; do not turn a red result green by skipping it. Managed OpenSSH 128/1152/10000/4 unchanged and raw 512 explicitly unproved.

## 2026-11-01 — WFP AppId root-cause cross-check: actual running EXE versus filter target (CI PENDING)

Exact prior Windows CI [#41334892725](https://github.com/i-shutov/flowbridge/actions/runs/41334892725) on source `a7666bd653de5f2b262b829da0e9e0704ea4e6c7` / test merge `20b8de41bce76cafe57fd1eed77f4ab3c24ed1dd` reported an **honest FAIL**: BFE port-only denied all clients and recovered after guard kill; AppId-only and AppId+port denied **neither** copied Rust QA client. Real Windows compiled Rust tests, native BFE read-only and installed GUI/SSH success elsewhere do NOT substitute for AppId matching. See redacted native run JSON; there is no per-EXE protection.

The new original-Rust QA-only experiment separately calls **FwpmGetAppIdFromFileName0 on the actual running executable and on the selected target within the same process** in three real Windows processes: the selected copied client, byte-identical EXE at a different path, and original Rust agent. It reports only three AppId equality booleans (no paths/IDs/packet payload). Then it runs five real BFE dynamic sublayer TCP experiments: port-only (all clients denied), AppId-only and AppId+port with the original agent as guard, then **the same two AppId conditions with the selected copied QA executable as guard**. All require actual TCP deny/permit/half-close and post-forced-guard-death recovery; a non-matching identity or missing selected denial is a hard CI **FAIL**. This distinguishes application-ID path lookup from runtime classification, and tests whether the guard's own path changes the effect. The 20-second dynamic WFP guard remains limited to the disposable loopback CI port and QA executable; no production policies, NDISRD, persistent filter, Defender/firewall settings, or VPS experiment are touched.

**NOT accepted until exact-source Windows CI, merge SHA and downloadable SHA-256 evidence pass.** Even a pass only proves narrow temporary loopback EXE discrimination on hosted Windows Server 2025, NOT NDISRD WFP ordering, crash-persistent fail-closed, arbitrary selected-app packet/PID identity, DNS/UDP/IPv6 leak-free or Win10/11 release acceptance. Managed 128/1152/10000/4 and raw 512 characterization remain unmodified.

## 2026-11-01 — **REAL Windows WFP scoped TCP-port BLOCK works; per-EXE AppId BLOCK does NOT** (P0 still open)

On exact PR #56 source `86ff884453cf3935e7f9e6f4c698180b73cdcaa6` / GitHub merge `65f089b9666593361a5855807f70c084afe2dd8e`, the [actual Windows Server 2025 capture integration #41334411322](https://github.com/i-shutov/flowbridge/actions/runs/41334411322) deliberately **FAILED** overall; the app-ID protection is **not** implemented. A bounded **real** WFP `FWPM_LAYER_ALE_AUTH_CONNECT_V4` dynamic sublayer test showed a decisive A/B/C distinction for one OS-assigned ephemeral loopback TCP port, tested with original Rust and separate Python processes:

- **Port-only WFP BLOCK: actual PASS** (`selected_denied=true`, separate executable denied, unrelated Python denied, each restored after guard forcibly killed).
- **App-ID-only WFP BLOCK: FAIL** (`selected_denied=false`, unrelated process allowed).
- **App-ID + TCP + port WFP BLOCK: FAIL** (`selected_denied=false`, unrelated process allowed).

Thus the Windows hosted host actively enforces a real narrow WFP port filter, and prior failures are specifically **app-ID binding/classification** rather than a wholly inert WFP engine or wrong port/protocol values. This does not distinguish an incorrect Rust supplied AppId from absent/ambiguous loopback app identity or a higher-priority OS policy, and does **not** demonstrate app-specific protection or permanent fail-closed. No WFP rule remains after the QA guard is killed. There was no NDISRD, Defender/firewall/Secure Boot policy change, persistent system filter, user data or external test destination. Real WFP effect was measured, not inferred from API success.

**Independent artifact audit:** downloaded Actions artifact **#13094586445**, exact outer ZIP SHA-256 `3670266d6b786ddc9ab7912689f4a342c5504cdb2d6f1e024b400327fcc3c7b4` equals GitHub digest, seven expected entries. Nested five-file Rust ZIP SHA-256 `7477f0ae842f5b46e6654b96af692f12775a2260f324bfdb7fb8036b13f381b0`; verified manifest `pr_head_sha`, merge SHA, all 4 payload SHA-256, three genuine PE32+/AMD64 headers (machine 0x8664/optional 0x20b). Original Rust agent SHA `83e04666bf5fad71b7d1aa2f6ce6f6aba0b8c2c5f933f1c8798b742aae7d1ad9`, CLI `b2677cb82d610a6f10e1cb9b9b993a791ab3fdbfb88b55d94aa35190fc1003a5`, panel `83caa7cba73eef8a3d4fd0b7b3b44aa43aaf50c8021c523d68cac045bbbc68e7`. No ProxiFyre, vendor driver or legacy C++ helper. Candidate release and protected flags correctly false. Port-only test is not a product capability and **must not be promoted to general selected-app redirection**. App-ID matching needs isolated causal investigation, then dynamic and persistent crash tests and NDISRD ordering; Win10/11 native acceptance still open.

Code-only follow-up fixes the strict rustfmt check triggered at one long consent condition; it does **not** weaken or bypass the failing native app-ID test.

## 2026-11-01 — Actual WFP app-ID-only and app+port both failed; bounded port-only control pending

Downloaded [Windows CI artifact #13094995094](https://github.com/i-shutov/flowbridge/actions/runs/41333935041) and **independently confirmed ZIP SHA-256 `cab844664f0409c3eb155f51175c6d83899e87cda578b0a0958eaa761fb75b1c` equals GitHub digest**. Exact source `4b5b136adc3eea2bbe3d927fdb5c6952b0dbb3cf`, test-merge `25c46e50dc4320e00adb56aaa9f69f45ab21c6da`, actual installed Rust agent SHA `c9ac1e58778cde09ebbb1d82e96bee7671dcdd36144ab800a3e734294990a73d`. Real Windows Server 2025 BFE dynamic sublayer + filter registration succeeded, but both **AppId-only** and **AppId+TCP+high-port** trials FAILED actual denial (`selected_denied=false`); unrelated executable and Python remained available and all guards were killed/recovered. Thus protocol/port matching is NOT the explanation. Native selected-app WFP interception remains unproven; no protected filter passed. 81 compiled Windows Rust capture unit tests and original BFE read-only passed separately.

Next diagnostic adds a **third control trial**: only one OS-assigned ephemeral high remote TCP port of a disposable loopback QA listener, regardless of executable, for 20-second maximum via same dynamic WFP session. This is QA-only and deliberately denies both the selected client, distinct byte-identical client and independent Python ONLY during that narrow trial; verifies all reconnect after killing guard. It differentiates general BFE-enforcement/layer/loopback behavior from AppId path matching. The other two trials still require unrelated-process permissions. Never enable this mode on rented VPS or production, never claim persistent fail-closed, native WFP/NDISRD ordering, arbitrary process binding, DNS leak-free or Win10/11 acceptance. Exact-SHA Windows Actions and artifact audits still mandatory.

## 2026-11-01 — P0 BFE diagnostic matrix after still-ineffective private WFP sublayer (CI pending)

Exact source `5cc3ea20796ff194b6dc2b47de67c4fe9eea4540` compiled with Rust tests/Clippy, but hosted [capture #41333564019](https://github.com/i-shutov/flowbridge/actions/runs/41333564019) still **FAILED** the real TCP classification: an explicitly blocked QA executable connected despite successful WFP dynamic session + private sublayer + filter creation. Sublayer priority therefore did not fix the problem. This revision runs two **separate, independent real Windows BFE classification trials** under bounded QA-only disposable sessions: application-ID-only, then application-ID + TCP protocol + high remote port. It requires actual denial of the selected copied EXE, permits a second byte-identical EXE at a different path and unrelated Python, and verifies recovery after forced guard death. The sanitized machine-readable diagnostic matrix is saved even if a trial fails; its result distinguishes AppId matching from protocol/port matching, without converting API registration to PASS. The AppId-only mode is intentionally restricted to disposable QA binary and a 20s session and **must not be used for production routing**. No persistent filter, NDISRD mode, OS firewall/Defender/Secure Boot changes, arbitrary-app selection, DNS/IPv6 leak-free or native Win10/11 acceptance are claimed. Exact-source CI and artifact hashes required.

## 2026-11-01 — QA-only WFP dynamic app-ID enforcement: first Windows test FAIL, private sublayer correction PENDING

Exact source `e3959c5cac4e8eccfbb916ac6a3beb8c84ac3182` [Windows CI #41332344179](https://github.com/i-shutov/flowbridge/actions/runs/41332344179) failed a REAL blocking check: a selected QA binary still connected after `FwpmFilterAdd0` succeeded. Neither `FWP_EMPTY` nor `FWP_UINT8`=15 in `FWPM_SUBLAYER_UNIVERSAL` proved effective; API success is not actual enforcement. The new trial creates a separate **nonpersistent** high-weight sublayer in the same short-lived BFE dynamic session, and requires actual selected-client denial, different-path executable permission, independent Python permission and recovery after killing the guard. The rule is confined to one dedicated temporary test executable and one TCP high port, and never touches NDISRD/Defender/firewall configuration. This is an experimental loopback diagnostic, **NOT** crash-persistent protected mode or WFP/NDISRD ordering. Exact-head compiled Windows CI, actual JSON and SHA audits are mandatory before any PASS claim.

## 2026-11-01 — Real WFP dynamic scoped app/TCP guard experiment (CI pending)

A new independent original Rust QA-only WFP ALE_AUTH_CONNECT_V4 block, with BFE `FWPM_SESSION_FLAG_DYNAMIC`, targets only a temporary copy of the client binary named `FlowBridgeWfpLabClient.exe`, a single high destination port, and TCP. A real Windows test proves selected-executable connectivity before and after guard death, attempted block while guard is active, and unaffected Python client concurrently. Force-killing the Rust guard must cause the WFP rule to disappear. The filter is nonpersistent; neither NDISRD nor any system security settings are changed. The test records binary/source hashes and explicit negative acceptance fields.

**Important: this does NOT implement crash-persistent protected fail-closed.** Dynamic session cleanup on a process crash explicitly permits later direct connections. This QA experiment cannot establish WFP/NDISRD ALE ordering, arbitrary packet-to-PID, leak-free DNS/UDP/IPv6, Win10/11 native acceptance or release readiness. No claim is accepted until exact-source Windows CI and downloaded byte-level artifacts are audited.

# ACCEPTED 2026-11-01 — original Rust Windows BFE read-only + live TCP, exact SHA evidence

**Tested code HEAD:** `9fbb3c16398594df938ab36e95a84175715abbb6` (existing PR #56, no main/release). **GitHub test merge:** `92c640d05bec036ea881414a6afb5727a272691a`. The new original Rust `wfp-readonly` CLI enumerated 648 accessible Base Filtering Engine filter records on hosted Windows Server 2025 in three read-only snapshots **before, during and after a separately held real TCP socket**. All samples complete, socket bytes survived; no process identity, address, filter ID/name/provider GUID or packet contents logged. `windows-wfp-readonly.json.passed=true`. This is **BFE inventory feasibility, not a fail-closed or packet-to-PID result**. No WFP filter rule or NDISRD mode altered; no protective policy installed.

**Actual source-exact CI:** [capture #41329233551](https://github.com/i-shutov/flowbridge/actions/runs/41329233551) 3/3 PASS; [Rust/native #41329233552](https://github.com/i-shutov/flowbridge/actions/runs/41329233552) 5/5 PASS; [native DNS #41329233592](https://github.com/i-shutov/flowbridge/actions/runs/41329233592) 3/3 PASS; [Windows real OpenSSH #41329233583](https://github.com/i-shutov/flowbridge/actions/runs/41329233583) managed + raw-characterization jobs both PASS **as independently scoped tests**. In real managed OpenSSH on exact test merge: 128 TCP channels held, 1152 new attempts rejected, 10000 authenticated binary churn connections completed (0 failed) and 4 independent owned SSH child processes. Bare one-process raw reaches 246 held, **512-channel stability FALSE**.

**Independent byte-for-byte Windows artifact audit:** GitHub Actions capture artifact #13092563238 ZIP SHA-256 `8eb90d6f816d3c0c76ebcb11f1af67614fc05533435b83b7d876c2f1dbaf577d`, matching GitHub digest. The 18-file archive includes `windows-wfp-readonly.json`; exact candidate nested ZIP `832c0ec4a5efcede5e15b87be3ace49fb3a95d887639aeb1044cd86964120df0` agrees with sidecar and NSIS build report. All five candidate payload SHA-256 checked. Three x64 PE32+ binaries (AMD64 `0x8664`, PE32+ `0x20b`):
- `flowbridge-agent.exe`: `486409d9424c6708a1485ce913cf4da04277af27d7b467a12427890e1ab7df2c`
- `flowbridge.exe`: `0d7a81391e464d540e656adb5b060969bcfeb34281fb50413110e1294aa472d1`
- `flowbridge-panel.exe`: `067704f4be1f54b353322d0e8e3e5b86b5387eb1138767ac4e4798e473fd712e`
- Actual separate UNSIGNED Rust-only NSIS setup SHA-256: `807f9703b6de24389cddaa59f6f1f4c4121ccfae001cb0bb484e39ade4ac72bc`.

Real Windows installed GUI → original Rust IPC → authenticated Microsoft-signed OpenSSH/Banner First/SOCKS and fault-injected NSIS rollback still PASS. Windows raw #13092970450 outer ZIP SHA-256 `4b6384c024180a0ee385b80fbe4273cb4b373dd82117e062cc26ac801927d6f0`, max 246 held. Windows managed #13092967129 outer ZIP SHA-256 `fb3ac9f5c0658b345ea5c2e275c7d577c423a2b605c17e3d7ad313b112031a37` independently matches source/test-merge and reports 128/1152/10000/0/4.

**Strict P0 open boundaries:** WFP ALE filter flags do NOT prove a persistent block works after agent failure or that signed NDISRD sees selected packets under the block. Windows IP Helper snapshots do NOT attest arbitrary packet-to-PID+creation epoch. No native protected fail-closed, no DNS/UDP/IPv6 leak-free, no Windows 10/11 acceptance, no release 1.0. Driver mode 0 is ordinary DIRECT-capable networking. A separate VNC/SYSTEM-recoverable, explicitly scoped native WFP/NDISRD ordering trial is needed; do not weaken Defender/Secure Boot/Memory Integrity or change the paid VPS without safety gates. Code accepted on `9fbb3c16398594df938ab36e95a84175715abbb6`; this checkpoint is documentary, not a new native acceptance.

---

### 2026-11-01 — P0 cross-layer feasibility: ORIGINAL Rust READ-ONLY Windows BFE filter snapshot with LIVE TCP (CI PENDING)

PR #56 only, starting from exact code HEAD a01ba2f5824d01c46d115708b52efd33b06f27b9. This is an explicitly *non-mutating feasibility step*, not a bypass or substitute for native protected fail-closed. New original-Rust `windows_wfp_readonly.rs` opens the local Windows Base Filtering Engine through documented `FwpmEngineOpen0`, enumerates at most 8192 accessible filter records in 128-element pages via `FwpmFilterCreateEnumHandle0/FwpmFilterEnum0` and closes/frees each BFE allocation through RAII. It reads only aggregate counts of visible, persistent and boot-time flagged filters: NO filter display names/keys/provider GUIDs/paths/PIDs/addresses/packet bytes, no `Add0`, `Delete`, filter configuration, driver IOCTL, installation or privileges change. Explicit `wfp-readonly` original-Rust agent CLI and Windows-only test query BFE three times: before, during and after a real separately created TCP socket/HTTP-like byte exchange held open across an enumeration. TCP must remain functional, and each inventory must enforce true read-only semantics and false native/protected/DNS/release flags. Concurrent OS policy churn is not misreported as a FlowBridge mutation. New evidence is placed in `windows-wfp-readonly.json`.

This checks **BFE query feasibility only**, not whether filters actually enforce connection decisions, whether NDISRD observes packets after WFP ALE permit/deny, whether process fields authoritatively bind arbitrary packets, or whether a block survives agent death. A separate explicitly consented VDSina VNC+SYSTEM rollback native ordering experiment remains required *after* the read-only prerequisite is independently CI checked. Driver mode 0 still allows ordinary DIRECT routing. No vendor binaries, WFP driver, firewall rules, Secure Boot/Defender changes, new PR/main release. Exact new HEAD/CI merge/digests must be checked before any PASS claim; do not repeat an earlier SHA's acceptance.

### 2026-11-01 — Windows real signed PowerShell TCP canary / denied-GO / forced-idle-stop, hosted CI PENDING

Baseline exact-source `d5c193c22a7963a69dbe1ff8b4e2979d28d43881`
[Windows capture run #41318846772](https://github.com/i-shutov/flowbridge/actions/runs/41318846772)
FAILED its separate **live original Rust embedded fixed Microsoft-signed PowerShell client** regression,
at `tests/windows_powershell_lab_client.py:166`, after the host had already
completed SCM tests. The failing test waited only 12 seconds for the
PowerShell process to exit after issuing explicit GO, independently of
whether the HTTP listener had accepted and completed the transaction;
`subprocess.TimeoutExpired` also dumped the full
`-EncodedCommand` in public logs. The run is a real failure, not a
proven NDISRD or user GUI regression.

The next original cross-process QA block requires **three** independently
spawned actual Windows PowerShell socket phases using the EXACT Rust-embedded
immutable script and Microsoft Authenticode check:
(1) keep stdin open with NO GO, observe no TCP, forcibly terminate the child
and observe no post-kill TCP; (2) send REJECT and prove no TCP; (3) send GO
only after an observed pre-GO quiet period, require the bounded HTTP server
to receive the exact request through TCP half-close, send the exact response,
then require child termination and matching JSON byte counts. The server
completion is now its own bounded event instead of racing the child's
`Popen.wait(12)`. All timeouts still FAIL closed; exceptions for the GO
and REJECT deadlines no longer print the base64 command, personal socket
ports or environment. SHA-256 of the tested Rust embedded script is emitted
without script contents or per-process identity. There is **no** automatic
retry of a failed GO transaction, no relaxed assertion and no direct-route
fallback.

This is hosted Windows Server 2025 loopback QA, **not** native NDISRD
selected-app PID attestation, crash-persistent protected fail-closed, DNS
leak-freedom, affected external SSH route or Win10/11 acceptance. New exact
HEAD/test-merge CI jobs and independently audited artifacts are required
before calling this block PASS. The separate raw 512 SSH experiment remains
a real FAIL; managed 128/1152/10000/4 must continue untouched.

# ACCEPTED hosted Windows installed GUI / real OpenSSH integration — exact source 2026-11-01

This evidence checkpoint is tied to **code+QA source HEAD `4b157a26c3363b66feb038d95b7e9475bcbabdcc`**, GitHub Actions test merge **`55e16d8eac9bf5fcb6d3f79d81b2e7d311608c85`**, [capture workflow #41318214762](https://github.com/i-shutov/flowbridge/actions/runs/41318214762) **3/3 SUCCESS** on hosted Windows Server 2025, macOS 15, Ubuntu 24.04. The previously failed cross-process Windows EDIT injection was repaired in QA by correctly using system-marshalled `WM_SETTEXT/GETTEXT` and verifying the exact path roundtrip; native parent `WM_COMMAND/BN_CLICKED` now carries an untruncated child HWND. No safety gate or product runtime requirement was disabled.

Actual installed unsigned Rust-only NSIS → native Win32 `flowbridge-panel.exe` → restricted same-user pipe → original Rust agent/SOCKS → actually installed Rust Banner First helper → genuine isolated Microsoft-signed Windows OpenSSH with strict public-key auth + host-key verification → binary SOCKS/half-close PASSED. `installed-panel-real-ssh.json` reports all **`gui_cross_process_edit_verified`**, `gui_immediate_start_not_lost`, `gui_real_authenticated_ssh_socks`, `gui_reloaded_live_authenticated_ssh`, `gui_denied_ssh_carrier_swap`, `gui_confirmed_stop_closes_ssh_and_socks` true. Genuine installed Rust launcher and SSH listeners close on forced agent crash; failed SSH gate never becomes DIRECT. Two independent fault-injected installer stages rollback without deleting unrelated user files and normal installation into the recovered target passes; safe uninstall preserves user JSON profiles. `windows-rust-installed-lifecycle.json.passed=true`, `installed-real-openssh.json.passed=true`. This is controlled Win32 message/real socket test; **not physical mouse/keyboard acceptance** on Win10/11.

**Independent artifact audit** of [Windows artifact #13088610300](https://github.com/i-shutov/flowbridge/actions/runs/41318214762): outer 17-entry ZIP SHA-256 `b601610ec9305828272f1e2005dec6a28ae3aec3bd0366b95762f9f22bf63cd4` equals GitHub digest; nested exact 5-file original-Rust candidate SHA-256 `bd681322d0c3cb60d57481d01294f82167926384a57d43ad1af7780115e6cfac`, equals source sidecar and installer report; checked exact source+test merge SHAs, all inner payload hashes, three PE32+ x64 machine `0x8664`, no ProxiFyre/vendor/legacy C++/WFP binaries, no private keys. Windows PE digests: `flowbridge.exe=62504b2ed362420ab6e39159ad27ea0bcba3f84ab77bdec47778a4768e1729d5`, `flowbridge-agent.exe=efb191def9fcb98c6febc3d4e726d5d0d022ed5d1c8cfa43841817e205bd5af1`, `flowbridge-panel.exe=581fcc5f7804786f16188d8d5ccc86edd20381d2646203cc987e7e2f029ac44a`; unsigned NSIS installer `00614ec2c653d2158e7edbf9ef4b0fb0089f5774b72f284522126a68b37c9907`. Detailed trace: [issue #41 comment 6559617223](https://github.com/i-shutov/flowbridge/issues/41#issuecomment-6559617223).

**Still false (not waived):** native arbitrary app packet→PID+process epoch, persistent protected fail-closed, DNS/UDP/IPv6 leak-free, physical Win10/11 acceptance, 1.0 release. No NDISRD divert/driver/firewall/Defender changed in this hosted run. Managed 128/1152/10000/four-worker and raw-512 OpenSSH are separate workflow #41318214769; never infer 512 stability. This documentation checkpoint adds no Rust code, executable, workflow or assertion changes; newer documentation-only SHA is not evidence of a new binary release.

---

## 2026-11-01 — confirmed cross-process Win32 EDIT test-oracle error, fixed without relaxing GUI/SSH assertions (CI PENDING)

New exact-source [capture run #41317764641](https://github.com/i-shutov/flowbridge/actions/runs/41317764641), source `46f6c9e05d29ffd804d1fb45c8fe70ea9959bda6`, **FAILED the installed Win32 GUI acceptance**. Earlier pointer-sized parent-button notification was corrected, but the new independent strict EDIT readback showed `Cross-process profile edit did not retain the exact JSON path` before Start. Actual Windows `SetWindowTextW` is not a reliable setter for an EDIT control owned by *another process*, despite nonzero return; the test was launching a panel with the default nonexistent profile instead of the intended existing temporary JSON. This explains earlier `OPERATION: status` with no agent and prevents falsely blaming the Rust agent or weakening its rejection of absent profiles. Source QA now uses bounded system-marshalled `WM_SETTEXT` and independent `WM_GETTEXT`, requiring byte-for-byte Unicode round-trip **without logging paths** before posting native, full-width HWND-checked `WM_COMMAND/BN_CLICKED`. Both explicit SOCKS-only and managed-SSH installed-GUI scenarios now produce `gui_cross_process_edit_verified` and the downstream installer requires that flag; physical keyboard/mouse on Win10/11 still NOT established. No privileged code, driver, Defender or firewall changed.

**Full gate still pending:** real installed Rust Win32 GUI -> restricted pipe -> SOCKS block/reload/stop and managed authenticated OpenSSH/Banner First/half-close/outage; both injected NSIS recovery stages; exact-source GitHub Actions, downloaded artifact and PE/ZIP SHA-256. Any remaining failure must remain FAIL, not waived. No arbitrary packet/PID proof, crash-persistent fail-closed, DNS leak-free or Win10/11 release.

---

## 2026-11-01: installed Win32 GUI SOCKS / managed SSH — pointer-width QA correction (CI PENDING)

Actual [capture #41312113733](https://github.com/i-shutov/flowbridge/actions/runs/41312113733), source `3f25386f3e87205917b3d713c705b2ed1d807c41`: all Rust/native, DNS and hosted Windows managed OpenSSH jobs passed but **installed Win32 GUI Start did NOT produce an agent pipe**; status remained the initial `OPERATION: status`. This is NOT a passing GUI acceptance. A suspect QA defect is its use of `ctypes.wintypes.LPARAM/WPARAM`, which may truncate an x64 child HWND; the production Rust panel intentionally rejects parent commands with an incorrect child HWND. The QA now posts parent `WM_COMMAND/BN_CLICKED` using explicit full-width `c_size_t/c_ssize_t`, checks the cross-process profile EDIT value before Start and retains genuine installed Rust panel -> restricted pipe -> real SOCKS5, installed authenticated OpenSSH/Banner First and safe uninstall acceptance. No physical pointer/keyboard proof is inferred; `physical_button_input_accepted=false` remains. No NDISRD or OS security modifications.

**Do not accept this correction before fresh exact-head Windows GUI/IPC/SOCKS/real OpenSSH PASS**, both NSIS fault-injected rollback stages PASS and the downloaded SHA-bound candidate/installer artifacts are independently inspected. Managed OpenSSH 128 held / 1152 denied / 10000 verified / four independent processes remains required; raw-512 experimental status remains separate. Arbitrary packet-to-PID, persistent native protected fail-closed, leak-free DNS and Win10/11 acceptance remain unproven.

---

### 2026-11-01 — Win32 GUI Start: explicit null standard handles for installed Rust agent (CI PENDING)

A native Windows-subsystem panel has no guaranteed valid inherited stdin,
stdout or stderr. Its original same-user child launch inherited all three
handles implicitly, unlike Python/terminal launches that already passed.
A GUI-originated CreateProcess may reject invalid handles even though the
same original Rust agent and profile run successfully from a console. The
installed panel now explicitly passes Windows null standard streams to
its sibling original-Rust `flowbridge-agent.exe` with separate arguments and
`CREATE_NO_WINDOW`, preventing inherited-console assumptions and accidental
agent output to GUI/parent handles. No shell, elevation, SSH credential
transfer, driver IOCTL, or routing policy change. Together with the
already-added preserved Start-error UI, the next full installed-GUI QA
must establish real same-user agent/SOCKS readiness, then the separate
authenticated Banner First/OpenSSH route and closed-gate negatives.
This is a hypothesized root-cause repair, NOT a CI PASS.

---

### 2026-11-01 — Preserve failed native GUI Start diagnostics under queued Refresh (CI PENDING)

The first exact native-control-command Windows Server 2025 run
[#41311313166](https://github.com/i-shutov/flowbridge/actions/runs/41311313166)
compiled and reached the real unsigned installed Rust panel, but **FAILED**
its actual Start->agent->SOCKS assertion. Its final text still showed an
unavailable *status* result, which may have overwritten a failed Start
result: neither operator nor QA could see whether the Start action was
dispatched but rejected or never dispatched. The Rust GUI worker now keeps
a failed Start error visible when an already-queued auto/manual Refresh
follows it in the *same worker batch*, while retaining FIFO Refresh after
successful Start and permitting later explicit Refresh after worker idle.
No test assertion, driver guard, protection rule or SSH gate is weakened.
Exact-head Windows installation and real SSH/SOCKS CI must still pass.
The native Windows button source-HWND check and honest noninteractive QA
scope from the preceding checkpoint remain in place.

---

### 2026-11-01 — Hosted Windows GUI input: native BN_CLICKED dispatch with source HWND validation (CI PENDING)

The Rust operator panel's strict Start/Refresh/Reload/Stop handler now validates
that a zero-notification WM_COMMAND comes from its *own existing* corresponding
button HWND, never from unrelated menus/accelerators. The actual installed
Windows GUI acceptance now drives this **exact native BN_CLICKED command
notification** through the genuine Win32 parent procedure, including immediate
Start-vs-initial-Refresh ordering, same-user restricted IPC, installed agent
and authenticated Banner First/OpenSSH/SOCKS. On a noninteractive hosted runner,
a cross-process BM_CLICK may be silently ignored when its button is inactive;
WM_COMMAND with the exact installed child HWND tests the native command
handler deterministically without inventing any agent or proxy response.
The native modal Stop confirmation is still shown and accepted by its real
button. These checks do NOT prove physical mouse input, UI focus/keyboard
accessibility, arbitrary selected application interception, protected
fail-closed, DNS privacy or Windows 10/11 acceptance. Preserve all original
install/recovery, real SSH, and managed-load checks. A fully completed
exact-head CI and byte-verified artifact are required to accept this block.

---

### 2026-11-01 — Actual hosted Win32 GUI QA: cross-process EDIT status oracle correction (CI PENDING)

A real installed GUI Windows run on source `69f5ca82ffb72d4b30ec518e7b11665e5456741a`
failed because its Python QA process continued seeing the EDIT control's
initial `Checking the local agent...` text, even after serializing Start
against WM_CREATE status. **Root cause investigated at the Windows API
boundary:** Microsoft documents that `GetWindowTextW` cannot retrieve
changing control text from another process; for another application's EDIT,
send `WM_GETTEXT` instead. The QA now uses bounded
`SendMessageTimeoutW(WM_GETTEXT, SMTO_ABORTIFHUNG)` with an explicit
buffer/timeout, and on failure reports only boolean pipe reachability and
GUI liveness (no profile path, keys or secrets). This is a correction of
an invalid cross-process GUI test oracle, **not** a waiver of real click,
SOCKS, SSH or lifecycle assertions. A new exact-head CI run must actually
prove the panel works. The existing bounded action queue remains to ensure
Start/Refresh clicks cannot be silently dropped.

---
## 2026-11-01 — Integrated native Windows GUI -> installed Banner First / real OpenSSH / SOCKS (CI PENDING)

The installed Rust-only NSIS candidate now must pass **two actual Win32 control
verticals** on disposable hosted Windows Server 2025. The first presses Start
immediately after the automatic WM_CREATE status request, then Refresh, runs a
real SOCKS5 BLOCK, accepts atomic configuration reload, and performs confirmed
Stop. Native button commands are serialized with a bounded same-user action
queue: the previous GUI silently discarded Start while the initial status
worker was busy. The test deliberately races these commands; it cannot pass
merely because the window opens.

The second reuses the separately signature-verified Microsoft OpenSSH fixture,
temporary pinned host key and ephemeral test-only identity. The **actually
installed Win32 panel** starts its sibling original-Rust agent with a managed
profile, invokes the **actually installed** original Rust Banner First helper,
observes real authenticated OpenSSH readiness, transfers binary SOCKS5 TCP
bytes, reloads engine-only configuration, rejects an SSH-carrier swap without
breaking the live tunnel, and confirms Stop closes both owned listeners.
The new `installed-panel-real-ssh.json` report and the installer acceptance
are hard-fail gates; no mock SSH success is accepted. Exact source SHA,
Actions test-merge SHA and independently verified binary/artifact SHA-256
must be recorded only after the workflow completes.

This is **same-user SSH/SOCKS GUI functionality**, NOT privileged NDISRD
capture, arbitrary selected-app PID binding, permanent protected fail-closed,
DNS/UDP/IPv6 privacy, Windows 10/11 acceptance, signed final installer or
release 1.0. No driver installed, no Defender/Secure Boot/Memory Integrity
changes, no keys in product or artifacts. Release flags remain FALSE.

---

## 2026-11-01 — Original Rust native Windows operator panel + installed SOCKS/SSH candidate (CI PENDING)

Integrated block for **PR #56 only**: add a real, separate-subsystem **native Win32
Rust** process flowbridge-panel.exe to the original Rust candidate archive,
unsigned per-user NSIS installer and Start Menu shortcut. Preserve the exact
source-head/test-merge/payload SHA-256 checks: the Windows candidate now has
**five files** (Rust agent, Rust CLI, Rust panel, README and manifest); macOS and
Linux remain the existing four-file candidate. NSIS adds LICENSE separately.
The panel is a genuinely interactive same-user client of the preexisting
restricted named pipe, with Start from an explicitly entered absolute JSON
profile, Refresh, Reload (engine-only; SSH identity unchanged), and confirmed
Stop. It spawns only the installed sibling Rust agent via separate Windows
process arguments, not cmd.exe, an elevated service, or ProxiFyre. The agent
remains foreground/same-user and never touches the NDISRD kernel service in
this path. Closing the panel is not an implicit tunnel stop.

A new **actual Windows hosted** test must install the candidate, find the real
FlowBridgeRustPanelV1 window and five native controls, enter an explicit
temporary profile through its EDIT control, click Start, verify the restricted
pipe controls a real 127.0.0.1 SOCKS listener, obtain actual SOCKS5 BLOCK
response on a genuine TCP connection, edit the profile and click Reload,
observe engine generation increment, click Stop and accept its modal Win32
confirmation, prove the listening socket closes, then close the actual panel.
Compare the installed panel and agent SHA-256 to the exact candidate manifest.
All preexisting fault-injected installer rollback, real installed Rust Banner
First -> Microsoft-signed OpenSSH -> SOCKS5, KEX, half-close, SSH outage, and
strict hosted managed 128/1152/10000/four-worker requirements remain intact.

**Explicit non-claims:** This panel does not select arbitrary applications,
bind NDISRD packets to PIDs, enable native diversion, provide persistent
fail-closed, prevent DNS/UDP/IPv6 leaks, install a driver, install an SCM
service, or qualify for Windows 10/11 beta/release. Its main window visibly
warns of those limitations. The initial operator UI is functional but not
the final product design; privilege-separated protected-mode user workflows
remain P0. An unsigned per-user candidate is not a release installer.

**Acceptance status:** PENDING independent exact-HEAD GitHub Actions, test
merge SHA and downloaded artifact digest verification. Do not report this
as completed from source review alone.

---

### CI correction — rollback of newly created EMPTY directory (before acceptance)

First implementation HEAD `f4830874fe9c8e6d749bd6eeb1f6dec078347f28`,
[Windows capture job #124834787482](https://github.com/i-shutov/flowbridge/actions/runs/41302027291)
**FAILED** the recovered-normal-install stage. Both QA injected faults returned nonzero
and left no files or HKCU registration, but the rollback intentionally left
the now-empty target folder. NSIS `IfFileExists "$INSTDIR\\*.*"` treats an
**existing empty directory** as an occupied target, so the subsequent normal
install refused. This is a genuine integration failure, not acceptable evidence.

Correction: the NSIS rollback now switches `SetOutPath` to `$TEMP` and
issues **nonrecursive `RMDir "$INSTDIR"`** only after deleting allowlisted
payload names. The preflight always refuses ANY pre-existing directory before
mutation, so on an ordinary successful preflight this only removes the new
installer-created empty directory; if another file appears, RMDir fails rather
than deleting it. No recursive delete, no user-profile cleanup. CI also now
requires stage-specific NSIS exit codes **46/47**, zero product files and
**absent directory** after each injected failure, then the exact same normal
installer's full real SSH/SOCKS lifecycle. This change is **not accepted** until
new exact-source CI and artifact audit finish. Raw-512 characterization
remains separately failed (244 held, WinError 10054), not silently waived.

## 2026-11-01 — Windows Rust-only NSIS: fault-injected partial-install rollback and recovered authenticated SSH (CI PENDING)

Within the existing PR #56, the unsigned **user-owned** original-Rust NSIS candidate now checks every individual file copy, uninstaller creation and HKCU registry write, with rollback restricted to candidate-owned filenames and registry keys. Registry registration remains the final commit marker; occupied directories and in-place upgrades still fail without mutation.

Two **compile-time-only, GitHub-hosted-Windows-only** QA installers deliberately abort (A) immediately after copying the Rust CLI and (B) after writing the uninstaller but before registry registration. The real Windows process test requires both independent aborts to fail and leave no partial product files, service or HKCU markers, preserves unrelated user data, and then requires the NORMAL installer to succeed **at that same formerly failed path**. All previously required real installed Rust IPC / Banner First / Microsoft-signed OpenSSH strict host key / SOCKS binary half-close / crash listener closure / protected profile-preserving uninstall checks remain mandatory. Fault EXEs and their reports stay under RUNNER_TEMP and are never uploaded as product binaries.

This is controlled-process error rollback, **not** atomic power-loss recovery, a signed production installer, Windows 10/11 driver acceptance, arbitrary PID attribution, protected fail-closed, DNS privacy, GUI or release. Exact-source Actions/test-merge and downloaded artifact evidence are required before calling the block accepted. Main/release unchanged.

## 2026-11-01 — Separate unsigned original-Rust Windows installer + real installed process/SSH Banner First/IPC/SOCKS candidate (CI PENDING)

The old production-oriented Windows package contains legacy C++/WFP artifacts and must not be confused with the new Rust/NDISRD architecture. PR #56 now has an **independently named** per-user **UNSIGNED, NOT RELEASE** NSIS installer built only from the strictly verified four-file original-Rust candidate ZIP and project LICENSE. The package requires exact PR HEAD + Actions test merge SHA, independently verifies all input SHA-256 and PE32+ AMD64 binaries and rejects unexpected entries, links, vendor/legacy binaries or elevated acceptance flags. It contains **only** the Rust CLI, Rust agent, candidate manifest, README and LICENSE. It neither installs an NDISRD driver nor stages an SCM service or configures a protected route.

A real disposable hosted Windows Server 2025 CI user installs it into a path **with spaces**, compares SHA-256 of every installed payload file, executes the installed Rust SSH server-first binary adapter (binary transparency, interactive KEX flush, missing-banner non-disclosure), runs installed Rust agent through genuine Windows named-pipe controls, native IP Helper *candidate-only* selftest, loopback SOCKS5 BLOCK and denied/accepted atomic reload with listener teardown, refuses a second install without mutation, then uninstalls and proves exact user profile preservation plus registry/service cleanup. This is a full installed *user-mode* loopback vertical, not a selected arbitrary application or authenticated real external affected route through the actual installed NSIS package. The existing Windows hosted authenticated OpenSSH/Banner First suite remains a separate real process fixture and is not bypassed.

**No release claim:** packaging and Windows CI results PENDING for the first new exact-source commit; this isolated candidate has **no GUI, arbitrary packet-to-PID attestation, crash-persistent fail-closed, native DNS/IPv6 leak-free guarantee, driver installation, Win10/11 acceptance or release approval**. Its unsigned installer is only suitable for private engineering QA and should never be shipped as 1.0. A correct future product must integrate Rust user-mode GUI/service with signed separately obtained NDISRD, safe update/rollback, privacy gating and genuine Win10/11 tests.

**First CI run #41297327342 failed the new installation assertion on Windows-only NTFS name casefolding (test checked forbidden `FlowBridge.exe`, which aliases the legitimate Rust `flowbridge.exe`).** The actual NSIS build and exact original-Rust candidate SHA checks PASSED; failure was an incorrect test oracle, not observed legacy payload. Corrected test uses exact directory allowlist with case-insensitive filenames and same file count; next exact-head Windows CI must still pass before this is called accepted. No security/driver gates waived.

**Second exact-head Windows run #41297710720:** real Rust candidate NSIS installation, payload hashes, installed Rust Banner First, installed Rust Win32 named-pipe/SOCKS lifecycle, and rejected second install passed through to the uninstall stage; test then asserted immediate file deletion after NSIS `/S` launcher exit. NSIS self-copy uninstaller may complete asynchronously, so the QA oracle now waits up to 20s for **both** file and HKCU uninstall-registry removal and verifies the user profile remains intact. A deadline failure remains a hard FAIL with exact remaining filenames (no private paths). Result pending a fresh exact-SHA rerun.


## 2026-11-01: Windows original-Rust managed Banner First under spaced install path — exact-head CI PENDING

The owner's affected-route Python gate on macOS successfully authenticated;
this remains **distinct** from the original Rust helper and from Windows 10/11.
The existing Windows Server 2025 hosted tests already proved both direct
Rust-gate -> authenticated OpenSSH -> SOCKS and Rust Supervisor -> Rust gate ->
OpenSSH -> SOCKS on loopback. This change extends the **same-user Rust agent
and restricted Windows IPC vertical**: copy the real compiled original-Rust
CLI to an ordinary installation-like directory with spaces, apply a strict
file ACL, start the agent with explicit opt-in Banner First in its managed
SSH profile, verify a real authenticated SOCKS5 binary/half-close roundtrip,
reload only the user-mode SOCKS profile, refuse an attempted carrier change,
and forcibly kill the owner to require BOTH local listeners to close.

For Windows only, the Banner First path grammar now permits spaces in
normal local-drive directory components and quotes the entire executable
in OpenSSH ProxyCommand. It still denies network/UNC/NT device paths,
relative paths, dot components, shell controls, environment-variable
expansion, alternate data streams, DOS device names and trailing
dot/space aliases. Missing explicit consent, shell metacharacters and ADS
are independently rejected before launch. The destination SSH server
remains verified by OpenSSH host-key pinning and public-key auth; Rust
does NOT replace the SSH cryptographic implementation. Tests fail if
the spaced helper cannot execute through OpenSSH on hosted Windows.

**Boundaries:** the test uses loopback SSH and debug-built local Rust
binaries, with no NDISRD driver activation and no selected application
packet/PID proof. The helper's path/ACL is tested for this fixture, not a
full production immutable installer or TOCTOU-proof provenance. Killing
the agent may clean up its owned user-mode listeners; it does NOT install
a persistent kernel fail-closed rule. This is **not** proof the user's
specific affected Internet route is fixed by the Rust implementation,
Windows 10/11 acceptance, DNS leak-free behavior or release 1.0.
Exact-head CI logs, all job conclusions, source/test-merge SHAs and
independently verified ZIP/binary SHA-256 must be recorded below and in
issue #41 before this block is called accepted.

---


## 2026-11-01: IPv6 signed-NDISRD self-owned TEST-NET UDP quarantine candidate (CI and native proof PENDING)

An **additional**, opt-in original-Rust `udp6-testnet-drop-lab` complements
the independently verified IPv4-only native canary. Only Windows x64 with
separately installed signed NDISRD may use it; it requires exact
`NATIVE_SELF_IPV6_UDP_TESTNET_DROP_LAB` consent, a preexisting unique
Ethernet adapter, IPv6 MTU ≥1280, a specific non-loopback/non-link-local
unicast source and a reachable **IPv6 route to documentation-only**
`2001:db8::53`. There is **no fallback to IPv4**, no public DNS change,
no application selection and no automatic NDISRD installation.

The process binds and IP-Helper-checks its **own** local UDP socket before
activating a bounded NDISRD session, emits only 2–4 datagrams **after**
adapter diversion, and drops all outbound IPv6 packets from that source to
that exact documentation destination. This deliberately includes unknown
upper-layer/extension/fragment packets, because interpreting the initial
IPv6 next-header as UDP would allow a fragment ambiguity. It may overblock
unrelated same-source/same-destination protocols in this short lab. Other
frames are reinjected byte-for-byte. The socket closes before restoring
adapter mode 0. A separate authenticated VNC recovery path, SYSTEM rescue
watchdog, signed-driver hash/Defender/network gates and exact-source binary
manifest verification are mandatory **outside** the Rust process.

Portable Rust regressions cover Ethernet/QinQ, plain UDP, fragment and
extension headers, unrelated IPv6 sources/destinations, ingress, truncated
frames, wrong EtherType, explicit consent/bounds and injection-prevention
inputs. **No native IPv6 DROP success is claimed until the paid-VPS
driver test and independent rollback evidence are checked.** If the VPS
lacks an IPv6 unicast source or route, that is a **not-tested capability**
rather than a fabricated PASS. A real driver trial on Windows Server 2025
does not establish Windows 10/11 acceptance. Mode 0 is ordinary
DIRECT-capable networking, not persistent fail-closed. Packet ownership,
IPv6 leak-free containment, QUIC/DoH/DoT and release remain false.

---

## 2026-11-01: End-to-end SSH/DNS user-mode crash and deadline containment (NEW CI PENDING)

This original-Rust integration adds two distinct **real process and socket**
safety regressions. The DNS-over-SOCKS lab now applies its requested **single
absolute wall-clock deadline** to both an in-flight SOCKS5 handshake/DNS TCP
transaction and the final local UDP reply, not merely the next `recv_from`.
The old code could overrun a 650 ms consented session by waiting up to two
seconds for SOCKS and five seconds for the outer DNS transaction. Its
separate-process three-platform fixture now exercises a genuine stalled local
SOCKS peer, checks the 650 ms deadline (<1750 ms wall elapsed to accommodate
hosted scheduling), confirms zero UDP reply, no direct resolver contact and
zero leaked relay permits, while retaining the full normal query, closed-gate
and recovery scenarios. This is **not** native DNS packet interception.

The original-Rust Windows-managed SSH control fixture additionally starts
real authenticated OpenSSH under the **same-user Rust controller**, verifies
binary/half-close through the live Rust SOCKS listener, then forcibly kills
the owning agent process without clean IPC stop. It requires **both** the Rust
SOCKS listener and the separately spawned OpenSSH dynamic SOCKS listener to
be unreachable, validating Windows Job Object kill-on-close rather than merely
a graceful `stop`. Failure must fail the existing hosted managed SSH job.
Neither test provides persistent Windows firewall/kernel fail-closed; all
unselected OS traffic and NDISRD modes are unchanged. No raw 512 acceptance,
Win10/11, general packet-to-process or DNS leak-free claim.

## 2026-11-01: explicit UDP DNS -> Rust SOCKS5 -> DNS-over-TCP transport (CI PENDING)

A new original-Rust bounded laboratory vertical `flowbridge-agent dns-udp-lab
<JSON>` accepts only an exact opt-in consent, loopback UDP bind, loopback
upstream FlowBridge SOCKS listener, numeric DNS resolver endpoint, a maximum of
16 questions, 15-second total time and 1,232-byte DNS UDP payloads. Remote
non-loopback resolvers are permitted only on DNS TCP port 53. It validates
uncompressed single-question DNS queries (optional one bounded EDNS OPT),
reuses the supervised `RelayPool` real SOCKS CONNECT and the new cancellation-
aware one-transaction TCP DNS length-framed exchange, verifies response ID/QR,
and returns UDP only to the original loopback source. Malformed packets,
SOCKS rejection, timeout, oversized response or mismatched DNS ID are dropped
without connecting to the DNS server directly. It does not change the system
resolver, DNS registry settings, NDISRD mode or firewall.

An additional integration fixture now targets the **real authenticated OpenSSH**
supervisor already established in the existing Linux and Windows managed SSH
acceptance harnesses. The same explicitly consented Rust UDP DNS listener
negotiates a DNS TCP query over FlowBridge SOCKS and the managed SSH tunnel to
an independent loopback TCP DNS server. It proves a positive answer, a closed
SOCKS gate with no TCP resolver contact, invalid DNS denied before SSH, and
recovery with the same supervisor. The fixture emits only aggregate counters,
source and binary SHA, and explicit false release flags. Neither this fixture
nor its new source has been accepted until the exact-head hosted OpenSSH runs
and downloadable JSON evidence are checked. The separately tested independent
SOCKS-only fixture is retained; two levels of evidence must remain distinct.
The helper does not use NDISRD or authenticate arbitrary Windows applications,
and it changes no global DNS resolver settings.

Independent three-platform CI exercises a **separate agent process** plus a
real UDP socket, a real local SOCKS5 listener, a separate TCP DNS resolver
socket, successful DNS replies, denial while the SOCKS gate is closed, invalid
DNS before proxy, recovery, exact counters, no unexpected resolver TCP
connection and missing-consent denial. Native Win10/11 DNS interception and
DNS leak-free evidence are NOT part of this scenario. In particular, the test
SOCKS server is a local synthetic fixture, not authenticated OpenSSH; existing
separately validated real-SSH probes are not equivalent to this new full
DNS/SSH vertical. Do not mark this item accepted until exact-head CI and
downloaded artifacts are checked. This is a meaningful real-socket DNS-over-
SOCKS building block, **not** transparent routing or containment of selected
application UDP/QUIC/DoH/DoT/IPv6 DNS traffic.

## 2026-11-01: Native IPv4 canary fragmentation quarantine (exact-HEAD CI/native evidence pending)

The bounded Windows x64 NDISRD **laboratory** reflection now detects IPv4 TCP
fragmentation for the single explicitly configured canary (source IP, remote
IP, TCP protocol), including Ethernet VLAN tags. Because noninitial IPv4
fragments do not contain authoritative TCP ports, the lab **DROPs** these
ambiguous frames rather than reinjecting them as Original/DIRECT. The same
heuristic is used by the native selected-direct counter, avoiding false zero
counts when an incomplete fragment cannot yield a TCP tuple. This does not
rewrite fragments or claim universal packet-to-PID ownership.

The trade-off is explicit: unrelated fragmented TCP traffic to that exact
remote IP can also be dropped during the bounded lab, while ordinary
unfragmented unselected TCP and traffic to unrelated destinations remain
Original. This is not a production DNS/IPv6/UDP solution, a persistent
fail-closed policy, or Win10/11 acceptance. Offline Rust regressions cover
first/continuation/VLAN fragments, unselected same-IP unfragmented traffic,
unrelated fragmented endpoints and the DF-only case. Actual signed-driver
VPS confirmation and exact PR CI/manifest/ZIP SHA remain REQUIRED before
claiming this block natively validated.

## 2026-11-01: Separate real Windows managed OpenSSH acceptance from raw 512 characterization (pending new exact-HEAD CI)

Previous exact-HEAD run [41245389707](https://github.com/i-shutov/flowbridge/actions/runs/41245389707) on Windows Server 2025 **FAILED**, but the machine-readable summary independently reported that the actual managed FlowBridge tests had already passed: 128 live held SSH streams, 1,152 denied at budget, 10,000 byte-verified completed streams, and four independent worker processes. The later **unmanaged raw OpenSSH** saturation experiment reached only **244 simultaneous byte-verified channels**, then failed at real Winsock **10054** (server reset), with sshd reporting **Too many open files** and **ppoll: Not enough space**. Neither 512 stability nor capacity recovery was shown. The former single Windows job conflated these independent acceptance boundaries.

The existing workflow now starts **two independently failing/passing Windows jobs** using a strict `--scenario managed|raw` selector. Managed executes *all* real authenticated SSH, banner-gate, capture relay, 128/1152/10000/4 and process-lifecycle checks without running raw characterization. Raw executes the same isolated signed-OpenSSH server fixture, ephemeral keys and strict host-key verification, but runs the independent 512-tier capacity experiment. **Raw's nonzero exit is not swallowed, marked allowed, renamed PASS, or converted to a successful required check.** `strategy.fail-fast: false` preserves raw evidence even when another job fails. Each job uploads separate JSON and hashed binary provenance. The workflow as a whole remains failing if raw characterization fails; the managed job status is independently visible. The raw JSON separately reports actual attempts, peak held, failures and recovered channels; a requested tier does not prove 512.

This is **CI evidence separation, not a new interception capability**. No native Win10/11 acceptance, protected fail-closed, packet-to-process proof or DNS leak-free claim is implied. Do not accept this block until both jobs run on the exact newly committed HEAD and report their real outcomes; the raw expected failure remains a real failure, not a waived test.

## 2026-10-31: Native Windows UDP local-bind owner-candidate vertical (pending exact-HEAD CI)

A new original-Rust Windows-only UDP IP Helper vertical exercises actual IPv4
and, where available, IPv6 loopback UDP datagrams; two bounded
`GetExtendedUdpTable(UDP_TABLE_OWNER_PID)` snapshots; pinned process-object
PID, creation time and image consistency; and negative ambiguity rules for
wildcard, zero-PID, duplicate and IPv4-mapped binds. The public CI runs the
built x64 Rust executable and saves a privacy-redacted JSON report with a
strict negative checklist. Tests must confirm the report against the exact
PR head/merge SHA and Windows artifact before this can be accepted.

**Trust boundary:** UDP owner tables identify only a **local socket bind**,
not the remote tuple, intercepted NDISRD packet, DNS query, per-app routing,
or leak prevention. This diagnostic does not enable protected mode or change
NDISRD, firewall, DNS or SSH state. IPv6 loopback test availability must be
reported, not converted into a fabricated native IPv6 NDISRD acceptance.
It complements but does not supersede signed-driver VPS packet observations.

# Rust capture integration candidate — NOT a protected beta or release

## Windows reversible SCM staging/upgrade/removal candidate (pending exact-head CI)

The original Rust agent now has explicit, admin-only Windows SCM operations:
`service-stage <absolute config>`, `service-replace <old absolute config> <new absolute config>`,
and `service-remove <absolute config>`. These are not invoked by packaging
or ordinary startup. They manage ONLY the fixed on-demand candidate service
`FlowBridgeRustCandidateCI`; no service is auto-started, no driver is
installed or supplied, no NDISRD mode is changed, and no protected mode is
enabled. Strict profile validation rejects application-specific SOCKS rules
without packet ownership evidence and non-loopback SCM listeners. SCM install
refuses any existing record. Upgrade requires the old exact binary command,
an already STOPPED service, and a valid new profile, then verifies the
changed SCM config and attempts rollback of the old command if verification
fails. Removal requires a stopped service with EXACT prior executable and
config path matching, refusing to delete a foreign/modified service. Status
remains redacted and explicitly reports protected=false, dns_leak_free=false.

A separate actual hosted Windows integration script must prove full
stage -> SCM start -> live SOCKS5 -> running-upgrade refusal -> SCM stop ->
invalid-upgrade refusal -> stopped upgrade -> new-port real SOCKS5 ->
named-pipe stop -> exact Rust removal, and pre-existing/other config
ownership denial. This is service-lifecycle/installer staging only, NOT a
complete production upgrade/rollback with signed releases or protected
selected-app interception. Do not mark this block accepted until exact
HEAD + test-merge CI and separately hashed Windows candidate artifacts
have been examined and recorded in issue #41.

## What is now one component

`flowbridge-capture` consolidates the original Rust packet validators, Ethernet/VLAN
rewrite, process-stamp flow ledger and protected verdict gates into a stateful
bidirectional packet pipeline. A real asynchronous SOCKS5 connector activates a
reserved lease only after the server's CONNECT success reply. It preserves
half-close and binary data, bounds concurrency, aborts on supervisor loss, and
has no DIRECT retry path. A DNS hostname supplied to the explicit SOCKS interface
stays in the SOCKS request; native IP packets do not magically recover hostnames.

`flowbridge-agent` is an independently implemented Rust Windows NDISRD client.
It does not load ndisapi.dll, ProxiFyre.exe or a custom WFP driver. The official
signed kernel driver must be installed separately under its own terms. No driver
binary or installer is included in this candidate.

### Critical ABI repair

The preceding #53 adapter query mistakenly modeled the published `pack(1)`
NDISRD ABI as naturally aligned `repr(C)`. Its tests repeated that assumption.
This integration replaces it with explicit native-x64 little-endian byte codecs:
`TCP_AdapterList` 8836 bytes (handles at 8196), `ADAPTER_MODE` 12 bytes,
`ETH_REQUEST` 16 bytes, `INTERMEDIATE_BUFFER` data at offset 52. Independent
Python ctypes fixtures and literal Rust byte fixtures check the contract.
Do not infer native success from either fixture.

Published contract: wiresock/ndisapi `include/Common.h` blob
`ba42da741693816d2d843f59b241aa827c1a3d3d` (packing, layout and IOCTL numbers).
Only interface facts are used; no vendor user-mode implementation or ProxiFyre
AGPL source is included or translated. The x64 queue-size input is 8 bytes
(`sizeof(HANDLE)`), not an old x86 web documentation table's 4 bytes.

## Safe default commands

```
flowbridge-agent capabilities
flowbridge-agent status
```

Both are read-only. Status combines the original FlowBridge SCM observer from
#46 with device version and adapter inventory using the corrected ABI. The agent
does not install/start/stop the driver or change system security configuration.
Opaque driver handles, packet payloads and SSH secrets are not exposed in JSON.

## Explicit bounded laboratory operation (native verification still pending)

`lab` accepts a strict JSON object with `adapter_name`, `duration_ms` (1..60000),
`consent`, and optional `passthrough`. Adapter names are selected exactly from
read-only inventory, never provided as raw handles. The service must be running
as a kernel driver, device open is requested exclusive, media/MTU checked, and a
nonzero preexisting adapter mode causes rejection rather than takeover.

- `consent: "LISTEN_ONLY"`: listen/copy mode. Original networking remains intact;
  the agent reads bounded batches and NEVER injects copied packets.
- `passthrough: true` with `consent: "EXPERIMENTAL_DIVERT_AND_REINJECT"`: laboratory
  tunnel mode reads and reinjects original frames in their original directions.
  It does NOT proxy selected apps. It can temporarily interrupt connectivity if
  I/O fails; run only on a disposable native test environment after review.

Every normal exit or detected error explicitly restores adapter mode 0, verifies
it, flushes the queue and reports cleanup failures. Drop makes a final best-effort
attempt, not a guarantee. Forced termination, power loss, driver hangs and other
processes' device handles remain native test cases. **Mode 0 restores ordinary
networking; it is NOT a persistent kill switch or fail-closed protection.**
Out-of-band VLAN metadata and checksum-offload bytes are preserved unchanged in
passthrough mode. Packet mutation belongs only to the separately validated
policy pipeline, not to unconditional laboratory forwarding.

## Exact safety boundary

The native agent does not promote IP Helper snapshots to packet-owner proof.
`PacketBound` is a non-serializable in-process evidence label for a future trusted
native resolver; synthetic tests use it explicitly. The current CLI cannot turn
it on or advertise protected redirect. DNS/UDP containment and authenticated
carrier/relay binding are not implemented as a native protected product.

The existing C++ WFP research target and its old GUI/installer remain in the
repository for regression coverage, but are deliberately EXCLUDED from the
Rust candidate archive. This candidate is not a replacement full GUI installer.

## CI evidence, packaging and remaining gates

Existing workspace Rust/native/DNS/OpenSSH workflows stay enabled. Additional
Windows Server 2025, macOS and Linux integration jobs test the same driver
lifecycle using injected errors, real loopback SOCKS connections and strict
negative CLI cases. These are not native Win10/11 driver tests. The archive
manifest pins actual checked-out source SHA (including a PR test-merge SHA), PR
HEAD SHA, every payload hash and explicit false acceptance flags. Payload is
allow-listed to the original Rust agent, Rust CLI, this readme and manifest.

Unclosed release gates: actual Win10/11 NDISRD signature/provenance and RX/TX;
packet/process binding under PID and tuple reuse; selected app -> Rust relay ->
FlowBridge SOCKS -> SSH native trace; carrier exclusion; protected crash failure;
IPv4/IPv6 DNS/UDP/QUIC no-leak evidence; secure service/IPC/GUI and installer
upgrade/uninstall/rollback; native resource soak. macOS NE remains independent.
Do not mark 1.0 or DNS leak-free without evidence and owner approval.

## Real Rust relay coupled to supervised OpenSSH (still NOT native packet proof)

The existing isolated Linux and hosted Windows SSH fixtures now run the Rust
agent's explicitly consented `relay-probe` through the actual FlowBridge SOCKS
listener backed by a separately supervised OpenSSH process and a counted
loopback echo destination. The probe validates 4,097 exact binary bytes,
TCP half-close, release of the admission permit, denial with the upstream gate
closed (zero reconnect grace and zero target connections), and recovery after
the gate is reopened. It records the real SSH PID, exact source SHA and agent
binary SHA-256 in machine-readable evidence. Existing 128/1152/10000/4 and
raw-512 assertions remain intact. The helper may **never** claim driver
interception, packet-to-PID authority, DNS containment or Windows 10/11
acceptance, irrespective of the probe result.

## Cross-component owned TCP lease lifecycle (integration head after 529a9ead)

The new Rust owned-flow boundary joins the existing packet-policy ticket to a
**real** SOCKS5 connection and a real user-mode TCP ingress stream. Activation
is only after SOCKS CONNECT succeeds; STREAM termination, cancellation, upstream
supervisor disappearance, or Drop removes the exact ticket and alias without a
DIRECT fallback. The packet-worker mutex is **not** held across an awaited
network operation. An independent terminal-only cleanup API avoids advancing
(or rewinding) the packet clock from unrelated async I/O and refuses stale
generation/owner tokens. Lock poison or unprovable cleanup revokes the entire
offline pipeline. Cross-component tests cover IPv4/IPv6 VLAN-tagged synthetic
packets and bidirectional offline rewrite alongside actual binary/half-close
SOCKS streams, plus refusal, abandoned connections, PID/generation and
supervisor-loss negatives. This does **not** connect native NDISRD packets to
that relay, prove PID attribution, or provide protected crash persistence.

An aborted async SOCKS handshake additionally owns a pending-token guard: task
cancellation is tested against an actual TCP/SOCKS handshake stalled before
the CONNECT reply. Dropping that future must release the exact pending lease
and capacity slot without a direct dial.

## Windows foreground Rust control and explicit SOCKS lifecycle (R7 partial)

The independent Rust agent additionally supports a bounded, LOCAL named-pipe
control of the existing Rust SOCKS Engine in explicitly configured mode:

```powershell
flowbridge-agent.exe control-serve C:\path\to\explicit-profile.json
# From another terminal, same user:
flowbridge-agent.exe control status
flowbridge-agent.exe control reload
flowbridge-agent.exe control stop
```

The controller runs in the foreground as the invoking user, with a fixed named
pipe. Windows security is enforced at pipe creation with an explicit protected
ACL (SYSTEM, Administrators and pipe owner), rejects remote clients, requires
the first pipe instance, bounds input/output frames and deadlines, and provides
only three strict commands. Status contains bounded aggregate counters, NOT
SSH credentials, client destinations, EXE paths or opaque kernel handles.
No service registration, elevation, driver installation, SSH key acquisition
or NDISRD interception is performed by this feature.

The controller validates explicit SOCKS profiles, deliberately DENIES enabled
application-specific rules because the source process is not attested by
SOCKS5, and rejects live listener/capacity changes. An invalid reload leaves
the running engine's configuration generation unchanged; a valid reload
increments it. Stop closes the real listener and cancels its live connections.
This is NOT a persistent fail-closed kernel barrier. Profiles can contain
explicit DIRECT rules: the controller does not claim a security kill switch.

Windows Server hosted CI adds an actual second-process named-pipe control
test against an independently running Rust agent and real loopback SOCKS5
handshake. It checks blocked target connectivity, failed reload rollback,
successful hot reload and graceful stop; it writes SHA-tied JSON evidence into
the allow-listed candidate CI artifact. Other platforms test protocol
validations and real Rust Engine lifecycle without claiming native Windows
driver evidence. An actual Windows SCM service, restricted unauthenticated
GUI views, crash recovery, authenticated owner binding, selected-app packet
capture, protected DNS/UDP and Win10/11 installation remain OPEN.


## Native signed-driver proof on VDSina, 2026-10-31 (R1 read-only/RX partial)

This is **actual separately installed signed Windows Packet Filter NDISRD 3.6.2.1
on the owner's VDSina Windows Server 2025 VM**, driven by the original Rust
FlowBridge agent built for prior PR head
`51bdc3b16f46e6bee99ec3bf213ca47276335450` / hosted merge
`3b2f5867b7b6ee55f50dc3826008184a68e1d447`. It is **not**
Windows 10/11 acceptance. The owner's independent provider VNC was tested, the
self-hosted Windows x64 runner was elevated, Defender real-time remained active,
and neither secure boot nor memory integrity was disabled or claimed verified.

- Official separately installed MSI SHA-256
  `9c388c0b7f189f7fa98720bae2caecf7d64f30910838b80b438ecf8956b8502c`;
  Microsoft WHCP-signed driver SHA-256
  `8623a9c34531cf73de4286ad518b84af03a331c78959769a1ca38723e3258984`.
  No driver/ProxiFyre binaries are included in the FlowBridge candidate.
- The original independent Rust agent SHA-256
  `bd74827262da07c538c9a78ea6c96d048aa6a1df49026cf56e691435cd4ce92e`
  actually opened the NDISRD device and executed its real version/adapter
  query IOCTLs. Real API version `0x06023000`; one adapter, native
  packed adapter wire inventory 8836 bytes; invalid-consent lab request
  rejected. Exact self-hosted
  [read-only PASS](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41182781861),
  with sanitized private [proof](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6540906999).
- **First real Rust NDISRD LISTEN-only RX PASS**:
  [self-hosted run 41183317849](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41183317849),
  private workflow source SHA
  `4e2d14f45e60d28a885047ae9ae4f578d7f2e0de`.
  Native copy-only LISTEN_BOTH mode received 55 real packets in 5500 ms
  (28 outbound, 27 inbound), with **0 reinjections**, real Rust process exit
  code 0, successful loop, explicit verified restoration to adapter mode 0,
  working outbound network and active Defender after the test. A local SYSTEM
  scheduled emergency driver-uninstall watchdog was armed immediately before
  any adapter mode change and safely disarmed only after restoration and
  security/network checks. The driver remained installed. No packet payload,
  IP address, MAC, adapter name, SSH keys, or secrets entered artifacts.
  [Private JSON evidence](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6540972621);
  downloaded outer artifact ZIP SHA-256
  `052d5f6d6e03882a5251e3cc6934dc4087f29b8f41be2a7fca647819edf0e92a`,
  independently verified against GitHub artifact and JSON assertions.
- Prior native observations (70 and 62 real packets) already proved read-only
  device RX and mode-0 restoration, but private workflow verdicts were
  **FAIL because of Windows PowerShell harness Process.ExitCode handling**.
  Independent signed-driver/agent/status checks and healthy networking/
  Defender permitted safe rescue disarm; the final run above fixed the
  test harness without relaxing its exit-zero or rollback gates. Do not
  retroactively mark those earlier runs PASS.

This establishes **native signed-driver -> original Rust DeviceIoControl ->
packet copy-only receipt -> verified normal-network rollback**. It does
**not** close native packet divert/injection, process/PID creation-epoch
binding, packet-to-Rust-local-relay-to-SOCKS/SSH-selected-app routing and
reverse flow, persistent protected fail-closed, IPv4/IPv6 DNS/UDP/QUIC
containment, GUI/SCM/installer, or actual Win10/11 protected acceptance.
Returning to adapter mode 0 resumes **ordinary** connectivity and is not
a protective kill switch. No release or DNS-leak-free claim follows from
this result. See [issue #41](https://github.com/i-shutov/flowbridge/issues/41)
for the detailed independent evidence checkpoint.


## 2026-10-31 — independently verified real native original-frame RX/TX on VDSina

Advance beyond prior read-only LISTEN_BOTH: a guarded, bounded real NDISRD
TUNNEL_BOTH lab session received **109 native frames (53 outgoing, 56 incoming)**
and completed **109 successful original-frame sends**, with actual driver I/O
from the original Rust agent, no ProxiFyre and no distributed driver. This is
still not selected-app proxying, DNS containment, protected kill switch or Win10/11
acceptance. Tested Windows Server 2025 only. Agent source HEAD
51bdc3b16f46e6bee99ec3bf213ca47276335450, prior tested merge
3b2f5867b7b6ee55f50dc3826008184a68e1d447, agent SHA-256
bd74827262da07c538c9a78ea6c96d048aa6a1df49026cf56e691435cd4ce92e.

- [Private native run 41184740167](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41184740167)
  and [sanitized evidence](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6541158423):
  workflow SHA 708f5ca08ffdc000a3ef186accfabe699f409c57; 7503 ms; process
  exit 0, loop completed; in-session TCP/443 and post-session network PASS;
  signed official kernel driver and active Defender PASS. Independently armed
  local SYSTEM uninstall rescue was disarmed only after mode-0 restoration and
  health verification. NDISRD remains installed.
- Downloaded private artifact 13035917293 ZIP SHA-256
  27f08238aabdd71d8f201cb5a44adf2d47245cd4297d0833af0c02c345d02588
  matches GitHub digest. Independent checks verified receipt/sends, both packet
  directions, reset, watchdog and Defender. No packet payload, IP/MAC/adapter
  names or credentials were written to evidence.
- These were the **original, unmodified packets**. No reliable packet ownership
  binding to PID + creation epoch, no TCP selected-app redirect to relay/SSH,
  no reverse-path proxy rewrite, and no persistent fail-closed. Restoring NDISRD
  adapter mode 0 resumes ordinary DIRECT-capable networking; not a kill switch.

Prior documentation-only HEAD f44070c74c5ef489e88956179e7285c64c8bfec4
had tested PR merge 754b39b9cf568254917bb2f4c949d3da581ea68d.
All four exact-head CI workflows succeeded:
[capture 3/3](https://github.com/i-shutov/flowbridge/actions/runs/41183457267),
[Rust/native 5/5](https://github.com/i-shutov/flowbridge/actions/runs/41183457221),
[DNS 3/3](https://github.com/i-shutov/flowbridge/actions/runs/41183457222), and
[real Windows managed OpenSSH](https://github.com/i-shutov/flowbridge/actions/runs/41183457268).
The Windows capture Actions ZIP SHA-256 was independently reproduced as
c7468766066029a7fe082e2d56b2d9d6b2d944f7fd4b233a46666e2305b0400c,
and nested allowlisted candidate ZIP as
ce0152d47dc9a64b7b43db0e6dc4a67e3a7662e24618c2c559c0307209707e26.
Real Windows SSH Actions artifact SHA-256 was
51b207771f423417621486050c098d1562f6236e0211742b62ef6c960643a2b0.
Managed OpenSSH acceptance remains 128 actual held/1152 rejections/10000
byte-verified successes with zero errors/4 distinct subprocesses. Separate
raw OpenSSH characterization only reached 246 held, not stable 512.

All protected, DNS leak-free and release claims remain explicitly FALSE.


## Windows IP Helper owner candidate integration (unaccepted until exact-head CI)

The Rust capture crate now owns the single original read-only implementation
of Windows GetExtendedTcpTable TCP owner-candidate lookup used by BOTH
flowbridge-agent and the existing flowbridge-ffi API. The FFI ABI remains
unchanged, and the former duplicated lookup module is a thin reuse layer.
Only the Windows APIs and Rust code written for FlowBridge are used; no
ProxiFyre/AGPL source or shipped vendor user-mode binaries are involved.

The new CLI command 'flowbridge-agent owner-selftest' executes an actual
self-owned loopback TCP socket while retaining both TCP endpoints, samples
the native IP Helper TCP table TWICE, pins a query-only process handle,
compares PID, creation FILETIME and queried image identity, and fails if
the live socket or process epoch cannot be confirmed. CLI output deliberately
suppresses PID, process creation timestamp, executable path, endpoint and
payload. A real Windows hosted integration test requires the CLI to succeed
and verifies the absence of sensitive identity fields. Regression tests
preserve exact tuple, stale/duplicate-state and IPv6 scope checks.

IMPORTANT evidence boundary: this is a real native Windows TCP owner
snapshot CANDIDATE, not a kernel-authenticated assignment of an NDISRD
packet. IP Helper lookup does NOT grant PacketBound, CapturePolicy, a
selected-app route, or protected allow. Selftest never opens NDISRD or
changes adapter modes; no DNS/UDP containment, fail-closed, service,
Win10/11 acceptance or release claim. The current protected gate remains
DENIED. Native packet binding and selected-app ingress/return path remain OPEN.

Exact GitHub CI run, PR HEAD/merge SHA and independently checked artifact
digests will be added only after verification; no PASS from source alone.


## Bounded native NDISRD-to-IP Helper candidate observation (Windows Server native evidence; NOT PacketBound)

The **same** native x64 Rust PacketSession now offers a copy-only packet
observer that is explicitly denied in divert/passthrough mode. An additional
owner-candidate laboratory request requires `owner_candidates:true`, explicit
consent `LISTEN_ONLY_OWNER_CANDIDATES`, an exact adapter name, and <=15 seconds.
It reads genuine NDISRD LISTEN_BOTH frames when executed on an eligible host,
parses supported checksummed IPv4/IPv6 Ethernet TCP frames, and attempts at most
24 IP Helper double-snapshot process-creation-epoch candidate lookups. Reverse
wire direction is reversed before a local/remote socket query; IPv6 link-local
frames are excluded because Ethernet does not supply the scope ID. All frames
and process/tuple identities are discarded, with **only redacted counters**
returned. The observation callback cannot mutate raw frames or reinject them.

These counters are a diagnostic cross-check, NOT kernel-authenticated
packet-to-PID proof. In particular, an IP Helper row can race NDIS receive,
so even a consistent two-snapshot PID/path/creation time does not produce the
CapturePolicy `PacketBound` authority. `native_packet_attribution_proved`,
`authorizes_capture` and `protected_redirect_available` remain false.
No selected-app route, fail-closed safety, DNS leak-free or Windows 10/11
acceptance is claimed. Dangerous protected operation is not enabled. A VPS
native run, if performed, requires pre-armed independent rescue and owner-
confirmed emergency VNC; no unsolicited divert, installer or kernel changes.

### Exact-head GitHub and real NDISRD outcome, 2026-10-31

- Original Rust integration source: PR #56 HEAD `f8951bf2af69fbbfbd6cd8ccfbb662c8d65a735f`, tested pull-request merge `8a6dc373c809f06419964c1865ca7866ad09be20`. Strict hosted [capture integration 41193920767](https://github.com/i-shutov/flowbridge/actions/runs/41193920767) 3/3 PASS; [Rust/native 41193920774](https://github.com/i-shutov/flowbridge/actions/runs/41193920774) 5/5 PASS; [DNS 41193920895](https://github.com/i-shutov/flowbridge/actions/runs/41193920895) 3/3 PASS. Windows SSH 41193920780 was still running at this checkpoint; no overall pass claimed early.
- Independently downloaded hosted Windows capture artifact #13039838605: outer ZIP SHA-256 `318038b34a28f98e0aebb353c32ce2f1687c63bc0aa460ae12d318161dfbefe7`; nested four-file allowlisted Rust-only candidate ZIP `97076498b274c243e24e61f0deabb26150f3d4b9ca8d10947026319cc8deb95f`; original `flowbridge-agent.exe` `491f1a07fb610b0ca75b2c94f8e8da49c252390f2242e59ace6eed28887fe922`. All manifest payload hashes independently matched, PR HEAD and tested merge both matched.
- Real VDSina Windows Server 2025 Standard build 26100, signed separately installed NDISRD, Defender active, owner-confirmed VNC, independently prearmed SYSTEM recovery, **copy-only LISTEN_BOTH**: [private native Actions 41194272084](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41194272084), private workflow SHA `42b8ff7820dc42f779799dd0398c383814ac49d4`. 6504 ms, **71 actual driver frames (31 outbound / 40 inbound), zero injected**, 24 bounded live IP Helper double-snapshot queries: **18 consistent process candidates, 4 absent, 2 indeterminate**. The adapter was restored to mode 0; in-session capture completed, network and Defender checked healthy, independent rescue DISARMED, no MSI uninstall. Only aggregate counts were written.
- Independently downloaded private sanitized evidence artifact #13040235105: ZIP SHA-256 `f0c1ad2d7b0ae42b37cc261725d3a5c3e461f4dfab914bba22dc2c2b08ab362d`; internal `listen-only.json` SHA-256 `c70d5800131c152e139e2fdd86174e12fd7db907867d0a837b3cfdc46303c679`. Both source/merge SHA and mandatory rollback/no-reinjection security booleans checked against downloaded bytes. Evidence is also copied to private [VPS issue #1](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6542425846).

**Important:** Even 18 consistent IP Helper PID + creation-time snapshots are temporal *candidate associations*, NOT kernel-authenticated assignment of NDISRD frames to process identity. The implementation does not synthesize `PacketBound` or authorize a selected app, and cannot yet route intercepted TCP through the SOCKS/SSH relay. No protected fail-closed, DNS/UDP/IPv6 leak containment, Windows 10/11 native acceptance, complete service/installer, macOS NE acceptance or release is proved. Mode 0 returns to ordinary networking, NOT a protected kill switch. Raw unprotected OpenSSH 512-channel stability is still not established.


## Windows native SCM candidate — cross-component beta staging (pending verified CI)

The original Rust capture agent now has an **on-demand, manually installed**
SCM dispatch entrypoint `service-run <absolute-config>`. No kernel driver,
ProxiFyre executable, custom WFP component or extra dependency is installed.
The test-only SCM service identity is `FlowBridgeRustCandidateCI`; no service
is installed during package creation or ordinary agent invocation. It refuses
an unbounded/non-absolute profile path and refuses non-loopback SOCKS listeners
**before** the Engine begins listening. It opens the same real SOCKS Engine and
same fixed-ACL local-only Windows named pipe as the previous foreground mode.
Service STOP/SHUTDOWN signals request graceful engine stop, close the listener
and report SERVICE_STOPPED; pipe STOP also terminates its SCM instance.
No opaque service command can change NDISRD mode, set a trusted PID token,
or change the service identity/configuration path.

On hosted Windows, a dedicated script tests REAL SCM create/start/stop/restart,
real TCP SOCKS5 handshake, local IPC/status/reload, generation reset and
termination via both SCM STOP and pipe STOP. It always attempts to remove its
own manually-created test service. This is independent process/SCM evidence,
**not** Win10/11 NDISRD, protected packet routing, crash-persistent fail-closed,
remote-DNS containment, automatic upgrade or installer acceptance. The SCM
candidate starts **only with explicit SOCKS and loopback bind** and never
activates native capture. Any claim of a protected Windows beta still requires
a separate native interposition/safety/installer implementation and acceptance.

## Native controlled self-owned Windows TCP → NDISRD → Rust relay → SOCKS/OpenSSH: first verified chain

2026-10-31 exact *code* SHA `f947bf9f27923a6a669f6f2c521f6235796cc74c`,
PR #56 test merge `22c3b698ef01a7b945e6360d6ed37bfddea11413`.
The public capture 3/3, Rust/native 5/5 and DNS regression 3/3 GitHub Actions
passed on this source. The **separate** Windows OpenSSH workflow **FAILED**
its experimental raw 512-channel characterization (Winsock 10054 /
sshd "Too many open files") even though managed 128 held / 1152 denied /
10,000 byte-verified successes / four independent SSH processes passed.
Do not represent raw 512 as PASS or the overall SSH workflow as green.

Actual VDSina VPS #3293462 Windows Server 2025 [native run
41207789454](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41207789454)
**PASS**, private workflow SHA `f04e7fbb2cec46532828381055e825659fa4d827`;
[private truthful evidence](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6544300447).
An internally-owned and live socket was captured via official separately
installed signed NDISRD, reflected to the Windows TCP stack and the original
Rust relay, then genuine FlowBridge SOCKS and authenticated supervised
Microsoft-signed OpenSSH; the HTTP response returned through inverse
reflection. Connected: 5/4 reflected client/relay frames, 57/313 bytes.
Gate denied: 4/3 reflected frames, no HTTP reply and no SOCKS CONNECT.
Recovered: 5/4 reflected frames, 57/315 bytes on the SAME SSH supervisor.
All three native runs report zero selected original frames sent to adapter,
an internally verified owner PID+epoch, and mode rollback.

Independent SYSTEM recovery armed and later disarmed; temporary scoped
firewall rule removed; mode zero/network/Defender healthy. Actual downloaded
artifact #13044882622 outer SHA-256
`2a381eafdf040e50dc29c320cd1c35c8b16fc02348a9a2e9932327bc80a85359`
equals GitHub digest, one JSON entry SHA-256
`6ecdc8338249a9e7ae63895511238bb1500d2325ebcad64cebee03cc14b06be0`.
Verified source/merge SHA and all acceptance/negative flags; no packet
payload or PID/IP identity persisted. See
[full native lab dossier](NATIVE_SELF_REDIRECT_LAB.md).

**NOT proof** of another application's packet ownership, not protected
system-wide interception/crash fail-closed, not DNS leak-free/UDP/IPv6,
not Windows 10/11 desktop native acceptance, not a beta/1.0 release.
Adapter mode 0 is normal networking. Private VPS is still useful for
additional negative native tests and owner/driver containment work.


## Real NDISRD parent/child cross-process TCP → Rust SOCKS → authenticated OpenSSH (6/6 PASS; 2026-10-31)

**Scope:** this advances beyond the parent-owned socket: an entirely separate
original Rust child process binds its own source port, waits for an explicit
parent GO handshake until NDISRD diversion is active, and completes real
HTTP request/response via actual native driver interception, Windows TCP
reflection, Rust relay, FlowBridge SOCKS5 and supervised OpenSSH. The parent
pins the child process object and verifies PID/creation FILETIME alongside
two consistent native IP Helper TCP table snapshots. The exact reserved
child flow is reflected, and the child is killed/joined **before** restoring
ordinary networking. A parent-spawned, known-socket canary is **NOT**
transparent arbitrary selected-app capture or authenticated packet ownership.

- Exact public source commit `81419f764ba51dab9c4aa91bda1de81ccb581383`,
  exact CI PR merge `dc70e093c40490aa728455fa52a22eca38bef7d7`.
  Public [capture integration 41210372566](https://github.com/i-shutov/flowbridge/actions/runs/41210372566)
  **3/3 PASS** (Windows/Linux/macOS, strict Clippy/rustfmt), [Rust/native
  41210372560](https://github.com/i-shutov/flowbridge/actions/runs/41210372560)
  **5/5 PASS**, and [DNS regression 41210372591](https://github.com/i-shutov/flowbridge/actions/runs/41210372591)
  **3/3 PASS**. [Windows OpenSSH 41210372578](https://github.com/i-shutov/flowbridge/actions/runs/41210372578)
  was still executing when this exact code was independently checked.
  Managed 128 held/1152 denied/10000 byte-verified completed/4 distinct SSH
  processes remain prior evidence; separate raw 512 stable channels are NOT proven.
- Independently downloaded public capture Windows artifact
  #`13045349444`: outer ZIP SHA-256
  `c616b6666d71d00b587a441c43c8ec08deac3458ba4383a010b729526c440c9b`,
  allowlisted Rust candidate ZIP
  `04a90b470a60530294511a89b5651796ab042df4c1f465d9895315cad0554a13`,
  original agent PE
  `3aa4ecaaa027f6b0f4091c83e7e445ba060cdce6caff14e185247307f9259283`.
  Separate *testing-only* native FFI/tools artifact #`13045109828`:
  outer SHA-256
  `d0011d624c6ac5081780193de629e8b0e39e3454cd4ce34386b4fb63dde8157a`,
  FFI DLL SHA-256
  `8ad037271bf3231180801a820b9a2880b0007bc6bc20af19963107fe4c2f9d63`.
  Both source/merge SHA and every file hash checked against the downloaded
  manifests. No driver, ProxiFyre binary, C++ WFP sidecar or keys in candidate.
- [VDSina Windows Server 2025 self-hosted native run #41210941526](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41210941526)
  **PASS**, private workflow SHA `68b690adde99fb730c9f8f7f9c6c67768437b812`.
  [Sanitized actual JSON in private issue #1](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6544806370).
  Six actual driver/SSH phases: parent connected/closed/recovered and
  **separate child connected/closed/recovered**, all 6/6 PASS. Child positive
  had **5 forward / 4 inverse reflected native TCP frames; 57 bytes sent,
  314 bytes received**, confirmed HTTP response. Child gate closed had
  **4 / 3 frames, 0 bytes received, no DIRECT, no SOCKS CONNECT**; recovery
  had **5 / 4, 57/314 bytes**, same authenticated SSH supervisor. The parent
  also passed its full positive/closed/recovery triple (57/311 success).
  All six report zero selected original frames sent to physical adapter.
- Independently downloaded private evidence artifact #`13045204941`:
  outer SHA-256
  `d9740fb5505eb8c884410b98755567ab630ae0f16de3c628761dec29d262317c`,
  exactly one sanitized JSON SHA-256
  `55d60ac595bb4024c406e14a5f043c126c96fb9f17200328fc7d5a5b7f5829b9`.
  Validated public and private SHAs, 6× native frames/HTTP/denied/recovery,
  child-vs-parent identity distinction, native driver access, agent/FFI binary
  hashes, no payload/process identity retention and **all false release gates**.
- Safety: independently scheduled local SYSTEM MSI-uninstall rescue armed
  beforehand and disarmed after positive **adapter mode 0** recheck,
  network and Microsoft Defender active, exact scoped firewall rule removed.
  `rollback_needed=false`, no teardown incident, vendor driver remains
  separately installed. Normal adapter mode 0 permits DIRECT traffic and is
  **NOT protected fail-closed**.

**Explicitly NOT ACCEPTED:** arbitrary application NDISRD packet→PID+creation
epoch authentication, transparent selected app routing, persistent protected
crash/SSH failure policy, DNS-leak-free, UDP/QUIC/IPv6 containment, personal
Windows 10/11 acceptance, macOS NE, raw OpenSSH 512 capacity or release 1.0.
Next genuine blocker: attach unrelated selected-app flow to *defensible* owner
authority and independently enforced protected drop, with native negative
tests under guaranteed rollback. Server 2025 is only an integration laboratory.


## Fixed Microsoft PowerShell test-client vertical (2026-10-31, native proof pending)

The Windows-only Rust agent now supports one further *bounded laboratory*
client type: the OS PowerShell executable in the fixed system directory,
running a static source-owned script to reserve an IPv4 TCP source port,
announce it to the Rust parent and wait for GO. The parent pins the distinct
process object and exact creation epoch; the same native packet-reflection
worker requires two consistent IP Helper TCP-owner snapshots before reflecting
the single reserved flow through Rust SOCKS and authenticated OpenSSH. The
PowerShell process is ONLY a traffic generator, not a router or privileged
backend. No caller-provided executable path, script or PID is accepted.

This mode requires the distinct NATIVE_POWERSHELL_CHILD_TCP_REFLECT consent,
rejects conflicting client modes, validates the live owner and returns the
socket child to a terminated/joined state before the NDISRD tunnel is
disarmed. The Python native harness requires connected, denied and recovered
phases for the PowerShell client, with separate identity and negative
PacketBound/release flags. Native VDSina execution MUST verify the system
PowerShell Authenticode signature before driver mutation, keep the independent
SYSTEM rescue armed, and check source/merge/binary/artifact SHA-256. This
paragraph records the new SOURCE CANDIDATE only, not a native test PASS.

Even if these further native phases eventually pass, a known parent-created
PowerShell process with an explicit GO handshake does NOT establish arbitrary
app packet attribution, persistent crash fail-closed, DNS/UDP/IPv6 containment
or personal Win10/11 acceptance. Mode zero remains ordinary DIRECT-capable
networking.


## VERIFIED native nine-phase parent/Rust-child/signed-OS-PowerShell NDISRD → Rust SOCKS → real SSH (2026-10-31)

The prior "native proof pending" source checkpoint above is historical: the
fixed Microsoft-signed OS PowerShell child has now passed **actual NDISRD**
interception and bidirectional reflection on a separately rented Windows
Server 2025 Standard system. This **does not** authorize arbitrary
selected-app/packet-to-PID binding, persistent fail-closed or a beta release.

**Pinned code and hosted CI:** PR #56 code HEAD
`6ec22db996276aef19e378aed799476a0068166a`, exact test merge
`6aaadd172cf7425ab314eb51a91d994c00e7be41`; public base `main`
`5b5afc2feeda2195f302380e615ba003d4906e09` unchanged. Hosted
[capture integration #41214148509](https://github.com/i-shutov/flowbridge/actions/runs/41214148509)
**3/3 PASS**, including Microsoft Authenticode-checked in-box PowerShell
negative GO (no connection before authorization) and real TCP half-close HTTP
response. Hosted [Rust/native #41214148179](https://github.com/i-shutov/flowbridge/actions/runs/41214148179)
**5/5 PASS** and [DNS regression #41214148223](https://github.com/i-shutov/flowbridge/actions/runs/41214148223)
**3/3 PASS**; *DNS regression is not leak-free acceptance*. Long
[real Windows OpenSSH #41214148092](https://github.com/i-shutov/flowbridge/actions/runs/41214148092)
was still running at this evidence checkpoint: no PASS claimed; separate raw
512-channel stability was not established.

**Independent downloaded public artifacts**, exact hosted source and test
merge cross-checked against internal manifests:
- Windows capture artifact `13047248828`: outer ZIP SHA-256
  `d0a4290ccf76717de437654eb30a0a1c5de6f6c4008d26caf3bac93e0ef60a48`;
  allowlisted four-file candidate ZIP
  `c5f559db68cd2ca8dda744463228dce29c366e1e994315acd9d2a9b8d51d3978`;
  Rust agent PE SHA-256
  `5cfd2fba229c6c5d3e0c7a9bc11070603d69ab930f931151cd2c9a98fbe82f69`.
- Separately allowlisted **test-only**, not product, native tooling
  `13047547909`: outer ZIP SHA-256
  `dd957942bdc0ffbb299539e8b17b667f49b1d4b2d3142c31efc61d1497300280`;
  Rust FFI DLL SHA-256
  `d0a341647436d5644c7fdadc0cdee876b6a06ea428bbdd6a543ece8104f21079`.
  Every manifest payload hash and file count passed independent inspection;
  no vendor driver, ProxiFyre, AGPL implementation, legacy C++ sidecar or
  credentials in the product candidate.
- Hosted `powershell-client-lifecycle.json` has `passed=true`,
  `negative_go_no_tcp=true`, `positive_half_close_http=true`,
  `verified_http_reply_bytes=57`, `native_driver_tested=false`.

**Actual VDSina VPS #3293462 native test:** [private Windows Server
2025 GitHub Actions #41214578775](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41214578775)
**PASS**, pinned private workflow SHA
`cf86df971cf4044963119b43c0bb3099453c46f9` and exactly the public
source/merge/binaries above; [sanitized evidence in private issue
#1](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6545349434).
Independent **signed Microsoft PowerShell executable prerequisite**, signed
NDISRD, Defender, firewall, exact adapter and owner-confirmed VNC were checked
*before* diversion. Independent SYSTEM rescue was armed before network
mutation, and then disarmed after confirmed mode-zero rollback, network,
firewall rule removal and Defender health; `rollback_needed=false`.

All **9/9 real NDISRD/real authenticated OpenSSH phases PASS**:
parent-owned socket **connected/denied/recovered**; distinct parent-spawned
Rust child **connected/denied/recovered**; distinct fixed Microsoft-signed OS
PowerShell child **connected/denied/recovered**. PowerShell connected:
**5/4** client/relay reflected native frames, **57/311 bytes** sent/received
and HTTP reply; closed upstream: **4/3** reflected frames, **0 reply
bytes**, no SOCKS connection or DIRECT; recovered: **5/5** frames,
**57/314 bytes** and same live SSH supervisor. Distinct PowerShell PID/creation
epoch and double-snapshot IP Helper ownership candidate matched the reserved
flow in all three phases, but no PID, endpoint or payload was recorded.
All nine native phases report **zero selected original frames sent to physical
adapter**; return traffic was reflected through Rust and the Windows TCP stack.

Independent downloaded **private native evidence** artifact `13047204447`:
ZIP SHA-256 `8bd0151566173fee517147c486e4935f1e7285197e042a7605364d6805fc8f8b`
matching GitHub digest, exactly one redacted JSON SHA-256
`548f0d3b185f3437955e23a6c18e192f6e4a3fe97c4a9b6090b45fab1156a916`.
All nine phase flags, counts, source/merge/workflow SHA, agent/FFI digests,
nine rollback flags and negative release claims were independently checked.

**Still open / explicitly FALSE:** arbitrary unrelated selected-app packet
ownership (the PowerShell canary is parent-created and pre-authorized),
kernel-authenticated `PacketBound`, transparent process redirect,
crash-persistent protected fail-closed, DNS/UDP/IPv6 leak containment, personal
Windows 10/11 native acceptance, macOS NE, raw 512 stable SSH channels,
DNS leak-free and release 1.0. Mode 0 restores ordinary DIRECT-capable
networking, not a protected kill switch. Keep the paid VPS only while further
bounded native tests materially advance these open gates; no deletion or
release without explicit owner approval.

## Verified independent signed-PowerShell sibling 12-phase native NDISRD / Rust SOCKS / OpenSSH integration (2026-10-31)

**Scope and safety:** This supersedes the historical **nine-phase** maximum
checkpoint above, without changing its original evidence. Native driver
integration passed for **four explicitly controlled traffic generators**,
each with connected / SOCKS-gate-closed / recovered phases: (1) Rust agent's
self-owned TCP socket; (2) parent-spawned distinct Rust child; (3) Rust
parent-spawned fixed Microsoft-signed OS PowerShell child; and **(4) an
independently QA-launched fixed Microsoft-signed OS PowerShell process,
not created by the Rust agent**. The fourth generator owns and reserves a
source TCP port before announcing a bounded loopback GO-control port; it is
still a **known, consenting test canary**, not arbitrary selected-app capture.

**Found and fixed a real false-ownership bug before accepting the run:**
private [failure 41216230392](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41216230392)
and the first pinned [failure 41217430715](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41217430715)
already demonstrated successful bidirectional traffic for the independent
PowerShell canary but the Rust report incorrectly returned both
`self_owned_socket_pid_epoch_consistent=true` and
`external_sibling_socket_pid_epoch_consistent=true` for one flow. The
private QA harness correctly failed. New original-Rust
`owner_evidence_flags` is an exclusive four-category assertion: self,
spawned Rust child, spawned signed OS PowerShell child, independent signed OS
PowerShell sibling; any ambiguous/unchecked observation produces all-false.
Dedicated negative/positive Rust unit tests verify every combination. This
fixes only the *reported laboratory ownership category*, not kernel
PacketBound or arbitrary-app authorization.

**Pinned source/build:** exact draft PR #56 source HEAD
`64118bbbf15d2c0fa2eb5d76c76c2eb36539ef37`, tested GitHub merge
`9b73dd051fd06eeb54b95ca24f92d3d8c3e31912`; base `main`
`5b5afc2feeda2195f302380e615ba003d4906e09` unchanged. Original
Rust capture [CI 41217812299](https://github.com/i-shutov/flowbridge/actions/runs/41217812299)
**3/3 PASS** (Linux/macOS/hosted Windows Server, Clippy/rustfmt, signed OS
PowerShell positive/negative tests), [Rust/native 41217812303](https://github.com/i-shutov/flowbridge/actions/runs/41217812303)
**5/5 PASS**, [DNS 41217812321](https://github.com/i-shutov/flowbridge/actions/runs/41217812321)
**3/3 PASS**; generic DNS CI is **not** DNS containment.
[Real Windows OpenSSH 41217812301](https://github.com/i-shutov/flowbridge/actions/runs/41217812301)
**1/1 PASS**, independently downloaded exact merge artifact `13048599045`
outer ZIP SHA-256
`de6a935d0a16bfbe36c213dc65d2cf4837f9bfc75e17bf058eb074b7a0c793b3`.
Verified all six JSON files: real supervised OpenSSH with **128 actual held**,
**1,152 admission denials**, **10,000 byte-verified successful churn** with
zero failures and half-close, **four distinct owned SSH processes**, plus
real Rust agent TCP→SOCKS→OpenSSH→TCP 4,097-byte round-trip and upstream-gate
denial/recovery. **Separate unprotected raw-backend capacity characterization
reached peak 246 held** and returned the Windows OS handle count to near
baseline; a stable **512 channels was NOT demonstrated** (the 512 tier
accepted 0 additional). OS HANDLE is not an internal OpenSSH FD slot count;
`windows_fd_limit_verified=false`. This is hosted Windows Server 2025 and
does not establish Win10/11 native protected packet capture.

**Independently downloaded and inspected binary provenance** from the exact
hosted test merge:
- Windows capture artifact `13048604939` outer ZIP SHA-256
  `46812abb7ffbe9253c4e0fa441518ed7cdc481881edd76b0169626b010dedda7`,
  allowlisted four-file inner Rust candidate ZIP
  `a6a6014774def5291064514b3e2842d8e580c465be7f864bc8984c92bdfaecab`,
  `flowbridge-agent.exe`
  `fad4638ac26603bf3b01cbcfad2298e07fde09c72ccf4261ef2bfafed372a0b1`.
  Every manifest payload digest and six hosted verification JSON booleans
  checked. Candidate contains **only** two Rust executables, README and
  manifest; no vendor driver, ProxiFyre binary, legacy C++/WFP research,
  private SSH keys or credentials.
- Separately allowlisted **test-only** tooling artifact `13049295236`,
  outer ZIP SHA-256
  `9e5854a4cdae32ade2df7122e6eafae2cb11e768bad7506da4a764602695daf5`,
  Rust `flowbridge_ffi.dll` SHA-256
  `0b656ecdcafcdc4cb9f51d6cbee874fda59edf38cb7aa7a8c5c3074f01ef35d0`,
  all ten payload hashes verified against test manifest. This DLL/test
  harness does **not** ship with the personal Windows product.

**Real signed-driver network evidence on rented VDSina VPS #3293462
(Windows Server 2025, NOT Win10/11):**
[private Actions 41218337232](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41218337232)
**12/12 PASS**, private QA workflow commit
`50323de71b019492ce0ef8081df18dfc08352c21`, pinned exact
public source/merge and Rust binary digests. The
[redacted private issue #1 report](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6545884850)
confirms **real NDISRD TUNNEL_BOTH, 12 bidirectional TCP experiments,
real FlowBridge SOCKS, authenticated supervised Microsoft OpenSSH and
HTTP response delivered to selected laboratory process**.
Each generator had a positive HTTP reply, an upstream gate-closed test with
**zero application reply bytes and no SOCKS CONNECT**, and a recovered
HTTP reply under the **same SSH supervisor**. No original selected frames
were sent directly to the physical adapter in any of the 12 trials.
Independent PowerShell sibling positive: **5 client / 5 relay native reflected
frames, 57 B sent / 311 B received**; gate closed: **4/2, 0 B received**;
recovered: **5/4, 57/311 B**. The mutually exclusive sibling flag remained
true and parent self-owned flag false in all three; the pinned process exited
before returning NDISRD adapter to normal mode. No PID, endpoint, SSH secret or
packet payload saved in evidence.

**Independent private artifact audit:** `13048839212`, outer ZIP SHA-256
`8ee5cd749277f95c3a26f5fe5c8bde5eba45849e12c2ea5fb5ef2d087f21b1fe`
matching GitHub digest, exactly one sanitized JSON SHA-256
`b2734bc57d1143fd4e4ce3a763400dc83a2c4a9db1c929d701765d21af033c9a`.
Verified every one of 12 phase flags and the independent process authority,
zero DIRECT selected original packets, no SOCKS while gate closed, rollback
and **all negative security/release claims**. Independently scheduled
local SYSTEM MSI-uninstall rescue armed before driver mutation and disarmed
after exact adapter **mode 0** recheck, network reachable, Defender active
and scoped Windows Firewall rule removed; no rollback incident.

**DO NOT PROMOTE THESE RESULTS:** A reported two-snapshot IP Helper
PID+creation-time candidate plus a preannounced source TCP port in a controlled
canary is **not kernel-authenticated packet-to-process authority**. The
general arbitrary selected-EXE `PacketBound` capability and transparent
routing are NOT accepted. NDISRD mode 0 **restores DIRECT-capable networking,
not persistent fail-closed**. Native crash/SSH-death protection, DNS/UDP/QUIC/
IPv6 containment, actual Win10/11 x64 signed-driver acceptance, production
upgrade/uninstall, macOS NE and personal beta/1.0 remain blocked. VDSina stays
useful only for further carefully bounded native testing with verified VNC
and independently armed rollback; never delete/disable protections or publish
release without the owner. [Public issue #41 checkpoint](https://github.com/i-shutov/flowbridge/issues/41#issuecomment-6545902118).

### 2026-10-31 — Bounded native packet protocol inventory (source candidate, not leak containment)

A new `LISTEN_ONLY_PROTOCOL_PROFILE` request collects **aggregate** Ethernet/IPv4/IPv6/TCP/UDP counters and DNS/DoT/QUIC/mDNS/LLMNR *port hints* with the real NDISRD listener. It never copies packet payload, port values, IP addresses, process identities, or DNS questions into reports. It recognizes up to two VLAN tags, bounded IPv6 extension headers and IPv4/IPv6 fragments, refusing to infer transport identity for fragments or truncated frames. An exclusive consent and 15-second cap prevent changing to divert or owner sampling in the same request. Results always explicitly say `dns_leak_free=false`, `native_packet_owner_proved=false`, and `selected_application_containment_proved=false`. TCP/443 DoH cannot be distinguished from HTTPS without deeper authorized testing. Network traffic not present in the observation window cannot be ruled out.

This source addition is distinct from previously verified 12/12 IPv4 TCP native routing; it is **not native VPS proof** until the exact commit is built, a supervised LISTEN_ONLY profile is run on VDSina with independent rollback, and its artifact SHA and actual source/merge SHA are checked. No Win10/11 acceptance or protected-routing claim follows from this inventory.

### 2026-10-31 — Verified native IPv4 UDP/53 *port-hint* detection (not real DNS traffic or containment)

**Exactly verified source HEAD** `b5db12e0cc5aadb3a4fc2e62897e06f297dd8388`, **public GitHub Actions PR merge SHA** `0c288d7bc2d59d433b5634f3250c636747a6e359`. At this executable source, [capture CI run 41219951857](https://github.com/i-shutov/flowbridge/actions/runs/41219951857) **3/3 PASS** (Windows 2025, Ubuntu and macOS, strict Rust tests, Clippy, rustfmt, Windows SCM/control/installer tests). [Rust/native CI 41219951849](https://github.com/i-shutov/flowbridge/actions/runs/41219951849) and [DNS regression 41219951846](https://github.com/i-shutov/flowbridge/actions/runs/41219951846) both **PASS**; DNS regression is NOT a DNS leak-free claim. The signed Windows artifact #13049801271 was actually downloaded and independently hashed: outer SHA-256 `07d8fb15a69438662fba4b0ff391bd92905fa83a832945139c9634448020f128`, allowlisted four-file inner Rust candidate ZIP `04acc679b78b3fc1d3df014194237fabbd15e82d5551d1e721282b5799ed145b`, native x64 PE agent `f8fc762fa9d4d446f391ce13ca6328ae4e7d8e7519005860fa1e4fa019f7f7b8`. Checked inner manifest SHA-256 for each payload file, binary PE machine type and exact manifest `pr_head_sha`/`source_commit`. No vendor binary, ProxiFyre, WFP research, keys or credentials distributed; `protected_mode_available=false`, `release_accepted=false`.

**Independent VDSina Windows Server 2025 x64 native NDISRD read-only PASS #1:** [private workflow 41220444067](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41220444067), native QA source SHA `3966d2bcb36fff369f4940556b341168a116b270`, [private issue #1 report](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6546165681). 5,504 ms of signed-driver LISTEN_BOTH: 10 copied real frames (4 outgoing, 6 incoming), all IPv4 TCP; **0 UDP, 0 IPv6** in that window. No re-injection or routing. The report artifact #13049358997 was independently downloaded: outer SHA-256 `641a8d640671ead6ced956c983d56d6d6f607a3a6405283bcb6ab48510093693`, one JSON SHA-256 `995ea179e95ba0ff888b0f8ba8bda1db0bfacce40e924c22adb0840899fdb7cf`.

**Independent native UDP port-hint PASS #2:** [private workflow 41220798994](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41220798994), private QA branch SHA `6559721afc09d7f2a49721bf768b5ad9877ec01f`, [private issue #1 report](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6546212998). A separate Windows socket transmitted exactly **three four-byte zero-only UDP datagrams** with TTL=1 to a reserved **RFC5737 TEST-NET-1 documentation address**, destination port 53. This fixture contains **no valid DNS query, domain or personal data** and should not propagate beyond the first hop; its sole purpose is to produce observable real NDISRD packets on the live NIC. The original Rust read-only observer returned **23 real frames** (9 outgoing, 14 incoming), **23 IPv4, 17 TCP, 3 UDP and 3 other IP transport**, **3 UDP/53 hints**, **0 native IPv6**, no truncation, and **0 packet modifications/reinjections** in 5,501 ms. These are *native protocol/port classification* results, **not actual DNS transaction semantics, process ownership, encrypted DNS detection, leak-freedom, redirection or fail-closed**. The native JSON omits `release_accepted`; no approval is inferred from omission, and the checked public candidate explicitly marks it false.

Both native tests prearmed and subsequently disarmed an **independent Windows SYSTEM scheduled rescue** able to uninstall only the hash-pinned official signed NDISRD MSI after runner/network failure; both verified adapter mode restoration to **normal DIRECT-capable mode 0**, active Defender, network recovery and unchanged Windows Firewall policy. The private test did not install an untrusted driver. Second independently downloaded native artifact #13049887754 outer ZIP SHA-256 `6ef1d72249d46441b1e92cdd9e56596680086660046ca7099a44292b1949a0b8`, single sanitized JSON SHA-256 `da9d36d76fd3af7b6d93771c4a9a6404548779cc6e46c37c48213e7cb8957c49`; hashes, original Rust agent binary, reported counts, source and PR merge SHAs, rescue/Defender/rollback and negative acceptance fields independently checked.

**Strict current full OpenSSH workflow is NOT PASS:** [GitHub Actions run 41219951979](https://github.com/i-shutov/flowbridge/actions/runs/41219951979) on the same tested source/merge **FAILED** in the separate single-process raw-backend characterization. The actual managed real OpenSSH result independently confirmed **128 held / 1,152 refused / 10,000 successful churn, 0 churn failures**, and **4 independent process lifecycle PASS**, genuine Rust relay 4,097-byte SOCKS/SSH/half-close and closed-gate denial PASS. But the subsequent unthrottled single OpenSSH process capacity probe reached **244 accepted channels and then an existing stream reset** (`WinError 10054`; sshd log `Too many open files`); it did **NOT** verify a stable 512 nor even the raw probe's full lifecycle. The full workflow must remain RED until separately fixed without weakening checks. Downloaded failed workflow artifact #13049484314 outer SHA-256 `352a14b07be0d233dfeb5f12b621b89ca5b2a7f5f3768aee3b8fe2bec0e73009`, six JSON files independently inspected; no SSH passwords/keys kept. Raw backend characterization is distinct from 128-flow FlowBridge-managed acceptance; do not conflate them.

**Open product blockers:** arbitrary app selected without known socket/parent-client control, authoritative packet→PID+creation time binding, persistent protected fail-closed across service/driver crash and SSH death, real DNS/DoT/DoH/UDP/IPv6 containment with leak tests, signed Windows 10/11 native acceptance, GUI/installer upgrade+rollback and owner sign-off. The 2026-10-31 private VDSina tests are Windows **Server 2025** only, not Win10/11. VPS remains useful for next explicitly safeguarded native tests; no unsupported kernel/security changes, no public release, no main merge. [Issue #41 baseline](https://github.com/i-shutov/flowbridge/issues/41#issuecomment-6546184307), [native IPv4 UDP addendum](https://github.com/i-shutov/flowbridge/issues/41#issuecomment-6546223924).


### 2026-10-31 — Candidate: privacy-safe UDP/53 first-question wire-shape gate (native proof pending)

The observe_protocol_profile_lab counter path now separates UDP/53 **port-only** frames from bounded standard RFC 1035 first-question *wire-shaped* queries/responses, without saving QNAME labels, addresses, process IDs, packet contents or raw ports. The parser checks DNS header and first uncompressed question, forbids overlong labels/truncation, and deliberately leaves compressed first questions, nonstandard opcodes, encrypted DNS, split TCP and unobserved packets unclassified. This is a heuristic only: **not** successful DNS resolution, definitive DNS authentication, selected-application containment or leak freedom. Exact source CI, native candidate and downloaded artifact evidence must be appended after execution. Old zero-only UDP/53 canaries remain port-only, NOT DNS-shaped queries. The flowbridge-tunnel macOS test accepts multiple verified pre-child bind collisions inside its existing bounded three-retry helper; every unrelated failure remains fatal. No release, protected mode or main merge is authorized.


### 2026-10-31 — NATIVE VDSina DNS-shaped/non-DNS UDP/53 discriminant VERIFIED (read-only, NOT containment)

**Functional source HEAD 35bc288388c1e0aa4b7765ef5b4d1f9e22fc063f**, exact GitHub PR merge 72f41929bb213c17c1ea6f22ea1c4615d71d516e, capture [run 41222055274](https://github.com/i-shutov/flowbridge/actions/runs/41222055274) 3/3 PASS, DNS [run 41222055231](https://github.com/i-shutov/flowbridge/actions/runs/41222055231) 3/3 PASS. Windows candidate [artifact 13050796112](https://github.com/i-shutov/flowbridge/actions/runs/41222055274) independently downloaded: outer SHA-256 ec14b2d63b5c01667c4cfbc94887753315570f3c56d98e372b9d2779aad3649e; exactly four-file inner ZIP SHA-256 dc013c7658f9c825f84cc716be39c839bd3dda68a6e53b006e4fb7dec353246a; PE x64 Rust agent SHA-256 7b6c0b20b447422911866932051815a3d22e37691b92d62529291af415ff3985. Verified every payload manifest hash and exact source/merge; no vendor binary, AGPL code, keys or driver bundled. All release/protected/Win10+11 acceptance flags false.

**Actual signed NDISRD Windows Server 2025 native run [41222511041](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41222511041) PASS** on private QA workflow ef0408b4adf7ba4a5e9689ceac54d60d51d94ef4; [private sanitized issue #1 report](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6546463379). Independent artifact 13050248367 ZIP SHA-256 25146bdf9e4eb30aa82d48d007d2fe071f62c8598f50678e73f957287e45ed11; exactly one JSON SHA-256 6debe374cef8812fb4bc3045021cd130363f740dcb3674b32a4fdec0672565bf, independently parsed with all negative acceptance gates. In 5.5 sec **22 real NDISRD packets** (10 outgoing, 12 incoming); 6 real IPv4 UDP/53 port hints: **3 first-question standard DNS wire-shaped** synthetic RFC2606 reserved example.invalid canaries and **3 non-DNS four-zero-byte payloads**, TTL=1 to RFC5737 documentation endpoint. No genuine OS resolver, DNS reply, production domain, native IPv6 or captured arbitrary application. **0 original frames reinjected**; active Defender, network reachability, restored adapter mode zero, separately armed/disarmed local SYSTEM rescue confirmed. Mode zero is ordinary DIRECT-capable networking, not a kill switch. No payload, DNS name, PID, endpoint or adapter identity stored in JSON.

**CI blocker identified without weakening tests:** Rust/native [run 41222055272](https://github.com/i-shutov/flowbridge/actions/runs/41222055272) had all Windows/macOS jobs pass, but Ubuntu real OpenSSH job failed on second repetition **before SSH launch**: three sequential close-then-bind(0) test-only allocations reused a port and tripped existing four-port uniqueness assertion. This checkpoint groups the correction in the same #56: reserve all three ephemeral listener ports simultaneously before releasing them, preserving the assertion and all functional SSH checks. A new exact-head workflow MUST pass before declaring this fix verified. The separate raw Windows OpenSSH 512 characterization is still not accepted; 128/1152/10000/4 managed requirements are never substituted by raw backend attempts. No claim of native arbitrary selected-app PID binding, DNS leak-free, protected fail-closed or Win10/11 acceptance.

## Stopped-only Rust executable upgrade and rollback candidate (pending exact-HEAD CI)

The original Rust `flowbridge-agent service-binary-replace <old-config> <next-sibling-x64-exe> <next-config> <sha256>` command only changes an *exactly owned, stopped, manual* SCM service. It requires a valid loopback-only profile, canonical same-folder sibling image, bounded x64 PE32+ validation and a Windows CNG SHA-256 match while an exclusive-read handle is retained across the SCM transition. It checks the new SCM command and STOPPED state and attempts verified rollback to the prior command if the postcondition fails. It neither installs NDISRD nor changes capture policy, firewall, service auto-start or Windows protections. No binary is downloaded, copied or installed by this command; the caller must separately stage files with controlled filesystem ACLs. Windows ACL hardening, crash-atomic on-disk upgrade and arbitrary native app routing are **not** claimed.

The Windows hosted integration workflow builds two distinct original Rust agent executables (release and debug), stages the next image beside the running one and performs real Windows SCM + explicit SOCKS5: stage/start/stop -> hash-pinned binary and profile replacement -> start/handshake/stop -> reverse binary and profile replacement -> restart/handshake/stop/remove. Negative checks reject wrong hashes, invalid executables, an already running service and a mismatched service record. Its JSON result is `scm-binary-upgrade-lifecycle.json`; **do not accept this block until the exact PR source/merge SHA, all CI steps and downloaded artifact hash have been independently verified**. This tests two compiled variants, not two product releases, driver capture or installer ACL/atomicity.


### 2026-10-31 — in-progress pinned TCP ownership freshness hardening (not native acceptance)

On integration branch #56 the original Rust bounded native TCP reflection laboratory now requires fresh two-snapshot IP Helper process ownership candidate evidence for **every selected original outbound TCP segment**, not only the first SYN. The pinned OS process handle and creation epoch are checked before and after the table observations; a change/ambiguous/missing tuple rejects the segment instead of silently accepting a previous candidate. The single-flow lab report records aggregate check/denial counters only, keeps native owner/PacketBound/protected/DNS/release flags false, and fails a trial if candidate validation was denied. A real Windows loopback unit regression covers exact tuple, wrong source/destination, stale epoch, and wrong PID. This deliberately does not claim kernel packet ownership and may expose legitimate race conditions; no genuine signed NDISRD acceptance is claimed for this new source until its own exact-SHA CI and bounded native VPS trial are obtained.


### 2026-10-31 — Real signed NDISRD TCP owner snapshot closure race (native FAIL preserved)

A new exact-source self-hosted 12-phase native test for `9bf51bd79a911dfb75979de2b2e7e8e514f3aeb3` (PR merge `2dc1194f12eb23faa58d8e6a2b483ae6f8b6c185`) exposed a real timing race in the *first* self-owned TCP HTTP canary: 57 request bytes, 311 reply bytes, four native client frames and four relay frames successfully reflected through actual NDISRD→Rust→SOCKS/SSH, but the fifth selected TCP packet could no longer be corroborated in two fresh IP Helper snapshots, producing `fresh_tcp_owner_candidate_denials=1`, `selected_frames_dropped=1` and **0 selected original frames to the wire**. Native trial correctly returned FAIL under a new over-strict `owner_candidate_denials == 0` expectation. Safety rollback was independently verified: rescue armed/disarmed, adapter mode 0, network and Defender healthy, scoped firewall rule removed. [Private failure report](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6548140331) and [native run 41234631625](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41234631625). The lost owner evidence **must always DROP that packet**; a post-closure missing row is not grounds to declare a previously completed HTTP transaction invalid or to send DIRECT. New original Rust negative test covers owner loss after established SYN (ACK, FIN, RST all DROP). The bounded laboratory now reports both the exact denied-count and the `fresh_tcp_owner_candidate_denials_dropped` invariant, and accepts completed HTTP only if *every* denied witness was safely dropped, all transport/rollback protections are true, and selected packets sent to adapter are zero. This does NOT authorize arbitrary application capture, general PacketBound, protected fail-closed or Win10/11 acceptance; fresh-source CI and new native rerun remain required.


### 2026-10-31 — verified signed-driver 12/12 fresh TCP owner candidate witness (not PacketBound)

Source-of-truth Rust implementation **`934c418284fa8f20645bc9cdde3a57888c61132f`** (actual PR #56 CI synthetic merge SHA **`b6b296f50112df7b1733177edd709ad454570e1a`**), with independent Windows executable manifest/hashes, was compiled and exercised on self-hosted Windows Server 2025 with official signed NDISRD, real SOCKS and supervised authenticated OpenSSH. No third-party code/binary or driver was distributed in the candidate.

The initial new per-packet two-snapshot IP Helper owner-candidate requirement produced a **truthful native FAIL** (source `9bf51bd...`, [private issue report](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6548140331)): the HTTP request and response had already completed, but later FIN/ACK traffic lost its active TCP table entry. A dropped owner candidate is **always DROP**, with no packet DIRECT. The corrected bounded lab accepts the completed HTTP exchange only when every owner-candidate rejection maps to a dropped segment, selected original adapter sends equal zero, transport and rollback checks all pass. The new negative unit regression explicitly checks that subsequent ACK/FIN/RST after a valid SYN cannot escape with missing ownership. This is not a production packet-owner capability; IP Helper is still only an observational candidate and is not efficient enough as a per-packet general routing implementation.

**Independent exact-source build:**
- [Capture CI #41235001162](https://github.com/i-shutov/flowbridge/actions/runs/41235001162): **3/3 PASS** on Linux/macOS/hosted Windows 2025, including x64 SCM and actual Windows loopback tests.
- [DNS CI #41235001097](https://github.com/i-shutov/flowbridge/actions/runs/41235001097): **3/3 PASS** without claiming leak-free.
- [Rust/native CI #41235001064](https://github.com/i-shutov/flowbridge/actions/runs/41235001064): all hosted matrix jobs PASS; real Windows OpenSSH #41235001158 is a separate long-running gate and is not assumed PASS until concluded.
- Independently fetched Windows Actions ZIP SHA-256 **`d28ef23b92d1c9af0f0a1add07b5c17ef4ff8da2892b57b7f21c2d387c8f1dd7`**, nested allowlisted candidate ZIP **`e4c27988f96b44df4c19e157b3d6fe5ca397cdc5d1425acbb29a2d8c26a93bab`**, agent x64 EXE **`ccbb94d5b7464dd9bbd57eca6b4e42ea19fb23524f0686f30c31697323c67257`**, companion x64 CLI **`97742703d9733a2c8f1438c4de667e3f472bd2018232f4e0c2e795b4081ef6b2`**, original Rust test FFI **`2029d318a9c57c6b2d0726ae3d4ec8727f6277e6ab73c19dd462105a6b200140`**. The manifest matched exact source SHA and merge SHA, all internal SHA-256, x64 PE, 4-file candidate and 11-file distinct test-tool allowlist. No vendor binaries or credentials.

**Real guarded native verification:** [self-hosted signed-NDISRD Actions #41235346068](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41235346068), private QA SHA **`077c23e22dc878cd93ec304005e499d80b251a32`**; [sanitized private issue #1 evidence](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6548237214); independently fetched SHA-256 of native report ZIP **`d65fe1699970a39cfd75045adb41130803e3eadd64b61496518dcf6fb80b2e14`**. **12/12 PASS** across self-created Rust socket, spawned Rust, spawned Microsoft-signed OS PowerShell and independent Microsoft-signed PowerShell client; each positive, closed-gate denial, and restored-gate HTTP scenario. Total **57 fresh selected-segment IP Helper candidate checks**, **10 absent/changed candidates all dropped**, **zero selected original packets reinjected to adapter**. HTTP positives delivered 311–314 bytes, denial phases 0 bytes. Each phase `rollback_confirmed=true`, and overall `rescue_armed=true`, `rescue_disarmed=true`, `rollback_needed=false`, `mode_zero_rechecked=true`, `scoped_firewall_rule_removed=true`, `post_network_healthy=true`, `defender_active_after=true`. Source binary/QA tooling hashes match manifest and private pinned SHA exactly.

**Explicit exclusions:** These are controlled known-socket laboratory clients and *not* arbitrary application selection or kernel PacketBound. Returning driver mode to 0 is ordinary networking and **not** persistent fail-closed after a process crash. DNS leak-free, UDP/IPv6 containment, actual Windows 10/11 signed NDISRD acceptance, macOS NE and public release 1.0 all remain **NOT ACCEPTED**. Preserve raw OpenSSH 512 ceiling as separate failure; managed 128/1152/10000/4 is not evidence of 512. The paid VDSina VPS remains useful for remaining native experiments, but Windows Server 2025 never substitutes for Win10/11. No `main` merge or release.

## Explicit Rust SSH identification-order A/B diagnostic (NOT a protected route)
Run `flowbridge ssh-diagnose --endpoint 192.0.2.10:22 --timeout-ms 2000 --consent DIRECT_SSH_DIAGNOSTIC`. It creates two explicitly consented DIRECT TCP connections to an IP literal, server-first and client-first identification; it neither authenticates nor alters OpenSSH, driver modes or packet routing. Bounded banners and binary packet-header checks produce only stage/timing JSON, not endpoint, identification, credentials or payload. A header is NOT KEX completion, and a differential result is NOT proof a banner-gate workaround helps the user's SSH stall. Cross-platform CI executes compiled CLI against a separate live loopback server plus no-consent negative. Native protected routing, DNS safety and Win10/11 acceptance remain open.

## 2026-11-01: explicit managed Rust SSH Banner Gate — integrated vertical, evidence pending

FlowBridge's existing independently implemented SSH Supervisor can now optionally
launch its original Rust `flowbridge` CLI as an OpenSSH `ProxyCommand` using
`banner_gate_executable`, `banner_gate_consent=BANNER_FIRST_EXPERIMENTAL` and
`banner_gate_timeout_ms` (100..10000). No implicit enablement, no fallback to
DIRECT, no KEX rewriting, no password storage and no host-key relaxation.
The helper path is absolute, local, shell-inert, basename constrained, without
untrusted substitutions. Host must be a numeric IP. macOS remains denied until
additional helper capture-carrier NE exclusion is reviewed. This provides a
bounded compatibility experiment, not a fix proved on the owner's SSH host.

Independent real-SSH fixtures now exercise the **actual Rust FFI Supervisor**
with that config, authenticating against a real isolated OpenSSH sshd via the
original Rust helper and verifying SOCKS binary half-close, both on hosted
Windows and Linux. Prior standalone CLI and ordinary supervisor routes,
native NDISRD QA, protected status, DNS and raw-512 assertions are not modified.
The new exact-HEAD CI, merge-SHA and artifact evidence must be checked before
accepting this end-to-end block. Windows Server 2025 is not Win10/11 acceptance.


## 2026-11-01: SSH banner-gate local executable safety and independent managed/raw CI (pending exact-source rerun)

At PR #56 source `47c9f83b404c766109af04852cfe74cec197d029`, the first full post-integration CI reports **Rust/native FAILURE**: Linux `flowbridge-tunnel` rejected-path negative test correctly flagged a dangerous input that actual validation had accepted, `//server/share/flowbridge`. This is **not** a rustfmt flake, and the required test must not be weakened. The exact job was [Linux rust/native #41253086494](https://github.com/i-shutov/flowbridge/actions/runs/41253086494), where 25/26 tunnel tests passed and the UNC-like double-slash negative failed. The same source passed hosted Windows/macOS Rust jobs and capture/DNS workflows, but the matrix is NOT green.

The fix extends the original Rust supervisor's strictly opt-in experimental `ProxyCommand` executable validation: reject double-leading-slash roots (implementation-defined POSIX and Windows UNC), backslash UNC/device roots, Linux backslash escaping, and both slash/backslash dot components. Retain the exact inert-character, expected-basename, absolute-local-path and numeric-host constraints. A new IPv6 `[::1]:port` endpoint construction regression verifies no ambiguity. The independent original Rust banner bridge also rejects multicast/unspecified addresses and zero ports before dialing, with local socket-free negatives; existing real OpenSSH binary KEX/half-close, handshake, consent and no-DIRECT tests remain mandatory.

The same full-source run split Windows OpenSSH into real managed and raw jobs: managed `128 held / 1152 refused / 10000 verified / four SSH processes` **SUCCESS**; raw experimental `512` **FAILURE** at 244 held with Winsock 10054. It is an *unresolved raw capacity characterization*, not a reason to obscure or relax the managed acceptance. Keep the jobs, their JSON reports and job statuses independent; do not make raw failure green with `continue-on-error`. Neither result is native Win10/11 driver acceptance.

The code and these notes are a single integrated safety-and-CI correction on the existing PR, **not** a release or evidence that the user's affected external SSH host benefits from Banner Gate. CI, exact source/test merge SHA and actual candidate ZIP/agent SHA-256 must be verified after commit before marking this block accepted. Packet-to-PID, protected crash persistence, DNS/UDP/IPv6 containment, real Win10/11 native acceptance and macOS NE remain open. No changes to `main`.


## Rust-owned OpenSSH + SOCKS Windows control candidate (pending exact-HEAD CI)

The optional, explicitly consented `RUST_MANAGED_SSH_SOCKS_CANDIDATE`
configuration envelope joins our **original Rust** OpenSSH supervisor to our
existing original Rust TCP SOCKS engine and same-user foreground restricted
Windows named-pipe controller. Legacy explicit-SOCKS configuration remains
supported unchanged. **SCM stage/replace and service-run reject managed SSH**
until an independently proven privileged service-account identity, config ACL,
SSH credential and binary provenance model exists. This prevents an
owner-writable config from turning an elevated service into arbitrary process
execution; ordinary explicit-SOCKS SCM staging remains supported.
The supervisor owns OpenSSH process lifecycle; the local SOCKS route is pinned
to one literal 127.0.0.1 port, one SOCKS5 proxy, no DIRECT/default-chain/rule,
max 128 admission slots, explicit absolute client binary/key/known_hosts paths,
and strict public-key/host-key OpenSSH options. The engine starts with the
upstream gate **closed**, a bounded worker only opens it when managed OpenSSH
reports local SOCKS readiness, and stop/reload refuse to replace carrier
identity while running. Status does not emit SSH key paths, usernames,
hostnames or credentials. The gate closes if SSH degrades and never retries
DIRECT; this does **not** establish remote authenticated readiness before
first SOCKS CONNECT. The original SSH process is Windows job-object owned.

A real hosted Windows OpenSSH/loopback fixture validates failed SSH denial,
authenticated SSH+SOCKS binary half-close, restricted pipe status/stop and
invalid direct/mismatched-profile refusal. The fixture does not claim native
NDISRD packet ownership, system DNS containment, a crash-persistent
kernel kill-switch or personal Windows 10/11 acceptance. SCM launch under
a service account requires separately provisioned and secured per-account SSH
identity material. No credentials are included in CI artifacts.

**Acceptance is pending exact HEAD, test-merge SHA, all hosted CI and actual
downloaded artifact inspection. Do not claim a completed beta or release.**


## 2026-11-01: Native self-owned UDP TEST-NET quarantine — CODE CANDIDATE, NOT ACCEPTED

The PR #56 integration adds a clean-room original-Rust `udp-testnet-drop-lab` path, strict JSON/consent validation, live signed-NDISRD `PacketSession::poll_lab_redirect` invocation, and Ethernet/VLAN/IPv4 fragment offline regressions. This is an **explicit laboratory DROP trial**, not general selected-application routing. Consent is exactly `NATIVE_SELF_UDP_TESTNET_DROP_LAB` together with explicit `rescue_attested=true` (a caller assertion, **not** independent proof of the watchdog); duration 2–8 seconds; 2–4 fixed 25-byte DNS-shaped queries; only an internally created UDP socket on a caller-selected **non-loopback local IPv4** may send. The fixed remote address is documentation-only **TEST-NET-2 198.51.100.53:53**, not a resolver chosen by users. The test refuses wildcard/loopback/multicast source, unknown fields, missing consent, wrong mode and unbounded settings.

Prerequisites: user-confirmed independent VNC rescue/watchdog on remote hosts, official separately installed signed NDISRD running, exact single Ethernet adapter/MTU, controlled source bind. The Rust agent connects a UDP socket to select a route **without sending**; before mode change it checks the actual UDP IP Helper local-bind PID/creation-time candidate. This is NOT packet ownership proof. The real driver must confirm `TUNNEL_BOTH` before any canary datagram is sent. Every outbound IPv4 UDP datagram from the local IP to the fixed TEST-NET host is dropped rather than reinjected, including untrusted UDP port/checksum or continuation fragments with no source port, 0/1/2 on-wire VLAN tags; short-lived unrelated traffic is reinjected unchanged. The socket is closed before explicit adapter mode-0 restoration and queue flush. Driver error/cleanup is reported as failure and mode=0 remains ordinary DIRECT-capable networking, **not** persistent fail-closed.

**Historical acceptance gates (superseded by independent native evidence below):** verify exact source HEAD and CI test merge SHA; require real native Windows Server 2025 driver evidence showing at least 2 actual observed/dropped canary frames, `selected_original_frames_sent_to_adapter=0`, true cleanup, healthy post-network and Defender, no rescue triggered, and source/binary/action ZIP SHA-256 written to issue #41 and the private VPS QA issue #1. First run all nonprivileged Rust/Clippy/negative JSON CI; do NOT execute privileged native test remotely unless the independently functioning rescue remains verified. Synthetic Ethernet tests do not prove interception. Even successful native VPS results will not prove arbitrary app→PID ownership, Windows 10/11 native acceptance, IPv6/QUIC/DoH/DoT containment, DNS leak-free, or a security kill switch. No vendor binaries or keys enter artifacts.


## 2026-11-01: Native signed NDISRD self-owned UDP TEST-NET DROP — independently accepted lab (NOT Windows beta)

Exact public Rust implementation HEAD `f072d4b8f846fb3ed6f68e10fb86eaaa474e1c11`, GitHub Actions PR merge checkout `18e578d87be47e1b629e85865231cd19881ba72b`, base main `5b5afc2feeda2195f302380e615ba003d4906e09`. The dedicated *private* VDSina Windows Server 2025 QA workflow (commit `2ef84a783dca1d4dc7cfd2f844a75fe0cdc053ae`) ran [signed-driver native Actions #41276713022](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41276713022) with confirmed independent provider VNC, official separately installed signed NDISRD driver, active Defender/firewall and pre-armed independent SYSTEM MSI-uninstall watchdog. No Defender, Secure Boot or security-feature disabling.

The workflow retrieved the audited hosted Rust x64 candidate from [capture CI #41274836772](https://github.com/i-shutov/flowbridge/actions/runs/41274836772), and checked the exact ZIP, four allowlisted files, source/merge manifest, embedded payload SHA-256, original Rust agent and signed-driver SHA-256 **before any adapter mutation**:
- Candidate ZIP SHA-256: `bc79ec83ef72bcd93ab9480dfc21bc18eafc74728ab6c6501a023cd7da1f481f`.
- Agent x64 SHA-256: `caa7613555a9cd125487aad79dcf932cd2994463c73bb7f361b724e26ceaa1b6`.
- Signed NDISRD driver SHA-256: `8623a9c34531cf73de4286ad518b84af03a331c78959769a1ca38723e3258984`.

**Actual native DROP result:** the original Rust agent created an internally owned non-loopback UDP socket and sent **3 fixed reserved TEST-NET canaries after confirmed real driver diversion**; the native NDISRD queue/original Rust policy observed and **dropped all 3 selected outgoing frames**, sent **0 selected originals to the physical adapter**, observed **20 frames total**, and reinjected **17 unrelated frames unchanged**. It closed its canary socket before restoring adapter mode 0. Subsequent mode-zero re-entry, network HTTPS and Defender health passed; independent rescue was armed then disarmed; `passed=true`, no packet content, local IP, adapter name or process identity saved.

**Independent downloaded native report:** private [evidence issue #1 comment #6553884226](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6553884226), private Actions artifact **13071785449**. Its actual ZIP SHA-256 was independently computed as `053a7198fec8a4fd5260171ac7e754e6a4c2259b2919dcecf0bc71b15afb1022`, matching GitHub's artifact digest; the archive contains exactly one sanitized `result.json` with agreeing SHA/counters. At original code HEAD, capture **3/3**, DNS **3/3**, Rust/native **5/5** PASS. Windows OpenSSH **managed** passed strict 128 held / 1,152 refused / 10,000 byte-verified completions / four independent processes; separate raw 512 experimental check remains **FAIL** at 244 held (Winsock 10054), not waived.

**Accepted only:** bounded self-created IPv4 TEST-NET UDP drop with *real signed NDISRD* on *Windows Server 2025*. It is NOT proof of arbitrary selected-app packet→PID/creation-time identity, general DNS/UDP interception, leak-free DNS, IPv6/QUIC/DoH/DoT containment, persistent protected fail-closed after agent/SSH crash, Windows 10/11 acceptance or GUI/installer readiness. Driver mode 0 is ordinary DIRECT-capable networking, not a kill switch. No main merge, public beta/1.0 release or owner signoff is implied. Keep the paid VDSina VPS for remaining feasible native-driver work.


## 2026-11-01: bounded actual-driver IPv4 fragmentation trial — evidence PENDING

The separately consented IPv4 UDP fragment experiment extends the existing
self-owned TEST-NET-only original Rust quarantine. An optional JSON field
"fragmented_canary":true requires consent NATIVE_SELF_IPV4_FRAGMENT_TESTNET_DROP_LAB,
exactly two synthetic 2048-byte UDP datagrams, a 4–8 second window and an
independently verified signed NDISRD, single physical Ethernet adapter with
MTU <=1500, and independently armed SYSTEM rescue plus owner VNC. The only
remote endpoint remains the reserved, non-resolving 198.51.100.53:53.
All canaries are sent only AFTER TUNNEL_BOTH confirmation, with the owned
socket dropped before mode-zero rollback. The default 25-byte trial and its
old consent are unchanged. No production DNS, driver installer, traffic rule,
firewall setting, Defender setting or remote address is modified.

The driver reports actual fragmented outgoing UDP frames separately from
large unfragmented/offload frames. The fragment trial fails its acceptance
condition unless at least one actual IPv4 fragment is seen for each emitted
canary, zero selected original frames are reinjected, the signed-driver
transaction finishes and rollback is confirmed. NIC offload can postpone
fragmentation: in that case the correct verdict is NOT PROVEN, not PASS.
Other network frames are reinjected unchanged. Mode 0 is ordinary DIRECT.

Before acceptance: cross-platform strict CI and negative JSON/fragment tests,
exact PR HEAD and test merge SHA, Windows PE x64 candidate and SHA-256, then
an independently audited controlled signed-driver trial on Windows Server 2025
with real VNC/SYSTEM rescue, active Defender/firewall, no network regression,
and private issue #1 + public issue #41 evidence/real artifact ZIP hashes.
Code and synthetic fixtures do NOT prove native fragmentation; the native
experiment must be explicitly reported on its own. General packet-to-PID,
protected crash persistence, arbitrary-app DNS leak-free, Windows 10/11
acceptance, and release remain OPEN.


## 2026-11-01: REAL signed-NDISRD IPv4 UDP fragmentation DROP, independent native lab PASS (NOT beta)

This checkpoint **supersedes only the pending native-evidence status** of the
separately consented IPv4 fragmented-UDP candidate above, not its exclusions.
Actual Rust **implementation HEAD** `7e8c84fc9f94ea9afdb6637b114a5ba0170b0d12`;
actual GitHub Actions test **merge-SHA** `39d4ccaff3d2fb0e00499a8ad127178627e16656`
(main base `5b5afc2feeda2195f302380e615ba003d4906e09`).
Original Rust code introduces an opt-in **separate consent string**, exactly two
bounded 2048-byte self-owned UDP sends to the fixed reserved TEST-NET address
`198.51.100.53:53` after signed NDISRD TUNNEL_BOTH activation, and requires
actual observed IPv4 fragment frames and complete cleanup. Default 25-byte
UDP-drop lab is unchanged. These are controlled canaries, not arbitrary
selected-application traffic or a production DNS server.

Independently pinned **private** QA workflow SHA
`f813613478dd9d068858ba8011ca665a9a456065`; actual
[VDSina native Actions run #41284856306](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41284856306)
**SUCCESS** on Windows Server 2025 with the separately installed genuine
signed NDISRD driver (driver SHA-256
`8623a9c34531cf73de4286ad518b84af03a331c78959769a1ca38723e3258984`).
**Native counters:** 2 x 2048-byte canaries issued, **4 actual IPv4-fragmented
outbound frames selected and dropped**, 0 selected originals transmitted to
adapter, 37 driver frames observed, 33 unrelated frames reinjected unchanged.
These counters prove real driver-observed fragment DROP; they do **not** include
individual IPv4 identification values, so do not upgrade the aggregate to
per-datagram PacketBound proof. No real Windows 10/11 was tested.

The job checked Active Defender and Windows firewall, authenticated signed
driver and pinned candidate **before** any adapter mode change; user-confirmed
provider VNC and an independently armed SYSTEM MSI-uninstall rescue were used.
Afterward adapter mode 0 re-entry, external network and Defender health were
verified; rescue was disarmed without recovery, no packet payload or
host/process identities were logged. **Mode 0 enables ordinary DIRECT**
and is NOT a protected crash-persistent kill switch.

**Independent downloaded-byte QA**:
- Public Windows capture Actions run
  [#41284517082](https://github.com/i-shutov/flowbridge/actions/runs/41284517082)
  **3/3 SUCCESS**. Actions outer ZIP SHA-256:
  `8c55d90eaed1c70e6755a93c3fd01bed955204b53dac6a8c09ba03cff8db3d5a`;
  nested allowlisted original-Rust candidate ZIP SHA-256:
  `9bad7a22ab88cee4cd65cd20a62d42c5a23acd9e5dd10956a5d05f7e632430d1`;
  PE AMD64 original Rust `flowbridge-agent.exe` SHA-256:
  `a18b42d0af96411ad22707e9185957f4b89abb9842be9955cbfaabf74cab6d2a`.
  Its exact four files, manifest HEAD/test-merge, both PE AMD64 machine
  `0x8664`, inner SHA-256 and no-vendor/no-legacy/no-release flags were checked.
- Independent Linux and macOS outer capture ZIPs SHA-256:
  `1c1b089f4846068b819c9469106b1c5ce04c76388fe6edc1151bd7beb4e21b9b`
  and
  `118237d0ddfd122222dd4a26f52418f6a3b5fd937b5e6bf26885730be8d8424c`.
  Their nested four-file manifest/HEAD/test-merge and all payload hashes passed.
- Private native report Actions artifact **13074895840**, independently
  downloaded one-file JSON ZIP SHA-256
  `3d2fba01ec269541d2021f697d5dccb884661b118b66b8b0865dd6f27677e841`,
  matching GitHub artifact digest and
  [private issue #1 evidence #6554967126](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6554967126).
  Exact source/merge/binary/driver SHA, aggregate counts, rescue/rollback
  and explicit false acceptance flags independently checked.

**Unweakened hosted gates for implementation HEAD:** DNS **3/3 PASS**;
capture **3/3 PASS**; Rust/native matrix **5/5 PASS after Windows-only
unchanged-SHA rerun**. The original Windows Rust test attempt had a real
transient bind/port race (Winsock 10048) in the unrelated runtime lifecycle
test; retain that failure in history, do not suppress it. Windows **managed**
OpenSSH 128 held / 1152 refused / 10000 verified / four independent processes
**PASS**; **separate raw-512 characterization FAIL** at 244 held with
Winsock 10054, as a nonwaived experimental capacity limit. Public
[issue #41 checkpoint #6554982282](https://github.com/i-shutov/flowbridge/issues/41#issuecomment-6554982282)
contains the exact original source and downloaded artifact evidence.

**Open/forbidden claims:** NDISRD has no trustworthy embedded process owner;
IP Helper local bind snapshots are NOT PacketBound. Arbitrary-application
packet-to-PID/creation-time attribution, persistent protected fail-closed
across agent/SSH crash, leak-free DNS/UDP/IPv6 including QUIC/DoH/DoT,
native Windows 10/11 acceptance, macOS Network Extension, GUI/installer
acceptance and public 1.0 remain unproven. VDSina lacks a non-link-local IPv6
source/usable documentation route, so no native IPv6 DROP is claimed.
This checkpoint is native lab acceptance only; **no main merge or release**.

### 2026-11-01 — Rust SCM local file provenance guard (candidate pending exact-HEAD CI)

The original Rust Windows SCM staging, stopped-only profile replacement, service-run, current binary verification and x64 hash-pinned binary upgrade now reject UNC/device/extended-namespace paths, NTFS alternate streams, dot/parent traversal and reserved DOS names. The exact-local-drive validator also canonicalizes existing files to refuse reparse/junction destinations escaping into UNC/device namespaces. Windows hosted end-to-end tests verify malicious aliases do not create or mutate the service, then exercise genuine SOCKS negotiation, SCM and local-pipe STOP, configuration change, executable upgrade and rollback. This only proves local path provenance at verification time, NOT immutable ACLs, atomic disk upgrades, persistent NDISRD fail-closed, arbitrary packet/PID attribution, DNS containment, native Win10/11 acceptance or release readiness. No driver install or protected networking is performed.


### 2026-11-01 — installed Windows original-Rust Banner First / authenticated SOCKS vertical (CI evidence pending)

The Windows **unsigned, experimental, per-user** NSIS Rust-only candidate now
has a separate reproducible test path from **installed binaries on disk** all
the way through a genuine Windows OpenSSH handshake, strict pinned ephemeral
host key and public-key authentication, original-Rust Banner First transport,
SOCKS5 binary half-close, engine reload, unreachable SSH rejection without
DIRECT fallback, and termination of both Rust and OpenSSH listeners after
forced agent exit. The test must also complete an uninstall and verify user
files survive. It is deliberately NOT a privileged packet-capture installer.

The capture workflow builds the exact GitHub test-merge Rust agent+CLI, checks
the four-file SHA-256/PE32+ manifest before NSIS packaging and performs a
guarded, consented disposable Windows Server 2025 install. It independently
downloads a hash-pinned official OpenSSH-Win64 server archive and verifies
Microsoft Authenticode for sshd, Windows' ssh.exe and ssh-keygen.exe. Isolated
sshd binds loopback only and uses fresh short-lived test keys; the server
configuration, keys and stderr log are **not uploaded**. The installed
flowbridge-agent.exe controls the installed flowbridge.exe in a path with
spaces through the restricted Windows pipe; neither developer-tree executable
is substituted in the installed-path control scenario. Outputs contain
only SHA-256 and booleans, not credentials/process IDs/host keys.

The installer now rejects a pre-occupied unregistered installation directory
BEFORE copying any files; CI places an unrelated same-name flowbridge.exe
and a user profile in that directory, verifies both remain byte-for-byte
unchanged and no registry install marker/uninstaller is created. In-place
reinstallation is separately denied, and uninstall removes only allowlisted
Rust payloads while keeping any user-created profile. Native NDISRD, SCM
service, global firewall, Defender, DNS and Windows system SSH service are
never modified in this scenario.

**Gate requires fresh evidence**: actual PR HEAD and GitHub test-merge SHA,
Windows hosted capture job success including
windows-rust-installed-lifecycle.json,
installed-real-openssh.json and installed-managed-ssh-control.json,
installer/executable SHA-256, and independent artifact inspection before this
can be called an accepted Windows Server lab candidate. A green build alone
does not prove the installed authenticated path. Raw 512-channel backend is
a separately nonwaivable characterization; 128 managed held/1152 refused/
10000 verified/4 independent SSH processes remain a separate acceptance gate.

This is still **NOT** a Windows 10/11 beta or public release. It has no GUI,
no arbitrary application packet-to-PID/creation-time proof, no persistent
protected fail-closed after service/driver crash, no selected-app DNS/UDP/IPv6
leak-freedom, no tested affected external route for this exact Rust build,
and no Win10/11 native-driver acceptance. Do not merge main or publish 1.0.


#### Independently verified installed Windows SSH acceptance — source HEAD 96087b9 (NOT Win10/11)

The preceding installed-binary acceptance was **actually run and accepted for
Windows Server 2025 only** on PR #56 HEAD
96087b9de17fbf8139779469fae82ada95e47063, GitHub Actions test merge
9297de22e09b514fc3647ad1e3c20431ba19d43a, base main unchanged.
[Capture integration #41299054965](https://github.com/i-shutov/flowbridge/actions/runs/41299054965)
completed 3/3 PASS; verified Windows artifact
13079864214 outer ZIP SHA-256
3b57b11f871f4d7e0b090997ab0e8fd0019b24b22a5e981ebfe186e84c497f12,
equal to GitHub's artifact digest. Original-Rust nested candidate ZIP SHA-256
34536e1f7ebf1de46a5aa96666b7fef985edbc449fdb1b1a2e29ff1e8b557ee1.
Both original-Rust EXEs individually match manifest, are AMD64 0x8664 /
PE32+ 0x20b: agent
257381b00ea8066797777d03faf6637d4a4f7c0b1e4dc1a4e8f26f9f0a4f937b,
CLI f84c02d277ac515ef3fd24249f958bda85641c978e49b8e1bba98e7716f4c06a.
Four allowed inner files only; no legacy C++/WFP, vendor binary, GUI,
selected-app native packet identity, protected mode or release claim.

The actual unsigned NSIS setup SHA-256 is
68faa94765f366793e129c4799a3ebfac9ffa54622b6c8ddfd56ddf2939b698d,
verified from downloaded setup bytes. Actual JSON reports
windows-rust-installed-lifecycle, installed-real-openssh and
installed-managed-ssh-control each have passed:true. The *installed* agent
and *installed* CLI passed genuine signed OpenSSH strict host-key/public-key
authentication, binary SOCKS5/half-close, restricted Win32 pipe, atomic live
SOCKS reload, no DIRECT on unreachable SSH, refusal of carrier swap,
explicit stop, forced crash closing both owned listeners, no-consent and
injection/ADS rejection, occupied-directory no-overwrite, refused unsafe
reinstallation and uninstaller preserving a user-owned profile and removing
registry entries. Verified ephemeral keys removed; no system sshd service,
driver or firewall modified.

**Separate nonwaived regressions from this source HEAD:** full Rust/native
macOS unit matrix hit a genuine intermittent test-fixture Lease(ClockRewind)
in the synthetic PacketBound fixture after real async SOCKS handshake. The
integration correction uses consistent monotonic test timestamps after an
actual awaited handshake; production ledger ClockRewind denial is unchanged.
The experimental raw backend 512-channel Windows characterization also
failed again (actual peak below 512). Managed 128/1152/10000/4 acceptance
is an *independent* gate; avoid calling all workflows green before its
exact-head result is available. No public release or main update.

## 2026-11-02 — Canonical file-handle WFP AppId end-to-end experiment (CI pending)

This coordinated Rust/Python QA experiment keeps the strict **real TCP AppId
deny** acceptance gate. It does not accept AppId registration or a read-only
match as proof. The disposable Windows Server 2025 test copies two distinct
original Rust EXEs, verifies the actually running native process image path
against the same executable opened by a Windows file handle, and obtains both
DOS and NT-volume final paths through `GetFinalPathNameByHandleW`. The former
(with only the extended-path prefix removed) is supplied to
`FwpmGetAppIdFromFileName0` for the existing ephemeral dynamic guard. The
latter is compared privately to the actual `FwpmNetEventEnum0`
`CLASSIFY_DROP` AppId of the exact live temporary BFE filter. Both the
original caller-spelled file AppId and the handle-canonical AppId are compared.
This discriminates an AppId lookup path alias from the kernel's observed
image path, while preserving independent Python and sibling-EXE negatives.

QA reports contain only boolean equality results and aggregate counters:
no raw paths, volume strings, PIDs, stable identifiers, filter IDs, event
blobs, packet payloads or SSH secrets. The filter still disappears when the
guard process dies; mode 0 remains DIRECT-capable. The Windows native gate
remains **FAIL** until a selected EXE is really denied while the distinct
EXE and Python remain allowed, on localhost and any available same-host
non-127 IPv4 route, followed by successful recovery after guard termination.
All installed Rust GUI/SSH/SOCKS, SCM, NSIS rollback, and signed PowerShell
acceptance run ahead of this diagnostic gate. This is not general kernel
packet-to-PID proof, crash-persistent fail-closed, DNS privacy, Win10/11
acceptance or permission to publish a release. Source, CI merge SHA,
Windows JSON, artifact and PE SHA-256 must be recorded only after actual
CI and byte-level artifact inspection.


### 2026-11-02 — **VERIFIED** canonical file-handle AppId: real selected-app WFP denial (Windows Server 2025 QA ONLY)

The parent functional source `a45cab065da98f6bd220584c246b815076b05d7f`
was exercised by GitHub test-merge
`01faf2b6b573fb32f3049d7473c8c3e33f717379`, actual
[capture integration run #41359888484](https://github.com/i-shutov/flowbridge/actions/runs/41359888484):
**3/3 Windows Server 2025, macOS 15, Ubuntu 24.04 SUCCESS**. The strict
Windows real-process WFP dynamic QA AppId matrix reports `passed:true`
with NO test waivers. All app-only and app+port transient BFE guards,
both from the independent agent and from the copied selected Rust EXE,
**actually denied the selected EXE only**, while allowing both the
different-name byte-identical Rust EXE and the unrelated Python TCP
client; rollback after killing each dynamic guard really restored traffic.
The independent host-owned non-127 local IPv4 route was available and
independently passed the same strict application-specific matrix. This
is same-host local delivery, NOT external physical-interface capture.

Read-only EXACT active filter-ID event evidence: 3 `CLASSIFY_DROP` events
with nonempty UTF-16LE AppId; both selected and other copied Rust image
events matched their **file-handle-canonical** BFE AppIds (1 each) and
NT-volume handle paths (1 each), with the Python event matching the original
AppId (1). Original caller-spelled AppIds did not match either copied
Rust event. This is strong functional evidence that the prior failure
was caused by path representation/canonicalization when constructing the
BFE application condition. The independent
`QueryFullProcessImageNameW(PROCESS_NAME_NATIVE)` paths do **not** yet
compare equal to `GetFinalPathNameByHandleW` native paths; this additional
identity comparison remains a negative diagnostic, NOT a security gate.
The **actual live BFE enforcement**, rather than this secondary equality,
is the success criterion.

Independently DOWNLOADED and byte-audited [Windows artifact #13104917343](https://github.com/i-shutov/flowbridge/actions/runs/41359888484):
the outer 19-file GitHub ZIP SHA-256 is
`31b56299c6a1f964f16d2456b6f30d23b26e1c65a53655c6b406df56eae1fe0f`,
matching GitHub's reported digest. Five-file original Rust nested ZIP:
`f0e832ee810639068853eca1604f92757ed740bb016618d33cacf7ec4b10bf4b`,
sidecar + manifest consistent, PR source/test-merge pinned. Verified all
three PE32+ AMD64 machine `0x8664` / magic `0x20b`:
agent `4e62dde15f607ee109efd0160efdb6304808796ce9ba93f444d950a017ce6935`,
CLI `addd9ca6e959310abcc86925f27add015bf9bbdd681d8fd12182174ba145ebd5`,
panel `b7bb46831827e1ec26080c306a5094121296e48168e216999a79c8ba3c22d612`.
Actual unsigned NSIS installer
`9837b7105a767669eccca598377df470d035a87656ca3fc455f638d1e637eeb0`
matches recorded build manifest. Installed Rust panel → IPC → real strict
host-key Microsoft-signed OpenSSH → SOCKS, SCM lifecycle/upgrade, genuine
signed PowerShell, two NSIS fault injection recovery cases all PASS.
Rust/native [#41359888514](https://github.com/i-shutov/flowbridge/actions/runs/41359888514)
5/5 SUCCESS, DNS [#41359888495](https://github.com/i-shutov/flowbridge/actions/runs/41359888495)
3/3 SUCCESS.

Windows OpenSSH [#41359888626](https://github.com/i-shutov/flowbridge/actions/runs/41359888626):
experimental raw job SUCCESS only as a **characterization**, peak 246 held;
`raw_backend_512_stability_proved=false`. Managed 128/1152/10000/four-worker
gate must be checked independently on that exact SHA (PENDING at
documentation checkpoint). No inference of 512 stable channels.

**Critical security limits STILL OPEN**: the passing disposable *dynamic*
WFP ALE filter disappears when its process dies, so it is NOT persistent
protected fail-closed. No general arbitrary NDISRD packet→PID+epoch binding,
no verified NDISRD/WFP ordering under native traffic, no leak-free
DNS/UDP/IPv6/QUIC, no native Windows 10/11 acceptance, no release. WFP
dynamic QA never activated NDISRD or changed Defender/Windows security
settings. The paid VPS #3293462 was not modified. This documentation-only
follow-up commit does not change the verified executable code.


### 2026-11-02 — WFP selected-application UDP/IPv4 localhost experimental integration (AWAITING CI)

The original Rust dynamic BFE AppId guard now has a distinct **high-port
UDP/IPv4 only** laboratory consent, and a real Rust UDP canary. A Windows
Server 2025 acceptance gate creates two byte-identical, differently named
executables and an unrelated Python UDP client; it requires healthy unfiltered
controls, a BFE-read-back-verified **real selected-only UDP denial** without
delivery to the real UDP listener, simultaneous sibling/Python success,
then immediate restoration after forced guard death. All paths, process
identity, filter identifiers, addresses and packet contents are omitted from
the report. TCP and existing SCM/GUI/SSH tests remain mandatory.

This uses a *dynamic* ALE_AUTH_CONNECT_V4 AppId+UDP protocol+ephemeral port
filter. It is NOT a system DNS/53 policy, not leak-free DNS, not native NDISRD
UDP or packet-to-PID proof, and does NOT survive the guard process crash.
The test must stay red until live Windows kernel enforcement is observed.
No persistent WFP policy, system resolver, Defender, packet diversion,
external route or Win10/11 release flag changes. Exact-head CI and artifact
hashes are required before recording PASS.


### 2026-11-02 — Native Windows IPv6 dual-protocol WFP lab integration (CI PENDING)

New original Rust disposable `ALE_AUTH_CONNECT_V6` AppId+high-port guards and `::1` socket probes for **both TCP half-close and UDP echo**. Strict Windows CI must see selected EXE denied, identically copied different-name EXE and independent Python allowed, no selected packet/connection at real server, and full selected recovery after forced guard-process termination; no skips when IPv6 loopback unavailable. BFE filter readback validates exact V6 layer, AppId and protocol. No NDISRD, protected persistence, DNS resolver, general arbitrary packet PID ownership, real Win10/11 acceptance, or release claims. This checkpoint is **unverified until exact HEAD CI and artifacts finish**.


### 2026-11-02 — Original Rust crash-persistent WFP single-EXE high-port QA (CI EVIDENCE PENDING)

On disposable **GitHub-hosted Windows 2025 only**, a new exact-consent Rust
BFE experiment uses an independently prearmed elevated SYSTEM Scheduled Task
(three-minute rescue) before creating a persistent AppId+protocol+single high
port rule for one temporary copied Rust test EXE. It tests four real socket
paths (TCP/UDP × IPv4/IPv6): selected-only denial, byte-identical sibling
and independent Python allow, guard-process forced death, **continued
selected denial after guard exit**, explicit independent Rust cleanup and
full recovery. BFE readback must confirm the persistent rule/sub-layer.
The rules are never created if the host is self-hosted, the rescue is absent,
the selected EXE is outside RUNNER_TEMP, or the port is not high. On failed
cleanup the independently scheduled task must remain in place. No vendor
driver, keys, global firewall, SSH server or Defender setting is modified.

This is an experimentally persistent **one-EXE, one-port canary**, NOT
protected production fail-closed after SSH/service/NDISRD crash. It does
not bind arbitrary packets to PID, validate WFP/NDISRD order, prove DNS
leak-freedom or constitute native Win10/11 acceptance. Do not execute it
on paid VPS #3293462. This section is NOT a PASS until a full exact-SHA
Windows CI execution, native JSON report, test-merge SHA and independently
audited binary/artifact hashes confirm the strict functional matrix.


### 2026-11-02 — Exact SHA-pinned official portable NSIS dependency for both Windows installed-product acceptance tracks (CI PENDING)

At source `aeea41636c4ee6a3e8b99917bd103ef4ccd8d162`, the required Windows capture and legacy/native installer jobs FAILED before entering the new persistent WFP lab: the Chocolatey community NuGet V2 endpoint returned HTTP 503 twice. The capture gate remains **FAIL (not tested)**, and no persistent-WFP PASS, installed candidate verification, or accepted artifact can be inferred from earlier Rust-native/DNS successes. The independent OpenSSH load gate is separate; raw 512 has not been established.

The next integrated PR #56 candidate replaces the single-point Chocolatey dependency **in both** `.github/workflows/capture-integration.yml` and `.github/workflows/ci.yml` with a checked-in original PowerShell helper `scripts/ci-setup-nsis.ps1` restricted to `RUNNER_ENVIRONMENT=github-hosted` Windows. It retrieves the **official standalone NSIS v3.13 portable ZIP** from SourceForge, enforces the exact vendor-published SHA-256 `ba63dffc4410ee89193e1cb5a41989991bd77c61068da17e3156d136b7b0b3d8` and actual `makensis /VERSION=v3.13`, and emits compiler provenance into both Windows QA artifact trees. The build tool is **never packaged into the FlowBridge candidate**, never installed into the paid VPS and never enables driver mode or changes Windows security. Mismatched/unavailable ZIP, wrong compiler or unexpected host remains a **hard failure**, not a skipped installer test. Official downloadable ZIP metadata is at https://sourceforge.net/projects/nsis/files/NSIS%203/3.13/nsis-3.13.zip/download .

**Pending strict gates:** real installed-product/fault recovery; persistent one-EXE/high-port WFP rule after guard crash with independent SYSTEM rollback, TCP/UDP IPv4/IPv6; exact-head 3/3 capture, 5/5 Rust/native, 3/3 DNS, separately 128/1152/10000/4 real OpenSSH, test-merge SHA and independently downloaded artifact / PE SHA-256. None of these is equivalent to arbitrary NDISRD packet→PID attestation, protected native fail-closed, DNS leak-free, Windows 10/11 acceptance, or release. No `main` modification or signed/unsigned product publication authorized.


### 2026-11-02 — Exact code SHA VERIFIED: hosted original-Rust persistent AppId/high-port crash-survival, independent SYSTEM recovery

**Functional source** `5a2db4d66fde8a28e27fe394b67b7e18430a1edb`, GitHub PR test-merge `cc1569b688a1df01c858ce9bd046965d06b5e0b0`, base `5b5afc2feeda2195f302380e615ba003d4906e09` unchanged. The previous CI-PENDING sections above are historical and are superseded for **this exact code SHA** by [capture Actions #41379171590](https://github.com/i-shutov/flowbridge/actions/runs/41379171590) **3/3 PASS**, [Rust/native #41379171757](https://github.com/i-shutov/flowbridge/actions/runs/41379171757) **SUCCESS** and [DNS #41379171625](https://github.com/i-shutov/flowbridge/actions/runs/41379171625) **SUCCESS**. Separately [managed OpenSSH #41379171674](https://github.com/i-shutov/flowbridge/actions/runs/41379171674) remained *in progress* at this checkpoint; do not inherit historical 10k PASS. Raw 512 was separately negative (246 peak held).

**Actual Windows Server 2025 hosted WFP report:** Independently extracted `windows-wfp-persistent-hosted.json` has `passed=true` and **all 15/15 strict checks true for each** `tcp4`, `udp4`, `tcp6`, `udp6`: preselected/sibling/Python allowed; independently prearmed elevated SYSTEM rescue; persistent BFE filter+AppId high-port readback; selected copied Rust executable DENIED and absent from real loopback receiver; differently named byte-identical Rust executable and independent Python allowed; guarding process forcibly killed; filter still present, selected still denied and sibling still working; exact filter/sublayer removal; selected transport recovered; rescue disarmed only after cleanup. This is *crash survival of a narrowly scoped experimental persistent WFP filter*, **not** production protected mode or blanket network denial. Its active temporary rule is never created on VDSina self-hosted runner.

**Independently downloaded Windows artifact #13113090988:** outer 23-entry ZIP SHA-256 `b60b351a92e033c6829b329909bd899db37adb958d2810e6a8fb3a12ce6975f7` equals GitHub digest; inner exact five-file original-Rust candidate SHA-256 `cdb072b358aaf7522fa30eeae456fe28cf0224507e1b7bab47ebe22f490fc6e2` matches independent sidecar. Nested manifest binds source and test merge, all payload hashes independently checked. Three PE32+ AMD64 SHA-256: agent `a9ea52911693022ca3d64c6148a5a16be6a4a02aa11648602effe57743d2a3aa`, CLI `fac163b40b099707c091a2bd0b2c575d80edd629d0128500de1fe03d1dc7ab54`, panel `57ee097070bce2ac51db664c26b55b72974bf044f4cc10040395d3331d2d7edd`; unsigned NSIS setup `64f44db9c414cdb6c26e3955743f630c6861b4c65a0ad79d1835242e82b5ac99`. Actual installed GUI→IPC→authenticated OpenSSH/SOCKS, two fault-injected NSIS rollback scenarios, recovery and uninstall passed. The SHA-pinned official SourceForge NSIS 3.13 ZIP `ba63dffc4410ee89193e1cb5a41989991bd77c61068da17e3156d136b7b0b3d8` contains a root wrapper and the real `Bin/makensis.exe`; CI now strictly verifies the latter, its include/stubs resources and version, without relaxing installer QA. Neither NSIS compiler, vendor NDISRD, ProxiFyre, private keys nor legacy C++ WFP helper enter Rust candidate. Full checkpoint [issue #41](https://github.com/i-shutov/flowbridge/issues/41#issuecomment-6567876243).

**NON-CLAIMS / REQUIRED NEXT GATES:** tests are GitHub-hosted **Windows Server 2025** not personal Win10/11 x64, and operate on ONE QA EXE and ONE HIGH LOOPBACK PORT. They do NOT prove general native NDISRD packet→PID+creation-epoch ownership, WFP↔NDISRD order or active driver bypass, SSH-failure/service crash systemwide protected fail-closed, arbitrary app DNS/DoH/UDP/QUIC/IPv6 leak-freedom, or release 1.0. The signed NDISRD native VPS trials in private issue #1 were on earlier pinned source SHAs; the VPS was not touched in this block and remains useful for an independently rescued driver/WFP ordering trial. The docs-only checkpoint itself makes no new native execution claim.


### 2026-11-02 — Hosted-only AppId-wide crash-persistent IPv4/IPv6 DENY (STRICT CI PENDING)
Original Rust `windows_wfp_appwide_lab.rs` adds a separate exact-consent,
independently rescued, persistent BFE **AppId-only** (no port condition)
IPv4+IPv6 ALE_AUTH_CONNECT block for **one copied temporary QA EXE only**.
The independent hosted-only Python integration launches two distinct high-port
real listener sockets per TCP4/UDP4/TCP6/UDP6 transport; all selected client
connections must fail while byte-identical differently named sibling and
unrelated Python connections continue. The guard is killed, both BFE filters
must persist with selected denial still enforced, then exact cleanup must
remove two filters and sublayer and restore all eight selected connections.
An independently pre-armed 3-minute SYSTEM task remains active on cleanup failure.
VDSina/self-hosted runners are explicitly rejected. No NDISRD mode, SSH,
Defender, firewall global configuration or vendor binary is modified.

This is a valuable restricted crash-denial *mechanism demonstration*, not
a production protection policy, not system resolver/DoH leak-proofing,
not native NDISRD/WFP ordering and not arbitrary packet→process identity.
Do not claim PASS until exact-source CI, Windows report, test merge SHA and
independently downloaded archive and binary hashes are checked.


### 2026-11-02 — SIGNED VDSina NDISRD + original-Rust WFP coexistence and copied-packet owner sampling (exact \`d4ab8d7\`)

These are **two separate, real Windows Server 2025 native experiments on the exact audited public source HEAD \`d4ab8d7eb20ed1aee9161bcf6e5afd63207aff02\`**, test-merge \`d35dec9b85db1d83ea27c306860f596c24692e5e\`, agent PE SHA-256 \`0d712d1363320b410b6fcf4f71e0b7f8c1c0d604f3196bc79076fee64c272729\`. They are not new Windows 10/11 acceptance, nor proof of WFP/NDISRD packet ordering.

1. **Signed driver loaded + disposable selected-only WFP IPv4/TCP coexistence, actual local sockets — PASS.** Private restricted QA commit \`448dbfd773cbf1b82abee30033bed2d2a47d5e6c\`, [run #41392042494](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41392042494), [private evidence #1](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6569565712). Exact signed running NDISRD driver SHA-256 \`8623a9c34531cf73de4286ad518b84af03a331c78959769a1ca38723e3258984\`; Defender and firewall remained enabled. **13/13 actual strict assertions**: selected EXE denied by live BFE dynamic AppId filter; byte-identical differently named sibling and independent .NET socket client allowed; blocked packet absent at receiving loopback socket; forcibly killed WFP guard caused access to recover. No persistent WFP object, no driver mode change and no NDISRD packet interception. Independently downloaded **3-file** native artifact #13118017261, outer ZIP SHA-256 \`4dc56b6717cdee7bbaff042e780b8af6a00f763981064fc8d32213ab8c57d6c7\` matches GitHub digest; JSON reports \`passed=true\`, \`wfp_ndisrd_order_proven=false\`.
2. **Real signed NDISRD native RX in bounded LISTEN_BOTH copy-only + IP Helper candidate correlations — PASS for observation, explicitly NOT PacketBound.** Private QA fast-forward commit \`6d75416f82082a8977fae6cdcb9ab801f3f05baf\` in existing private QA integration branch, [run #41392989022](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41392989022), [private report #1](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6569663954). Pinned five-file hosted Rust candidate ZIP SHA-256 \`9a0d3a59b7df7d0d05873d396c3a3d5fba6e8e0181e6be10d70d7aeef069fee5\` plus all four manifest payload hashes verified on the native host BEFORE any driver mode change. Exact official signed kernel driver and Defender gate, active firewall, unique native adapter, signed-MSI hash gate, independent **SYSTEM rescue task armed before mode I/O**. A bounded **6.503 s** real NDISRD listen-only trial observed **26 Ethernet packets: 12 outgoing and 14 incoming**, and made **24** bounded IP Helper candidate queries (**18 consistent snapshots; 4 missing; 2 indeterminate**). **Zero reinjected packets**, zero persisted payload/identity/endpoints, process exit code 0. Native adapter mode rollback confirmed; independent rescue task disarmed only following verified network recovery and active Defender. Independently downloaded one-file artifact #13118595210, ZIP SHA-256 \`df82a634131217f1e29358d441395b518139d970cb9e60e3cdb1e3486ebad780\` (matches GitHub published digest), inner \`listen-only.json\` SHA-256 \`cf4b12b54c07019f67d03ab435cab1ac1946bebefb0852ffdab5f243197870bb\`.
3. **Release/security gates still OPEN:** IP Helper two-snapshot correlations are **NOT packet→PID+creation-epoch authorization**; LISTEN-only canary does not demonstrate production interception, selected-app TCP rewrite, protected fail-closed, DNS/DoH/UDP/QUIC/IPv6 leak containment, or WFP/NDISRD ordering under simultaneous packet diversion. Hosted/private Windows Server 2025 does not substitute for native Win10/11. The restricted live driver mode returned to 0, which again permits ordinary DIRECT traffic, not a protected-denial state. Raw OpenSSH 512 remains FAIL (last exact code peak ~244); managed 128/1152/10,000/four independent workers independently PASS on \`d4ab8d7\` only. No main merge, signed third-party redistribution, security-protection disabling or release authorization. VPS #3293462 was used for this bounded trial and remains useful for ordering research with independent rescue; it cannot be retired solely on this outcome.

*The parent code SHA and artifact checks above belong to the prior reviewed source; this documentation-only commit requires its own CI and does not silently inherit a new executable SHA.*

## 2026-11-02 — Experimental WFP↔NDISRD TEST-NET UDP observation harness (ORIGINAL CANDIDATE; VERIFIED TRIAL BELOW)

An original Rust copy-only NDISRD LISTEN_BOTH canary profile now accepts exactly two distinct ephemeral UDP ports and matches only outbound IPv4 frames addressed to fixed RFC 5737 TEST-NET `198.51.100.53`. It rejects fragmented or truncated transport headers and reports only aggregate first/second counts; independent Rust QA executable copies can emit exactly two bounded datagrams each. A VPS native orchestration must prove **positive baseline selected and sibling frames, WFP dynamic AppId-specific denial of selected while sibling frames remain visible, and restored selected frames after guard death**, under a previously armed independent SYSTEM rollback and signed-driver/Defender/firewall preflight. The ports are only controlled correlation hints: no packet→PID or WFP/NDISRD general ordering claim follows from read-only counts alone; absence without positive controls is INCONCLUSIVE. This change cannot activate divert, process-wide policy, DNS leak freedom or protected mode. All binaries/manifest/CI exact HEAD and real native trial evidence are pending; do not promote to Windows beta or release. Prior signed-driver native LISTEN-only evidence remains pinned to `d4ab8d7...`.

## 2026-11-02 — VERIFIED signed NDISRD LISTEN-only + real WFP dynamic AppId-deny TEST-NET ordering canary (NARROW native PASS)

**Reproducible exact provenance.** The original Rust experiment is source PR #56 HEAD `0039a528a20a211b1a720c7b482ad70b497ab364`, official GitHub PR test-merge `61fa455229601e8bd1e2d277c9dc015eb4d9f109` (parents main `5b5afc2f...` and that HEAD). [Hosted capture CI #41398902923](https://github.com/i-shutov/flowbridge/actions/runs/41398902923) 3/3 PASS, [Rust/native #41398903004](https://github.com/i-shutov/flowbridge/actions/runs/41398903004) 5/5 PASS, [DNS #41398902871](https://github.com/i-shutov/flowbridge/actions/runs/41398902871) 3/3 PASS. These CI runners are **Windows Server 2025 / macOS / Linux**, NOT personal Windows 10/11 evidence. Independent downloaded Windows capture artifact #13120398882 is exactly 24 files and SHA-256 `3ebb24951d547a0cfd749b17cd6b93d68e8fe8695821a5724715d6b317f355c5`, equal to GitHub digest; nested five-file Rust candidate SHA-256 `6a8924c3b2c1044c7f645c29e0b29ec71c985e38496750a9d0cc36609a6db25c`, original PE32+ x64 agent SHA-256 `3de9f24531a424ac237fbd853a1ea9bf3220e997a7d7deab54da9999e572314a`, CLI `3e6a2dcdb508c4bbf8236b6e5dc608a7293b2f2dbd078ad71f93ccf2b0798723`, panel `bb42b20af26ee0b176947130db091a8f53ffb8a0f319ad2f7aad666a7dcf859b`, unsigned NSIS `5dc7f40ab14fccfc29aaaffe3efc9c3c9f7898e483f770044b45e4bf3bcf7a1f`. Manifest, sidecar and payload hashes independently compared; no vendor driver, ProxiFyre, C++ WFP sidecar or secrets in candidate.

**Real independent native ordering experiment.** Private `i-shutov/flowbridge-vps-qa` workflow HEAD `e2eb165d1804df8ca21f6e2c7d9e0d656644bcee`, [real VDSina Windows Server 2025 run #41400224489](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41400224489), [private issue #1 evidence](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6570697616) **PASS**. The exact verified agent was run with separately installed Microsoft-signed official NDISRD driver SHA-256 `8623a9c34531cf73de4286ad518b84af03a331c78959769a1ca38723e3258984`, active Defender and all firewall profiles. Two byte-identical original Rust EXE copies with different filenames generated 2 UDP datagrams each to the fixed documentation-range IPv4 and two distinct high UDP destination ports while the actual signed NDISRD listened in copy-only `LISTEN_BOTH`. Counts were:

| Phase / actual NDISRD outbound observation | Selected QA EXE | Sibling QA EXE |
|---|---:|---:|
| WFP rule absent, positive baseline | 2 | 2 |
| Dynamic BFE AppId + UDP-port BLOCK for selected, verified BFE readback | **0** | **2** |
| Guard process forcibly killed (dynamic filter removed) | **2** | **2** |

Each of three bounded NDISRD sessions returned mode to ordinary network (explicit Rust IOCTL readback / rollback PASS); **zero original packets reinjected**. Independent locally scheduled SYSTEM MSI-uninstall rescue was armed before the first adapter mode change and disarmed only after all three successful rollbacks, confirmed signed driver, active Defender/firewall, native status and working network. No dynamic filter persisted. No IP, port, PID, binary path, payload or private identity entered evidence. Independently downloaded single-report private artifact #13120998070 outer SHA-256 `933debb651a445fa0887358459d5a3f2798026a362269e3a13e910607e08ad07` equals GitHub digest, inner `wfp-testnet-ordering.json` SHA-256 `694b4bbb0f67535ff2ed1eeeaadfadc0076f7fcb37780c9574ad394c5f5b6bc9`, JSON keys unique and strict values independently checked. Earlier private #41399993406 demonstrated same 2/2 → 0/2 → 2/2 but had a *report-field naming mismatch*; corrected evidence is pinned **only** to #41400224489.

**What was actually proved and NOT proved.** In this narrowly controlled outward TEST-NET IPv4 UDP experiment, a real selected-app WFP AppId/port block prevented the selected canary's frames from appearing in an NDISRD **copy-only** observation while sibling frames continued, and killing the dynamic guard restored selected frames. This is a strictly bounded empirical WFP-deny/NDISRD-observer interaction, **NOT** a general WFP/NDISRD ordering guarantee with driver DIVERT, arbitrary packet→PID+creation epoch, or selected-app SOCKS redirect. A tuple/port match is NOT identity authentication. The host was **Windows Server 2025**, not Win10/11. Returning driver adapter mode to 0 permits ordinary network/direct; it is NOT protected fail-closed. No DNS/UDP/QUIC/DoH/IPv6 leak-free acceptance, crash-persistent full product denial or release approval.

**Real OpenSSH on same exact source/test-merge:** independently downloaded [managed run #41398902890](https://github.com/i-shutov/flowbridge/actions/runs/41398902890) artifact #13120534787, SHA-256 `b7fbac9d53faac4703b78175da949405fad033c716318e26885c5de3c2663e6c` equals GitHub. Managed **128 held, 1152 rejected, 10000 verified successful/0 failed churn, 4 independent supervised OpenSSH processes PASS**. Separately, raw artifact #13120841872 SHA-256 `9683be67839c5f426899f2e4c857b46a4e3a8ef7ef469d3af21799e6b187324a` confirms **FAIL at 244 held**, `WinError 10054`; stable raw 512 is explicitly unproved. No weakening of the existing capacity/regression gates.

**Next native release gate:** independently attest process ownership/creation epoch, connect actual NDISRD redirect/TCP reverse traffic to selected Rust-owned process through local relay→SOCKS/SSH, provide persistent lifecycle fail-closed including driver/service/SSH crash/restart and DNS/UDP/IPv6 negative tests, then native Windows 10/11 x64 sign/installer/upgrade/uninstall acceptance. VPS #3293462 remains useful for these controlled signed-driver experiments; do not delete without owner's instruction. Public PR #56 only; main/release untouched.

## 2026-11-02 — Exact original Rust `892812bb` native NDISRD TCP→local relay→SOCKS/real OpenSSH: 12/12 PASS on retry, initial attempt FAIL (NOT a protected beta)

**Pinning and byte verification.** Existing integration PR #56 executable SHA `892812bb74d4225759a4d4a957c0d9d1df62e81f`, exact hosted PR test-merge `717053184d6215d8c6eed92ac38350954fe392bc`; the documentation HEAD before this note was `a9d2b38955476d802d67f4d2be6a684904a57a18` (documentation-only descendant, NOT a newly validated binary). [Hosted Windows capture #41415306058](https://github.com/i-shutov/flowbridge/actions/runs/41415306058) PASS. Its independently downloaded 24-file Windows artifact #13128360077 outer ZIP SHA-256 `9faa84a721bf7d58011e640734be52ab5e05b91e16540f893ade9428b2c41ac8`, nested five-file candidate SHA-256 `ac4c0b3c794a76a9cc015643c78023e8f9af99ae68fd7a533b5b696ead2e3f7d`, original Rust agent PE x64 SHA-256 `5493b62129263aa7eb97f544a221890557c3cb6eddc858cb517c8101edf71d0f`. Separate original Rust native QA tooling artifact #13127388236 outer SHA-256 `3e1549d7b129e0a3018693f611295077cbdd222381e9b1cd5bfe2242c9dcbb1f`; its Rust FFI DLL SHA-256 `734130182fe6e27fb3261e1e627862d26804f06c3aa5429b6f26e850b68cf9c9`. Both outer ZIP hashes equal GitHub published digests, all nested allowlisted file hashes match manifests, no vendor binary, private keys or C++ helper in product candidate.

**Real signed-driver integration.** Private native QA branch commit `542447401d1135f5fad6840abe26fb1823e7a042` changed the pre-existing guarded Windows Server 2025 workflow to pin those exact bytes, retaining Microsoft-signed, already installed official NDISRD SHA-256 `8623a9c34531cf73de4286ad518b84af03a331c78959769a1ca38723e3258984`, checked active Defender/firewall, fixed Microsoft-signed PowerShell/OpenSSH, independent *pre-armed* SYSTEM auto-uninstall watchdog and previously owner-confirmed provider VNC. [Real private workflow run #41432059957, attempt 2 PASS](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41432059957), [private issue #1 evidence](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6575372697). One supervised authenticated OpenSSH/SOCKS session served **12 of 12 genuine native NDISRD TUNNEL_BOTH TCP reflection trials**: independently owned Rust socket, spawned Rust child, Microsoft PowerShell child and separately launched Microsoft PowerShell process, each under connected → upstream-gate-closed → recovery phases. All four closed-gate phases denied transmission; all eight positive/recovery phases returned valid HTTP bytes over SSH. Across all 12 phases **zero selected original frames were sent DIRECT to the adapter**; all 12 used genuine NDISRD reads/writes and explicitly confirmed mode-zero adapter rollback. Independently launched OS client also exited before normal mode restoration. After the test: scoped firewall rule removed, SYSTEM watchdog disarmed, mode-zero verified again, network/Defender healthy. The **ordinary** network-enabled mode 0 is NOT protected fail-closed.

**Negative evidence is retained: not clean on first attempt.** The *same* private run #41432059957 attempt 1 **FAILED** its very first positive self-socket phase despite actual driver I/O and authenticated SOCKS/SSH: four client and three relay frames reflected, one failed fresh IP Helper TCP-owner candidate witness dropped conservatively, zero accepted HTTP bytes. It did not leak original selected frames and independently verified rollback/network/Defender/watchdog cleanup ([private failure report](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6575315336); failed artifact #13135265429 outer SHA-256 `03ab2ecd19d959ebb4780dd7543c6b00d54bac951fb1688cc0d7b11eaebbf702`). **Attempt 2 passed all 12 phases without weakening any assertions or changing public binaries**; several phases still recorded 1–3 conservatively dropped transient owner candidates. Native reliability is therefore **not yet established**: the owner-witness timing/race and negative/positive transaction completion require deterministic hardening and repeated evidence before beta. Never relabel a fresh IP Helper candidate as PacketBound.

**Independent pass artifact:** private #13135835010 outer SHA-256 `d1c9bf319df077417e756da7fef75ac6f264e3dfe5feca318713c599d78b3625` equals GitHub provider digest; its sole sanitized `native-self-redirect.json` SHA-256 `93da30b7eb82200a793f82bb8b337f3c145643a8d5d537e87590c08afbb99235` was independently parsed: 12/12 `passed`, 12/12 true `actual_ndisrd_tunnel`, 12/12 rollback, 4/4 expected closed gates, sum of `selected_original_frames_sent_to_adapter` = 0, four source types and common SSH supervisor confirmed. The JSON explicitly rejects arbitrary-app process authorization, generic PacketBound, crash-persistent protection, DNS leak freedom and Windows 10/11 acceptance.

**Current documentation HEAD CI caveat:** documentation-only `a9d2b38955476d802d67f4d2be6a684904a57a18` / PR test-merge `5fb52572284fda707bccde684ab3ca650b5c0cd4` had capture 3/3, Rust/native 5/5 and DNS 3/3 PASS, plus hosted Windows OpenSSH **managed** job 128 held / 1152 rejected / 10000 churned with zero failure / four independent child processes PASS. The separate **raw** OpenSSH characterization job FAILED at ~244 held on Windows OS resource/socket errors; do not claim all four workflows fully green or stable raw 512. This test is still not native Win10/11. Main and published releases unchanged.

**Still required for product beta:** reproducible native all-phase reliability, trustworthy arbitrary-app flow authority, WFP+NDISRD **simultaneous divert** and crash/SSH-failure fail-closed, DNS/UDP/QUIC/IPv6 containment, safe production service/IPC + GUI/installer lifecycle, then Windows 10/11 native evidence. VPS #3293462 remains needed for remaining controlled signed-driver lab work. Do not declare protected native PASS, leak-free DNS, stable raw 512, Win10/11 acceptance or release.


### 2026-11-02: strict IP Helper snapshot timing hardening (candidate, CI/native repeat pending)

The first VDSina native TCP/SSH canary attempt failed because a fresh IP Helper
owner candidate intermittently disappeared while the selected TCP packet was
held by NDISRD; the second identical-binary attempt succeeded 12/12. This is a
**reliability blocker**, not permission to promote IP Helper to PacketBound.

The new Windows-only lab witness path retains **two fresh TCP table snapshots
per attempted observation**, an OS-pinned process handle, process creation
epoch and unchanged exact local/remote tuple. Only a *missing* table row may be
sampled again, at most twice with 2 ms spacing. A conflicting PID, duplicate
tuple, stale TCP state, failed API read or changed/terminated process is
terminal. If the row remains missing, the packet is **dropped**, never
re-injected DIRECT. Additional snapshot attempts are counted separately in
sanitized native JSON. The original strict no-retry owner API remains intact.

Deterministic Windows unit contracts cover recovery from a transient missing
row, two-new-positive-snapshot requirement, immediate wrong-PID/duplicate/
stale-state/zero-PID rejection, bounded missing-row exhaustion and epoch
change. They do **not** prove native reliability by themselves. Next gate:
verify this exact new SHA in hosted CI, construct/download/hash its exact
candidate and perform repeated signed-NDISRD multi-process TCP/SSH trials on
VDSina with original negative first-attempt evidence retained. No broad
arbitrary app authorization, protected crash fail-closed, leak-free DNS,
Win10/11 acceptance or release is claimed.


## 2026-11-02 — Native repeated signed-NDISRD self-owned TCP/SSH candidate, exact SHA, independently audited

**Immutable source for ALL native trials below:** PR #56 head
\`877fe78b84e09421e8a2d131879b7d78fb2172cb\`,
GitHub Actions PR test-merge
\`caa0007f352cc6b06439226b576e53985b1c8dd8\`,
Windows hosted [capture integration #41435888350](https://github.com/i-shutov/flowbridge/actions/runs/41435888350).
This is Windows Server 2025 test evidence, **not Windows 10/11 acceptance**.
The exact signed installed NDISRD is reused, not bundled in the Rust candidate.

### Source / binary / integration evidence

Hosted capture: **3/3 OS jobs PASS** (Ubuntu, macOS, Windows).
Rust/native applications: **5/5 OS jobs PASS**
([#41435888347](https://github.com/i-shutov/flowbridge/actions/runs/41435888347)).
DNS vertical: **3/3 PASS**
([#41435888277](https://github.com/i-shutov/flowbridge/actions/runs/41435888277)).
Windows managed real OpenSSH: **128 held / 1152 rejected / 10000 successful churn / 4 separate processes PASS**.
The separate raw 512 characterization **FAILED**, peak 244 held,
\`WinError 10054\`, sshd \`Too many open files\`:
[#41435888262](https://github.com/i-shutov/flowbridge/actions/runs/41435888262).
NEVER convert a managed load or raw characterization into stable raw 512.

The Windows capture ZIP artifact **#13135869581** (26 top-level entries)
was downloaded independently; its complete outer SHA-256
\`614913145c2b3c1c2ec96e6390a7bb3f03b4122d01f96838a758f12e632ed1f3\`
matched the GitHub provider digest byte-for-byte. Inner five-file
\`FlowBridge-Rust-Candidate-Windows.zip\` SHA-256
\`5549f4f22a5a08b9c32e3fcffdd444d3bd3eea753b056b76a09cfc5006094676\`;
manifest SHA-256
\`38122ae6be1c842f8ad9931658d9a6f447708b21207d4744ec30491f648525a1\`;
original **x64 Rust agent** SHA-256
\`04901f36ee0e42aa3743c1ff81e2c144324003ae651722ee1e508981f4115c61\`.
The separate native test-tools artifact **#13135858863** outer SHA-256
\`eafe49fd5c7f00c7c884f2763aa71faf278292a7431fd5066feddfd87fef9198\`,
manifest pin agrees with source SHA/test-merge; original Rust FFI DLL
SHA-256 \`319b281fe1bfe43005a4ec86b66634035a0dcb4c6767b5041c0986b3170571bd\`.
Original unsigned NSIS **not released**, SHA-256
\`a7d8d871f366c0e8b3539e23204c37fe12104f5ef772bc29df34a38c0de9f5c4\`;
installed GUI/SSH/SOCKS and rollback were exercised in hosted Windows only.
Audit asserted 33 WFP true checks but **did not use the NDISRD driver** in
the hosted WFP job.

### Native four separate full 12-phase observations — 48/48 PASS, bounded canaries only

The private self-hosted VDSina workflow was repinned exclusively to the
above exact source+test-merge+build; owner had confirmed VNC and the
watchdog prerequisites. A first new-binary signed-NDISRD run
[#41436861388](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41436861388)
passed 12/12; [native private evidence #1](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6575994416),
artifact **#13136747055** provider/independently verified outer SHA-256
\`30fcdb9d217e401cffbe01ce3ca5a6f5e83d653d034e76e87bf79af7c9cf85e1\`,
single sanitized inner JSON SHA-256
\`369c4c6d7cd6c386c6281c9d10529102f3e6978a67ab980d9cad71f5839b40c5\`.

A new private QA harness commit
\`6c301eff6f82097a81ce9ecbb003e045e54ee277\` runs
**three sequential, independent** 12-phase trials
([workflow #41437279591](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41437279591)).
Each has an independently armed SYSTEM rescue, exact signed driver and
SHA-pinned original Rust binary, 5-minute rescue timer, individually
verified rollback to adapter mode zero, network/Defender/firewall health,
and a distinct immutable JSON artifact. No parallel driver diversion;
matrix \`max-parallel=1\`, \`fail-fast=false\`.

| Trial | Native phases | Gate-closed cases | Mode-zero rollback | Original DIRECT frames | Candidate denial drops | Extra missing-row retry attempts | Outer artifact SHA-256 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1, [private #1 report](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6576051530) | 12/12 | 4/4 | 12/12 | 0 | 13 | 0 | \`c9bb48219aa4b9ab96d4cd3f743f7f133a96130fe45176e82321c300f014932c\` |
| 2, [private #1 report](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6576074384) | 12/12 | 4/4 | 12/12 | 0 | 11 | 0 | \`b2067c33df40b60e1bfb8cb4ee08bc028291645b2b06691e9444e8508cc9b694\` |
| 3, [private #1 report](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6576099686) | 12/12 | 4/4 | 12/12 | 0 | 11 | 0 | \`6556c32f6e342af3539e4e8e6ac17f0509b9676b820d358d370883a6e67c5607\` |

Trial artifact IDs in order: **#13137116186**, **#13137181647**,
**#13137291508**. All three outer ZIPs were independently downloaded
and their SHA-256 matched the GitHub provider; each contained exactly one
\`native-self-redirect.json\`. Inner JSON SHA-256 respectively:
\`e41dc2d60bccda027a58ec22d56b922d4f8833491e7cfd31c4df699ac7467525\`,
\`63587d01d8636ae6b6978cd67abb904fbec0cffec0bc1eb8e663a3f3217fe8d3\`,
\`cd7503ea62773290874ef3b5138222124215de77d81e622efb9ae817b7d6575c\`.
Each independently parsed report attests driver I/O, authenticated
supervised OpenSSH, four controlled client types (parent, Rust child,
Microsoft PowerShell child, independently launched Microsoft PowerShell),
open→upstream-closed→recovered cycle per type, zero selected original
adapter sends, and the *explicit absence* of arbitrary packet/process
binding, crash-persistent protection, DNS leak freedom, Win10/11
acceptance and release.

**Honest interpretation:** The exact candidate has **four consecutive
12-phase native passes (48/48)** and **16/16 closed-gate denials**, with
48/48 adapter-mode rollback observations. The prior
\`892812bb...\` had a first-attempt **FAIL** and a subsequent unchanged
binary **12/12 PASS**: those two negative/positive original reports remain
preserved in private issue #1. The new bounded lab-only retry helper is
tested in deterministic Windows unit tests, but **all four new native
runs recorded zero additional missing-row retries**. Thus these runs do
NOT causally prove the timing fix prevented a missing-row race or
establish long-run flake-free operation; 46 per-packet owner-candidate
denial drops across the four new runs stayed fail-closed and did not
disrupt their completed HTTP transactions. IP Helper still does not
prove PacketBound for arbitrary apps. Adapter mode 0 is ordinary direct
networking, NOT persistent protected fail-closed.

**Release gate remains CLOSED:** no general native driver I/O→true
arbitrary PID/creation-time PacketBound, simultaneous production
WFP+NDISRD TCP diversion fail-closed across crash/SSH loss, leak-free
DNS/UDP/IPv6/QUIC, or Windows 10/11 native personal beta acceptance.
Never claim protected native PASS, no DNS leaks, stable raw 512, or v1.0.
Main/release unchanged. Paid VPS #3293462 remains useful for remaining
genuinely native signed-driver integration checks.


## 2026-11-02 — Pending native managed OpenSSH stop/restart integration extension

The existing signed-NDISRD self-created TCP / spawned-Rust / Microsoft
PowerShell child / separately launched Microsoft PowerShell fixture formerly
proved 12 NDISRD->Rust SOCKS->real supervised OpenSSH phases on source
\`877fe78b84e09421e8a2d131879b7d78fb2172cb\`, with four independent
sequential 12-phase passes (48/48) recorded above. The ORIGINAL previously
failed first attempt remains a separate negative evidence record.

The next single integrated QA block extends
\`tests/windows_ndisrd_self_redirect.py\` by **eight more native driver
phases** involving the **real supervised SSH process lifecycle**:
after the initial 12 phases, explicitly close the FlowBridge upstream SOCKS
gate, stop/reap the genuine managed \`ssh.exe\` child and verify its status
and absent PID. Exercise one strictly denied NDISRD TCP transaction in
each of the four controlled source categories; explicitly restart managed
SSH, require a different live supervised PID, reopen the gate, and
require one successful HTTP transaction per controlled source. Each
additional phase must independently prove signed-driver packet I/O,
selected original packets **never** reinjected to DIRECT, process/epoch
witness, bounded driver mode-zero rollback, and preserved negative
PacketBound/protected/release claims. The independent SYSTEM rescue,
Defender/firewall verification, VNC prerequisites and exact source/artifact
hash gates **must not** be relaxed.

**Status: new source CI / exact-artifact auditing / real native 20-phase
experiment NOT YET VERIFIED at this source checkpoint.** Neither the 8
additional phases nor production SSH-death safety may be reported as
native PASS until a new GitHub Actions binary and native signed-NDISRD
report have been inspected and SHA-matched. This specifically tests
an **explicit orderly SSH stop** and **manually closed gate**, not an
unexpected SSH crash, automatic fail-closed, arbitrary packet↔PID
attribution or persistent adapter safety on agent process death.
Adapter mode zero still restores ordinary DIRECT capability.
All Windows 10/11, DNS/UDP/IPv6, raw 512 and release gates stay open.


## 2026-11-02 — Independently audited 20-phase real SSH STOP/RESTART on signed NDISRD, 60/60 native PASS

**All native source identities belong to the already-verified code snapshot**
PR #56 **\`42de6090f58e5025e4cde7da046513d329cfb033\`**, GitHub
test-merge **\`fe7024ff4884a0cfd6eb70319b3221d80976f61e\`**,
**not** to a later documentation-only or installer-test-fix HEAD.
Hosted [Windows capture #41439631584](https://github.com/i-shutov/flowbridge/actions/runs/41439631584)
and [DNS #41439631532](https://github.com/i-shutov/flowbridge/actions/runs/41439631532)
PASS; neither hosted test alone activates NDISRD.
A separate Windows-application installer job on that SHA FAILED at
\`tests/windows_installer_native.py:259\`: **Uninstall registration remains**
immediately after the test observed executable deletion. The NSIS uninstall
script performs registration deletion **after** payload deletion; the test
waited only for the earlier file disappearance. This is a potential
asynchronous-uninstaller completion race, not a proven diagnosis of actual
registry cleanup. The next code change retains every strict final uninstall
assertion and requires the complete file/registry/shortcut terminal state
within the existing 90-second deadline. The fix is NOT considered passed
until a new exact-head Windows application CI run succeeds.
Raw OpenSSH 512 remains unproven; do not conflate managed 128/1152/10000/4
with raw 512.

### Independently downloaded and checked hosted source artifacts

- Hosted Windows capture artifact **#13137579164**, outer SHA-256
  \`460744b1591f4f60cd2d2c5fa731b028cdfb1542088bf77b7bc9414441ac50b6\`,
  exact **26** allowlisted files. Candidate five-file nested ZIP SHA-256
  \`420283c114fd0a0c86740fe08b4a0fc443d01811571b200550d7efc22facafb5\`,
  manifest SHA-256 \`e7c5dfa73c2823b646b15a48884779fe7bf0771dc440fee9f3cfffca67ed4615\`,
  original Rust x64 agent SHA-256
  \`38c920032577af6b03460d0afb70ae82fc453965a784462ee83cb08ea38fc7d1\`.
  Unsigned NSIS setup SHA-256
  \`87688d60babf6001582929ee8eb99a026bf0dbf666dfbff9c5212a1922c968d7\`;
  **not released**.
- Hosted Windows native tools artifact **#13138596201**, independently
  verified outer SHA-256
  \`fd97829378a2a4bd687e690bd0422e2264f9ed186130b6fa3f9dba50f7f2a1aa\`,
  exactly **11** allowlisted files; Rust x64 FFI SHA-256
  \`5c46738d9e992c478976520a5b2d932b15c7b8d2bbad6d26222021e1bfb9e2a3\`,
  new native Python harness SHA-256
  \`baf3ec9fae9020cbe80b5d43854c06f5cfa3e8dc4e46d2006e634a957a0dfb95\`.
  Manifest cross-checked the source HEAD, merge SHA and every payload.
  Independent Python compile verified the stop/restart harness; PE
  headers verified x64 agent, CLI, panel and FFI. No vendor driver,
  third-party binaries or credentials were bundled into the Rust candidate.
- Hosted exact-source WFP integrity audit verified **33/33** true security
  checks, including independently scoped sublayer veto and held-TCP soft
  lease revocation; this hosted audit did **not** run NDISRD.

### Paid VDSina Windows Server 2025 — three truly separate signed-driver trials

Private pinned QA workflow commit
\`6f242c18c51c7f72637cdaa6aae4f08d07e485c5\` ran
[private #41440585166](https://github.com/i-shutov/flowbridge-vps-qa/actions/runs/41440585166)
with three sequential jobs (no simultaneous driver diversion).
The jobs used the exact independently hashed public candidate and separately
installed **signed official NDISRD**, plus signed in-box Microsoft OpenSSH
and Microsoft PowerShell. Each job armed an independent local **SYSTEM
watchdog** before any diversion and confirmed its removal after
20/20 adapter-mode-zero rollbacks, continued Defender/firewall and network
health, and removal of its exact scoped firewall rule.

| Independent trial | Phases | Explicit SSH-stopped native denials | Distinct-PID real SSH restarted native successes | Confirmed adapter mode-zero rollbacks | Original selected DIRECT sends | Downloaded ZIP SHA-256 |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| [1](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6576537765) | 20/20 | 4/4 | 4/4 | 20/20 | 0 | \`0fbc6a920169f270f675e1603d16b245f3f987c765d89e8317e760f07eaa1def\` |
| [2](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6576562628) | 20/20 | 4/4 | 4/4 | 20/20 | 0 | \`f733f3d8e8a9c27afdb064eab89d3e8bd8c5b4a24c94cee6388d9c3217785da9\` |
| [3](https://github.com/i-shutov/flowbridge-vps-qa/issues/1#issuecomment-6576589213) | 20/20 | 4/4 | 4/4 | 20/20 | 0 | \`ca0911d711abe972d5cacd98c3162d5a6afb8fbe7be6bb8de76bd97985e0f1cd\` |

Each ZIP was independently downloaded. All three had exactly **one**
\`native-self-redirect.json\` with verified inner SHA-256 respectively:
\`8b571c3e7e671598e20f419214dfcb06aafa2b6c2dfa808efb638451b097deea\`,
\`a86675c7a6aeba194f7cbb5f650ccdc40921a550bdf61832b9a9a8068f986cb4\`,
\`7521ecb00ed2c0f981ee4efabacf893b0cfe7dd6d1dafe7c3786134ac04ccf99\`.
Each parsed JSON independently asserts native driver I/O, all 20 real
TCP+SOCKS+SSH phases PASS, 20/20 rollback, all selected-direct sends
zero, four controlled client/process categories, genuine SSH subprocess
STOP/reap, the absence of its PID, four explicit native denials, distinct
PID on SSH restart and four successful recovered binary/HTTP TCP
transactions. All four controlled client sources are tested; this is
**60/60 native phases**, including **12/12** additional stopped-SSH
denials and **12/12** additional restarted-SSH recoveries, and
**60/60** individual mode-zero rollbacks.

**Scope and blockers remain:** SSH stop was **operator controlled** with
SOCKS gate **manually closed BEFORE** stopping. This does **NOT**
demonstrate automatic fail-closed when SSH crashes, an agent crash, a
protected WFP+NDISRD production diversion, or arbitrary app packet↔PID.
The IP Helper snapshot is NOT PacketBound; returning adapter mode 0
restores ordinary DIRECT networking. Leak-free DNS, UDP/IPv6/QUIC,
Windows 10/11 native acceptance, stable raw 512 and release v1.0 remain
unproven. No main merge, no release, and no change to Secure Boot,
Memory Integrity or Defender. VPS #3293462 remains useful for subsequent
real native failure tests.

## 2026-11-02 — Pending: real unexpected SSH child death / AUTOMATIC foreground Rust gate closure

Following the verified 60/60 **deliberate**, manually gated native NDISRD
stop/restart phases, the Windows-hosted installed-original-Rust integration
now additionally kills **only** the OS-verified owned `ssh.exe` SOCKS listener
(PID and parent PID checked with Windows TCP table + CIM), **without**
pre-closing the Rust SOCKS gate or requesting graceful controller stop.
The same installed Rust controller must autonomously close the gate, reject
a live SOCKS CONNECT (not DIRECT), restart a **different** Microsoft OpenSSH
process, and restore a binary/half-close verified HTTP/SSH round-trip.
An 8-second restart delay is used **only in this disposable test fixture**
to make the gate transition observable. The acceptance is strict and is
added to the already-required installed signed OpenSSH/NSIS Windows workflow.

**Evidence status:** SOURCE CHANGE ONLY, not accepted pending exact-head
Windows GitHub Actions and verifiable artifact. This is **process-level
loopback/SSH** acceptance; it has **no NDISRD driver diversion** in that
hosted test, no unexpected NDISRD/agent crash containment, no persistent
kernel fail-closed, no arbitrary PacketBound, no DNS leak-free, no Win10/11
native acceptance or release authority. The earlier private 60/60 signed
NDISRD trials still prove only **manually** closed gate on the *older*
`42de6090...` source, never automatic gate closure on this new head.

## 2026-11-02 — Verified unplanned owned OpenSSH death, AUTOMATIC Rust SOCKS gate shutdown/recovery (hosted real Windows)

**New executable integration test:** exact source PR #56 head
`ef1e1666f414fac9b6b1bd213b68e4e1cf36467c`, GitHub PR
test-merge `677db06ed537dd62be7ae06fee97a7beebe82cbf`,
unchanged `main` parent `5b5afc2feeda2195f302380e615ba003d4906e09`.
Only the **source HEAD** is tested; this evidence checkpoint commit
is documentation-only and does not inherit a separate new-head CI PASS.

**Actual GitHub Actions on exact source SHA/merge:**
- [Windows/Linux/macOS capture #41442878311](https://github.com/i-shutov/flowbridge/actions/runs/41442878311): **SUCCESS 3/3**,
including strict Windows signed-OpenSSH/installed-Rust/GUI/NSIS,
the new *unexpected* owned-child process death case, all 33 WFP
byte/security safety checks. Hosted Windows Server 2025, **no NDISRD**.
- [Rust/native applications #41442878197](https://github.com/i-shutov/flowbridge/actions/runs/41442878197):
**SUCCESS 5/5**, including strict Windows install/upgrade/uninstall.
- [DNS regression #41442878087](https://github.com/i-shutov/flowbridge/actions/runs/41442878087):
**SUCCESS 3/3**, **not** native DNS leak-free evidence.
- [Real OpenSSH #41442878194](https://github.com/i-shutov/flowbridge/actions/runs/41442878194):
raw 512 **FAIL** (peak 244, Winsock 10054); managed 128/1152/10000/4
was still running at this checkpoint and must be verified separately.
The raw failure is NOT waived or relabeled a stable 512 PASS.

**Independent provider-byte integrity verification:**
GitHub Actions Windows capture artifact **#13139903929** had published
outer SHA-256
`6afa2e68c2c13a60a7b906600879b0be93450549f190717f91c9f7342e2acf0b`;
independently downloaded ZIP had **exactly 26 files** and this same hash.
The separately downloaded Windows native-test tools artifact
**#13139694789**, **exactly 11 files**, SHA-256
`522b7c210b97173a3b9a967391ad19a71bc0f2c171bde2b320c4fe9020ea1e2c`
also matches its GitHub digest. Original **five-file** (no vendor driver
or ProxiFyre) Rust candidate ZIP SHA-256
`3bc9a17fbd855bfda72aad7a760a683c2fca830acece39f8c87d9d3c5ba9b844`;
the exact installed x64 agent SHA-256
`fe1fd6ea74ee50dbf9f1cf103355cda5cada67a9a03f11629f550141b5ee9b8e`;
candidate manifest SHA-256
`e983b4825b47b2d7014609c65d781b2d7ede3ffed844db17fecef6d10a9e56a5`.
Unsigned Rust NSIS test candidate SHA-256
`a73ac06fc9fa37ffc2f293cf10e969fa66d6753431dfa562dbdccab80f1d0389`;
**not a release**.

**New true process-level fault test:**
`installed-managed-ssh-control.json` was independently extracted,
SHA-256
`2b91a4165c9b58b2bd38a5375d11f13f8fdb572249658a5bcd5b304fd2fd0f9c`,
with `passed=true`,
`unexpected_ssh_child_death_automatically_closed_gate=true`,
`unexpected_ssh_child_death_recovered_real_ssh_without_direct=true`,
`closed_gate_direct_attempts=0`.
The harness verified the exact listened-on `127.0.0.1` SOCKS port
belongs to **one** Microsoft `ssh.exe` child whose parent PID equals
the running Rust controller, then killed that *exact* child by Windows
taskkill **without manually closing the proxy gate**, observed Rust
supervisor/engine automatic closed-gate rejection, and verified a new
distinct SSH child and authenticated binary/half-close traffic through
the same installed Rust+GUI candidate. The fixture's 8-second restart
delay is disposable test-only; it does not alter product defaults.
The same report additionally verifies forced agent termination closes
its two owned user-mode listeners.

An **independent earlier Windows Server 2025 installer** artifact
[#13139133158](https://github.com/i-shutov/flowbridge/actions/runs/41441476242/artifacts/13139133158)
was downloaded with outer SHA-256
`7a540e4dfe697845b2471b8d41efaeeda5c8ef025e26c5ae0a69c4e8d0f76d8d`;
strict native install/upgrade/uninstall `passed=true` and
`silent_uninstall_convergence_ms=148`, with all prior registry,
file, shortcut and user-data preservation assertions retained.
This closes the **hosted installer harness race** only; no production
installer rollout is authorized.

**NON-PROMOTION:** This is true installed Windows OpenSSH process-death
recovery, but **NOT** signed-NDISRD native diversion or arbitrary
application PacketBound. The native 60/60 signed-driver phases above
were on earlier original code SHA `42de6090...` and **manually**
closed the SOCKS gate before deliberate SSH stop. Do not transfer the
automatic-close claim to those earlier VPS trials. Product's kernel
protected fail-closed on agent crash/SSH failure, adapter-mode-zero
safety, DNS/UDP/IPv6/QUIC/DoH leak freedom, Windows 10/11 native
acceptance, raw 512 and owner-authorized 1.0 release remain OPEN.
Keep paid VDSina VPS #3293462 for bounded native verification.


## 2026-11-02 — experimental new native unplanned SSH crash and DNS CI reliability (NOT YET PASS)

This new source change extends the existing 20-phase signed-NDISRD canary with three actual-driver independent Microsoft-signed PowerShell TCP phases routed through the original Rust control-plane agent, its managed SSH process and automatic SOCKS gate. It kills only the exact SSH PID tied to the Rust agent and listener, without manually closing its gate; then requires no selected original DIRECT packets, a failed native SOCKS attempt while closed, a different restarted SSH PID and a real native recovered response. Every phase retains independent prearmed SYSTEM rescue, driver mode rollback, strict process-witness checks and explicit false flags for generalized PacketBound and persistent protected fail-closed. It is a PENDING native experiment, NOT a native PASS or Windows 10/11 acceptance. The prior 60/60 manually gated native trials remain separate evidence on their older source SHA.

On exact previous HEAD 1dabe6e7b19896f2ac3b37764f8d63bbb9d1429f the Windows hosted DNS regression failed at remote DNS deadline expired with local fallback disabled (Actions run 41443942675); macOS and Linux passed. The local fixture deadline changes from 300 ms to 3000 ms, readiness lease from 10 s to 30 s, with all malformed/closed-gate/no-fallback assertions preserved. This is not DNS leak-free and needs new-head CI. Raw OpenSSH 512 still fails separately; managed 128 held / 1152 denied / 10000 verified / four processes passed on the previous head. Main unchanged, PR draft, no driver or credential redistribution, no release.
