# FlowBridge Windows 0.3.0-beta.2 — A6 independent release-review packet (NOT GO)

## ПРАВЯЩЕЕ РЕШЕНИЕ ВЛАДЕЛЬЦА — 17.11.2026: ТОЛЬКО ВНУТРЕННЕЕ ИСПОЛЬЗОВАНИЕ

Владелец прямо выбрал «пока только внутреннее». **Это не выбор MIT/Apache-2.0/проприетарной лицензии, не публичная публикация и не GO на развёртывание**. Допустима внутренняя разработка и ранее разрешённые тесты точного `0.3.0-beta.2` на Win10 Pro x64. Сохранены все original candidate SHA и доказательства A0–A3 PASS.

**Публичная дистрибуция, внешние установщики, маркетинговые релизы, GitHub Releases и release tags запрещены/не запрошены.** Собственная публичная лицензия FlowBridge не выбирается сейчас, это [будущий backlog #78](https://github.com/i-shutov/flowbridge/issues/78). Сторонние лицензии, фактические native SDK/runtime условия использования и security/privacy остаются важными даже внутри организации.

**Текущий путь:** `A5_INTERNAL_DEPENDENCY_RUNTIME_REVIEW_OPEN` → `A6_INTERNAL_SECURITY_PRIVACY_P0_GO_OPEN` → `A7_INTERNAL_DEPLOYMENT_GO_NOT_GRANTED`, см. [активную задачу #81](https://github.com/i-shutov/flowbridge/issues/81). A0–A3 Win10 приняты на оригинальных доказательствах, технический A5 и A6 CI PASS. Никакой live VM/driver/пакетной установки в этом изменении не выполнялось. Windows `1.0` WFP/G2 NO-GO. Windows 11/macOS отложены на следующие платформенные релизы.

[Машинная политика и точный checkpoint](https://github.com/i-shutov/flowbridge/blob/docs/release-win10-vm910136-20261110/docs/qa/release-1.0/checkpoints/INTERNAL_ONLY_DISTRIBUTION_DECISION_20261117.md). **Все прежние формулировки этого документа о необходимости сейчас выбрать публичную лицензию — исторические, заменены данным решением.**



## Актуальный A6 technical checkpoint — exact-head 4/4 CI от 17.11.2026

[**Draft PR #80**](https://github.com/i-shutov/flowbridge/pull/80) на `qa/a6-win10-beta2-release-20261117` exact HEAD `6cbebe418eeb88539dff86054332ee46f6801127`; [GitHub Actions #44041579615](https://github.com/i-shutov/flowbridge/actions/runs/44041579615) **COMPLETED SUCCESS 4/4**:

1. Windows and Linux adversarial tests for original ZIP names/paths, manifest tampering, SSH/cleanup result falsification and illegal release flag promotion.
2. Independent GitHub Actions job fetching **original unchanged** beta.2 verified candidate `0.3.0-beta.2` source `86583a1a...` and checking original ZIP/SHA/manifest/own-code unselected LICENSE; [original sanitized artifact #14308749465](https://github.com/i-shutov/flowbridge/actions/runs/44041579615/artifacts/14308749465) ZIP SHA256 `f06b4376098bb92a2a8ff65f7349c85ad73cb6b92bed2c1f82de30e789de3d9a`.
3. **New independent original Windows binary PE import audit**, original [artifact #14309039018](https://github.com/i-shutov/flowbridge/actions/runs/44041579615/artifacts/14309039018) ZIP SHA256 `817d939f4e0b1041f179ec3ee7064441a8ce5508e901a11f061a627ecf7acd23`. Original installer `0699bed4...`, GUI `0cf1749e...`, FFI `23b62d54...` exactly match frozen user/CI; parsed direct imports:
   - GUI `advapi32, comctl32, comdlg32, flowbridge_ffi, gdi32, kernel32, ntdll, ole32, shell32, user32` (all DLL names).
   - FFI `advapi32, api-ms-win-core-synch-l1-2-0, bcryptprimitives, iphlpapi, kernel32, ntdll, ws2_32`.
   - Installer `advapi32, comctl32, gdi32, kernel32, ole32, shell32, user32`.
   - `VCRUNTIME140.dll`/`MSVCP140.dll` **не обнаружены как прямые импорты** этих трёх файлов. **Рекурсивное дерево зависимостей, фактическая статическая линковка, лицензирование MSVC/SDK, независимая Win32/C++ security/privacy проверка не приняты**.
4. Сравнение оригинальных приватных V4 100/100 и V5 26/26 предоставленных владельцем Win10 ZIP с позитивными/негативными SSH/GUI, исходными source/exe/dll/installer SHA и восстановлением профиля проведено **отдельным локальным офлайн аудитом**; GitHub CI не получает и не публикует эти приватные исходники. Итог `A6_TECHNICAL_EVIDENCE_PASS_RELEASE_GO_BLOCKED` — **не** формальное A6 GO.

Указанные ниже прежние `3/3` — исторический промежуточный CI-срез (до добавления PE-аудита). **Новый актуальный технический CI — 4/4**. В едином машинном реестре A0/A1/A2/A3 PASS для Win10, **A5/A6/A7 false**, `windows_beta2_release_accepted=false`, `publisher_release_approved=false`. Win11/macOS отложены; Windows 1.0 WFP/G2 NO-GO. Лицензионное решение [#78](https://github.com/i-shutov/flowbridge/issues/78) остаётся внешним обязательным условием.



## 17 November — independently executed A6 original-byte gate

- [Independent read-only A6 QA PR #80](https://github.com/i-shutov/flowbridge/pull/80), final exact review HEAD `ff3cae712ad9ea65f2f4efcd95a3e3ff6bab7a90`: [Actions #44040978619](https://github.com/i-shutov/flowbridge/actions/runs/44040978619) **3/3 SUCCESS** (Windows and Linux adversarial ZIP/provenance/no-release tests; third job re-downloads and validates **original unchanged** candidate kit and source ZIP from run #43883696169). Original A6 CI verdict `ORIGINAL_CANDIDATE_PASS_PRIVATE_A3_REVIEW_NOT_RUN` is intentional: GitHub CI does **not** possess or upload the user's original private V4+V5 evidence.
- **Separate offline owner-original A6 review**, run with originally provided V4 and V5 in the private review environment, gave `A6_TECHNICAL_EVIDENCE_PASS_RELEASE_GO_BLOCKED`: V4 100/100 file hashes, V5 26/26, original source/payload SHA, GUI/SSH/Stop/restore positive/negative data consistent. This is a verification of original submitted records, **not** a cryptographically attested host or independently repeated physical test. Private self-contained handoff ZIP SHA256 `2864c7d9c0905126219bbd45a56021d5dc07e5f4029ee09369f91d39a6918112` retained for owner, **not** uploaded to public GitHub.
- The A6 checker now rejects **raw Windows ZIP names before Python filename normalization**, protecting against slash/backslash path coercion; the Windows-specific negative-control initially caught this and passed after repair. No FlowBridge binary, package, or original candidate SHA changed.
- Source-level privacy spot check: `fb_diagnostic_report_json` in `crates/flowbridge-ffi/src/diagnostics.rs` uses allowlisted numeric/enum records, without raw SSH errors/paths; unredacted GUI screenshots/logs can still contain local paths and are **not release deliverables**. This is **not** a comprehensive Win32/C++ code audit.
- [A5 owner license and native-runtime choice packet](https://github.com/i-shutov/flowbridge/blob/qa/a6-win10-beta2-release-20261117/docs/qa/release-1.0/checkpoints/A5_LICENSE_NATIVE_RUNTIME_DECISION_PACKET_20261117.md) was prepared with exact original 71/37 BOM metadata, NSIS/Unicode notices and Microsoft runtime terms. Project own-code `LICENSE` is still unselected. The owner must explicitly decide MIT, Apache-2.0, proprietary terms, or internal-only before external publication.

**Strict conclusion:** `A0–A3 Win10 PASS` and `A6 technical original-byte evidence PASS`; `A5_LEGAL_AND_NATIVE_RUNTIME=OPEN`, `A6_FORMAL_SECURITY_PRIVACY_RELEASE_GO=OPEN`, `A7_PUBLISHER_GO=NOT_GRANTED`. This is **NO PUBLIC RELEASE**. Windows 11/macOS remain deferred, and protected `1.0` WFP/G2 stays NO-GO.


**Scope amendment 17 November 2026:** owner explicitly selected **Windows 10 Pro 22H2 x64 only** for the current beta.2 and Windows 1.0 release plan. Windows 11 native QA, support announcement and publication are **DEFERRED to later releases; not PASS and NOT a current blocker**. [Decision and scope contract](WIN10_ONLY_SCOPE_DECISION_20261117.md). This is a technical pre-review, not a distribution authorization, release note publication, or merge/tag. Product remains an **unsigned Windows engineering prerelease, explicit SOCKS-only**. `release_accepted=false`, `publisher_release_approved=false`.

## 1. Exact immutable candidate identity and verified source chain

| Item | SHA/URL |
|---|---|
| Product code source | `86583a1a0487b9d383c0122b24558e620bde5b9c` |
| Source tree | `9f92e9e9e87725d127505c8ac415f37e42a8d148` |
| Candidate GitHub CI | [#43883696169, attempt 2, 11/11 SUCCESS](https://github.com/i-shutov/flowbridge/actions/runs/43883696169) |
| Original immutable verified artifact | [#14238314845](https://github.com/i-shutov/flowbridge/actions/runs/43883696169/artifacts/14238314845) |
| Inner candidate kit ZIP SHA256 | `9980c786ceea82d2609b0229eca87b7f3ba044dc742466fedfa5e3b08e7585ae` |
| Windows installer SHA256 | `0699bed4acaa1b9df9b63c658808b08fd65b5953cacdaaddb7a13953389e19f4` |
| Windows GUI EXE SHA256 | `0cf1749e7531659b1f5a42433818ecf31fe517d6815d11faeca6e04f9821325e` |
| Windows FFI DLL SHA256 | `23b62d54a89feea53331f3ac68fe7c3d348ca99ed72d816f3dcfbc94ef3fd2b4` |

**Do not accept a rebuild bearing the same version but different bytes.** If source/payload changes, freeze a NEW candidate and restart exact-byte receipt verification, including A3 native tests.

## 2. A0–A7 release gating review

| Gate | Status, factual basis | Required before GO |
| --- | --- | --- |
| A0 explicit-only | **PASS**: no WFP/NDISRD driver/extension, no transparent application capture, no system DNS or kill-switch claim | Maintain in UI/docs |
| A1 frozen candidate | **PASS**: one original source, 11/11 CI, independently reviewed Windows manifest 13/13 and candidate ZIP | Pin these hashes in every release output |
| A2 managed SSH | **PASS within bounded 128-flow product scope**: known-host, SSH-owned 1–4 workers, 10k churn, negative no-implicit-DIRECT, all-down; no guarantee for independent raw OpenSSH 512 | Do not assert 512 capacity or universal host limitations |
| A3 Win10 | **REVIEWED OWNER-ORIGINAL V4+V5 EVIDENCE ACCEPTED:** V4 100/100, GUI 17 PNG, 6/6 native install/upgrade/uninstall, real SOCKS5h/Stop/all-down; V5 26/26, 6 PNG, 23 UI actions, final beta.2 missing-key denial, healthy 10-byte control, stop and escrow restoration. [V5 checkpoint](BETA2_WIN10_A3_V5_INDEPENDENT_REVIEW_20261117.md). Owner host identity is asserted, not cryptographically attested; reviewer did not physically rerun tests | No further Win10 testing needed unless exact candidate changes |
| A3 Win11 | **DEFERRED_NOT_REQUIRED_FOR_CURRENT_WIN10_RELEASE**; no native Win11 test executed or accepted | Future platform release backlog [#79](https://github.com/i-shutov/flowbridge/issues/79); **do not test or advertise Win11 in this release** |
| A4 macOS | Native acceptance **DEFERRED** under Windows-first owner decision; hosted universal package passed but does not grant Mac release | Do not publish a Mac SKU as accepted |
| A5 technical | **PASS only for provenance/dependency metadata**: original kit 21 files + index/sums, 71 Windows and 37 Mac BOM; [QA PR #77](https://github.com/i-shutov/flowbridge/pull/77), [pinned A5 CI #43936785163](https://github.com/i-shutov/flowbridge/actions/runs/43936785163) 4/4 SUCCESS. RustSec original Cargo.lock, 75 dependencies, 0 known vulnerabilities at scanned DB version; native C++/security not covered | Complete owner own-code `LICENSE`, legal/redistributable Windows/MSVC/NSIS/SSH and native runtime/code security review, [issue #78](https://github.com/i-shutov/flowbridge/issues/78) |
| A6 formal independence | **NOT_APPROVED**: Win10 current-scope A3 original owner V4+V5 evidence accepted; A5 legal/native runtime, P0 and publisher review still outstanding. Win11 is not in current scope | Independent Win10-only exact-source review with no P0 FAIL/SKIP/UNKNOWN and complete A5 |
| A7 owner/publication | **NOT_APPROVED**: no selected own-code license, no release authorization or publisher signing, no tag | Explicit owner decision on Windows-only unsigned engineering prerelease vs signed distribution; confirm all release claims and checksum |

**No part of this A6 memo confers legal, supply-chain security or publisher approval.**

## 3. Honest unsigned engineering prerelease notes — DRAFT, NOT PUBLISHED

**FlowBridge 0.3.0-beta.2 — Windows x64 (engineering prerelease)**

- Scope: native Windows UI, explicit local SOCKS5/SOCKS5h TCP to configured clients, external proxy support and supervised OpenSSH with strict host-key checking, 1–4 SSH workers and bounded capacity; the app must be configured to use the SOCKS proxy.
- GUI status display now uses one concise connection headline; diagnostic text remains visible in journal. Added exact-beta GUI and SSH-negative regressions.
- Install/upgrade/uninstall are per-user and preserve separate user settings from stable FlowBridge; native Win10 owner original V4+V5 records reviewed. Windows 11 is not included or advertised for this release.
- **Do not use as protected transparent traffic interception.** No selected-app transparent interception, WFP/NDISRD driver, system kill switch or system-wide DNS no-leak guarantee. No UDP/QUIC-over-SSH, no restoration of existing TCP sessions after SSH break; browsers using own DoH/DoT or applications not configured for local SOCKS may use other routes.
- Publisher signing not complete. Both binary provenance via original GitHub Actions hashes and separate Windows OS/SmartScreen trust decisions matter. Do not tell users to disable Defender/SmartScreen or security controls to install an unsigned test build.
- Cross-platform source/build CI includes macOS but Mac native product support is not part of the Windows-first release.
- Do not describe the experimental independent raw OpenSSH backend as supporting 512 held channels; verified managed product scope is 128 concurrent flows with admission limits, 10k churn and up to four workers in hosted tests.
- Windows 10 Pro 22H2 is past standard Microsoft support and should not be represented as a secure host without verified eligible ESU/security updates.
- **Distribution license pending:** these notes are an internal draft until approved FlowBridge-specific project license and legally reviewed third-party notices/runtime terms are provided.

## 4. Explicit release decision dependency

**A6 reviewer cannot issue GO until [#78 license/legal/runtime](https://github.com/i-shutov/flowbridge/issues/78) and the remaining Win10-only security/release gates are accepted.** [Win11 #79](https://github.com/i-shutov/flowbridge/issues/79) was explicitly deferred and **must not block the current Windows 10 release**. Perform final A6 Win10-only P0/security/privacy audit, require explicit A7 owner approval and only then consider publishing a Win10-only prerelease. Do not merge a WFP driver stack into beta to satisfy unrelated product needs. Windows 1.0 WFP/ALE physical G2 is an independent mandatory release track and remains `NO_GO`.

## 5. Distinct WFP/1.0 blocker (not a beta release gate)

[WFP product PR #72](https://github.com/i-shutov/flowbridge/pull/72), exact `f1ac3b04369163ece245c4fea9520571cec112bf`: source/WDK/Windows BFE-scope/DNS checks PASS, but independent raw OpenSSH 512-characterization workflow FAIL under Windows sshd resource exhaustion and general Rust/native workflow records a cancelled macOS Rust job. No signed, loaded native driver, kernel socket-object binding, generation-safe AUTH reauth or physical no-DIRECT IPv4/v6/DNS packet proof. WFP G2 and `1.0` NO-GO; no traffic-filter changes on the existing owner VM are approved by this packet.
