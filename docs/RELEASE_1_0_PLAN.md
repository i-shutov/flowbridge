# FlowBridge — исполнимый план до 1.0


## Актуальная инженерная точка 17.11.2026 — исправление SSH runtime P1, source/build PASS

**Ветка [PR #88](https://github.com/i-shutov/flowbridge/pull/88)** поверх приватности [PR #84](https://github.com/i-shutov/flowbridge/pull/84), точный source **`44e3ba988ac5a9f7cf2d25b16d46c432ff3d8c38`**. [**CI #44076875289](https://github.com/i-shutov/flowbridge/actions/runs/44076875289) 3/3 SUCCESS**: Rust/Linux+Windows реальный подписанный Microsoft OpenSSH и unsigned fake `ssh.exe` отрицательный тест, no-PATH системный OpenSSH, `-V` при блокировке изменения файла, no raw stderr в FFI/GUI, native Win32 GUI/FFI explicit-only build. Source/build результат только, **не** новый проверенный installer. В расширенном [Rust/native CI #44076875466](https://github.com/i-shutov/flowbridge/actions/runs/44076875466) последние наблюдения: Windows app + Rust Windows/Ubuntu PASS, macOS jobs queued; полное workflow GO не приписывать до завершения.

**Старый `beta.2` остается точным неизменным комплектом** installer SHA256 `0699bed4acaa1b9df9b63c658808b08fd65b5953cacdaaddb7a13953389e19f4` и **НЕ содержит** новых P1 исправлений. Следующий `0.3.0-beta.3` пока **планируемый, не собран**: сначала защищённая/private доставка бинарников (репозиторий всё ещё Public и владелец отложил приватизацию [#83](https://github.com/i-shutov/flowbridge/issues/83)), затем новый pinned source+installer SHA, новая Win10 owner/native GUI+SSH/negative+Stop/restore и независимая оригинальная приёмка. Не переносить A3 старой beta.2 на новый EXE. Реальный Win10 ESU/signature preflight не исполнялся на host; [read-only Codex runbook](https://github.com/i-shutov/flowbridge/blob/qa/win10-internal-security-inventory-20261117/docs/qa/release-1.0/checkpoints/WIN10_A5_A6_READONLY_SECURITY_PREFLIGHT_CODEX_20261117.md).

[Подробный source/CI checkpoint](qa/release-1.0/checkpoints/WIN10_SSH_TRUST_SOURCE_BUILD_REBASELINE_20261117.md). **A5/A6 internal privacy+native security, A7 internal pilot GO OPEN**; no public release/tag, no own-code license grant. Windows 11/macOS отложены. Полноценный Windows 10 `1.0` WFP/G2 (подписанный native socket authority, физический no-DIRECT/DNS/UDP) всё ещё `NO-GO`.


## ПРИОРИТЕТ 17.11: реальные P1 безопасности до любого нового внутреннего кандидата

**Frozen `0.3.0-beta.2` не изменён**: source `86583a1a0487b9d383c0122b24558e620bde5b9c`; original Win10 A0–A3 пользовательские доказательства приняты по V4 100/100 + V5 26/26, CI 11/11 PASS. Однако **обнаружено реальное P1 раскрытие путей/hostname через OpenSSH stderr** в `Snapshot.stderr` и `Snapshot.events`/GUI journal. Старый installer **не содержит** патч.

- [P1 privacy #85](https://github.com/i-shutov/flowbridge/issues/85), исправление [Draft PR #84](https://github.com/i-shutov/flowbridge/pull/84), exact source `6057ff9b76ebd1d3148ac806313dc0aec0bd9158`. [Targeted CI #44061327017](https://github.com/i-shutov/flowbridge/actions/runs/44061327017) **3/3 SUCCESS**: Rust SSH на Linux/Windows, synthetic secret/host/path omissions из serialized snapshot, нативная компиляция Win32 GUI `FLOWBRIDGE_EXPLICIT_BETA_ONLY=ON`. Это **source/build PASS**, НЕ тест нового installer и НЕ общий A6 GO.
- [P1 executable trust #86](https://github.com/i-shutov/flowbridge/issues/86): существующий SSH backend разрешает explicit absolute path и PATH-lookup без runtime Microsoft Authenticode/pin доверия. [QA PR #82](https://github.com/i-shutov/flowbridge/pull/82) содержит read-only Authenticode + SHA + reparse проверку, но остаётся TOCTOU/непроверенный runtime. [Win10 owner Codex read-only A5/A6 preflight](https://github.com/i-shutov/flowbridge/blob/qa/win10-internal-security-inventory-20261117/docs/qa/release-1.0/checkpoints/WIN10_A5_A6_READONLY_SECURITY_PREFLIGHT_CODEX_20261117.md) нужно выполнить на реальной машине; не считать hosted Windows Server доказательством Win10.
- **P0 confidentiality** [#83](https://github.com/i-shutov/flowbridge/issues/83): repo остаётся Public при закрытой лицензии; пользователь приватизирует позже. Запросов на автоматическую смену visibility нет.
- **Win10 ESU**: read-only Year2/licensing/patch floor на фактической Win10 машине не проверен. Никаких MAK/ключей или личных путей в публичный GitHub.

[Интегральный P0/P1 checkpoint](qa/release-1.0/checkpoints/SECURITY_P1_FINDINGS_AND_BETA_NEXT_GATE_20261117.md). При принятии приватности SSH **собрать новый уникальный кандидат** (возможное имя `0.3.0-beta.3`) со своими SHA/manifest и Win10 native GUI/SSH негативами+позитивами, а не переписывать прошедший beta.2. **A5/A6 formal и A7 внутреннее развёртывание OPEN**. Win11/macOS отложены. **Защищённый Win10 1.0 WFP/G2 NO-GO**, никакой физический WFP-драйвер на owner VPS не ставился.


## Internal security audit — 17 November 2026, latest read-only CI

[Win10 closed-source security checkpoint](qa/release-1.0/checkpoints/INTERNAL_WIN10_SECURITY_REVIEW_20261117.md), [QA PR #82](https://github.com/i-shutov/flowbridge/pull/82) exact head `ab7d0d56dfa6af0843c183497d455a6b67578ea1`, [GitHub Actions #44055935443](https://github.com/i-shutov/flowbridge/actions/runs/44055935443) **4/4 PASS**. **9,399 Git objects / 2,769 historical blobs** from fetched refs and PR heads, zero high-confidence PEM/token-pattern matches, zero skipped large blobs. Independently screened exact frozen beta.2 source ZIP **303/303 files**, original owner V5 **27**, V4 **100** plus nested CI ZIP **25** files (large binary separately inspected): zero matches under the narrow high-confidence rules. This is not a comprehensive secret/security audit and cannot undo public history or external clones.

**P0 confidentiality:** repository remains **Public** although owner chose closed-source and internal-only; owner will privatize later. Track [#83](https://github.com/i-shutov/flowbridge/issues/83). Original NSIS still supports `AtLeastWin10` (does not forbid Win11), while scope is **Win10 Pro 22H2 x64 only**. [PowerShell 5.1 read-only pinned installer preflight](https://github.com/i-shutov/flowbridge/blob/qa/win10-internal-security-inventory-20261117/tools/windows/FlowBridge-Beta2-Win10-Internal-Preflight.ps1) verifies exact original EXE SHA256 and strict Win10 OS; hosted Windows Server 2025 expected negative CI PASS, **no installer executed**. No changes to frozen product source or binaries.

**Current release GO remains false:** A0–A3 Win10 PASS on original evidence, A5 technical and A6 technical PASS; independent third-party/native SDK rights, Win32/SSH GUI log privacy/code security review, Win10 ESU status, and A7 explicit internal pilot deployment approval remain OPEN in [#81](https://github.com/i-shutov/flowbridge/issues/81). External/public distribution disabled, license proprietary, Win11/macOS deferred. **Win10 1.0 signed WFP/G2 physical proof remains NO-GO.**


## ПРАВЯЩЕЕ РЕШЕНИЕ ВЛАДЕЛЬЦА — 17.11.2026: ТОЛЬКО ВНУТРЕННЕЕ ИСПОЛЬЗОВАНИЕ

Владелец прямо выбрал «пока только внутреннее». **Это не выбор MIT/Apache-2.0/проприетарной лицензии, не публичная публикация и не GO на развёртывание**. Допустима внутренняя разработка и ранее разрешённые тесты точного `0.3.0-beta.2` на Win10 Pro x64. Сохранены все original candidate SHA и доказательства A0–A3 PASS.

**Публичная дистрибуция, внешние установщики, маркетинговые релизы, GitHub Releases и release tags запрещены/не запрошены.** Собственная публичная лицензия FlowBridge не выбирается сейчас, это [будущий backlog #78](https://github.com/i-shutov/flowbridge/issues/78). Сторонние лицензии, фактические native SDK/runtime условия использования и security/privacy остаются важными даже внутри организации.

**Текущий путь:** `A5_INTERNAL_DEPENDENCY_RUNTIME_REVIEW_OPEN` → `A6_INTERNAL_SECURITY_PRIVACY_P0_GO_OPEN` → `A7_INTERNAL_DEPLOYMENT_GO_NOT_GRANTED`, см. [активную задачу #81](https://github.com/i-shutov/flowbridge/issues/81). A0–A3 Win10 приняты на оригинальных доказательствах, технический A5 и A6 CI PASS. Никакой live VM/driver/пакетной установки в этом изменении не выполнялось. Windows `1.0` WFP/G2 NO-GO. Windows 11/macOS отложены на следующие платформенные релизы.

[Машинная политика и точный checkpoint](https://github.com/i-shutov/flowbridge/blob/docs/release-win10-vm910136-20261110/docs/qa/release-1.0/checkpoints/INTERNAL_ONLY_DISTRIBUTION_DECISION_20261117.md). **Все прежние формулировки этого документа о необходимости сейчас выбрать публичную лицензию — исторические, заменены данным решением.**


> **ФАКТИЧЕСКИЙ СРЕЗ 17.11.2026 — ПОСЛЕ A6 4/4 CI.** Текущий продукт: **`0.3.0-beta.2`, только Windows 10 Pro 22H2 x64**. Источник `86583a1a0487b9d383c0122b24558e620bde5b9c`, весь candidate [11/11 PASS](https://github.com/i-shutov/flowbridge/actions/runs/43883696169); оригиналы owner Win10 A3 V4/V5 приняты по независимо проверенным SHA. **Технический A5** оригинальный пакет/SBOM/RustSec 4/4 PASS; **технический A6** [новый PR #80](https://github.com/i-shutov/flowbridge/pull/80), [CI #44041579615](https://github.com/i-shutov/flowbridge/actions/runs/44041579615) **4/4 PASS** включая проверку исходных PE импорта `FlowBridge.exe`/`FFI`/NSIS, без прямых `VCRUNTIME140.dll`/`MSVCP140.dll` зависимостей. Это **не юридический/полный native security review** и не release GO.
>
> **Текущие блокеры публикации:** [#78 выбор собственной LICENSE/copyright + independent native redistribution/security/legal](https://github.com/i-shutov/flowbridge/issues/78) (**A5 OPEN**); формальное независимое privacy/security заключение (**A6 OPEN**); отдельный явный Publisher/Owner GO (**A7 OPEN**). [Текущий A6 checkpoint](qa/release-1.0/checkpoints/BETA2_A6_RELEASE_REVIEW_PACKET_20261117.md), [A0–A7 machine](qa/release-1.0/BETA2_WINDOWS_A0_A7_20261116.json). **Никакого тега, Release, смены LICENSE, подписанного бинарника или main merge.** Win11/macOS только в следующих релизах. Защищённый Win10 `1.0` WFP/G2 по-прежнему `NO_GO`.


> **РЕШЕНИЕ 17.11.2026, ПРЕИМУЩЕСТВО НАД ПРЕЖНИМИ ПЛАНАМИ:** первый выпускаемый продукт — **Windows 10 Pro 22H2 x64 ТОЛЬКО**. Windows 11 Pro x64 **не тестировать и не публиковать сейчас**, перенос в следующие релизы; macOS также отложена. Историческое утверждение ниже «Windows 10 + Windows 11 first» **устарело**. См. [точный scope checkpoint](qa/release-1.0/checkpoints/WIN10_ONLY_SCOPE_DECISION_20261117.md), [Win10-only roadmap](qa/release-1.0/WINDOWS_FIRST_1_0_ROADMAP_20261115.md) и [A0–A7 matrix](qa/release-1.0/BETA2_WINDOWS_A0_A7_20261116.json).
>
> Текущий `0.3.0-beta.2` Windows 10 A3 **PASS on independently audited original V4+V5 evidence**, общий A0/A1/A2/A3 PASS. **A5/A6/A7 ещё открыты**: [LICENSE/legal/native runtime #78](https://github.com/i-shutov/flowbridge/issues/78), независимое Win10-only review, явное решение владельца на публикацию. Win11 [#79](https://github.com/i-shutov/flowbridge/issues/79) — **future backlog, не текущий P0**. `Windows 1.0` по-прежнему `NO_GO` из-за signed native WFP/G2, fail-closed и остальных P0. Никакого Win11 PASS, тега или GitHub Release эта корректировка не создаёт.


## 17 November 2026 — owner V5 independently reviewed; Win10 A3 subgate accepted

Original owner Win10 beta.2 V5 ZIP SHA256 `809dee21f0884e0d31dfa89a98033276cefaad859de1de64a87a2b90f454cb4c` was uploaded and independently audited: ZIP CRC, 26/26 file hashes, six real GUI images, 23 UI actions on the exact final installer/GUI/DLL bytes, missing-key OpenSSH denial without a listener or DIRECT on localhost, a healthy-key 10-byte bidirectional SOCKS5h control and Stop/restore all internally consistent. The prior V4 100/100 evidence was already audited. **[Win10 A3 reviewed evidence accepted](https://github.com/i-shutov/flowbridge/blob/docs/release-win10-vm910136-20261110/docs/qa/release-1.0/checkpoints/BETA2_WIN10_A3_V5_INDEPENDENT_REVIEW_20261117.md)**, with the explicit limitation that the host was not independently physically rerun/cryptographically attested. Note V5 `SOCKS_REP=null` because the local listener **never opened**, not `REP=01`.

**Windows target A3 overall remains OPEN** for independent real Win11 Pro x64. [Autonomous Win11 Codex exact-byte runbook](https://github.com/i-shutov/flowbridge/blob/docs/release-win10-vm910136-20261110/docs/qa/release-1.0/checkpoints/BETA2_WIN11_CODEX_NATIVE_ACCEPTANCE_20261117.md), no new Win10 GUI runs needed for unchanged beta.2. Original candidate [CI #43883696169](https://github.com/i-shutov/flowbridge/actions/runs/43883696169) attempt 2 11/11 SUCCESS; independent A5/SBOM and pinned RustSec [CI #43936785163](https://github.com/i-shutov/flowbridge/actions/runs/43936785163) 4/4 SUCCESS (0 known advisories in 75 locked Rust dependencies). **License of FlowBridge-specific code unselected**, and legal/SDK/native-runtime/security [issue #78](https://github.com/i-shutov/flowbridge/issues/78), A6/A7 independent GO, unsigned package approval remain OPEN. WFP G2 / Windows 1.0 NO-GO. No tag or published release.


> **Машинный gate-срез Windows beta.2 (A0–A7):** [BETA2_WINDOWS_A0_A7_20261116.json](qa/release-1.0/BETA2_WINDOWS_A0_A7_20261116.json). A0/A1/A2 PASS в пределах explicit SOCKS; **A3/A5/A6/A7 не приняты**, Win11 native открыт. Дата 16.11, оригинальный Source SHA `86583a1a...`; признак `windows_beta2_release_accepted=false`. Полное состояние: [blocker execution](qa/release-1.0/checkpoints/BETA2_RELEASE_BLOCKERS_EXECUTION_20261116.md).

> **16 ноября, новый checkpoint выполнения блокеров:** [beta.2 A3/A5/WFP release-blockers](qa/release-1.0/checkpoints/BETA2_RELEASE_BLOCKERS_EXECUTION_20261116.md). Оригинальный beta.2 CI `11/11 PASS`, Win10 V4 original evidence `100/100` integrity reviewed. **A3**: для финального EXE остался ровно один тест `INVALID_KEY_PATH_FINAL_BETA2`, [автономная задача для Codex V5](qa/release-1.0/checkpoints/A3_BETA2_CODEX_V5_MISSING_IDENTITY_NEGATIVE_20261116.md). **A5**: [PR #77](https://github.com/i-shutov/flowbridge/pull/77) source+artifact technical auditor `3/3 PASS`, но [owner license decision #78](https://github.com/i-shutov/flowbridge/issues/78), independent legal/runtime/vulnerability audit не закрыты. **WIN-01**: WFP [PR #72](https://github.com/i-shutov/flowbridge/pull/72) exact `f1ac3b0` WDK/source PASS, общие CI ещё не завершены; физический signed G2 NO-GO. `release_accepted=false`, `publisher_release_approved=false`, тег отсутствует.


> **НОВАЯ ОПОРНАЯ ТОЧКА 16.11 (после V4 review):** реальный владелец передал оригинальный архив A3 Codex beta.2; независимо проверены **100/100 SHA**, **41/41 V3**, **13/13 Windows payload**, **17 GUI screenshots**, оригинальные loopback SSH/Stop/negative JSON. Полный beta.2 candidate CI #43883696169 **attempt 2 SUCCESS 11/11**. [Проверяемый аудит Win10](qa/release-1.0/checkpoints/BETA2_OWNER_WIN10_A3_V4_INDEPENDENT_REVIEW_20261116.md). **Открыты** один beta.2 invalid-key-path negative case, независимое финальное A3-решение, Win11 owner QA, лицензия/A5, A6/A7. `1.0` WFP G2 остаётся NO-GO; публикации нет.


> **Source audit update, 16 November 2026 — Windows beta.2**: [PR #76](https://github.com/i-shutov/flowbridge/pull/76) exact head `86583a1a0487b9d383c0122b24558e620bde5b9c`. **Original GitHub Actions Windows artifact #14233377409 independently verified**: ZIP SHA/CRC PASS, 13/13 manifest payloads, final installer/GUI/FFI SHA256 match report; exact final GUI SHA in hosted installed-product JSON. [Independent audit checkpoint](https://github.com/i-shutov/flowbridge/blob/docs/release-win10-vm910136-20261110/docs/qa/release-1.0/checkpoints/BETA2_WINDOWS_GITHUB_ARTIFACT_INDEPENDENT_AUDIT_20261116.md). **Owner native V4 ZIP is NOT independently received/reviewed** (local owner-reported SHA `23844631907f96063f0b13db73a835b92c386a4be3ed13a174c484c3139606e2`); new beta A3 full remains OPEN. Unified candidate workflow #43883696169 attempt 1 FAILURE due cancelled macOS universal-package; targeted attempt 2 MAC queued. Windows-only release must use honest, separate Windows gate; no universal CI green claim. Raw SSH 512 not proved (peak 246, baseline 128). A5 LICENSE/legal, A6/A7, separate Win11 QA and Windows 1.0 WFP/G2 remain open.


> **Коррекция Codex A3 от 16.11:** первый реальный проход Codex вернул `BLOCKED_PROFILE_ISOLATION` и `BLOCKED_SIGNED_SSHD_UNAVAILABLE` (положительный GUI и SSH не исполнялись). Доказанный RCA: frozen GUI штатно хранит `profile.json` + `desktop-settings.json` в Known Folder текущего **Admin**; ранее принятый W2b1 уже умеет получить pinned Microsoft-signed portable `sshd.exe` без Windows Feature/service. Исправленное [Codex V2 задание](https://github.com/i-shutov/flowbridge/blob/8c23e10819e200e7bf38e596490fba2c1113cf37/docs/qa/release-1.0/checkpoints/A3_WIN10_CODEX_AUTONOMOUS_GUI_SSH_TASK_20261116.md) разрешает транзакционный Admin profile escrow/restore и pinned portable SSHD; [RCA](https://github.com/i-shutov/flowbridge/blob/ef1277d1bcc6ede436cc5800048d088d534c7b90/docs/qa/release-1.0/checkpoints/A3_CODEX_FIRST_PASS_BLOCKER_RCA_20261116.md). Нового пользователя/чистой VM/ручного GUI не требуется. **Это задача на повторный прогон, а не PASS.**


> **СВЕЖИЙ СРЕЗ — 16 ноября 2026:** [Windows-first 1.0 rebaseline](qa/release-1.0/checkpoints/WINDOWS_FIRST_RELEASE_REBASELINE_20261116.md), [актуализированный roadmap](qa/release-1.0/WINDOWS_FIRST_1_0_ROADMAP_20261115.md) и [машинный реестр gates](qa/release-1.0/WINDOWS_FIRST_GATES_20261115.json).
>
> - Windows `0.3.0-beta.1`: **Win10 original frozen automated A3 6/6 PASS, оригинальный JSON/5 BMP независимо проверены**. Интерактивные GUI+exact-kit SSH/SOCKS5h **не зачтены**, их выполнение делегировано [Codex на Win10](https://github.com/i-shutov/flowbridge/blob/8c23e10819e200e7bf38e596490fba2c1113cf37/docs/qa/release-1.0/checkpoints/A3_WIN10_CODEX_AUTONOMOUS_GUI_SSH_TASK_20261116.md) и пока не подтверждено оригинальными результатами. Остаются Win11 QA, LICENSE/A5, A6 и A7.
> - Windows `1.0.0`: **строго NO-GO**. WFP/ALE source/WDK-сборки и ABI4 CLAIM не заменяют signed native Win10/11 G2. P0: accepted-socket kernel authority, ticket lifecycle/reauthorization, no-DIRECT, DNS/UDP, ресурсная/24h SSH QA, Win10/11 RC, подписи/безопасность.
> - macOS NE/физическая Mac-приёмка перенесены после Windows 1.0 решением от 15 ноября; перенос не означает PASS. Русло Rust остаётся кроссплатформенным.
> - `main` не является 1.0 release, теги/публикация не создавались. Не устанавливать WFP-драйвер на пользовательскую VM в рамках beta GUI/SSH тестов.


> **ИСТОРИЧЕСКОЕ РЕШЕНИЕ — 15 ноября 2026: WINDOWS-FIRST 1.0, ЗАМЕНЕНО 17.11.**
> Тогда планировались **Windows 10 Pro 22H2 x64 + Windows 11 Pro x64**; **текущий релиз — только Win10**, Win11 отложена.
> macOS Network Extension, DNS, подписанные пакеты и ручная Apple Silicon/Intel QA
> перенесены на следующий платформенный релиз. Код macOS и единый Rust-core
> сохраняются и продолжают проходить portable-core CI.
> **Канонический текущий план**: [WINDOWS_FIRST_1_0_ROADMAP_20261115.md](qa/release-1.0/WINDOWS_FIRST_1_0_ROADMAP_20261115.md).
> **Машинный Windows-only контракт выпуска**: [WINDOWS_FIRST_GATES_20261115.json](qa/release-1.0/WINDOWS_FIRST_GATES_20261115.json).
> Прежний текст ниже (включая формулировку «обе ОС в 1.0»)
> — сохранённый исторический план, **не актуальная целевая матрица**.
> Ничего из прежних macOS PASS не засчитывается как Windows proof:
> Windows G2 kernel-origin connection provenance, native Win10/Win11 и fail-closed
> остаются обязательными. `windows_1_0_accepted=false`, `version_1_0_accepted=false`.


> **Актуальный срез на 13 ноября 2026:** [FlowBridge 1.0 — release rebaseline, beta/RC/G0–G6/R00–R10](qa/FLOWBRIDGE_RELEASE_REBASELINE_20261113.md).
> [19 машиночитаемых gate-решений](qa/release-1.0/gate_status_20261113.json) — RELEASE NO-GO.
> Следующий текст — **история и исходный контракт**, не текущая приёмка. Ветка main не меняется.

> **Актуальная контрольная точка на 10 ноября 2026:**
> [Единый план beta → WFP/ALE → 1.0 и новая целевая Win10 x64](qa/FLOWBRIDGE_RELEASE_ROUTE_20261110.md).
> Ниже сохранена историческая последовательность прежних gate-решений;
> статусы на старых source SHA не являются актуальной приёмкой.
> Новый план отдельно выделяет ограниченную SOCKS-only beta, read-only
> испытания реальной Win10 Pro и native kernel gates с обязательным rollback.


**Срез:** 30 октября 2026. **Исходная база:** `main` @ `6401b40b02fa00d5ae3f84aec2ac1916c266e6ea`.
**Текущий подтверждённый уровень:** локальная SOCKS5-бета, Windows x64 + macOS universal, собственные GUI, управляемый SSH-пул 1–4 процесса; проверенные 5/5 native/Rust jobs и 3/3 DNS jobs на exact PR head `a38fd84e`. [Checkpoint](qa/NATIVE_BETA_CHECKPOINT_20261030.md), [CI](https://github.com/i-shutov/flowbridge/actions/runs/41005277502), [DNS](https://github.com/i-shutov/flowbridge/actions/runs/41005277446).

## Актуальная контрольная точка: 30 октября, после PR #33

Эта секция является **живым реестром**, тогда как ссылки выше фиксируют
исторические подтверждения на исходных SHA. CI предыдущего коммита не является
доказательством работоспособности новой ветки.

| Gate | Состояние | Основание / необходимое действие |
|---|---|---|
| G0 — локальные TCP SOCKS5, Rust + нативные сборки | **Есть доказанные прежние PASS, перепроверять на каждом новом SHA** | 5-job CI и DNS, точные run IDs в верхнем checkpoint |
| G1 — нативные правила Windows | **Влито в main** | [PR #33](https://github.com/i-shutov/flowbridge/pull/33), squash `9cc3b1be`, нативный GUI smoke и строгая Rust validation |
| G2 — правила macOS | **PR открыт, CI верифицируется** | [PR #35](https://github.com/i-shutov/flowbridge/pull/35), SwiftUI sheet / cancel-safe draft; настоящая Mac GUI/VoiceOver приёмка отдельна |
| G3 — Windows SSH 10k churn | **PR открыт, не принят** | [PR #34](https://github.com/i-shutov/flowbridge/pull/34): предыдущий run #41027933355 остановился на 636/10000 при Winsock 10048, 3922 TIME_WAIT; починка только test harness |
| G4 — настоящий Windows WFP | **P0, BLOCKED до driver-loaded Win10/11 evidence** | [Issue #1](https://github.com/i-shutov/flowbridge/issues/1), идентичность процесса, рабочий redirect, удаление фильтров при Stop |
| G5 — настоящий macOS NE | **P0, BLOCKED до sign/install/approve на Mac** | [Issue #2](https://github.com/i-shutov/flowbridge/issues/2); CI-компиляция не включает entitlement |
| G6 — удалённый DNS без утечек | **Частично; P0 native capture не принят** | [Issue #5](https://github.com/i-shutov/flowbridge/issues/5), packet evidence на обеих ОС |
| G7 — DPI/доступность/инсталляторы | **Частично; P1 не принят** | [Issue #6](https://github.com/i-shutov/flowbridge/issues/6), реальные VM DPI и клавиатурная QA |

### Разделить две контрольные цели

**BETA-C (внутренняя полностью функциональная бета)**:
пользователь на *обеих* ОС выбирает приложение и визуально задаёт
правила, запускает собственный SSH и получает действительный перехваченный
TCP маршрут с журналом; Start/Stop/Apply/rollback/host-key/remote-DNS
проверены на реальном железе/VM. Для внутренней подписанной девелоперской
сборки допускается документированный developer signing при условии,
что system safeguards НЕ отключаются и все системные расширения действительно
активированы. Без G4/G5/G6 не выдавать локальную explicit SOCKS-бету за BETA-C.

**RC-1.0**: BETA-C плюс все R00–R10, выпускные сертификаты,
материализованные подписанные/нотаризованные установщики, OS matrix,
реальные TCP/DNS traces, 10k/24h ресурсная QA, ноль P0 SKIP/UNKNOWN.
Нельзя переименовать непринятую beta в 1.0.

Каждая принятая вертикаль обязана иметь `branch/head SHA → workflow run/job →
действительный тестовый сценарий → JSON/pcap/screenshot artifact + SHA-256 →
обнаруженные ограничения`. При изменении HEAD статус exact-head CI снова
становится **PENDING**; статус безопасности не наследуется автоматически.

**Принцип:** «1.0» обозначает проверенное приложение с реальным прозрачным TCP-перехватом на **обеих** платформах, а не число коммитов или успешно собранный WFP/NE модуль. Ни один обязательный ручной тест нельзя заменить зелёным hosted CI.

## 0. Контракт релиза 1.0 (scope freeze)

**Платформы:** Windows 10 22H2 и Windows 11 x64; macOS на Apple Silicon и Intel в явно опубликованной матрице поддерживаемых версий, согласованной с Xcode/entitlements (начальный target macOS 13+, фактическая поддержка — только после native QA). Это целевой, а не уже доказанный список.

**Должно работать без ручной SOCKS-настройки в выбранном приложении:**

1. Нативный **TCP IPv4/IPv6** перехват по проверенной ОС идентичности процесса/подписи, включая обычный пользовательский запуск и приложения с дочерними процессами. Прочие процессы сохраняют свои правила; нельзя превращать неподтверждённую идентичность в догадку.
2. Упорядоченные правила **App × Host/CIDR × Port → Proxy/Chain/Direct/Block**, со строгими wildcard/IPv4/IPv6/first-match semantics, исключениями localhost/LAN/SSH transport, проверкой конфликтов и понятным `explain`.
3. Локальные, SOCKS5/SOCKS4a и HTTP CONNECT upstream, смешанные proxy chains в объёме уже реализованных и доказанных транспортных возможностей, отдельные статусы ошибки/proxy/chain. Все существующие поддержанные возможности Rust-ядра доступны из GUI.
4. **Управляемый SSH**: 1–4 независимых OpenSSH-процесса, key/agent + строгий known_hosts, bounded admission, гарантированный Stop, честная диагностика перегрузки, new-flow failover на живой процесс, отсутствие незаявленного DIRECT. Разорванные established TCP не мигрируют и не переигрывают AI-запросы.
5. **DNS в явно определённом объёме:** checkbox «разрешать DNS на удалённом SSH-сервере» default-on; hostname в explicit SOCKS уходит как DOMAINNAME; в native interception подтверждена и документирована политика для выбранных приложений, localhost/LAN/split-DNS, bootstrap SSH, OS resolver и приложений с собственным DoH/DoT. Без доказательств нельзя обещать общий DNS no-leak. Неподдержанные случаи — явное «не защищено» или fail-closed по выбранной политике, никогда тихий DIRECT.
6. Компактный, нативный **rule editor / app selector / proxy-SSH editor / active connections / журнал ошибок / диагностический экспорт / режимы**. Сохранение, профильный import/export, атомарное Apply/Reload и безусловно правильный Stop. Пользователь без JSON должен настроить типовую схему.
7. Стабильные установщик/обновление/удаление, проверенная подпись release binary/driver/extension, пользовательские секреты только в OS secure store или безопасном внешнем источнике; без утечки в профилях/логах. Воспроизводимая сборка и проверяемые свидетельства на одном SHA.

**Честная граница 1.0:** Proxifier документирует прежде всего TCP-проксификацию. OpenSSH `ssh -D` не является UDP/QUIC-туннелем. Продукт обязан иметь видимую UDP/QUIC политику (явное исключение либо Block для выбранного protected mode), не выдавать UDP за проксированный TCP. Если для заявленного protected mode платформа не может обеспечить необходимый контроль, режим не включается. Подключения со своими DoH/DoT и уже сделанным local DNS разрешением не обещают DNS удалённого SSH, пока не получено отдельное доказательство.

**Не блокируют 1.0, если честно указаны в release notes:** совершенно прозрачное сохранение существующих TCP-сессий при физической потере SSH (#4, нужен remote relay), автоматическое повторение HTTP/AI requests, UDP-over-SSH, полной эмуляции платного Proxifier (NTLM/Kerberos, портативный kernel-less режим, каждый формат импортируемого профиля). Это отдельные features 1.x, не повод подменять провал обязательных TCP/DNS сценариев.

## 1. Критический путь и пакет PR

| ID | Трек / исполнитель | Содержимое и вход | Выход — объективная приёмка | Зависит от |
|---|---|---|---|---|
| R00 | Release/QA — один координатор | Утвердить именно этот scope, матрицу ОС, понятие protected/unprotected, release evidence schema, приоритеты. Старый PR #23 с CI-экономией пересмотреть на текущем main и принять/закрыть без дублей. | `docs/qa/release-1.0/matrix.json`, реестр P0/P1, все обязательные кейсы имеют test ID и способ проверки | Текущий main |
| R01 | Windows/WFP | Завершить kernel callout + SCM service, signed/allowed driver на выделенной Win10/11 VM, IPv4/IPv6 ALE_CONNECT_REDIRECT, original endpoint и **реальный** OS process identity; helper принимает профиль по SHA-256, SSH/key остаются вне UAC, owner-death unload | `tests/windows_wfp_redirect_runtime.py` + `windows_wfp_userchain_runtime.py` **PASS** на реально загруженном драйвере; selected→WFP→helper→Rust→SOCKS→echo; other EXE/direct не перехватываются; stop/crash не оставляет фильтров; обычный medium-integrity GUI запускает поток через разрешённый privileged helper | R00, Windows VM/driver identity |
| R02 | macOS/NE | Xcode SwiftUI/NE codesign с реальными Team/App ID и entitlement, approval/deny/restart, TCP bridge, selected signing identity, half-close/backpressure, capture lifecycle; минимум single SSH native с честной parity. 2–4 в NE — отдельная цель, если заявлена. | **Реальное** sign/install/approve/activate, selected app IPv4/IPv6 TCP через NE→Rust→SSH/echo; unselected bypass; failure no DIRECT; reboot/sleep/wake/disable/uninstall; машинные журналы на Apple Silicon и Intel | R00, Apple credentials/entitlements, Macs |
| R03 | DNS/policy — Windows | Разработать архитектуру per-app name preservation: DNS Client/shared-process, fake-IP map или другая доказуемая схема, TTL, resolver per profile, LAN/split-DNS и возврат mapped hostname до SOCKS; scoped resolver + network-capture. Не объявлять system-wide DNS без opt-in. | Сгенерированное uncached DNS-имя доступно **только** за SSH; клиент не запрашивает его локально, сервер разрешает; IPv4/6, bypass local domain, mixed apps, fail/no fallback; pcap + JSON | R01, #5 |
| R04 | DNS/policy — macOS | Интегрировать DNSProxyProvider/выбранную Apple-native схему с entitlement и transparent provider; reverse-map недопустим; app DNS/DoH/DoT status disclosed | Native Mac packet capture, unique domain on SSH server, measured local exceptions, uninstall resets system DNS, negative scenarios | R02, #5 |
| R05 | SSH/Windows reliability | Реально измерить выбранный Win OpenSSH (путь, хеш, `-V`, PID, internal errors), tier 64/128/192/256/512 attempted, actual `nchannels 251/252`; разные backend только по явному выбору; owned worker pool, overload backoff/fair queue, no loop, no DIRECT/DNS fallback, caps по замерам | `tests/windows_openssh_capacity_vm.py` + GUI-owner/WFP load; healthy-worker streams retained, all-down fails, 10k churn, sustained soak, no unbounded fd/handle/memory growth; issue #7 закрывается **только реальным** Windows evidence | R01 для end-to-end, отдельная QA возможна сразу |
| R06 | GUI/rules | Реальный визуальный editor: таблица с reorder/enable/clone, editable action, process path + verified identity, CIDR/wildcards/ranges, priority, dry-run `explain`; прокси/цепочки/тест, профили, сохранение, список подключений, счетчики и понятные errors; отсутствие необходимости редактировать JSON | Пройти сценарий «создать SSH → отметить Firefox/Code → направить через прокси → исключить LAN → остановить», проверено на обеих ОС без ручной правки JSON; ошибки профиля не убивают принятый маршрут | R00, интеграция R01/R02 |
| R07 | UI/QA | 1366×768/1920×1080, 100/125/150/200% DPI Win, multi-monitor, 5+ pages, keyboard accessibility, high-contrast, readable logging. Mac dark/light/Retina, resizing, focus/VoiceOver | 4 отдельные Windows DPI VM runs, screenshot sets + human review + keyboard/contrast checklist; снять Issue #6 только по доказательству | R06, Windows DPI VM |
| R08 | Security/packaging | Windows production driver signature via актуальный Microsoft Hardware Program/WHCP либо допустимый вариант (не старый cross-sign); signed desktop & installer, UAC/IPC authorization, copy/update/uninstall/rollback. macOS Developer ID, embedded NE, notarized `.app/.pkg`, revoke/approval recovery. OS secure store, no plaintext credentials. | Чистая Win10+11 и Mac ARM64+Intel: install→native activate→upgrade→rollback→remove; подпись проверена ОС, driver/extension/filters удалены, user profiles сохранены/мигрируют, пакет не требует отключения защит | R01,R02 и доступ к signing |
| R09 | QA/performance/release | CI 5+3 + WFP loaded-driver + NE activation + DNS leak + 24h profile soak + 10k TCP churn + Win selected app/VM, network transitions/VPN, IPv6, sleep-wake, crashed owner, corrupted profile, tight capacity; regression proof per SHA | `release-evidence.json` с exact source SHA, SHA-256 binary/installer, OS/build, test cmd, exit code, artifacts, PASS/FAIL; **0 FAIL/UNKNOWN/SKIP для P0**; defects triaged, no secrets in logs | R01–R08 |
| R10 | Release/ops | Version bump 1.0.0, changelog, end-user Quick Start, per-OS support/capabilities, migration, rollback, limitations, signed installer & notarized pkg, SHA-256/SBOM/licenses, tagged GitHub release, reproducibility | Release artifacts match signed tested RC SHA; `v1.0.0` tag, release notes, checksums, install smoke against published bytes; no claim unsupported UDP/NE/DNS | R09 |

### Порядок исполнения, а не календарная оценка

- **Фаза A — инфраструктура и расконсервация системного перехвата:** R00; сразу независимо R01 и R02. R05 можно проводить параллельно на Windows VM, R06 независимо по mock source identity. Если драйвер/NE не активируются, **не** идти в release, а закрывать blocker.
- **Фаза B — доказательство функциональной замены:** R01/R02 дают настоящие native TCP flows; R03/R04 создают DNS без незаявленного локального обхода; R05 устанавливает безопасные load limits. Конец B = *первая полноценная внутренняя прозрачная бета*, не 1.0.
- **Фаза C — потребительский продукт:** R06/R07 завершают rule editor и эргономику. R08 завершает безопасную дистрибуцию и life cycle. Конец C = функциональная бета с ещё проверяемым release pipeline.
- **Фаза D — Release Candidate → 1.0:** R09 полный прогон на одном замороженном кодовом SHA, исправление defects с повтором всей затронутой матрицы, затем R10. Gate 1.0 не «пройден с оговорками»: все P0 PASS и подписанные байты совпадают с проверенными.

### Release blockers, чёткие внешние зависимости

| Внешняя зависимость | Кто предоставляет | Почему не заменить GitHub hosted |
|---|---|---|
| Изолированная Windows 10 22H2 x64 + Windows 11 VM/ПК с администратором, WDK, разрешённой установкой driver, несколько DPI режимов и контролируемый loopback sshd | владелец тестовой инфраструктуры | hosted Windows не устанавливает/допускает наш kernel callout как production и не воспроизводит пользовательский Win SSH `MAX_FDS` failure |
| Microsoft Hardware Developer Program/EV submission и допустимый путь **production** подписания WFP driver | владелец издателя | нельзя выдать самостоятельную test-signed сборку за доверенный public driver |
| Apple Developer Team, нужные Network Extension entitlements/provisioning, Developer ID certs + нотарификация | владелец Apple Developer учётной записи | unsigned local `.pkg` не включает активированный системный NE |
| Реальный Mac Apple Silicon и Intel для entitlement/approval, clean install и user-level GUI | владелец тестовой инфраструктуры | xcodebuild на CI доказывает компиляцию, не пользовательское разрешение расширения |
| Контролируемый SSH сервер и DNS-only-on-server test domain, firewall/DNS packet traces | изолированный тестовый стенд | синтетическая local-echo проверка не доказывает отсутствие DNS-утечки |

Секреты/сертификаты, приватные SSH-ключи и доступы **не помещать в git или чат**. Подпись — в изолированных runner-secret stores и операторском контуре. Никогда не отключать Secure Boot или production code integrity ради зелёного отчёта.

### QA доказательства — запрет на «формальную готовность»

- Каждая ветка PR привязана к одному work package. Не меняем общий C ABI и kernel/SwiftUI code одновременно в несогласованных PR; интегратор проверяет совместимость, пересобирает на exact HEAD.
- Автоматические native/Rust проверки обязательны; manual Windows VM WFP, Windows SSH/FD, macOS NE и DNS packet captures обязательны как **отдельные** gates. `tests/*_vm.py` не засчитываются, если выполнена только синтаксическая проверка.
- После каждого пакета: commit SHA, workflow ID, artifact link + checksum, test-case counts/FAIL, manifest отчёта и отдельный checkpoint в `docs/qa/release-1.0/`. Большие подписи/private runtime evidence храним в закрытом хранилище с SHA-256 без публикации секретов.
- При изменении кодового SHA после RC — повторить затронутые функциональные и security tests; новый RC является новой проверяемой сборкой. Не переименовывать 0.2.0 в 1.0.0 пока P0 закрыты.

### Проверяемые трассы end-to-end, обязательные для Release Candidate

| Trace ID | Сценарий | Доказательство |
|---|---|---|
| T01 | Selected application без SOCKS settings → TCP IPv4/IPv6 WFP/NE → Rust → SSH → изолированный echo | real OS process ID + exact binary path/signing ID + path of connection + byte parity |
| T02 | Unselected app + localhost/LAN/corporate split DNS | остаётся только явно разрешённая Direct маршрутизация без loop |
| T03 | Remote-only hostname, cached/uncached and explicit SOCKS | DOMAINNAME на нужном hop; клиент не делает forbidden local lookup; DNS capture on both ends |
| T04 | Kill selected SSH worker while other child has active TCP | surviving streams exact bytes; new flows healthy worker; lost streams marked failed, no replay |
| T05 | All workers down, proxy overload/EMFILE, invalid SSH host key, driver/NE crashed | bounded refusal, no DIRECT fallback, no unwanted local DNS, correct UI/diagnostic |
| T06 | App-owned DoH, browser QUIC/UDP, IPv6-only/captive network | actual coverage and explicitly labeled unsupported/block/Direct exceptions; no fake universal no-leak status |
| T07 | Bad/corrupt profile, reload while active, negative proxy/chain credentials | previous accepted route persists where safe, never silently changes to Direct |
| T08 | Normal Stop, GUI crash, reboot/sleep-wake, upgrade/uninstall | OS filters/provider stopped, owned SSH children reaped, non-owned processes untouched, no orphan hooks |
| T09 | 10k churn, 24h soak, 64→512 attempted Windows SSH connection tiers | FD/HANDLE+RSS+latency+rejection counters, bounded limits, recovery and no leak |
| T10 | Compact 1366×768/4 DPI and macOS Retina, keyboard-only rule creation | all fields visible, correct captions/order/state, screenshots + human QA |

### Источники и границы проекта

- [Windows WFP Issue #1](https://github.com/i-shutov/flowbridge/issues/1); [macOS NE Issue #2](https://github.com/i-shutov/flowbridge/issues/2); [DNS Issue #5](https://github.com/i-shutov/flowbridge/issues/5); [UI/DPI Issue #6](https://github.com/i-shutov/flowbridge/issues/6); [SSH Windows exhaustion Issue #7](https://github.com/i-shutov/flowbridge/issues/7); [TCP resumption prototype Issue #4](https://github.com/i-shutov/flowbridge/issues/4).
- Existing acceptance procedures: [WFP VM](qa/WFP_REAL_VM_ACCEPTANCE.md), [Windows OpenSSH](qa/REAL_OPENSSH_CAPACITY.md), [Windows DPI](qa/WINDOWS_DPI_MATRIX.md), [macOS packaging](../packaging/macos/README.md).
- [Microsoft Driver Signing Options](https://learn.microsoft.com/windows-hardware/drivers/dashboard/driver-signing-offerings), [Microsoft cross-signing deprecation](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/deprecation-of-software-publisher-certificates-and-commercial-release-certificates), [Apple Network Extension Provider Deployment](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment), [Apple System Extensions signing](https://developer.apple.com/documentation/systemextensions), [Apple notarization](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution).
- Proxifier baseline: [Windows v4 TCP support](https://www.proxifier.com/docs/win-v4/index.html), [rule semantics](https://www.proxifier.com/docs/win-v4/rules.html), [fake IP and DNS tradeoffs](https://www.proxifier.com/docs/win-v4/dns.html).

**Release decision:** если хотя бы R01/R02/R03/R04/R05 обязательные проверки не закрыты, проект продолжает называться 0.x internal beta. Версия 1.0 не выпускается путём исключения трудных сценариев или изменения формулировки проверки.
