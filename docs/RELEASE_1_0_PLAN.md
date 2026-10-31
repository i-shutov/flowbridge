# FlowBridge — исполнимый план до 1.0

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
