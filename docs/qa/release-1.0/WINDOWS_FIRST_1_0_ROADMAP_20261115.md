# FlowBridge — Windows-first релиз 1.0: актуальный план

> Решение владельца от **15 ноября 2026**: первый полноценный релиз FlowBridge ориентирован на **Windows 10 Pro 22H2 x64 и Windows 11 Pro x64**. Кроссплатформенная архитектура обязательна; выпуск macOS и физическая macOS NE-приёмка переносятся в отдельный последующий платформенный релиз. Это изменение *приоритетов и обязательной матрицы выпуска*, не признание невыполненных macOS тестов успешными.

**Актуальный статус: Windows 1.0 NO-GO; Windows beta 0.3.0-beta.1 NOT_RELEASED.** Для всех защищённых режимов требуются реальные native доказательства. Исторический общий 19-gate реестр сохраняется: [gate_status_20261113.json](gate_status_20261113.json). Новый независимый Windows-gate реестр: [WINDOWS_FIRST_GATES_20261115.json](WINDOWS_FIRST_GATES_20261115.json).

## Обновление 16 ноября 2026 — новый source-of-truth статус

> **Новый контрольный срез:** [WINDOWS_FIRST_RELEASE_REBASELINE_20261116.md](checkpoints/WINDOWS_FIRST_RELEASE_REBASELINE_20261116.md). Исходное решение о Windows-first от 15 ноября не меняется. **Не объявлять релиз по количеству зелёных CI.**

| Маршрут | Фактический результат | Открытый release gate |
| --- | --- | --- |
| **Windows explicit SOCKS 0.3.0-beta.1** | На Win10 Pro реальный frozen kit: native automated install/payload/GUI smoke/upgrade/uninstall/stable preservation **6/6 PASS**; оригинальные JSON/5 BMP и SHA-256 независимо проверены [PR #73](https://github.com/i-shutov/flowbridge/pull/73). | **A3 interactive GUI и настоящий exact-kit managed SSH ещё не выполнялись**, затем отдельная Win11, A5 license/security/legal, A6 reviewer и A7 GO/tag. |
| **Codex на Win10** | Владелец делегировал GUI/SSH QA локальному агенту, не будет сам нажимать GUI. [Готовое pinned-задание](https://github.com/i-shutov/flowbridge/blob/48e7d15ee433fcb949ea866ff356563f4ee1436a/docs/qa/release-1.0/checkpoints/A3_WIN10_CODEX_AUTONOMOUS_GUI_SSH_TASK_20261116.md). | `CODEX_NOT_EXECUTED_OR_ORIGINAL_EVIDENCE_NOT_RECEIVED`. Принятие только после реальных действий и независимого ZIP-review; не повторять 6/6 без причины. |
| **Windows-first 1.0 G2/WIN-01** | WFP stack [#69–#72](https://github.com/i-shutov/flowbridge/pull/72): ABI4 CLAIM и hard-PERMIT veto, source/WDK PASS. Но driver ещё не был подписан и запущен в native Win10/11. | **P0:** доказанная связь AUTH/CLAIM с kernel socket object, поколение+reclaim tickets, reauthorization, реальное BFE/SSH/no-DIRECT/driver rollback. |
| **Native SSH capacity** | У frozen beta hosted managed SSH: 128 held/1152 rejected/10k churn/4 workers PASS. В отдельной direct OpenSSH пробе [#43823314443](https://github.com/i-shutov/flowbridge/actions/runs/43823314443) запрошенные 512 не достигнуты, около 244 удержано и Windows sshd показал resource errors. | Без универсальной цифры «max 244». Измерить реальный safe ceiling, 251/252, owner Win10/11 и 24h soak. |
| **1.0 CI/release** | В PR #72 4/5 workflows SUCCESS; общий Rust/native FAIL из-за macOS test port race, отдельно исправлен в [PR #74](https://github.com/i-shutov/flowbridge/pull/74). PR #74 portable-core SUCCESS, независимый Windows raw OpenSSH workflow FAIL. | Свести изменения в интеграционную RC-ветку и повторить exact-head CI, не скрывая raw SSH ресурсный отказ. |

**Граница релизов:** в Windows `0.3.0-beta.1` разрешена только честная explicit SOCKS функциональность. `1.0` требует полноценного выбранного transparent TCP и физического fail-closed. Mac NE/нотаризация отложены на следующий платформенный релиз, но Rust-core CI остаётся обязательным. Никаких разрешений на установку экспериментального WFP-драйвера на существующий пользовательский QA-хост данное обновление не даёт.

## 1. Что именно выпускаем первым

| Параметр | Windows 1.0 |
| --- | --- |
| ОС | Windows 10 Pro 22H2 x64 (с явной оговоркой о жизненном цикле Windows 10), Windows 11 Pro x64; обе требуют отдельных нативных испытаний |
| Назначение | Нативный пользовательский GUI и **прозрачный TCP-перехват выбранных процессов** без ручного SOCKS в каждом приложении |
| Маршруты | Proxy / Chain / Direct / Block и объяснение причины выбора, первое совпадение правил, выбранное приложение × host/CIDR × port |
| Транспорт | Общий Rust: SOCKS5/SOCKS4a/HTTP CONNECT, проверенный SSH SOCKS5 через управляемый OpenSSH 1–4 процесса |
| Гарантия | Никакого молчаливого DIRECT для выбранного защищённого соединения при неопределённом владельце, отсутствии доверенного kernel-ticket или отказе SSH |
| DNS/UDP/QUIC | Ограничения чётко отображаются. Недоказанные защищённые сценарии блокируются или protected mode не включается; не обещать универсальный no-leak |
| Дистрибуция | Подписанные и проверенные Windows бинарники/соответствующий драйвер, безопасные Install/Upgrade/Uninstall, rollback, защита конфигурации и пользовательских секретов |
| Не входит в Windows 1.0 | macOS app/NE, notarization, Apple Intel/ARM native release QA, macOS-specific DNS и VoiceOver; они **отложены, а не зачтены PASS** |

Сохранение действующих TCP-сессий после физического разрыва SSH, UDP-over-SSH, NTLM/Kerberos и полная совместимость со всеми функциями Proxifier **не обещаются**. Ограничения должны быть отражены в UI и release notes.

**Безопасность Windows 10 в 2026 году:** обычная поддержка Windows 10 22H2 закончилась **14.10.2025**. Мы сохраняем Win10 Pro в матрице совместимости, но до заявления о безопасности защищённого продукта требуется проверить получение актуальных ESU/security updates на конкретном стенде. Наличие работающей беты на необновляемой ОС не доказывает безопасность всей системы. Официальные сведения: [Microsoft lifecycle](https://learn.microsoft.com/en-us/lifecycle/announcements/windows-10-end-of-support) и [ESU](https://www.microsoft.com/en-us/windows/end-of-support). 
## 2. Жёсткий P0: подлинное происхождение Windows-соединения

**Разрешённая продуктовая архитектура обновлена 15.11.2026:** владелец явно санкционировал разработку и испытания WFP/ALE для Windows 1.0, см. [PR #69](https://github.com/i-shutov/flowbridge/pull/69). NDISRD остаётся изолированным ранее разрешённым направлением и не объявляется рабочим решением G2: `INTERMEDIATE_BUFFER` не содержит доверенного packet→PID+epoch. IP Helper/ETW 5-tuple snapshots не заменяют kernel-origin witness. Утверждённое направление WFP/ALE не означает утверждённую подпись, готовность драйвера к установке или native G2 GO. [Актуализированный архитектурный checkpoint](../WINDOWS_G2_BACKEND_DECISION_20261113.md).

**Задача блока WIN-01** — зафиксировать один *реально доказуемый* контракт packet/accepted-socket→kernel-origin process identity→epoch→policy generation→original destination→SSH/no-DIRECT. Если с разрешённым NDISRD это доказательство получить невозможно, прекратить итерации с корреляционными эвристиками. **WFP/ALE теперь выбран для разработки и испытаний**, но не для неограниченного развёртывания: требуется подписанный драйвер, тестовая Windows VM, backup/rollback/VNC и независимая native приёмка. Переход на сторонний лицензируемый driver вместо WFP по-прежнему потребует нового разрешения.

Текущая ветка `research/windows-wfp-ale-attribution-20261107` и исследования R182–R195 — доказательные модели/источниковый аудит, **не** production G2. R195 указывает на disconnected legacy WITNESS producer в исследовательском R19; нельзя считать это physical packet receipt. Пока WIN-01/WIN-02 не пройдут, protected прозрачный режим не выпускать. Выпуск меньшей explicit SOCKS beta — отдельный честный продуктовый путь, не переименованный в 1.0.

## 3. Блоки исполнения в порядке разблокирования 1.0

| Блок | Реальная инженерная работа | Объективный выход |
| --- | --- | --- |
| **WIN-00 Scope** | Windows-first SKU/OS/security claims, реестр исходных SHA, baseline CI | План согласован, независимые Windows gates созданы, **не** Release GO |
| **WIN-01 Kernel authority** | Подтвердить процесс + epoch + original destination с доверенным общим идентификатором в утверждённом backend; выбрать backend только с разрешением | Из реального нативного драйвера authenticated ticket, враждебные PID/tuple-reuse тесты, audit witness; не snapshot-корреляция |
| **WIN-02 Real TCP path** | На Win10/11: selected EXE→driver/accepted socket→Rust→owned SSH→remote echo, IPv4/v6, loop exclusion | Нативный packet/connection provenance, точный source SHA + binary SHA + pcap и byte parity |
| **WIN-03 Protected fail-closed** | SSH outage, policy/BFE/driver loss, reauth, crash/Stop, overcapacity и unknown identity | Нет выбранного DIRECT, независимый egress capture, безопасный rollback |
| **WIN-04 DNS/UDP/IPv6** | Resolver scope, selected-app DNS, remote hostname, split-LAN, browser DoH/QUIC, unsupported UDP block/deny | Uncached unique domains + packet traces с обеих сторон, IPv4/v6, отсутствует молчаливый fallback |
| **WIN-05 SSH endurance** | 1–4 owned OpenSSH workers, 251/252, host-key failure, 128 held/1152 reject, churn 10k и 24h soak | Счётчики ресурсных пределов и Win10/11 owner-native SSH proof; raw512 не выдавать за PASS |
| **WIN-06 Windows UX/rules** | Компактный Win32 GUI: app selector, Proxy/Chain/Direct/Block, explain, atomic Apply/Stop, status/export, keyboard/DPI | GUI screenshots + независимое интерактивное QA 1366×768, DPI 100/125/150/200, полная корректность правила |
| **WIN-07 Installer/security** | Согласованная лицензия, signed release + driver provenance, ACL/secure-store, update/uninstall/rollback | Нативное Win10/11 install/upgrade/uninstall, профиль сохранён, нет хвостов/секретов |
| **WIN-08 Frozen RC/native** | Одни и те же SHA проходят полноразмерные выбранные/невыбранные TCP+DNS+crash/Stop+soak Win10 и Win11 | Оригинальные JSON/pcap/BMP/логи, OS/build, exact SHA256, ноль P0 SKIP/UNKNOWN |
| **WIN-09 Independent GO** | Независимая физическая, security/legal и интерфейсная приёмка; явное решение владельца | Только после всех WIN-01–08: подписанные байты=тестовые байты, changelog/SBOM, Windows 1.0 tag/release |

**Параллельные работы без отвлечения от G2 (16.11):** frozen Windows explicit beta source `f5ecd48d8f81c594f755a55e7969b57d20903020` теперь имеет **Win10 owner automated 6/6 PASS с независимо проверенными оригинальными JSON/BMP** ([PR #73](https://github.com/i-shutov/flowbridge/pull/73)); оставшийся *интерактивный* GUI и SSH exact-kit поручены локальному Codex по [pinned ТЗ](https://github.com/i-shutov/flowbridge/blob/48e7d15ee433fcb949ea866ff356563f4ee1436a/docs/qa/release-1.0/checkpoints/A3_WIN10_CODEX_AUTONOMOUS_GUI_SSH_TASK_20261116.md), ещё **не приняты**. Отдельная Win11 owner native, A5/A6/A7 открыты. A4 Mac deferred и не блокирует Windows-only beta/1.0.

## 4. Оставляем архитектуру по-настоящему кроссплатформенной

1. **Единое Rust-ядро:** `flowbridge-core`, `net`, `runtime`, `tunnel`, `ffi` сохраняют версионированный профиль/первые совпавшие правила, Proxy/Chain/DIRECT/BLOCK, SSH lease/Stop, потоковый I/O и диагностику. Не добавлять WinAPI, NTSTATUS, NDISRD/ETW structs и Windows пути в общую policy модель.
2. **Явная граница `CaptureAdapter`:** Windows-specific источник подлинной identity+epoch, original destination, family, protocol и kernel session generation; macOS позже поставит независимо подтверждённые NE signing/audit сведения через **тот же семантический контракт**. Не выполнять policy на недоверенных PID/tuple данных.
3. **Единый FFI/API контракт:** версия DTO, состояния Ready/Paused/Failed, причина отказа и объяснение правил; платформенные детали только в adapter/evidence. Устойчивые отрицательные сценарии переиспользуются в Linux/macOS CI без эмуляции native acceptance.
4. **Платформенное UI и packaging:** Win32 сейчас первичный и выпускаемый; SwiftUI/NE, подписи/entitlements и macOS lifecycle сохраняются в отдельных ветках/PR без изменений общего core из-за Win32 UI.
5. **CI:** полный Windows user-mode и Rust/FFI test matrix в каждом интеграционном PR. Linux/macOS *portable-core build/unit regressions* продолжаются для недопущения регрессии кроссплатформенности. Прежние macOS подписанные/native activation и ручные GUI тесты **не являются релизными Windows 1.0 gates**.
6. **Не смешивать угрозы:** `DIRECT` возврат macOS NE, NDISRD frame trust и WFP ALE redirect authorization — разные доказательные границы. Ни одна не подменяет другую.

## 5. Правила управления выпуском

- Windows 1.0 release gate определяется только `WIN-00…WIN-09`, см. [машинный контракт](WINDOWS_FIRST_GATES_20261115.json). Старые R02/R04 macOS остаются `accepted=false`; их отсутствие не является основанием ложно пометить всю 19-gate матрицу PASS.
- Не выполнять опасные системные операции на рабочих машинах: driver install/load, WFP/NDISRD filter changes, firewall/Defender/BFE/SecureBoot/BCD/UAC без отдельного допуска на изолированный стенд и rollback.
- В каждом блоке: `branch/head SHA → точный CI run/job → native scenario → оригинальный artefact + SHA256 → независимый verdict`. Hosted PASS ≠ Win10/Win11 owner/native.
- Продолжать крупными блоками, фиксировать чекпойнт в `docs/qa/release-1.0/checkpoints/`, не засорять корень репозитория микродокументами.
- Существующие PR #60/#63/#65/#66 на macOS **сохранить**; не сливать в Windows-продукт без необходимости. Новые macOS фичи до выхода Windows 1.0 не являются приоритетом.

## Исторические контрольные факты на 15 ноября 2026 (заменены срезом выше)

- `main` на момент обновления: `5b5afc2feeda2195f302380e615ba003d4906e09` — Windows 1.0 ещё не интегрирован.
- Windows kernel G2: `NO_GO`, по issue #41; peer snapshot ≠ per-packet connection provenance.
- Frozen Windows beta: hosted 6/6 PASS, owner Win10/Win11 still NOT_RUN, release still NOT_APPROVED.
- Project-wide 19 legacy accepted flags остаются FALSE; новый Windows release contract тоже `windows_1_0_accepted=false`.

**Итоговая политика:** Windows 1.0 действительно включает прозрачный защищённый режим; Mac следует позже на общем Rust-ядре. Никаких переименований beta, отключения P0 Windows проверки или зелёных `SKIP` ради релиза.
