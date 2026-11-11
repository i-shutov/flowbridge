# FlowBridge — актуальный исполнимый план релиза (10.11.2026)

**Этот документ заменяет устаревший статус от 30 октября, а не исторические доказательства.**
Требования к полной версии остаются в [RELEASE_1_0_PLAN.md](../RELEASE_1_0_PLAN.md).
Статус утверждения: только инженерный план, **релиз не принят**.

## 1. Контрольные точки

| Объект | Точное состояние | Решение |
| --- | --- | --- |
| Product main | SHA 5b5afc2feeda2195f302380e615ba003d4906e09; FlowBridge 0.2.0 | Прежняя локальная SOCKS beta |
| SOCKS-only | [PR #56](https://github.com/i-shutov/flowbridge/pull/56), Draft, SHA c339df2e4d20edf1d11d45786581a68451a71929, 110 файлов | Скоуп одобрен, **не принят к выпуску** |
| Research WFP/ALE | research/windows-wfp-ale-attribution-20261107; SHA при проверке 992a84b87c328483e08744d98ac5051183914066 | R91 source-level NO-GO; не вливать в beta |
| Win11 lab | [PR #57](https://github.com/i-shutov/flowbridge/pull/57), Draft | Инструменты и тестовая подпись через hosted Windows; НЕ физическая загрузка |
| Win10 x64 target | Отдельная Windows 10 Pro 22H2 build 19045, установлен агент dot; командная сессия на этой машине ранее работала | Целевой стенд для user-mode и **позднее** native WFP |
| GitHub Releases | Публичных релизов при ревизии нет | v0.3.0-beta.1 и v1.0.0 — целевые названия |

Идентификатор компьютера, имя учётной записи, доступы, закрытые ключи и
инвентарь защищённой инфраструктуры не фиксируем в публичном документе.
Read-only диагностика получает точный hostname **локально**, аргументом.

На Win10 раньше подтверждены Git 2.56, VS Build Tools 2022, MSVC и SDK;
не доказано, что все доступны в **текущей** учётной записи и PATH.
Текущий процесс администратора был medium-integrity (UAC не elevated).
CIM/WMI иногда возвращал Access Denied. Компьютер dot/Work может быть
зарегистрирован, но это не переносит удалённую оболочку автоматически
между разными чатами. До получения новых логов **native PASS не существует**.

## 2. Две независимые линии выпуска

**A. Ближайшая тестовая beta v0.3.0-beta.1.**
Только явный SOCKS5/SOCKS5h, управляемый OpenSSH, CLI, GUI и локальные
Windows/macOS пакеты. Не заявлять прозрачный захват arbitrary EXE,
kernel-process identity, WFP/NDISRD, системный no-DIRECT/kill switch,
проксификацию UDP/QUIC или общую DNS leak protection.
Без издательской подписи — ограниченная, явно помеченная dev/beta.

**B. Full v1.0.0.**
Windows 10/11 x64 с доказанным ALE_CONNECT_REDIRECT v4/v6 и авторизованным
AUTH_CONNECT, жизненный цикл оригинального EXE/epoch, принадлежность
accepted SOCKET и real SSH socket records; macOS реально активированная
подписанная Network Extension; доказанные DNS/IPv6/UDP границы,
подписанные пакеты, rollback/upgrade, 10k churn и soak.
Успех A не повышает G2 до PASS.

## 3. Кратчайший путь к v0.3.0-beta.1

| Work package | Действие | Приёмка | Сейчас |
| --- | --- | --- | --- |
| A0 | Из PR #56 отделить только explicit SOCKS + supervised OpenSSH от 110-файловой WFP/NDISRD интеграции | Чистая release branch, no kernel installer/filter/transparent claim | OPEN |
| A1 | Заморозить точный SHA; cargo fmt/clippy/unit, DNS, Windows/Linux/macOS native | Весь обязательный **beta-scope** CI PASS на одном SHA с артифактами | PARTIAL |
| A2 | Изолированный managed-SSH 64/128 streams, bad host key, half-close, overload, Stop/reconnect, 10k churn | Исходные логи, byte parity, отсутствие DIRECT fallback для принятых SOCKS клиентов | PARTIAL |
| A3 | Win10 Pro x64: CLI + GUI, русские пути, установщик, upgrade/uninstall, loopback SSH | Нативные user-mode доказательства от **целевой** Windows, без драйвера/UAC | NOT_RUN |
| A4 | macOS universal: реальная сборка .app/.pkg, запуск, SOCKS, GUI, install/update/remove | Статус **local app** без заявленного activated NE | PARTIAL |
| A5 | Упаковка, сторонние лицензии/SBOM, SHA256SUMS и release notes | Источник/пакет/хеши сверены, scope ограничен | OPEN |
| A6 | Независимый reviewer: no P0 в **explicit SOCKS-only** scope | Матрица PASS/FAIL без замены native FAIL на фиктивный успех | OPEN |
| A7 | Тег и GitHub prerelease, 2 пакета, проверка скачивания | Только после A0–A6 | NOT_RELEASED |

Состояние проверенного beta SHA c339df2e:
- [Rust CI 42339966411](https://github.com/i-shutov/flowbridge/actions/runs/42339966411):
  5/5 jobs SUCCESS.
- [DNS CI 42339966468](https://github.com/i-shutov/flowbridge/actions/runs/42339966468):
  3/3 jobs SUCCESS.
- [G2 Capture 42339966586](https://github.com/i-shutov/flowbridge/actions/runs/42339966586):
  FAILURE: native ETW kernel connection ID не доказывает NDISRD frame ownership;
  исключение из **beta-scope** допустимо только с явной границей продукта,
  но сам FAIL остаётся документирован.
- [Windows OpenSSH 42339966362](https://github.com/i-shutov/flowbridge/actions/runs/42339966362):
  managed 128 SUCCESS; отдельный raw-512 FAIL после 244 успешных
  соединений с WinError 10054; raw-512 не выдавать за ACCEPTED.
  Если релиз обещает raw-512 — P0 blocker, без такого обещания
  независимая приёмка managed admission обязательна.
- Исторические G1 10/10 PASS относятся к другому source SHA и
  не переносимы на PR #56 / R39.

## 4. Исполняемый план использования отдельной Win10 Pro

Нет необходимости создавать nested Windows 11 VM на четырёх гигабайтах.
Готовая Win10 Pro — другая платформа, пригодная для отдельных испытаний,
но она **не** покрывает целевую матрицу Windows 11.

| Gate | Что выполняем на Win10 | Доказательство | Права/безопасность |
| --- | --- | --- | --- |
| W0 | Read-only inventory через tools/windows/flowbridge-win10-readonly-inventory.ps1, точный hostname аргументом | OS build/x64, current user integrity, tools, SDK/WDK, Secure Boot info, локальный JSON+SHA | Обычная учётная запись, без UAC |
| W1 | Exact-source Rust/cargo, MSVC, WinSock R83, broker/policy/hand-off unit + negative, compile only | SHA исходников и утилит, stdout/stderr, zero driver load | Non-admin, никаких фильтров |
| W2 | Реальные EXE GUI/CLI/SOCKS5h, контролируемый локальный SSH fixture, install/uninstall | Результаты приложений и журнал, no direct fallback в explicit scope, native Win10 user-mode | Только собственные user-mode процессы, не системные настройки |
| W3 | Независимо проверить emergency VM console/VNC, SYSTEM rescue, snapshot/rollback, physical egress observer, hash-pinned signed driver, UAC elevated/admin | Signed approval **на этой Win10 VM**. Без всех доказательств остаётся NO-GO | Требует отдельного протокола допуска |
| W4 | Controlled driver load; actual unprepared EXE → WFP ALE redirect v4/v6 → AUTH → accepted-socket CONTEXT/RECORDS → CLAIM → real outbound SSH → exact bytes | Сквозная физическая трасса с независимым наблюдателем | Только после W3, отдельная лабораторная процедура |
| W5 | Negative twin EXE, PID reuse/epoch, original process exit after CLAIM, remote/local bind, BFE/SSH failure, no-DIRECT, DNS/UDP/QUIC scope | Native FAIL/PASS без угадывания происхождения пакета; cleanup/rollback | Только после W3/W4 |
| W6 | Отдельная Win11 x64 + macOS NE acceptance | Полная матрица 1.0 | Нельзя закрыть одним Win10 host |

**Run W0 на хосте, а не на GitHub runner:** сохранить JSON локально,
сверить hostname и текущий токен. Скрипт ничего не устанавливает,
не перезапускает, не делает сетевых подключений, не читает пароли и
не включает TESTSIGNING. Создаёт только явно заданный отчёт.
Пример аргументов передаётся из приватной Work/dot сессии, не хранится
в открытой GitHub ветке.

Для W1/W2 источники: подписанный/контрольный исходный SHA из GitHub
и тестовые ключи/loopback fixture. Никакие реальные пользовательские
SSH-ключи, внешний интернет, production proxy или Win Server не нужны.
Проблема UAC в текущем Admin не блокирует W0–W2. Принудительное
повышение UAC и обход из локального агента запрещены.

## 5. P0 для native — latest source-level research, НЕ физические FAIL

- **R91:** глобальный kernel process ledger хранит до 256 eligible owners;
  unrelated process churn/PID reuse может необратимо запретить новые
  selected flows. Перед native soak требуется scoped ledger + правила памяти.
- **R90:** явно заданный local source IP может блокировать поток до ticket;
  отдельно проверить IPv4/IPv6 source-bind, не превращая отказ в DIRECT.
- **R87:** два документа Microsoft противоречат друг другу о наличии
  ORIGINAL_DESTINATION и LOCAL_REDIRECT_TARGET_PID на AUTH_CONNECT;
  измерить действительные metadata bits при native callback.
- **R80:** синхронный WSAIoctl + worker join способен не дать закрыть dynamic
  BFE session. Нужны bounded cancellation и отдельная fail-closed cleanup gate.
- **R41/R42:** origin exit после CLAIM не отменяет уже принятую SSH сессию
  без authenticated per-ticket event.
- **R88/R89:** original-AppId SSH self-block и destination namespace;
  отдельные native negative tests, не выводить из user-mode метрик.

Это пока source/doc/model NO-GO, не наблюдения traffic leak.
Research branch управляется отдельным исследовательским исполнителем.
Нельзя автоматически переносить её наработки в beta/main и считать
статистику unit tests доказательством native WFP.

## 6. Критерии GO и чекпойнты

1. Назначить product integrator: freeze A0, exact-source A1–A6,
   reviewer подписывает checklist без P0; только после этого prerelease.
2. Восстановить практический доступ к Win10 в том Work/dot-сеансе,
   где реально работает Computer Use/команды. Наличие dot само по себе
   не передаёт мне удалённую сессию в этот чат.
3. Сначала W0–W2 и отдельные JSON/logs; W3–W5 с kernel load только
   при доказанном rollback/VNC/SYSTEM/observer, не на Windows Server.
4. После каждого шага сохранять source SHA, script SHA, OS build,
   executor identity (без секретов в публичном отчёте),
   реальные файлы/хеши, причину отказа и reviewer verdict.
5. **v0.3.0-beta.1: NOT_ACCEPTED** до A0–A6.
   **v1.0.0: NO_GO** до W3–W6, Mac NE, production signatures и RC.


## 2026-11-11 — Win10 W0 observed; W1 script ready, target execution pending

The owner supplied actual elevated PowerShell stdout on the dedicated Win10 Pro
x64 machine: `W0: READONLY_HOST_CONFIRMED, W1: NOT_RUN, W3: NO_GO`.
The locally generated diagnostic ZIP SHA256 was
`a36f695e60361e4b8d568b3c11d835270f077d48dc649c48b8072865ec4ff828`.
This is **owner-submitted native stdout**, not an independently retrieved
inventory.json/ZIP or a physical kernel-driver test. Do not convert W3/G2 to GO.
The exact Run W0 executable SHA256 and precise host identity remain in the
user's private evidence; do not store device names or account identifiers here.

Next W1 uses [fixed-source user-mode script](../../tools/windows/FlowBridge-Win10-R39-W1-Usermode.ps1)
with source commit `992a84b87c328483e08744d98ac5051183914066`,
per-file pinned Git blob checks, and 4 separate Rust test executables.
[Hosted Windows source-and-compile CI #42981695756](https://github.com/i-shutov/flowbridge/actions/runs/42981695756):
**SUCCESS: 42/42** (handoff 19, ledger 11, auth_appid 7,
broker lifecycle 5), on **Windows Server 2025**, hence labeled
`PASS_NON_TARGET_HOST_ONLY`. This does not prove W1 on target Win10 and
never installs/loads the kernel driver. The script produces JSON, per-suite
logs, a ZIP and SHA256 manifest in its own evidence folder. If rustc is
missing, it reports a toolchain blocker and leaves Windows unchanged.
