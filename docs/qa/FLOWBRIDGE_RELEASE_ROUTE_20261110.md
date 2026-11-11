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

## 2026-11-11 — W1 actual Windows 10 Pro run (owner-provided console)

Dedicated Windows 10 Pro machine, PowerShell 5.1, source-verified W1 script
`tools/windows/FlowBridge-Win10-R39-W1-Usermode.ps1` at GitHub commit
`7a7fe922fe19269c1d88b0e9823a9024b628b0d2`.
Owner's displayed script SHA-256:
`1ec1dbd479fb94b2bb85524108e36aa9d162f57aca52b298d523846b62ed5da0`.
Actual console verdict **`W1: PASS_NATIVE_USERMODE_ONLY; W3/G2: NO_GO`**.
The user provided a local absolute `w1-report.json` path but not its JSON
contents, compile/test logs or ZIP; thus **W1 is owner-reported PASS, not
independently artifact-reviewed**, and an exact native count must not be
inferred solely from console summary. The script requires all four source blob
checks, successful compiler tests and positive test counts before emitting
PASS; on a separate Windows hosted runner those same sources yielded 42/42.
No kernel load, WFP filter activation or G2 network acceptance followed.

Next: W2a actual Windows10 native **explicit SOCKS CLI** `cargo build --locked`
and loopback-only `tests/smoke.py` with full logs and exact source SHA; W2b
managed OpenSSH isolated fixture and GUI/installer to follow independently.

## 2026-11-11 — W2a product CLI smoke is runner-PASS; target Win10 pending

W2a script: `tools/windows/FlowBridge-Win10-W2A-SocksSmoke.ps1`,
source-pinned beta PR #56 commit `c339df2e4d20edf1d11d45786581a68451a71929`,
exact version after bounding Cargo to two compilation jobs:
`ce99492b87cd69a41148451caec19d319b18e17f`.
No separate runner, service or driver installed. It clones source into a
new evidence folder (one GitHub remote), verifies HEAD exact, builds CLI
with `cargo build --locked -j 2 -p flowbridge-cli --bin flowbridge`,
runs `capabilities` (transparent interception must remain false) and
executes `tests/smoke.py`: actual loopback-only SOCKS5 TCP black-box tests.
All logs and file SHA256 manifest are local. The script limits Cargo/cache,
Git checkout and output to its own evidence folder.

[Hosted Windows W2a #42985646597](https://github.com/i-shutov/flowbridge/actions/runs/42985646597)
**SUCCESS** on source `ce99492b87cd69a41148451caec19d319b18e17f`;
actual CLI built and test script passed. Earlier first full CLI evidence
run #42985334613 had independently extracted report `smoke_tests_run=9`,
`source_exact=true`, `capabilities_explicit=true`, no errors, ZIP CRC
PASS. The newer two-job run's uploaded artifact is #13839317294,
SHA256 `bed4b401ee9177df6a75027551f39cc76714a712374436b09fb46ada2055b28b`.
Both runs **deliberately** return `PASS_HOSTED_NON_TARGET_ONLY`:
Windows Server CI does NOT count as Windows 10 Pro W2a.

To be accepted on the target Win10, W2a must return
`PASS_NATIVE_WIN10_USERMODE_CLI_ONLY` and its original JSON+test logs
should be reviewed. This **is not W2b** managed real SSH / GUI installer,
and G2 native WFP remains **NO-GO**. Only explicit SOCKS traffic is tested.

## 2026-11-11 — target Win10 W2a tool discovery RCA and correction

User-provided elevated Windows 10 Pro W2a console on the original
`ce99492b87cd69a41148451caec19d319b18e17f` script returned
`W2a: FAILED_OR_BLOCKED`, `Notes: cargo not found; no installation performed`.
Source code stopped during **PATH-only executable discovery**, before
`git clone`, `cargo build`, SOCKS sockets or GUI. This is a **tool-discovery
blocker**, not a failed native FlowBridge TCP test; no beta release acceptance.

The previously accepted W1 script located `rustc.exe` through
`%USERPROFILE%\.cargo\bin` even when absent from PATH. W2a did not check
that location for `cargo.exe`. Corrected `FindCmd` searches PATH,
optional `-RustBinDirectory`, preexisting CARGO_HOME/bin and current
user .cargo/bin without modifying persistent environment or installing tools.
Also supports Python launcher `py.exe -3` when python.exe is not on PATH;
reports all absent tools in one explicit blocker record. Diagnostic
`-ToolDiscoveryOnly` never downloads sources or executes build/tests.

[GitHub Actions #42987932602](https://github.com/i-shutov/flowbridge/actions/runs/42987932602)
**SUCCESS** on exact W2a source commit
`b368b822e199c1bf3166ce481142fe8ec19e7938`:
1. Deliberately removed Cargo's installation directory from PATH and
   provided a non-executable CARGO_HOME/bin/cargo.exe marker; tool-discovery
   probe found it **without execution** and returned NOT_ACCEPTED.
2. Then restored the real hosted Windows environment, compiled the pinned
   beta CLI and executed real loopback SOCKS smoke: `PASS_HOSTED_NON_TARGET_ONLY`.
3. Artifact 13841380479 ZIP SHA256
   `7f5133186f4cde204f1317d612a4c95ca11a6477605295f7d9122be06f066e2e`.

**Next gate:** only an actual rerun on target Win10, with
`PASS_NATIVE_WIN10_USERMODE_CLI_ONLY` and the source report/logs, may
close W2a. If Cargo truly does not exist, no automatic install is performed.
W2b managed SSH+GUI and W3 native WFP remain OPEN / NO-GO.

## 2026-11-11 — W2a target Win10 missing Python: dependency-free 4-test fallback

Second owner-reported actual Windows 10 W2a attempt with the corrected
Cargo lookup returned `FAILED_OR_BLOCKED`, diagnostics
`Missing executable(s): python-or-py`. This occurred **before clone,
compile, and SOCKS test traffic**, so it is an environment prerequisite
failure, not a failing FlowBridge binary.

Avoid installing Python for this stage. The self-contained script
`tools/windows/FlowBridge-Win10-W2A-SocksSmoke.ps1` now treats Python
as optional, and automatically uses a **separate PowerShell/.NET SOCKS5
black-box subset** on Windows lacking both `python.exe` and `py.exe`.
It exercises four cases with real loopback sockets against the pinned beta
CLI: SOCKS5 CONNECT + binary byte parity, UDP ASSOCIATE denial,
policy BLOCK without contacting the target, and failed upstream without
DIRECT fallback. It does NOT claim the full **nine Python smoke tests**
or managed SSH, GUI, kernel WFP, DNS leak control, or full beta acceptance.

[Actions #42991667473](https://github.com/i-shutov/flowbridge/actions/runs/42991667473)
on actual source `f9e5a817907f34dbf1a96dd0a283afb68a4a211e`: **SUCCESS**,
Cargo tool discovery without PATH PASS, pinned source clone and
`cargo build --locked -j 2` PASS, and the four PowerShell/.NET
end-to-end SOCKS5 checks PASS on a disposable hosted Windows runner.
Report: `smoke_engine=powershell-native-dotnet`,
`smoke_tests_run=4`, `smoke_coverage=powershell_four_test_subset_not_python_nine_tests`.
Artifact 13842146603, archive SHA256
`dca1732a3f93de5800ee9c8ba6b23b7080ea54ed8b366a8f0726dd64d70b7b51`.
Hosted result is only `PASS_HOSTED_NON_TARGET_ONLY`.

**Open:** owner must run this exact script on Win10 and provide
`PASS_NATIVE_WIN10_USERMODE_CLI_ONLY` with original JSON/log evidence.
Only then can W2a be provisionally accepted; 4 tests do not establish
the original nine-test coverage or A0-A6 beta release signoff.
W2b, W3, G2 and release remain NOT_RUN/NO_GO.

## 2026-11-11 — W2a completed on target Win10 (owner-generated native evidence)

The owner ran exact source-pinned W2a from commit
`f9e5a817907f34dbf1a96dd0a283afb68a4a211e` on the separately
authorized Windows 10 Pro x64, with the PowerShell-only TCP subset.
Reported local script SHA256:
`919f8eb231e040ed8ff3d248a792bf90b4cc877584d0a0fda9a8c5c5afae8608`.
Console returned **`W2a: PASS_NATIVE_WIN10_USERMODE_CLI_ONLY`**,
`W2b: NOT_RUN`, `W3/G2: NO_GO`.

Native report path was returned locally in
`C:\ProgramData\FlowBridge\W2A-Evidence\` and original owner-produced
ZIP SHA256 was
`66376d65d27b7640c2e9a215b152530880e701a8c5ac2572810b584c4ea0b56f`.
We have **not** downloaded/reviewed that private ZIP or `w2a-report.json`;
the accepted scope is owner-observed CLI+4 local TCP smoke, not independent
binary reviewer verification or Windows GUI/SSH. No driver, BFE session or
physical G2 native capture was installed/activated; product release is NO-GO
until full A0–A6 independent acceptance.

Next W2b: consume **the already built exact-SHA W2a executable**, do not
clone/rebuild automatically, and verify OpenSSH client/signature, managed
profile denial guards and fail-closed loss behaviour on the target Win10.
Any actual SSH authentication, native GUI installer and upgrade tests
remain separate gates until observed.

## 2026-11-11 — W2b-0 preflight: hosted exact-source managed SSH safety guards

W2a already passed on the owner's target Win10. The next action does **not**
rebuild Cargo or need Python: `tools/windows/FlowBridge-Win10-W2B0-ManagedPreflight.ps1`
finds the newest **locally completed** W2a JSON, verifies the exact pinned
PR #56 source SHA `c339df2e4d20edf1d11d45786581a68451a71929` and
compares the previously built CLI executable SHA against W2a manifest.

It reports the currently installed system OpenSSH executable
(Authenticode/Microsoft signature), optional ssh-keygen/sshd and
PATH-visible GUI build prerequisites (CMake/MSVC/NSIS). It launches
the *own exact-source CLI only* for three invalid managed profiles that
MUST be rejected **before** an SSH client is started:
1. missing exact consent string;
2. automatic/direct route disallowed in managed beta;
3. missing explicit SSH identity path.

The expected *reason* must match each case, not merely any nonzero exit.
The test creates only its own JSON/log files, uses no external SSH target,
makes no SSH connection, installs no service/driver and changes no network
or Windows security settings. W2b1 real SSH authentication and W2b2 GUI/
installer are separate **OPEN** gates.

[Hosted Windows CI #42998744754](https://github.com/i-shutov/flowbridge/actions/runs/42998744754):
**SUCCESS** at W2b0 script commit
`7d6583c711bd4675934bb928ece5dc21a5416e0a`, three exact
negative cases PASS, actual Microsoft-signed `ssh.exe` verified on
the hosted Windows runner. Original artifact 13844199728 SHA256
`0c198a4f2cf5cf3636756ded1c520a0d832fa808887f0edb379fe517614c956e`.
This is `PASS_HOSTED_NON_TARGET_CONFIG_DENIAL_ONLY` — **not** Win10
native W2b0 acceptance. Actual target execution of the same script
is next. W3/G2 and release remain NO-GO.

## 2026-11-11 — W2b0 native target completed; W2b1 isolated SSH next

Owner PowerShell output on the dedicated Windows 10 Pro machine:
`W2b0: PASS_NATIVE_WIN10_CONFIG_DENIAL_ONLY; W2b1 SSH: NOT_RUN;
W2b2 GUI: NOT_RUN; W3/G2: NO_GO`, using `W2b0` script commit
`7d6583c711bd4675934bb928ece5dc21a5416e0a`.
Displayed script SHA256:
`50dfc5d66ca395430331ce4492d118f04d977cd8f4895acbdcb18847129f08cd`.
Locally generated evidence ZIP SHA256:
`6b95fd8fb12a44216b62a9224143a97229528050711ec33e6d07e557687b4fc9`.

This is **owner-reported positive native W2b0**, requiring later independent
review of actual JSON/logs; it validates explicit managed SSH *configuration
denial* gates only. It does NOT authenticate over SSH, launch a managed
ready session, prove SSH child cleanup, exercise GUI/installer, or change
WFP/ALE native G2 verdict.

Next W2b1 is a strictly isolated loopback SSH fixture with
ephemeral keys and exact-source W2a-built user-mode CLI. No system
SSH service or driver installation, firewall/proxy/registry changes,
global TestSigning, login password reuse, or external SSH target.
