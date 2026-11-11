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
между разными чатами. По состоянию на **11.11.2026**, владелец предоставил консольные результаты **W0–W2b2 PASS**. Первоначальная строка относилась к исходной ревизии плана; независимая проверка ZIP/JSON ещё открыта.

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
| A3 | Win10 Pro x64: CLI + GUI, русские пути, установщик, upgrade/uninstall, loopback SSH | Нативные user-mode доказательства от **целевой** Windows, без драйвера/UAC | **OWNER-REPORTED PASS W0–W2b2**; отдельная проверка JSON/ZIP ещё открыта |
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

## 2026-11-11 — W2b1 isolated real SSH ready, tested on hosted Windows

Script: `tools/windows/FlowBridge-Win10-W2B1-RealSSH.ps1`,
fixed tested commit `8bc657db2f3b3824b594bf0360779429063c80bc`.
On the target Win10 this will reuse the **already accepted** W2a
source-pinned `flowbridge.exe` and its SHA from `w2a-report.json`;
no Cargo rebuild or Python dependency.

The test uses a pinned Microsoft-signed portable OpenSSH 10.4 preview
server fixture (official ZIP SHA256
`b67ff8becd203502190ec42ac7787c24c2cd3325ed7700485fe7a1c83d2a7957`)
without installing any Windows sshd service. It verifies the existing
Microsoft-signed SSH client/keygen, generates only ephemeral keys and
an isolated SSHD config under a fresh evidence directory, binds SSHD
strictly to 127.0.0.1, and establishes a real authenticated flow
through `flowbridge serve-managed` and its user-owned OpenSSH -D child
to a local TCP echo listener. Checks exact response-byte parity and
that the owned SOCKS listener closes on forced termination of only the
owned FlowBridge process; deletes ephemeral private keys before
packaging evidence. No firewall, DNS, system service, host keys,
TESTSIGNING, driver or WFP/BFE mutation.

[Hosted Windows Action #43001150579](https://github.com/i-shutov/flowbridge/actions/runs/43001150579)
**SUCCESS** at tested source `8bc657db2f3b3824b594bf0360779429063c80bc`.
The completed original evidence JSON was independently extracted from
artifact 13846955153 (archive SHA256
`3c277587c74ec8a6aad9bd859b026e519cd164a709d355c4cb0ed4e43ced0ae4`);
ZIP CRC validated. Results:
- `W2b1=PASS_HOSTED_NON_TARGET_REAL_SSH_LOOPBACK_ONLY`
- `real_ssh_authenticated=true`, `bytes_returned=16`,
  `ssh_child_owned=true`, `managed_owner_shutdown_cleanup=SOCKS_LISTENER_CLOSED`
- `ephemeral_keys_deleted=true`, `problems=[]`, `G2=NO_GO`

The native target Win10 W2b1 result remains **NOT_RUN** until this
exact version executes there. The SSH test proves neither Windows kernel
capture/PacketBound nor direct/UDP/DNS leak protection and does not
cover the GUI/installer W2b2, 128-channel/10k high-load acceptance,
upgrade, or macOS NE. Limited beta release A0–A6 remains open.

## 2026-11-11 — W2b1 physical Win10 owner report, full real SSH loopback

The owner executed source-pinned `FlowBridge-Win10-W2B1-RealSSH.ps1`,
source commit `8bc657db2f3b3824b594bf0360779429063c80bc`,
on the separately authorized physical Windows 10 Pro x64 target
in elevated PowerShell. The console returned:

```text
W2b1: PASS_NATIVE_WIN10_REAL_SSH_LOOPBACK_ONLY
W2b2 GUI: NOT_RUN
W3/G2: NO_GO
```

Displayed script SHA-256:
`b331ed3abcf06f2f6171ecc0585ee534c2926ac2ffd8dd866320e61414959e75`.
Owner-produced local evidence-only ZIP SHA-256:
`9b8c964e419d44a4f6404750f6c3bf117265f7e5f8d7582770488f86c86ec1a9`.

This is **owner-observed native W2b1 PASS**, not independent
review of private JSON, all original process logs, or a network
observer/remote destination proof. The script's internal positive gate
requires actual managed SSH TCP byte parity, pinned official portable
OpenSSH fixture, preexisting exact SHA W2a binary, and owned listener
close. Real remote SSH to external hosts is not tested, nor are GUI,
upgrades, managed stress 128/10k, system transparent capture,
DNS/UDP/QUIC or leak-free guarantee. W3/G2 remains NO-GO.

**W2b2 next:** build and QA a Windows GUI/NSIS engineering package
from the exact same beta HEAD `c339df2e4d20edf1d11d45786581a68451a71929`.
A prior native Windows CI installer passed on a PR test merge commit,
not on this exact user-tested SHA; do not substitute historical
artifact proof. The exact-source Windows action and PowerShell target
acceptance script are separate from driver and kernel work.

## 2026-11-11 — W2b2 exact-source Win32 GUI/NSIS: first installer NO-GO

The exact beta source `c339df2e4d20edf1d11d45786581a68451a71929`
has been compiled separately from the PR test-merge in hosted Windows CI:
[Run #43004408469](https://github.com/i-shutov/flowbridge/actions/runs/43004408469).
Native x64 Rust CLI/FFI, CMake Win32 GUI, WFP capture helper **compiled
without driver load**, the native C++ GUI runtime suite, and portable NSIS
construction all PASS. Existing `tests/windows_installer_native.py` passed
actual per-user NSIS install into a Cyrillic+spaced path, file hashes,
native GUI TCP, UI page screenshots and upgrade/user-data preservation.

**Exact-source uninstaller gate FAILED:** after `Uninstall.exe /S`,
one or more known installed payloads, HKCU registered values or Start Menu
shortcuts persisted beyond the existing 90-second convergence deadline.
This is an actual Windows hosted product acceptance failure, not evidence
of kernel capture, not a release PASS, and not yet reproduced on the user's
Win10 VM. DO NOT deploy this exact-source GUI installer on the user's VM
until a clean isolated undo/rollback is proven.

The PR test-merge-era installer PASS from #42339966411 was compiled from
the transient PR merge commit `ab6ed5273db6e9741915a96c74809433af125870`,
**not** from the user-tested product SHA. Therefore the earlier PASS must
not override exact-source uninstall NO-GO. The NSIS script blob matches
`main`, so this is not yet attributed to changed NSIS source; identify
the precise residual process, mutex, HKCU key or file and reproducibility.

Separate follow-up CI
[Run #43005363958](https://github.com/i-shutov/flowbridge/actions/runs/43005363958)
adds **read-only** diagnostic of the hosted VM's post-uninstall file,
registry, Start Menu, process and UI mutex state; do not apply any
blind cleanup/registry deletion on a machine with user data. The
W2b2 native target script is intentionally **not admitted**:
`requiredArtifactZipSha=NOT_PINNED_YET` and prior-install guard.
W2b2 remains NO-GO until both exact-source CI jobs and independent native
Win10 acceptance pass. W3/G2 remain separate NO-GO.

## 2026-11-11 — W2b2 apparent uninstall failure was an auditor bug (RCA)

**Root cause**: PowerShell target QA `FlowBridge-Win10-W2B2-GUIInstaller.ps1`
required `-not(Test-Path HKCU:\Software\FlowBridge)` after uninstall.
Actual `packaging/windows/FlowBridge.nsi` deliberately uses
`DeleteRegValue HKCU "Software\FlowBridge" "InstallDir"`, **not**
`DeleteRegKey`, explicitly preserving the user language preference and
profile. Thus the whole parent HKCU key may correctly persist.

The original installed-package sample on [CI #43006976889](https://github.com/i-shutov/flowbridge/actions/runs/43006976889)
was held until the incorrect 90-second timeout, but read-only residue
diagnostics showed:
- `gui_binary_remaining=false`; `uninstall_binary_remaining=false`
- `registered_install_dir=""`; `uninstall_registration=""`
- `shortcut_remaining=false`; `gui_session_mutex_exists=false`
- no matching FlowBridge/uninstall/NSIS processes, only preserved
  `user-owned-notes.txt`

The real product uninstaller had removed the owned binaries and
registration; the test was asserting deletion of a correctly retained
user-preference parent key. Fixed by replacing the whole-key assertion
with an explicit absence check for *InstallDir* (plus the existing
uninstaller registry key, shortcut and both binaries). No FlowBridge
product source, installer NSIS or user-data cleanup logic was changed.

**Independent retest** [#43012107772](https://github.com/i-shutov/flowbridge/actions/runs/43012107772):
**PASS_HOSTED_NON_TARGET_GUI_INSTALL_UPGRADE_UNINSTALL** using the
same exact existing source-pinned installer ZIP, without rebuilding code.
Also [two-job source-pinned GUI/installer CI #43012107722](https://github.com/i-shutov/flowbridge/actions/runs/43012107722)
passed: Windows native build + original Python installed-product suite
**11/11**, then a separate new Windows hosted runner with Python-free
PowerShell 5.1 GUI/NSIS/upgrade/uninstall suite **PASS**.

Canonical exact-beta package from source
`c339df2e4d20edf1d11d45786581a68451a71929`:
- Actions package artifact **13851018456**
- Original ZIP SHA256:
  `088d67ab94985d026f9f526a8772c578e674bc76de0d1399dc4bd1a6cf0751fb`
- ZIP bytes: **4,965,239**; independently verified by SHA, ZIP CRC, source
  SHA in bundle manifest, and original package's 11 acceptance checks
- Uninstaller/installer SHA256 *inside* ZIP:
  `a6631e66d12b708449e96ea9943a89883f42fe7880d17470f3a8954cd73adc37`
- UNSIGNED, version 0.2.0 engineering installer, **NOT** production
  0.3.0 beta and **NOT** production release; WFP driver not packaged
- User Drive mirror in dedicated subfolder:
  https://drive.google.com/file/d/1RLxFP4ETMiF3v5_2mDdzcsadcg-8oupo/view?usp=drivesdk
  (Drive file metadata confirmed 4,965,239 bytes, private/not broadly shared)
- Win10 target script `tools/windows/FlowBridge-Win10-W2B2-GUIInstaller.ps1`
  pins this original ZIP checksum and validates every file in the bundle,
  refuses an existing FlowBridge installation/profile and makes no changes
  to OS firewall, services, WFP, Defender, DNS or routes. The *installed
  per-user* package uses HKCU and Start Menu, then uninstalls, **preserving
  user-generated configuration**.

**W2b2 on owner's Win10 remains NOT_RUN**, despite hosted PASS.
Current [original ZIP native Windows PS5 replay #43013314496](https://github.com/i-shutov/flowbridge/actions/runs/43013314496)
tests the exact end-user `-BundleZip` path with GitHub artifact SHA
before starting the owner's physical Win10 QA.

W3/G2: **NO-GO**. Full limited beta A0-A6 including scope separation,
Windows/macOS packaging acceptance and signatures remains OPEN.

## 2026-11-11 — W2b2 exact original ZIP `-BundleZip` PASS on a third hosted Windows

[GitHub Windows CI #43013314496](https://github.com/i-shutov/flowbridge/actions/runs/43013314496)
**SUCCESS**: a fresh Windows PowerShell 5.1 runner downloaded the exact
canonical original Actions ZIP using read-scoped GitHub API credentials.
Its SHA256 was verified **before** any installer execution as
`088d67ab94985d026f9f526a8772c578e674bc76de0d1399dc4bd1a6cf0751fb`;
the archive length was exactly 4,965,239 bytes. Then it ran
`tools/windows/FlowBridge-Win10-W2B2-GUIInstaller.ps1`
with the actual user-facing `-BundleZip` path, not the special CI-only
extracted-folder shortcut. All exact source/manifest, installed GUI TCP,
5 separate window screenshot hashes, upgrade and uninstall checks passed.
The result was **`PASS_HOSTED_NON_TARGET_GUI_INSTALL_UPGRADE_UNINSTALL`**,
not native Windows10. Independent acceptance artifact 13851273032 SHA256
`a9ff38c83c4bbb098c71f2df98cce12ba08319850bbc1da9136deaaa48691bfe`.

Canonical GUI/NSIS ZIP mirrored from the same GitHub Actions artifact
to the user's private Google Drive dedicated FlowBridge/Win10 QA folder:
https://drive.google.com/file/d/1RLxFP4ETMiF3v5_2mDdzcsadcg-8oupo/view?usp=drivesdk
Drive metadata verified the exact 4,965,239-byte file, and source ZIP
SHA256, integrity, per-file package hashes and source commit were checked
independently. No sandbox:/ links are needed for user download.

**Physical target next:** On the previously tested dedicated Win10 Pro
host, download that exact ZIP from Drive, compare its SHA256 against the
above canonical digest and run the SHA-pinned script directly from
GitHub `05f77feb9a09f05f9879b8dfef3f709417d5bfc1`
with `-BundleZip` and expected host. Requires active interactive RDP.
The installer is **unsigned engineering package**, not an approved release.
It installs per-user, tests GUI, upgrade/uninstall in a fresh test directory,
and preserves new user profile and QA note. The target runner refuses any
pre-existing FlowBridge profile/registration; never delete a real user
profile or forcibly close unrelated processes to satisfy the gate.

Until target W2b2 returns `PASS_NATIVE_WIN10_GUI_INSTALL_UPGRADE_UNINSTALL`
and independent logs are reviewed, **W2b2 target NOT_RUN**.
W3/G2 NO-GO and 0.3.0-beta.1 release NOT_ACCEPTED (A0-A6 incomplete).

## 2026-11-11 — physical Windows 10 Pro user-mode W2b2 PASS (owner console)

The owner executed the exact verified `-BundleZip` acceptance script
from commit `05f77feb9a09f05f9879b8dfef3f709417d5bfc1` on
the previously accepted dedicated Windows 10 Pro 22H2 x64 host, with
the exact source-pinned GUI/installer engineering package. The
PowerShell console returned:

```text
W2b2: PASS_NATIVE_WIN10_GUI_INSTALL_UPGRADE_UNINSTALL; W3/G2: NO_GO
```

Native report path was produced under
`C:\ProgramData\FlowBridge\W2B2-Evidence\`.
Owner-provided evidence-only ZIP SHA256:
`dd3988e39a188d100ac5ded6c52d5b64102b0934e783c522649985ef68db9e37`.
This is **owner-observed Win10 GUI/installer PASS**, not a claim that
I received the private report JSON or checked image layouts independently.
The script's strict PASS requires exact-source/installer SHA, all files
in manifest, real installed GUI TCP, five unique BMP page hashes,
per-user NSIS install, upgrade to the same registered directory,
uninstall of app files/registration/shortcuts and preservation of
user profile and unrelated note. It does NOT install/enable a driver,
SCM service, system proxy, firewall changes, WFP/BFE filters or macOS NE.

### Current gates (post owner W2b2)

| Gate | Verdict | Important limitation |
|---|---|---|
| W0 | **OWNER PASS** | Exact Win10 Pro, elevated read-only inventory |
| W1 | **OWNER PASS** | Four pinned Rust model suites; no driver |
| W2a | **OWNER PASS** | Native CLI & 4 PowerShell SOCKS5 black-box scenarios |
| W2b-0 | **OWNER PASS** | 3 exact-denial managed SSH configuration tests |
| W2b-1 | **OWNER PASS** | Authenticated portable SSHD loopback and owned SSH cleanup |
| W2b-2 | **OWNER PASS** | Exact-SHA unsigned engineering GUI, NSIS install/upgrade/remove |
| Independent physical evidence audit | **OPEN** | Need original machine's JSON/evidence ZIP; console hashes recorded |
| A0 explicit SOCKS-only branch/scope separation | **OPEN** | Beta source still includes WFP/NDISRD research, not permissible protected release |
| A1/A2 and A4/A5/A6 beta release | **PARTIAL/OPEN** | Single-SHA acceptance, managed load and macOS/metadata/reviewer remain |
| A7 GitHub prerelease | **NOT_RELEASED** | No tag / signed package / owner acceptance |
| W3/G2 native WFP/ALE | **NO-GO** | No driver/physical owner proof attempted |

**Release sequence, not more Win10 ad hoc probes:** freeze an isolated
explicit SOCKS-only candidate at the accepted source lineage, remove
protected-driver/helper activation from published package, run managed
SSH stress acceptance, package macOS local-only, produce source/binary
hashes and third-party notices, get independent GO/NO-GO, then tag a
clearly limited `v0.3.0-beta.1` prerelease. Keep opaque independent
WFP research PRs out of this branch. Do NOT assert full 1.0 or
transparent process capture based on the Win10 tests.
