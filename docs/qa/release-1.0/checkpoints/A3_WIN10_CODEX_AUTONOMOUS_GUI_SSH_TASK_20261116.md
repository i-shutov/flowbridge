# FlowBridge A3 — Codex V2: ПОЛНАЯ QA под текущим Admin, без искусственных блокеров

**Дата:** 2026-11-16. **Статус задания:** READY_FOR_WIN10_CODEX; не является отчётом о выполнении.
**Машина:** `VM-910136`, Windows 10 Pro x64 22H2, **уже существующий пользователь `Admin`**, интерактивный `WinSta0\Default` (RDP). **Не создавать новую учётную запись, не требовать clean VM**. Для этой Codex-задачи владелец уже выдал Full Access и разрешил использование настроенного выхода из локальной песочницы для GUI/user-mode QA. Это не меняет Windows UAC и не даёт разрешения отключать защиту ОС. Продолжай со штатными полномочиями Admin, без нового запроса разрешений на каждый клик.
**Продукт:** исключительно оригинальные неизменённые байты `FlowBridge 0.3.0-beta.1`, explicit SOCKS-only.

## ВАЖНО: исправление первого ложного BLOCKED (приоритет выше прежних формулировок)

ПЕРВЫЙ ПРОХОД CODEX УЖЕ СОСТОЯЛСЯ, но остановился: `BLOCKED_PROFILE_ISOLATION`, `BLOCKED_SIGNED_SSHD_UNAVAILABLE`. Владелец **явно разрешил текущую учётную запись Admin и существующий профиль**. Эти две причины **устраняются локально**; повторять ту же ошибку запрещено. Пользователь не будет тестировать GUI вручную. Этот раздел отменяет любые прежние трактовки «нужен новый пользователь/чистая VM/установленный Windows Feature sshd».

### A. Исправление PROFILE_ISOLATION — транзакционное тестирование в профиле Admin

По точному frozen source `native/windows/main.cpp`, beta читает `%LOCALAPPDATA%\FlowBridgeExplicitBeta\profile.json` и `%LOCALAPPDATA%\FlowBridgeExplicitBeta\desktop-settings.json` через Windows `SHGetKnownFolderPath(FOLDERID_LocalAppData)`; это **ожидаемое поведение продукта**, а не ошибка и не основание отказывать в GUI QA. NSIS `packaging/windows/FlowBridgeExplicitBeta.nsi` сохраняет эти файлы после uninstall. Установка в другую директорию не изолирует Known Folder — **не пытайся подменить `%LOCALAPPDATA%`**.

**Исполняемый алгоритм без новой учётной записи:**

1. Установи, нет ли сейчас работающей beta. Перед сохранением снимка корректно останови только её собственный GUI/SSH через штатный Stop/Close; чужие процессы и стабильный `FlowBridge` не трогай. Запиши все PID. Сохрани SHA256-реестр и размер/ACL/время всех файлов `%LOCALAPPDATA%\FlowBridgeExplicitBeta` и `%LOCALAPPDATA%\FlowBridge`, а также экспортируй только `HKCU\Software\FlowBridgeExplicitBeta` и связанные user-only uninstall-значения, если они существуют. Резервную копию делай в закрытом локальном QA-каталоге (не загружай в публичный GitHub).
2. Создай **транзакционный escrow** исходного beta-каталога на том же NTFS-томе: при полном отсутствии открытых beta-процессов переименуй `%LOCALAPPDATA%\FlowBridgeExplicitBeta` в уникальное `%LOCALAPPDATA%\FlowBridgeExplicitBeta.A3-escrow-<UTC>`. Для надёжности скопируй escrow в резервную папку, проверь исходные SHA256 и отсутствие reparse points. Если каталог отсутствует, зафиксируй `ABSENT` и работай дальше без блокировки. Свои тестовые файлы и фиктивные ключи держи отдельно.
3. Используй **тот же Windows Known Folder и того же Admin**. Установи исходную неизменённую beta (если она действительно удалена после A3) и реально запускай GUI в интерактивной сессии, в которой есть разрешённый локальный UI Automation/Win32 SendInput. Если программа создаёт новый `%LOCALAPPDATA%\FlowBridgeExplicitBeta`, считай его *собственным тестовым состоянием* и не выдавай за оригинальный профиль. Разрешены действия с временной копией профиля, но не с escrow.
4. **Безусловный `finally`:** останови только собственные тестовые процессы, штатно удали только созданную QA-установку, затем при наличии нового QA-only beta каталога убери его в отдельную диагностическую папку (не удаляй оригинал). Атомарно верни escrow под `%LOCALAPPDATA%\FlowBridgeExplicitBeta`; восстанови исходные user-only registry значения, не трогая stable ветку; перепроверь все SHA256, список файлов, ACL и сохранение stable FlowBridge. Если не можешь выполнить rollback или SHA не сошлись — `P0_RESTORE_FAILED`, путь резервной копии и оригинальный снимок в отчёт, **не удалять escrow**.
5. После успешной реставрации **не оставляй пользователя с тестовой конфигурацией**. Отдельный временный каталог с приватными ключами уничтожай только после записи санитизированных технических доказательств. Никаких новых пользователей, clean VM, Defender/UAC отключений. Сам факт существования штатного профиля **НЕ является blocker**.

### B. Исправление SIGNED_SSHD_UNAVAILABLE — уже проверенный portable Microsoft OpenSSH

Нужный signed `sshd.exe` **не обязан находиться в Windows Optional Features**. Он есть в portable архиве, уже использованном успешным FlowBridge W2b1 и CI:

- Официальный файл: `https://github.com/PowerShell/Win32-OpenSSH/releases/download/10.4.0.0p1-Preview/OpenSSH-Win64.zip`
- **Закреплённый SHA256:** `b67ff8becd203502190ec42ac7787c24c2cd3325ed7700485fe7a1c83d2a7957`.
- Исходный проверенный сценарий: `tools/windows/FlowBridge-Win10-W2B1-RealSSH.ps1`, read-only использование fixture source/ACL из `tests/windows_real_ssh_hosted.py`. **Не запускать W2b1 без изменений** для приёмки beta: он ожидает *другой* прошлый CLI SHA, а новый тест должен использовать frozen installer `0.3.0-beta.1`.

Пример подготовки portable fixture в PowerShell текущего `Admin`:

```powershell
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:TEMP 'FlowBridge-A3-PortableSSHD'
New-Item -ItemType Directory -Force -Path $root | Out-Null
$zip = Join-Path $root 'OpenSSH-Win64.zip'
$uri = 'https://github.com/PowerShell/Win32-OpenSSH/releases/download/10.4.0.0p1-Preview/OpenSSH-Win64.zip'
$pinned = 'b67ff8becd203502190ec42ac7787c24c2cd3325ed7700485fe7a1c83d2a7957'
if (-not (Test-Path -LiteralPath $zip -PathType Leaf)) {
    Invoke-WebRequest -UseBasicParsing -Uri $uri -OutFile $zip
}
if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant() -ne $pinned) {
    throw 'PINNED_MICROSOFT_OPENSSH_SHA_MISMATCH'
}
$extract = Join-Path $root 'portable'
if (-not (Test-Path (Join-Path $extract 'OpenSSH-Win64\sshd.exe'))) {
    Expand-Archive -LiteralPath $zip -DestinationPath $extract
}
$sshd = Join-Path $extract 'OpenSSH-Win64\sshd.exe'
$sig = Get-AuthenticodeSignature -LiteralPath $sshd
if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate -or
    $sig.SignerCertificate.Subject -notmatch 'Microsoft') {
    throw 'SSHD_MICROSOFT_AUTHENTICODE_NOT_VALID'
}
$sshd
```

Проверь также подпись локальных `ssh.exe`/`ssh-keygen.exe`. Создай только ephemeral localhost `sshd_config`/host keys/authorized_keys и запускай `$sshd -D -e -f <TEMP_CONFIG>` отдельным **собственным** процессом, без Windows service/SCM, Feature Install или изменения firewall. Используй только порт `127.0.0.1`, `StrictHostKeyChecking=yes`, временные known_hosts с корректной и ложной host key. До теста и после него проверь PID/listener, не убивай чужие процессы. Если сеть GitHub временно недоступна, поищи *существующий* ZIP/fixture с **тем же SHA256**, не ставь feature и не проси вручную искать сервер.

### C. Что именно значит «проверить ВСЁ»

**Весь scope этой beta**: реальный GUI на текущем Admin, клавиатура/мышь/редактирование/Save/Cancel/restart, пять страниц, настоящий Microsoft signed localhost SSHD, GUI Start/Stop (если поддерживается), exact frozen CLI/FFI managed SSH, SOCKS5h/domain, бинарный echo/half-close, host-key rejection, wrong credentials, missing SSH, занятый порт, SSH crash/all-down, недопущение direct bypass **в explicit route**, recovery, аудит исходных профилей и cleanup. Не останавливайся только из-за предупреждения `Admin`, fixed Known Folder или отсутствия Windows Feature.

**Отдельный protected 1.0:** WFP/ALE и физический signed driver G2 **не включаются в эту beta**. Разрешены read-only toolchain/driver-readiness проверки; установка драйвера, изменение BFE, DNS, системных proxy, UAC, BCD, SecureBoot, Defender или firewall на живом RDP хосте — **не** часть теста и может оборвать ваш доступ. Для G2 нужен отдельный подписанный артефакт и изолированная rollback/VNC лаборатория. Не обещать ложный 1.0 PASS.

### D. Отчётность и порядок действий

После каждой крупной фазы: реальный verdict, скриншоты/логи, SHA, дефекты, **восстановление оригинального профиля**. Минимизируй оставшиеся BLOCKED: сначала выполни оба конкретных рецепта выше. Не объявляй `PASS`, если не было вызова настоящего GUI/sshd. Передай один ZIP с санитизированными доказательствами + SHA256. Старый первый Codex проход — только исторический `BLOCKED`, и его отчёт не был независимо загружен сюда.

---
## Исходный доказанный baseline

- Source commit **`f5ecd48d8f81c594f755a55e7969b57d20903020`**; original unified CI [#43407093536](https://github.com/i-shutov/flowbridge/actions/runs/43407093536).
- Inner candidate kit `FlowBridge-0.3.0-beta.1-candidate-f5ecd48d8f81.zip`, SHA256 **`4b51d4136878476b48946361ce1635cb6d630e62b50ca82c73df28a5902ed8b8`**.
- Windows installer `FlowBridge-0.3.0-beta.1-windows-x64-setup.exe`, SHA256 **`74ff309d2e8ae115083bed9c5d4f233fd02dc841a8084a22912f3430c1e4b504`**.
- Win10 user A3 preflight PASS, exact installer→payload→GUI smoke→upgrade→uninstall→stable preservation **6/6 PASS**; оригиналы JSON/5 BMP независимо проверены: [checkpoint](A3_OWNER_WIN10_ORIGINAL_EVIDENCE_REVIEW_20261116.md), [QA PR #73](https://github.com/i-shutov/flowbridge/pull/73). **НЕ повторять весь A3 install/upgrade/uninstall**, если нет обнаруженного дефекта.
- В предыдущем A3 `-Execute` тестовый установленный пакет был удалён штатно. Сохранившаяся директория отчёта `%USERPROFILE%\Documents\FlowBridge-A3\a3-nopython-20261116T013044Z-45f65939` содержит `kit\windows\` с точным установщиком; если нет, искать оригинальный внутренний ZIP в Downloads. Не использовать произвольный `main` / непроверенный installer.

## Цель и правила самостоятельности

Без участия владельца **реально запустить Windows GUI и взаимодействовать с ним**, провести проверки клавиатуры/фокуса/навигации/сохранения/отмены/состояний, затем проверить настоящий SSH SOCKS5h и отказовые сценарии с **локальным изолированным SSH-сервером**. Получить самодостаточный архив доказательств и проверяемый verdict. Предоставить промежуточный отчёт после каждого большого блока.

Использовать имеющийся Codex на Win10 и доступные штатные Win32 UI Automation, Accessibility, PowerShell 5.1/.NET/Win32 `SendInput`, `GetWindowRect`, `PrintWindow` или `CopyFromScreen` (возможны C# P/Invoke либо уже установленный проверенный инструмент автоматизации). Сначала исследовать реальный GUI и используемые control IDs; **не заменять интерактивное тестирование** запуском smoke harness, скриншотами без реальных действий, программным изменением JSON или статическим исходным аудитом. Перед SendInput сверять `HWND`/PID/foreground и desktop session. Снимки привязывать к действию и ожидаемому состоянию.

Если Codex запущен без доступа к интерактивному desktop или реальные кнопки нельзя нажимать никаким доступным способом, ставить `BLOCKED_GUI_AUTOMATION_UNAVAILABLE`, сохранять доказательство отказа; **не записывать GUI PASS**. Не просить владельца нажимать кнопки или выбирать тестовые варианты.

## Границы безопасности

Разрешены read-only инвентаризация, снимки, локальные автоматизированные тесты, создание временных файлов, запуск неизменённой per-user beta, установка/удаление её **в тестовом профиле и с сохранением первоначального состояния**, локальный ephemeral SSHD из ранее проверенного подписанного Microsoft OpenSSH и временных ключей, остановка **только созданных тестом** процессов. Если для теста нужно трогать уже существующие profile/registry/stable данные, сначала хешировать и сохранить их; не удалять/переписывать посторонние данные. Следить за локальным диском на 4 GiB RAM Win10-VM, ограничить параллельность.

**Запрещены**: загрузка/установка/подпись WFP или NDISRD `.sys`, WFP/BFE/SCM фильтры и системные службы, изменение Firewall, Defender, Secure Boot, BCD, UAC, глобального proxy, DNS, маршрутов, системного store сертификатов, добавление пользователей, отключение антивируса, подключение к production SSH, публикация ключей/секретов. Не запускать неподписанные скачанные exe. Не изменять замороженные EXE/DLL/manifest, не переводить release accepted/G2 в true. Если действия требуют этих операций, `BLOCKED_REQUIRES_SEPARATE_NATIVE_G2_LAB`.

## Блок 0 — проверенная исходная точка

1. Зафиксировать hostname, `whoami`, ОС/build/arch, user/admin token, session ID, DPI, screen resolution, RDP desktop, UTC time, `codex --version`, доступные средства Win32/UIA.
2. Найти `kit\windows\FlowBridge-0.3.0-beta.1-windows-x64-setup.exe` и `explicit-beta-package.json` из принятого A3. Проверить SHA-256 установщика по независимой pinned константе выше, source SHA/версию и разрешённые 13 payload. Оригинальный A3 report **не перезаписывать**. Если отсутствует — проверить исходный ZIP по pinned SHA, распаковать в отдельное staging.
3. Выполни **обязательный escrow/backup/restore алгоритм A** выше в **том же Admin-профиле**. Используй только исходный NSIS per-user beta и verified FFI/CLI/GUI hashes; `capabilities` должен подтвердить explicit SOCKS и отсутствие transparent WFP, UDP, kill switch. Существующий beta profile НЕ повод для `BLOCKED_PROFILE_ISOLATION`; только подтверждённая невозможность безопасной реставрации после собственных попыток может быть `P0_RESTORE_FAILED`.

## Блок 1 — реальный GUI, интерактивные сценарии

Проверить **поддерживаемые в этой beta** страницы Dashboard, SSH, Proxy, Applications, Advanced (или фактически найденные их аналоги):
- Открытие/закрытие и поиск именно установленного GUI по PID, заголовку, версии, executable SHA. Проверить отсутствие немедленного падения, дочерних ошибочных процессов и неуместного UAC.
- **Настоящие действия:** переходы мышью, TAB/Shift+TAB, Enter/Escape/Space, перемещение фокуса, ввод безопасных временных тестовых значений, Save/Apply/Cancel (если присутствуют), возврат без потери/незапрошенной записи, сохранение/перезапуск и восстановление тестовой настройки.
- Проверить сообщения ошибок на пустой/некорректный адрес/порт/путь/конфигурацию, что ошибки видны, редактирование обратимо; секреты не отображаются в clear text в событиях/скриншотах.
- Проверить, что WFP capture, system kill switch, UDP и protected mode **явно выключены и не включаются** в explicit beta; это **ожидаемое ограничение**, а не дефект.
- Скриншоты до/после каждого ключевого действия и журнал действий `control ID → input → observed UI state → verdict`, реальные координаты/геометрия и DPI. Нет очевидных перекрытий/обрезаний при текущем desktop resolution; дополнительные DPI проверять только если возможно без системных изменений. Не приписывать Win10 125/150/200 DPI PASS на основе одного снимка.
- Если конкретное управление отсутствует в beta, `NOT_APPLICABLE_TO_EXPLICIT_BETA` с доказательством capabilities/GUI; тестировать настоящий 1.0 rule editor в рамках A3 **запрещено**.

## Блок 2 — настоящие SSH + SOCKS5h на pinned beta, без внешней сети

1. **Самостоятельно скачать и проверить portable signed Microsoft `sshd.exe` по алгоритму B выше**. Это уже проверенный URL и ZIP SHA из `tools/windows/FlowBridge-Win10-W2B1-RealSSH.ps1` и hosted CI. Запустить отдельный изолированный loopback `sshd` без службы Windows, ephemeral keys + `StrictHostKeyChecking=yes`; затем испытать **точные DLL/CLI/GUI из frozen installer**, а не старый `c339df2e` или новую сборку. Перед каждым тестом записывать binary SHA.
2. GUI SSH Start/Stop — если в beta реально реализован этот путь; отдельно CLI/FFI managed SSH тесты. **CLI PASS не заменяет GUI-driven PASS**. Контролировать число дочерних OpenSSH процессов и listener PID, не убивать чужие процессы.
3. Положительный: правильный host key/public-key auth → Ready; реально подключить SOCKS5 к `127.0.0.1:port`, send `ATYP=DOMAINNAME` для `localhost` (SOCKS5h), удалённый TCP echo, бинарный payload, half-close/EOF parity, Stop → listener/owned child gone. Регистрация домена на SOCKS доказывает тип запроса, **не** абсолютное отсутствие системных DNS-утечек.
4. Отрицательные: неверный host key, недоступный локальный SSHD, занятый порт, неверные credentials, Stop во время подключения, all-down/SSH child exit. Сравнить ожидаемый fail-closed: новая связь НЕ должна незаметно обходить заданный SOCKS-путь по DIRECT. Только локальный 127.0.0.1 egress тестового стенда; для утверждений о системном no-leak потребуются отдельные packet traces и G2.
5. Не делать 10k/24h soak в этом коротком интерактивном A3-блоке и не признавать raw 512 каналов доказанными. Ресурсная нагрузка `WIN-05` — другой gate.

## Блок 3 — доказательства, отказовые выводы и восстановление

Рабочий каталог: `%USERPROFILE%\Documents\FlowBridge-ReleaseQA\A3-Codex-<UTC>` (без изменений в корне репозитория). Структура:

- `report.json`: schema, start/end UTC, product source and installer SHA, host/build/session/DPI, per-case `PASS|FAIL|BLOCKED|NOT_APPLICABLE`, expected/observed, reason codes.
- `screenshots/`: реальные изображения окна до/после действий, аннотация action ID и geometry; `ui-automation.json`: control tree/control IDs и фактические действия (не синтетика).
- `ssh/`: sanitized config, host-key failure diagnostics **без приватных ключей**, SOCKS5 handshake metadata, целостность echo, pid/listener/Stop evidence, негативные результаты.
- `sha256-manifest.json`: хеши каждого deliverable, копия pinned SHA-256, SHA архива, исходные GitHub URLs, команда воспроизведения.
- `README.md`: исполненные сценарии и что точно не было протестировано; `CHECKPOINT.md`: итоговая матрица блокеров, условия нового запуска, next actions.

После тестов остановить только собственные test child процессы, штатно закрыть свою beta и отменить собственные настройки; сохранить все **исходные** stable/profiles/registry. ZIP только с sanitized отчётом/скриншотами/логами, без `identity_file`, private key, known_hosts с чувствительными данными, токенов или полных приватных конфигураций.

Инварианты verdict:
- `A3_GUI_NATIVE_AUTOMATED_PASS` только при фактических GUI actions + screenshots;
- `A3_SSH_REAL_LOOPBACK_PASS` только при точном frozen binary + **реальном** OpenSSH + SOCKS5h/echo/negative/Stop;
- `A3_INTERACTIVE_EVIDENCE_READY_FOR_REVIEW` только если оба PASS и артефакты полны;
- всегда `a3_full_acceptance=false`, `release_accepted=false`, `wfp_g2_accepted=false` до внешнего review/GO;
- `UNKNOWN`/невозможное испытание — явный `BLOCKED`, никогда fake PASS.

Создавать подзадачи/QA-скрипты и, если нужно, отдельную `qa/...` Git-ветку и Draft PR без merge в main. В публичный GitHub — **только** санитизированный checkpoint с отчётным SHA и без приватных данных/скриншотов. Отдать владельцу **один ZIP** и короткое резюме: PASS/FAIL/BLOCKED, текущие P0, что точно нужно для приёмки A3. Не публиковать release/tag, не менять roadmap gate-флаги без независимой приёмки.

**Важно:** настоящая Windows 1.0 физическая WFP/G2 приёмка проводится отдельно после наличия подписанного драйвера, изолированной Win10/Win11 лаборатории, VNC/снапшота и согласованных rollback procedures. Этот Codex запуск проверяет только beta GUI/SSH.
