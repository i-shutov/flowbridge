# FlowBridge A3 — автономное native GUI / SSH тестирование агентом Codex на Win10

**Дата:** 2026-11-16. **Статус задания:** READY_FOR_WIN10_CODEX; не является отчётом о выполнении.
**Машина:** уже открытая интерактивная Windows 10 Pro x64 22H2, host `VM-910136`; запускать задания в текущем пользовательском desktop-сеансе.
**Продукт:** исключительно оригинальные неизменённые байты `FlowBridge 0.3.0-beta.1`, explicit SOCKS-only.

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
3. Сохранить fingerprints существующих beta/stable файлов и HKCU; **не устанавливать поверх живой beta**. Если пользовательский профиль после A3 сохранён, читать и не удалять его. Установить **только** исходный user-mode NSIS в отдельную тестовую директорию после safety preflight, либо использовать уже установленный строго сопоставленный binary. Проверить installed FFI/CLI/GUI хеши по original manifest; запуск `capabilities` должен подтвердить explicit SOCKS, отсутствие transparent WFP, UDP и kill switch. В случае конфликта профиля — сохранять исходные данные, помечать `BLOCKED_PROFILE_ISOLATION`, не обходить защиту.

## Блок 1 — реальный GUI, интерактивные сценарии

Проверить **поддерживаемые в этой beta** страницы Dashboard, SSH, Proxy, Applications, Advanced (или фактически найденные их аналоги):
- Открытие/закрытие и поиск именно установленного GUI по PID, заголовку, версии, executable SHA. Проверить отсутствие немедленного падения, дочерних ошибочных процессов и неуместного UAC.
- **Настоящие действия:** переходы мышью, TAB/Shift+TAB, Enter/Escape/Space, перемещение фокуса, ввод безопасных временных тестовых значений, Save/Apply/Cancel (если присутствуют), возврат без потери/незапрошенной записи, сохранение/перезапуск и восстановление тестовой настройки.
- Проверить сообщения ошибок на пустой/некорректный адрес/порт/путь/конфигурацию, что ошибки видны, редактирование обратимо; секреты не отображаются в clear text в событиях/скриншотах.
- Проверить, что WFP capture, system kill switch, UDP и protected mode **явно выключены и не включаются** в explicit beta; это **ожидаемое ограничение**, а не дефект.
- Скриншоты до/после каждого ключевого действия и журнал действий `control ID → input → observed UI state → verdict`, реальные координаты/геометрия и DPI. Нет очевидных перекрытий/обрезаний при текущем desktop resolution; дополнительные DPI проверять только если возможно без системных изменений. Не приписывать Win10 125/150/200 DPI PASS на основе одного снимка.
- Если конкретное управление отсутствует в beta, `NOT_APPLICABLE_TO_EXPLICIT_BETA` с доказательством capabilities/GUI; тестировать настоящий 1.0 rule editor в рамках A3 **запрещено**.

## Блок 2 — настоящие SSH + SOCKS5h на pinned beta, без внешней сети

1. Использовать изолированный loopback `sshd` без службы Windows, ephemeral host/user keys и отдельный `known_hosts` с `StrictHostKeyChecking=yes`. Переиспользовать безопасную механику из `tools/windows/FlowBridge-Win10-W2B1-RealSSH.ps1` и/или `tests/windows_real_ssh_hosted.py`, **но привязать исполняемый product к точным DLL/CLI/GUI из frozen installer**, а не к старому `c339df2e` либо newly rebuilt artifact. Перед каждым тестом записывать binary SHA.
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
