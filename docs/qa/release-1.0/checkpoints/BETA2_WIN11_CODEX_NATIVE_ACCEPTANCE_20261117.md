# FlowBridge 0.3.0-beta.2 — автономная Win11 Pro x64 owner-native A3

> **ОСТАНОВЛЕНО И ПЕРЕНЕСЕНО РЕШЕНИЕМ ВЛАДЕЛЬЦА ОТ 17.11.2026. НЕ ВЫПОЛНЯТЬ ЭТО ЗАДАНИЕ СЕЙЧАС.**
> Текущие beta.2 и Windows 1.0 планируются **только для Windows 10 Pro 22H2 x64**. Windows 11 **не проверяем, не публикуем, не заявляем как поддерживаемую** до будущего отдельного релиза. Этот документ — **исторический runbook**, который потребуется обновить под новый frozen source SHA при возобновлении работ. Отсутствие Win11 QA **не блокирует** нынешний Win10 релиз. [Scope decision](WIN10_ONLY_SCOPE_DECISION_20261117.md) · [future backlog #79](https://github.com/i-shutov/flowbridge/issues/79).

**Подготовлено 17.11.2026. Статус `WIN11_NATIVE_NOT_RUN`.** Это последнее ОС-свидетельство Windows-first beta.2, **не** запуск WFP/1.0 и не повторение уже принятого Win10 V4/V5.

## Исполнитель и границы

Локальный Codex на **действительной Windows 11 Pro x64**, под уже разрешённой интерактивной учётной записью с доступным рабочим столом и механизмом UI Automation. **Не** применять Win10 VPS `VM-910136` и не выдавать hosted Windows Server 2025 за Windows 11. Задача выполняется автономно в пределах обычного GUI/SSH/per-user QA, без ручных кликов владельца. Если доступ к другой Windows 11 машине отсутствует, вернуть `BLOCKED_REAL_WIN11_HOST_NOT_ACCESSIBLE` и доказательства среды; не создавать фальшивые PASS.

**Строго запрещено**: WFP/NDISRD/WinPcap драйверы, установка системных служб/пакетов Windows Features, изменение DNS/Firewall/Defender/UAC/BCD/SecureBoot/BFE/маршрутов/глобального proxy. Не подключаться к production SSH, не копировать ключи из пользователя. Если отсутствие активного UI desktop препятствует настоящим кликам — `BLOCKED_INTERACTIVE_DESKTOP`, не заменять GUI smoke-only.

## Immutable source-of-truth

| Параметр | Точное значение |
| --- | --- |
| Релизный кандидат | `0.3.0-beta.2`, explicit SOCKS-only |
| Source SHA | `86583a1a0487b9d383c0122b24558e620bde5b9c` |
| Source tree SHA | `9f92e9e9e87725d127505c8ac415f37e42a8d148` |
| [Original 11/11 candidate CI](https://github.com/i-shutov/flowbridge/actions/runs/43883696169) | attempt 2 SUCCESS |
| [VerifiedCandidate artifact #14238314845](https://github.com/i-shutov/flowbridge/actions/runs/43883696169/artifacts/14238314845) | official complete bundle |
| Inner ZIP | `FlowBridge-0.3.0-beta.2-candidate-86583a1a0487.zip` |
| Inner ZIP SHA-256 | `9980c786ceea82d2609b0229eca87b7f3ba044dc742466fedfa5e3b08e7585ae` |
| Windows installer SHA-256 | `0699bed4acaa1b9df9b63c658808b08fd65b5953cacdaaddb7a13953389e19f4` |
| Installed GUI `FlowBridge.exe` SHA-256 | `0cf1749e7531659b1f5a42433818ecf31fe517d6815d11faeca6e04f9821325e` |
| Installed FFI DLL SHA-256 | `23b62d54a89feea53331f3ac68fe7c3d348ca99ed72d816f3dcfbc94ef3fd2b4` |
| Portable Microsoft OpenSSH server ZIP SHA-256 | `b67ff8becd203502190ec42ac7787c24c2cd3325ed7700485fe7a1c83d2a7957` |

Сначала скачать **оригинальный verified candidate** из Actions и сверить SHA-256 внутреннего ZIP по закреплённой константе. Распаковать только безопасные пути в отдельный локальный QA-каталог; сверить Windows manifest/13 allowlisted файлов, отсутствие драйверов и ложных protected-claims. **Не использовать новую сборку** или Win10-прошлые EXE вместо pinned installer.

## Большой блок 1: host/preflight и сохранение данных

1. Зафиксировать `hostname`, `whoami`, `Get-CimInstance Win32_OperatingSystem | select Caption,Version,BuildNumber`, разрядность, UI desktop/сессию, экран/масштаб DPI. Требуется подлинный Win11 Pro x64 **build >= 22000**. Проверить `Git SHA → kit SHA → installer SHA → установленный EXE/DLL SHA`.
2. Снять исходные metadata SHA/ACL/attributes/timestamps для пользовательских `%LOCALAPPDATA%\FlowBridgeExplicitBeta` и `%LOCALAPPDATA%\FlowBridge`; HKCU beta registration/uninstall значения. Изолировать только тестовую beta Known Folder через безопасный **same-volume escrow rename** с дополнительной независимой копией и обязательным `finally` restore; не удалять stable-данные. Для тестовой установки `Admin` не обязателен: нужен доступ к **реальному интерактивному user desktop**, QA не требует повышения.
3. Установить исходный beta.2 NSIS per-user. Проверить файлы по manifest/FFI capabilities, отдельную регистрацию, отсутствие WFP/NDISRD/system-service/глобального DNS и невозможность включить protected transparent routing.

## Блок 2: GUI и реальный localhost SSH

1. Настоящие GUI действия через UIA/Win32: открыть Dashboard/Connection/Applications/Advanced, мышь, клавиатура TAB/Shift+TAB/Enter/Escape, Save/Apply/Cancel и повторное открытие. Проверить 980×680 и 1366×768 окна, текущий OS DPI; на иных DPI фиксировать реальный результат, если доступно без глобальных опасных изменений. Сделать несколько снимков **реального** HWND и UI action JSON.
2. Подготовить **только user-owned loopback** portable подписанный Microsoft `sshd.exe` из официального `10.4.0.0p1-Preview` `OpenSSH-Win64.zip` и проверить pinned ZIP SHA+Authenticode. Не изменять OpenSSH Windows Features или SCM. Ephemeral host key/user key и `known_hosts` StrictHostKeyChecking=yes.
3. Через точный installed GUI+DLL проверить Start → `SSH 1/1 Ready` → SOCKS5h DOMAINNAME `localhost` → 10 бинарных байт + half-close EOF → GUI Stop/child-reap; проверить известные негативы: wrong host key, wrong publickey, nonexistent identity_file, backend absent, occupied local port, SSH down/all-down no DIRECT **в explicit SOCKS localhost scope**. Поведение в неподдерживаемых WFP/UDP/system DNS сценариях заявить `NOT_APPLICABLE_TO_EXPLICIT_BETA`.
4. Проверить upgrade одного verified exact beta.2 пакета поверх собственного тестового профиля и uninstall, сохранение специально созданных user settings и stable SHA. Если присутствует исходная beta.1 и переход beta.1→2 уже сохранён в Win10, Win11 может проверить отдельно, но **не заменять обязательные собственные install/upgrade/uninstall**. Не трогать чужую установленную beta.

## Блок 3: завершение, доказательства и независимое ревью

В `%USERPROFILE%\Documents\FlowBridge-ReleaseQA\Win11-Beta2-Codex-<UTC>` сохранить `report.json` (schema, источник, install/exe/dll SHA, OS/build/DPI, per-case PASS/FAIL/BLOCKED), `screenshots/*.png` + UIA controls/action log, `ssh/*.json` + redacted stderr, `lifecycle/*.json`, `restore-checks.json`, `sha256-manifest.json`, `CHECKPOINT.md`. Удалить только созданные временные тестовые ключи, процессы, listener и тестовую установку; исходные user profile/ACL/HKCU восстановить точно. Собрать один sanitized ZIP и SHA-256, вернуть путь для передачи независимому reviewer. **Никогда не публиковать приватные ключи, оригинальные пользовательские конфигурации или личные пути в публичный GitHub.**

**Вердикт:** `WIN11_BETA2_OWNER_NATIVE_TESTS_PASS_PENDING_INDEPENDENT_REVIEW` только если действительно выполнены все относящиеся к release-gate сценарии и нет FAIL/SKIP. Любые пропуски `BLOCKED` с кодом и оригинальными доказательствами. Ревьюер принимает Win11 только после ZIP/хешей. `A5/A6/A7_accepted=false` и `WFP_G2_accepted=false` независимо от итогов этого теста.

**Уже закрытая Win10 приёмка:** [V4+V5 independent reviewer decision](BETA2_WIN10_A3_V5_INDEPENDENT_REVIEW_20261117.md), **не дублировать**.
