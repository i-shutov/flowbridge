# FlowBridge — план и фактическое исполнение

Дата: 2026-10-28. Текущая версия: 0.2.0. Состояние подтверждается [VERIFICATION.md](VERIFICATION.md), не числом написанных файлов.

## Архитектурные решения

Общая логика и транспорт на Rust; native Win32 C++ и SwiftUI поверх C ABI. GUI и CLI используют один Engine. Системные адаптеры получают process identity и original destination от платформы и передают TCP через общий транспорт. На Windows — WFP kernel callout + SCM service; на Mac — Network Extension. WebView/Electron не нужны.

Win32 installer распространяет проверяемый local SOCKS режим. Активация непроверенного kernel driver не добавляется автоматически. Mac-сценарии создают `.app` и `.pkg` настоящими Apple-инструментами; их наличие не заменяет native compile/sign/run.

## Агенты и модели

Пользователь разрешил выбирать модели для субагентов. Для реализации изолированных компонентов выбран GPT-6.1 Sol с high reasoning; для WFP/NE и платформенного lifecycle — GPT-6 Astra с high reasoning. Сложные границы дополнительно проверены независимым ревизором. Это распределение по характеру задач, не заявление о формально измеренной скорости/стоимости моделей.

| Агент | Модель | Сделано |
|---|---|---|
| `runtime_v02` | GPT-6.1 Sol / high | Reusable Engine, start/stop/reload, telemetry, C stream ABI, lifecycle/socket tests, pre-connect tests, active-record retention, Windows IO review fixes |
| `windows_v02` | GPT-6.1 Sol / high | Win32 GUI, quick/JSON profile editor, worker/metrics, CMake, native NSIS installer |
| `macos_v02` | GPT-6 Astra / high | SwiftUI controller, native activation manager, bounded NE TCP adapter, XcodeGen, universal app/pkg scripts |
| `wfp_backend_v02` | GPT-6 Astra / high | Собственный driver context/IOCTL/classify, SCM service, dynamic filter manager, trusted identity, pre-connect records integration, WDK project |
| `review_v02` | GPT-6.1 Sol / high | Независимая ревизия UI/runtime/macOS/WFP; исправления editor state, upgrade directory, stale callbacks, Direct capacity; обнаружение WFP arbitration и Windows timeout semantics |
| Основной агент | GPT-6 Astra Pro | Статическое исследование референса, контракт, CLI/runtime интеграция, socket preparation hook, сборки/пакет, Windows ABI+GUI harness, документация и артефакты |

Предыдущая итерация 0.1 реализовала core policy, протоколы и базовый ABI; результаты сохранены в истории исходного пакета. В 0.2 эти модули интегрированы в работающий desktop control plane.

## Выполненные этапы

1. **Исследовать reference.** Пароль применён; installer и ресурсы изучены статически; версия и WFP компоненты установлены; собственный код отделён от предоставленных бинарников.
2. **Унифицировать управление.** Start подтверждается реальным bind, stop отменяет соединения, reload сохраняет прежнее состояние при ошибке; CLI и GUI разделяют Engine.
3. **Нативные оболочки.** Win32 связан с Rust DLL, SwiftUI использует C ABI; никакого фиктивного индикатора включённого системного перехвата.
4. **Native data path source.** WFP/NE адаптеры содержат реальный I/O и lifecycle. Windows records устанавливаются до connect на каждой попытке. Unknown identity не превращается в выдуманное имя процесса.
5. **Упаковка Windows.** PE32+ x64 GUI/DLL/CLI, NSIS installer/uninstaller, сохранение профиля, upgrade reuse path, dependency notices. Результат установочного теста — в VERIFICATION.
6. **Mac build path.** Universal source build, отдельные local/native схемы, подписываемый productbuild-пакет; Linux корректно отказывается подделывать Apple build.
7. **Уточнение AI/Web.** Встроенный OpenSSH supervisor/watchdog, ожидание новых соединений при reconnect, современный native UI, локальная эвристика приложений и общий каталог AI/Web; отдельная архитектура следующего resumable remote relay.
8. **Проверки.** Rust/CLI/C ABI, Windows executable GUI smoke, dependency/PE checks и retained logs. Конкретные успешные/неуспешные gates фиксируются отдельно.

## Что отделяет этот выпуск от полной замены Proxifier

| Следующий gate | Среда/вход | Критерий завершения |
|---|---|---|
| Windows desktop release | Чистые Windows 10/11 x64 | Install/upgrade/remove, настоящая сеть/SSH, IPv6, длительные соединения, sleep/wake, signed release artifacts |
| WFP kernel build | WDK + Windows SDK + MSVC | Driver компилируется без ошибок, INF/cat/ABI проходят проверки; service собран на canonical SDK |
| WFP native validation | Windows VM/устройство с kernel-debug/Verifier | PID/app identity, original endpoint, redirect records, v4/v6, loop/coexistence, crash/unload, bounded shutdown |
| Windows capture distribution | Реальный процесс подписывания драйвера | Microsoft-accepted driver signature и испытанный installer/rollback; разрешения GUI/service IPC отдельно |
| Mac local application | Mac M1/M4 (и Intel), Xcode | Swift compile, app run, SOCKS traffic, profile/reload, pkg install/remove |
| Mac system extension | Реальные Apple Team/App IDs, provisioning, signing | Approve/deny/restart, active readiness, policy/half-close/outage/sleep/wake tests, notarization для распространения |
| Непрерывность установленных TCP | Постоянный remote relay + fault injection | Resumable framing/ACK/offset/epoch, bounded buffers и доказанная дедупликация; обычный SSH restart этого не обеспечивает |
| DNS/UDP coverage | Отдельный дизайн + packet capture tests | Явная модель DNS identity/UDP/QUIC, подтверждённый scope; только после этого расширять обещания |
| Product polish | Оба native окружения | Визуальный rule editor, credential stores, profile import, signed updates, accessibility и локализация |

Ни отсутствие Mac/WDK в текущем runner, ни необходимость подписи не скрыты за «100% готово». Пользователю передаются реально собранный Windows installer и полный исходный проект с конкретными оставшимися gates.
