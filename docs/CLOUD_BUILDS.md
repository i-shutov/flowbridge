# Сборки FlowBridge: локально и в облаке

Проверено 28 октября 2026 года. Для уже собранного Windows-пакета внешний сервер не нужен: Rust DLL/CLI, настоящий Win32 GUI и NSIS-инсталлятор собираются в текущей Linux-среде через Rust `x86_64-pc-windows-gnu`, MinGW-w64, CMake и NSIS. Полученные PE-файлы и интерфейс проверялись через Wine. Это не заменяет проверку на настоящей Windows и не является подписью выпуска.

Для следующего этапа подходит GitHub Actions: подготовленный `.github/workflows/ci.yml` запускает отдельные задания на Windows и macOS. Анонимные публичные RDP-компьютеры для этого не нужны. Используется выбранный вами репозиторий и управляемые CI-машины; описания доступных runner есть в [официальной документации GitHub](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

## Что готово и чего ещё нет

| Задача | Среда и инструменты | Текущее положение |
| --- | --- | --- |
| Windows GUI, DLL, CLI и установщик `.exe` | Linux cross-build; либо Windows + MSVC, Rust, CMake, NSIS | Локальная кросс-сборка уже выполнена; внешний сервер не требуется |
| Нативная сборка и smoke-тест GUI на Windows | Задание `windows-application` в GitHub Actions | Workflow подготовлен; подтверждённого облачного запуска ещё нет |
| Windows WFP kernel driver и реальный перехват | Совместимые Visual Studio/SDK/WDK, отдельная Windows test VM или физический компьютер, процедура подписи драйвера | Отдельный этап; обычный GUI job не доказывает готовность драйвера |
| macOS `.app` / локальный `.pkg` | macOS runner, Xcode, Rust, XcodeGen | Скрипты и job подготовлены; в этой сессии удалённая macOS-сборка не запускалась |
| Распространяемый macOS Network Extension | Apple signing team, зарегистрированные идентификаторы, сертификаты, provisioning profiles и entitlements | Без реальных данных разработчика и проверки активации завершённым выпуском не считается |

**GitHub теперь подключён и авторизован: доступен аккаунт `i-shutov`.** Список GitHub App installations пуст; среди репозиториев с owner affiliation доступен только посторонний публичный `personal-site`. Частного репозитория FlowBridge среди доступных нет, операция `create_repo` в подключённой интеграции не предоставлена. Исходники FlowBridge не загружались, удалённые задания не запускались. Наличие YAML и локальных артефактов не является свидетельством успешного GitHub Actions run.

## Что потребуется для облачного запуска

Интеграция уже установлена; следующий необходимый ресурс — выбранный частный репозиторий FlowBridge с подходящим доступом. Его можно создать через интерфейс GitHub, поскольку инструмента создания репозитория в текущем подключении нет. После предоставления доступа нужно проверить операции записи/запуска workflow: сама авторизация не означает автоматически наличие всех этих разрешений. Существующий `personal-site` относится к другому проекту и не выбран для FlowBridge. Альтернативно владелец нового репозитория может загрузить проект и запустить Actions через интерфейс GitHub или авторизованный `gh`.

Рекомендуемый порядок после выбора репозитория:

1. Разместить содержимое корня проекта FlowBridge в корне репозитория, включая `.github/workflows/ci.yml`, `Cargo.lock`, ресурсы и скрипты упаковки.
2. Разрешить GitHub Actions для репозитория и проверить бюджет/лимиты аккаунта.
3. Для ручного запуска поместить workflow в default branch и выбрать **Actions → rust-and-native-applications → Run workflow**. GitHub требует `workflow_dispatch` и права записи для такого запуска: [Manually running a workflow](https://docs.github.com/actions/managing-workflow-runs/manually-running-a-workflow).
4. Проверить логи Windows/macOS jobs и скачать artifacts. В текущем YAML срок хранения — 14 дней; публикация Release автоматически не выполняется.

В текущей сессии подключение уже проверено, но размещение исходников FlowBridge, создание репозитория и запуск Actions от имени пользователя не выполнялись.

## Что именно делает подготовленный CI

`rust` проверяет форматирование, Clippy, Rust-тесты и CLI smoke-тесты на Ubuntu, Windows и macOS.

`windows-application` собирает `flowbridge-ffi` и CLI в Release, передаёт CMake DLL import library `target/release/flowbridge_ffi.dll.lib`, собирает GUI и `FlowBridgeNativeSmoke.exe`, копирует DLL/каталог приложений к исполняемым файлам и запускает настоящий smoke-тест. Затем устанавливает NSIS и вызывает:

```powershell
python packaging/windows/build-installer.py --skip-build
```

Скрипт берёт GUI из `build/windows/Release/FlowBridge.exe`, переименовывает CLI в `flowbridge-cli.exe`, собирает payload и пишет установщик/SHA-256 в `../artifacts/` относительно корня репозитория. Именно этот каталог указан в `upload-artifact`.

`macos-application` вызывает:

```sh
bash packaging/macos/build-pkg.sh local
```

Скрипт собирает universal Rust-библиотеку и локальное приложение для arm64/x86_64, затем пакет в `build/macos/local/packages/*.pkg`; этот путь совпадает с загрузкой artifacts. Следующая команда CI отдельно проверяет компиляцию native scheme с `CODE_SIGNING_ALLOWED=NO`. Она не подписывает и не активирует расширение.

Команды и пути workflow сопоставлены с текущими CMake/скриптами упаковки; конкретного несоответствия не найдено, YAML оставлен без изменений. Первый настоящий запуск всё равно нужен: только его логи подтвердят поведение на актуальных hosted runner.

## Стоимость и ограничения

По [правилам GitHub Actions](https://docs.github.com/en/actions/concepts/billing-and-usage), стандартные GitHub-hosted runner для публичных репозиториев предоставляются бесплатно; для частных репозиториев действуют включённые в тариф квоты минут и хранения, а сверх них — условия оплаты/блокировки аккаунта. Большие runner оплачиваются отдельно, в том числе для публичных репозиториев. Актуальные условия: [GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions) и [Actions runner pricing](https://docs.github.com/en/billing/reference/actions-runner-pricing).

Не следует публиковать частный проект только ради бесплатных минут. Для выбранного частного репозитория сначала проверяется его тариф и бюджет. Бесплатность стандартных public jobs не является обещанием отсутствия ограничений времени задания, параллелизма, хранения или условий сервиса.

## Почему драйвер и Apple-подпись — отдельные этапы

Для обычного Windows GUI достаточно C++/Rust toolchain. Kernel driver требует совместимых SDK/WDK и отдельного процесса тестирования: [Download the WDK](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk). Проверки на управляемой Windows VM/реальном компьютере должны охватывать установку, WFP-перехват, отмену/очистку и отсутствие обхода политики. Сборка `.sys` в CI сама по себе этого не подтверждает.

Для публичного выпуска новых Windows kernel drivers действуют требования Microsoft к подписи через соответствующий процесс Hardware Dev Center; обычная подпись GUI или локальная тестовая подпись её не заменяют. См. [Kernel-Mode Code Signing Requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-requirements--windows-vista-and-later-) и [Driver Signing Options](https://learn.microsoft.com/windows-hardware/drivers/dashboard/driver-signing-offerings). Текущий обычный установщик не устанавливает драйвер автоматически.

macOS runner может собрать локальный `.pkg` без ваших release-секретов, но это не готовый подписанный продукт с работающим Network Extension. Для распространения расширения нужны корректные entitlement/profile/certificate вашего Apple Developer account: [Network Extensions Entitlement](https://developer.apple.com/documentation/BundleResources/Entitlements/com.apple.developer.networking.networkextension). Для обычного выпуска вне Mac App Store также проверяются Developer ID signing и notarization: [Notarizing macOS software before distribution](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution). Никакие фиктивные Team ID или обход требований macOS не используются.
