# FlowBridge 0.2.0

Нативное приложение для маршрутизации TCP через SOCKS5, SOCKS4a и HTTP CONNECT, с общим ядром на Rust, Win32-интерфейсом и SwiftUI-интерфейсом. Самостоятельная реализация функций, исследованных на примере Proxifier 4.14.

**Этот выпуск содержит собранное приложение и установщик Windows x64 для локального SOCKS-режима. Полная прозрачная замена Proxifier пока не готова к установке: Windows WFP требует сборки/подписи драйвера и испытаний, macOS — сборки Xcode и проверки расширения на Mac.** Исходники этих модулей включены; режимы не выдаются за проверенные по факту наличия кода.

## Установка на Windows

Запустите `FlowBridge-0.2.0-windows-x64-setup.exe`. Установка для текущего пользователя, обычно в `%LOCALAPPDATA%\Programs\FlowBridge`, без прав администратора. Ярлык появится в меню «Пуск». Требуется Windows 10 x64 или новее. Пакет пока без подписи издателя.

### Встроенный SSH — без отдельной команды

На странице **Подключение** выберите **Управляемый SSH**, укажите сервер, SSH-порт, пользователя и ключ либо используйте уже настроенный SSH agent. При необходимости выберите known_hosts. Keepalive, compression, таймауты и повторные подключения настраиваются в приложении. Нажмите **Подключить**: supervisor запускает нативный OpenSSH без терминала, проверяет локальный SOCKS и только после готовности запускает движок.

OpenSSH client должен быть установлен в системе. В этом выпуске поддержаны key/agent authentication и строгая проверка host key; неизвестный/изменившийся серверный ключ требует проверки fingerprint и регистрации в known_hosts. Парольная форма, первый trust wizard и secret stores пока не реализованы. Параметры не передаются shell, пароли в desktop JSON не сохраняются.

Во время переподключения локальный SOCKS остаётся на `127.0.0.1:1081`. **Новые** соединения могут ждать до 30 секунд; старые TCP/AI streams при полном разрыве SSH могут оборваться. Прикладные запросы не повторяются автоматически. Для сохранения старых TCP нужен дополнительный remote relay — он спроектирован, но ещё не реализован. Подробно: [SSH_AND_RECONNECT.md](docs/SSH_AND_RECONNECT.md).

### Уже существующий прокси

Выберите **Существующий прокси** и задайте его host, port и protocol. По умолчанию это SOCKS5 `127.0.0.1:1080`; приложение использует его без управления процессом. Этот режим подходит и для уже работающего SSH dynamic forward.

В обоих случаях приложению-клиенту local-режима нужен SOCKS5 `127.0.0.1:1081`. Проверка:

```powershell
curl.exe --proxy socks5h://127.0.0.1:1081 https://example.com/
```

В таблице видны назначение, правило, маршрут, состояние и байты. **Отключить** прекращает engine/managed SSH. `socks5h` передаёт имя назначения upstream; уже выполненный клиентом локальный DNS отменить нельзя.

### AI / Web шаблоны

На странице **Приложения** выберите AI, Web или AI + Web и запустите поиск. Программа локально проверяет установленные приложения/процессы; показывает имя и найденный путь, позволяет снять отметки и добавить своё приложение. Каталог hints — `resources/presets.json`; он не доказывает установку или издателя.

Шаблоны создают системный профиль: выбранные приложения через proxy, остальные по умолчанию Direct. В Windows-пакете системный захват ещё недоступен, поэтому найденные приложения и экспорт native-профиля не выдаются за действующий перехват. Local SOCKS обслуживает только явно настроенные на него клиенты. Для Mac применение application criteria связано с проверенной readiness native provider.

Установщик не включает драйвер или автоматическую активацию системного захвата. Для программ без собственных настроек SOCKS нужен завершённый системный backend. В local SOCKS исходный процесс неизвестен; enabled application rules отвергаются, чтобы они не обходились молча.

## Профили и управление

**Open JSON** загружает черновик, **Export JSON** сохраняет черновик в выбранный файл. **Start** и **Apply / Reload** проверяют профиль, применяют его и сохраняют принятый профиль в `%LOCALAPPDATA%\FlowBridge\profile.json`.

Изменение upstream host, port или protocol сохраняется для выбранного прокси и при переключении на другой. SOCKS5, SOCKS4a и HTTP CONNECT доступны в quick editor; JSON позволяет задавать несколько прокси, цепочки, правила и listener. Выбор записи в dropdown редактирует эту запись; фактический маршрут определяют `rules` и `default_action`.

Reload атомарный: ошибочный профиль оставляет прежнюю конфигурацию работающей. Уже принятые соединения сохраняют свою ревизию; новые используют новую. Listener и `max_connections` изменяются после Stop. Снимок содержит все активные соединения, последние 512 завершённых и 256 событий.

Установка обновления использует прежний каталог. Перед обновлением или удалением закройте GUI и остановите CLI. Удаление убирает известные файлы приложения и ярлыки; профиль и сторонние файлы в каталоге остаются.

## Реализованные возможности

| Область | Состояние 0.2.0 |
|---|---|
| TCP SOCKS5 CONNECT / SOCKS4a / HTTP CONNECT | Реальный транспорт с тестами протоколов |
| IPv4, IPv6, hostname, смешанные цепочки | Поддерживаются; SOCKS4a не передаёт IPv6 |
| Direct / Block / Proxy / Chain | Правила по порядку, hosts, CIDR, ports; приложение только при достоверной платформенной идентичности |
| Аутентификация upstream | SOCKS5 username/password, HTTP Basic; `password_env` вместо пароля в JSON |
| Управление движком | Start / Stop / atomic reload / live counters, общий runtime для CLI и GUI |
| Управляемый SSH | Нативный OpenSSH child, watchdog, keepalive/backoff, readiness, Stop, ожидание новых local connections при reconnect |
| Шаблоны и discovery | AI / Web / AI + Web, локальный поиск, выбор приложений и системный профиль с честным scope |
| Windows GUI и установщик | Реальные PE32+ x64, Win32, Rust DLL, NSIS; точные результаты проверки в VERIFICATION |
| Windows WFP | Собственные исходники драйвера/SCM-службы; C ABI передаёт redirect records до connect; не активируется поставляемым установщиком |
| macOS | SwiftUI, TCP Network Extension, activation manager, scripts для universal `.app`/`.pkg`; Apple SDK build/run ещё не выполнялся |
| UDP/QUIC, системный DNS, kill switch | Не реализованы; не обещаются |
| TLS до upstream, failover, PPF/PPX import | Не реализованы |

Ошибка выбранного прокси завершает соединение, без автоматического Direct fallback. Это свойство маршрута, а не системный kill switch: неохваченный трафик и другие приложения используют обычную сеть ОС. Самоподключение первого TCP hop блокируется после проверки полного DNS-набора; удалённый localhost за SSH/другим прокси сохраняет удалённую семантику. Циклы через неправильно настроенные сторонние локальные прокси нужно исключать конфигурацией.

## macOS

На Mac с Xcode, XcodeGen и Rust:

```sh
./packaging/macos/build-pkg.sh local
```

Сценарий собирает universal Rust-библиотеку, SwiftUI `.app`, затем настоящий `.pkg`. Local-схема не включает Network Extension. Она использует ad hoc подпись и остаётся development-сборкой. Готовый Mac-инсталлятор в текущем Linux-окружении не создан.

Для native-схемы нужны ваши реальные Team ID, App ID и provisioning/signing. Команды и проверяемые gates: [packaging/macos/README.md](packaging/macos/README.md). Ключи/сертификаты не нужно помещать в исходники.

Native TCP scope задаётся портами, по умолчанию 80 и 443. UDP, DNS и другие порты остаются direct. Application criteria используют наблюдаемый signing identifier. Достоверное имя назначения доступно не у каждого flow; IP не превращается в hostname через предположение. Native upstream должен быть IP-литералом для исключения повторного захвата. Эти ограничения отображаются в интерфейсе и описаны в документации.

## Сборка ядра и CLI

```sh
cargo build --locked --release --workspace
cargo run --locked --release -p flowbridge-cli -- validate --config examples/ssh-socks.json
cargo run --locked --release -p flowbridge-cli -- serve --config examples/ssh-socks.json
```

В Windows-инсталляторе CLI называется `flowbridge-cli.exe`, чтобы не конфликтовать с GUI `FlowBridge.exe` на файловой системе Windows.

| Команда | Назначение |
|---|---|
| `validate --config PATH` | Проверка схемы, ссылок, диапазонов, пригодности для explicit SOCKS |
| `explain --config PATH --host HOST --port PORT` | Объяснение решения без открытия соединения |
| `explain ... --application NAME [--resolved-ip IP]` | Проверка гипотетических признаков; не подтверждает их происхождение от ОС |
| `check --config PATH --host HOST --port PORT` | Открыть маршрут без прикладного payload и закрыть |
| `serve --config PATH [--json-logs]` | Запустить общий движок; остановка Ctrl+C |
| `capabilities` | Фактически доступные возможности |

Примеры: `direct.json` — прямой forwarding, `ssh-socks.json` — локальный SSH SOCKS, `chain.json` — шаблон смешанной цепочки. Для authenticated proxy переменная с именем `password_env` должна быть доступна процессу приложения/службы. GUI и system extension не наследуют автоматически окружение вашей shell. Keychain/Credential Manager ещё не подключены.

### Семантика конфигурации

Схема 1, максимум 1 MiB. Unknown fields, неправильные ссылки, дубли ID, неоднозначные числовые IP и некорректные параметры отвергаются. Hostname — ASCII/punycode; IPv6 без квадратных скобок. Первое enabled правило выигрывает. Между группами applications/hosts/networks/ports — AND; внутри списка — OR; пустой список — any. Маски `*` и `?` сопоставляют всю строку, ASCII case-insensitive. IP сравниваются как адреса; IPv4 CIDR учитывает mapped IPv6. Policy не делает DNS/PTR. CIDR для hostname без `resolved_ip` не совпадает.

## Проверка и документы

```sh
python3 tools/verify.py --cross --c-abi
```

Без установленных cross targets: `python3 tools/verify.py`. `--c-abi` предназначен для GCC/Linux. `tests/windows_native_smoke.cpp` проверяет DLL и настоящий Win32 GUI; запускайте только в одноразовом пользователе/VM или изолированном Wine prefix, поскольку GUI сохраняет тестовый профиль. Наличие CI workflow не означает, что удалённые runners запускались.

- [ARCHITECTURE.md](docs/ARCHITECTURE.md) — архитектура и первичные источники.
- [PLAN.md](docs/PLAN.md) — задачи, агенты и оставшиеся gates.
- [SSH_AND_RECONNECT.md](docs/SSH_AND_RECONNECT.md) — watchdog, ограничения и архитектура resumable relay.
- [CLOUD_BUILDS.md](docs/CLOUD_BUILDS.md) — реальные Windows/macOS runners, доступ к репозиторию и отдельные требования драйвера/подписи.
- [REFERENCE_REVIEW.md](docs/REFERENCE_REVIEW.md) — статическое изучение предоставленного архива.
- [PLATFORMS.md](docs/PLATFORMS.md) — реальные платформенные границы и пути сборки.
- [WINDOWS_WFP.md](docs/WINDOWS_WFP.md) — исходники перехвата и WDK-проверки.
- [VERIFICATION.md](docs/VERIFICATION.md) — фактические результаты, логи, ограничения.
- [packaging/windows/BUILD.md](packaging/windows/BUILD.md) — воспроизводимая упаковка Windows.

Архив-референс раскрыт предоставленным пользователем паролем. Installer изучен статически; оригинальные executables и вложенный keygen не выполнялись. Их код/ресурсы/бинарники не включены в FlowBridge. Зависимости перечислены в `third_party/THIRD_PARTY_NOTICES.txt`.
