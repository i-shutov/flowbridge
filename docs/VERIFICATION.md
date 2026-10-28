# Проверка FlowBridge 0.2.0

Дата: 28 октября 2026. Основная среда: Linux x86_64, Rust 1.99.1. Windows PE-файлы собраны MinGW-w64; Windows-код выполнялся в Wine64. Это отчёт о выполненных проверках, а не о запланированных тестах. Первичные журналы находятся в `docs/verification/`.

## Результаты

| Проверка | Фактический результат |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --locked --offline --workspace --all-targets -- -D warnings` | PASS |
| `cargo test --locked --offline --workspace` | **82 теста PASS** на Linux |
| `cargo build --locked --offline --workspace` | PASS |
| `python3 tests/smoke.py` | **8 сквозных сценариев PASS**, реальный CLI и loopback TCP |
| C ABI, GCC с `-Wall -Wextra -Werror` | PASS; 1000 циклов validate/evaluate/free, null handling |
| Rust cross-check Windows MSVC x64, Mac arm64 и x86_64 | PASS; это проверка Rust-кода, не native SDK build |
| Windows GNU release DLL и CLI | Реальные PE x64 собраны |
| Нативный Win32 GUI + C++ smoke harness | Собраны MinGW, выполнялись в Wine64 |
| Windows-target Rust FFI и SSH tests | **23 теста PASS в Wine64**: 11 FFI + 12 tunnel |
| Native GUI smoke | PASS: реальный трафик/half-close, метрики, Apply/Start/Stop, rollback, страницы, SSH-форма, discovery, presets, native export, clean exit |
| NSIS AMD64 Unicode installer | Собран; payload SHA-256 проверен после установки |
| Установка и обновление в Wine | PASS: все 11 файлов, 3 ярлыка, registry, установленный CLI/GUI; upgrade сохраняет каталог и профиль |
| Обычное удаление в Wine | **PASS** в изолированном `/tmp` prefix: реальные файлы/ярлыки/регистрация удалены, профиль и посторонний файл сохранены |
| WFP service user-mode | CMake/MinGW compile/link PASS; driver не собран |
| macOS native sources/scripts | Shell syntax, plist/YAML/resources/FFI и targeted source checks выполнены; Apple SDK compile/run не выполнены |
| Подпись, macOS `.app/.pkg`, driver `.sys/.cat` | Не выполнены; неподтверждённые файлы не создавались |
| GitHub Actions на внешних runners | Workflow подготовлен; подключённый аккаунт доступен, подходящий репозиторий ещё не предоставлен, запуска нет |

Файл `verification/results.json` отражает только основной `tools/verify.py`: его старое поле `native_ui_built: false` описывает работу именно этого runner. Отдельные Windows-сборки, GUI и installer подтверждаются другими журналами и manifest; это поле не редактировалось задним числом. 23 Windows-теста частично повторяют Linux-тесты, поэтому их нельзя складывать в число независимых сценариев.

## Что проверяют тесты

| Компонент | Linux-тестов | Основные границы |
|---|---:|---|
| `flowbridge-core` | 20 | Строгая схема, неизвестные/повторяющиеся поля, refs, Action variants, first-match/default, неизвестный процесс, CIDR и mapped IPv6, hostname/port validation |
| `flowbridge-net` | 33 | SOCKS5/4a/HTTP CONNECT, auth, смешанные цепочки, remote DNS, fragmented/coalesced bytes, header limits, timeouts, half-close, idle progress, no direct fallback, loopback recursion, preparation до connect |
| `flowbridge-ffi` | 9 | JSON ownership/handles, limits, реальные stream I/O, shutdown/close, registry cancellation и WFP input guards |
| `flowbridge-runtime` | 8 | Start/bind, occupied port, stop/restart, atomic reload/rollback, метрики, history, reconnect gate и независимые маршруты |
| `flowbridge-tunnel` | 12 | Config/argv, occupied-port ownership, startup/readiness/restart/Stop, постоянные ошибки, ограничение stderr, отмена reader при унаследованном дескрипторе |

SSH tests используют управляемый тестовый child и локальные SOCKS endpoints. Подключение к реальному внешнему SSH-серверу и проверка пользовательских ключей не выполнялись: сервер/учётная запись для этого не предоставлены. Успешный SOCKS greeting подтверждает локальный endpoint, а не доступность всего интернета.

Windows-specific FFI tests проверяют nonblocking `WSAPoll` и разделение временного ожидания готовности от фатального socket timeout. Native harness передаёт двоичные данные через фактическую DLL, проверяет ответ после half-close, счётчики и отмену. Выбор AI/Web приложений проверяется как генерация native-профиля; он не выдаётся за работающий WFP capture.

## Исправления, найденные проверками и ревизией

- Строгая deserialization Direct/Block больше не пропускает неизвестные поля.
- First-hop DNS разрешается один раз, проверяется весь набор IP, connect использует тот же набор: закрыт обход recursion guard через DNS alias.
- WFP socket preparation выполняется до каждой connect-попытки; ошибка preparation не допускает подключения без redirect records.
- Engine хранит все активные соединения отдельно от последних 512 завершённых и сохраняет прежнюю конфигурацию при ошибке reload.
- На Windows FFI заменил повтор blocking timeout на nonblocking I/O с ограниченным `WSAPoll`; настоящий socket timeout завершает поток.
- SSH stderr reader сделан отменяемым и ограниченным. Унаследованный descendant-дескриптор больше не удерживает нормальный Stop; Windows Job закрывается до ожидания reader.
- Native UI не применяет параллельный профиль во время pending startup; ingress/SSH port collision отклоняется до запуска; неудачный combined Start очищает принадлежащие ему ресурсы.
- macOS Direct не блокируется квотой proxy-pump. Live Apply привязан к UUID текущей provider-сессии; устаревшие replies/timeouts не меняют новую сессию. Это source review, пока без Apple SDK runtime.
- Установщик использует разные имена `FlowBridge.exe` и `flowbridge-cli.exe`, закрепляет upgrade за зарегистрированным каталогом и перечисляет только собственные файлы при удалении.

## Первичные свидетельства

- `verification/results.json` и соседние Rust/CLI/C ABI журналы — реальные команды, коды завершения, время и stdout/stderr.
- `verification/windows-rust-tests.json` / `.txt` — выполнение Windows-target FFI/tunnel tests в Wine.
- `verification/windows-package.json` — размер/SHA-256 установщика и каждого payload файла.
- `verification/windows-installer-results.json` / `windows-installer-smoke.txt` — последний полный install/upgrade/uninstall run. Поле `passed` выставляется только после проверки фактического удаления, registry/shortcuts и сохранения профиля.
- `verification/windows-installer-isolated-run.json` и `windows-installer-summary.txt` — финальный воспроизводимый запуск в отдельном `/tmp` prefix, exit 0, все шесть групп проверок PASS; обычный `/S`, без `/NCRC` и внешней процедуры восстановления.
- `verification/windows-installer-first-attempt-*`, `windows-installer-alias-recovery-*` и diagnostic logs — сохранённые неудачные/диагностические попытки; они не заменяют последний воспроизводимый результат.
- `ui-windows-overview.png` — снимок реального Windows GUI в Wine после сетевого smoke test, не макет.

В предыдущих прогонах внутри синхронизируемого рабочего каталога наблюдалось повторное появление уже удалённых файлов и противоречие между состоянием registry и payload. Эти попытки не записаны как успешные. Контрольный полный прогон использовал отдельные `/tmp` prefix, копии проверенных байтов и журналы; после завершения перенесены только свидетельства. Тот же установщик прошёл нормальное удаление без изменения продукта или выключения CRC. Прежние гипотезы о несовпадении NSIS stubs, неверной CRC или роли Unix path alias не подтвердились.

## Воспроизведение

Основное ядро после установки Rust и загрузки зависимостей:

```sh
rustup target add x86_64-pc-windows-msvc aarch64-apple-darwin x86_64-apple-darwin
python3 tools/verify.py --cross --c-abi
```

`--c-abi` этого runner рассчитан на Linux/GCC. `--offline` применим при уже загруженных зависимостях. Windows GUI/NSIS: `packaging/windows/BUILD.md` и `packaging/windows/build-installer.py`. Native smoke target включается CMake-флагом `FLOWBRIDGE_BUILD_NATIVE_TESTS=ON`; запускать его нужно в disposable profile, поскольку он сохраняет тестовую конфигурацию.

Wine install smoke запускается через один `xvfb-run` на весь Python-процесс и использует отдельные `/tmp` prefix и журналы с ownership marker; перенос журналов в рабочий каталог — после завершения:

```sh
xvfb-run -a python3 tests/windows_installer_smoke.py \
  --prefix /tmp/flowbridge-disposable-wine-prefix \
  --installer /absolute/path/to/FlowBridge-0.2.0-windows-x64-setup.exe \
  --manifest docs/verification/windows-package.json \
  --harness build/windows-gnu/FlowBridgeNativeSmoke.exe \
  --output /tmp/flowbridge-installer-verification
```

Скрипт отказывается работать с чужим немаркированным prefix. Его назначение — проверка пользовательского installer, не установка/испытание kernel driver.

## Непокрытые области и границы выпуска

Wine не заменяет Windows 10/11. Не выполнены native Windows runtime, WDK compile/sign, Driver Verifier, VPN/EDR coexistence, macOS Xcode/signing/activation, end-to-end SSH authentication, DNS/UDP packet-capture guarantees, длительная нагрузка/soak и сторонний security audit. MSRV 1.85 объявлен в Cargo, но проверенный компилятор здесь 1.99.1.

Поставляемый Windows пакет работает как explicit SOCKS с optional managed SSH. Он не включает драйвер перехвата, системный kill switch, автоматический DNS/UDP capture или remote relay для сохранения TCP после потери SSH. Исходники этих платформенных направлений и проект relay не являются доказательством готового продукта.
