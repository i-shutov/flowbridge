# Explicit SOCKS beta: проверка конкретного кандидата на Windows и macOS

Этот протокол закрывает автоматизируемую часть A3/A4 на выбранной владельцем
машине. Он относится к **explicit SOCKS**, отдельному приложению
`FlowBridgeExplicitBeta` и неизменяемым байтам выбранного кандидата. Прежний
W2b2 на `c339df2e` не принимает новый пакет. WFP/NDISRD, Network Extension,
прозрачный перехват, DNS no-leak и выпуск 1.0 этим протоколом не принимаются.

## Что подготовлено

`tools/explicit_beta_acceptance.py` использует только стандартную библиотеку
Python 3.10+. По умолчанию он проверяет четыре независимо заданные привязки:

- SHA-1 исходного коммита из manifest и утверждённого candidate index;
- SHA-256 установщика и его размер;
- SHA-256 manifest;
- SHA-256 самого скрипта проверки.

На Windows отдельно проверяется `FlowBridgeNativeSmoke.exe`: его SHA-256 и
размер должны совпасть с `qa_harness` в закреплённом manifest. Этот EXE —
отдельная часть **QA kit**, он не входит в пользовательский установщик.
Для запуска harness создаётся отдельный временный каталог с его проверенной
копией и побайтной копией DLL из установленного продукта.

Проверка хешей не является установкой или функциональным испытанием.
Результат такого запуска — `VERIFIED_BYTES_NATIVE_NOT_RUN`, а install/launch/
upgrade/uninstall остаются `NOT_RUN`. Чтобы выполнить сценарий, нужен флаг
`--execute` и точное имя машины `--expected-computer`.

**Значения ожидаемых хешей берутся из независимо опубликованного immutable
candidate index.** Вычисление хеша полученного файла с последующим объявлением
этого же значения «ожидаемым» не доказывает происхождение файла. Предлагаемые
ниже команды используют обозначения для значений из index; фиктивные хеши
не встроены в документацию.

## Содержимое QA kit и manifest

| Платформа | Обязательные файлы | Manifest |
|---|---|---|
| Windows x64 | Скрипт, установщик `.exe`, `FlowBridgeNativeSmoke.exe`, manifest | `flowbridge-explicit-beta-windows-qa-package-v1`: `source_sha`, `installer_sha256`, `installer_bytes`, строгий `payload`, `qa_harness`; отдельный namespace и выключенные native controls |
| macOS universal | Скрипт, установщик `.pkg`, manifest | `flowbridge-explicit-beta-macos-qa-package-v1`: `source_sha`, `pkg_sha256`, `pkg_bytes`, `bundle_id=org.flowbridge.FlowBridgeExplicitBeta`, отсутствие system extension |

Абсолютные пути внутри build manifest относятся к CI. Их не надо исправлять:
на целевой машине пути задаются `--package`, `--manifest` и `--harness`.
Изменение manifest нарушит его закреплённый SHA-256. Скрипт не требует
установки Rust, Xcode, WDK, Git или изменения настроек сети на Windows.
На Mac используются штатные `pkgutil`, `installer`, `codesign` и `xcrun lipo`;
последний требует доступных Apple developer command-line tools.

## Windows 10: VM-910136

Запуск выполняется обычным пользователем в интерактивном рабочем столе.
Установщик работает в HKCU и не требует администратора. Тесту нужен доступный
GUI; не запускать его в закрытой либо неинтерактивной сессии.

Перед запуском закрыть FlowBridge. Скрипт откажется, если в текущем профиле уже
существуют установка, профиль или ярлыки **beta**. Он не предлагает их удалять:
для повторного опыта нужен чистый отдельный пользователь. Существующая stable
установка и профиль могут оставаться; скрипт считывает их контрольные хеши и
проверяет неизменность. Пользовательские профили не копируются в отчёт.

В PowerShell 5.1, из распакованного QA kit, указать реальные значения из index:

```powershell
$Source = '<40 hex source SHA>'
$PackageSha = '<64 hex installer SHA-256>'
$ManifestSha = '<64 hex manifest SHA-256>'
$ToolSha = '<64 hex acceptance script SHA-256>'

$Common = @(
    '.\explicit_beta_acceptance.py',
    '--manifest', '.\explicit-beta-package.json',
    '--package', '.\FlowBridge-0.3.0-beta.1-windows-x64-setup.exe',
    '--harness', '.\FlowBridgeNativeSmoke.exe',
    '--expected-source', $Source,
    '--expected-package-sha256', $PackageSha,
    '--expected-manifest-sha256', $ManifestSha,
    '--expected-tool-sha256', $ToolSha,
    '--expected-computer', 'VM-910136'
)

# Проверка полученных байтов; продукт ещё не устанавливается.
py -3 @Common --output '.\native-qa-preflight'
if ($LASTEXITCODE -ne 0) { throw 'Проверка закреплённых файлов не прошла' }

# Настоящие install → GUI/TCP → upgrade → uninstall.
py -3 @Common --execute --output '.\native-qa-windows'
if ($LASTEXITCODE -ne 0) { throw 'Native QA не пройдена; см. native-acceptance.json' }
```

Сценарий устанавливает только beta в новый временный каталог, проверяет все
файлы по manifest, реальную выдачу `capabilities` и запускает тот же скомпилированный
Win32 smoke harness, что используется для hosted-проверки. Harness проверяет
GUI/FFI, локальный TCP, Start/Stop, выключенные capture controls и создаёт пять
различных снимков страниц. Это не испытание настоящего SSH-сервера.

Повторная установка проверяет сохранность каталога и настроек. Удаление
должно убрать пакетные файлы, beta registration и ярлыки, сохранив созданный
тестовый пользовательский файл и профиль beta. Скрипт также сверяет stable
профиль, основные binaries и четыре связанные registry values с исходным
состоянием. Пользовательские настройки не удаляются автоматически.

## macOS: Apple Silicon и отдельный Intel-прогон

M1 и M4 проверяют семейство Apple Silicon. Успех на них не подтверждает Intel.
Версия macOS и архитектура записываются в отчёт. Bundle должен отсутствовать
в `/Applications/FlowBridgeExplicitBeta.app`; профиль beta и её package receipt
также должны отсутствовать. Stable `/Applications/FlowBridge.app` и её данные
сохраняются и проверяются по хешам.

Скрипт запускается обычным пользователем. Для штатного installer необходима
предварительно открытая оператором сессия `sudo`; сам скрипт использует только
`sudo -n` и не запрашивает/сохраняет пароль. Не запускать весь Python через sudo:
это выберет неверный пользовательский профиль.

```bash
source_sha='<40 hex source SHA>'
package_sha='<64 hex pkg SHA-256>'
manifest_sha='<64 hex manifest SHA-256>'
tool_sha='<64 hex acceptance script SHA-256>'
expected_computer='<точное имя целевого Mac из hostname>'

common=(
  ./explicit_beta_acceptance.py
  --manifest ./explicit-macos-package.json
  --package ./FlowBridge-0.3.0-beta.1-macOS-universal-explicit-beta.pkg
  --expected-source "$source_sha"
  --expected-package-sha256 "$package_sha"
  --expected-manifest-sha256 "$manifest_sha"
  --expected-tool-sha256 "$tool_sha"
  --expected-computer "$expected_computer"
)
python3 "${common[@]}" --output ./native-qa-preflight

# После успешной проверки файлов, в интерактивной сессии владельца:
sudo -v
python3 "${common[@]}" --execute --output ./native-qa-macos
```

До установки проверяются реальные пути внутри pkg, единственный component
receipt, отсутствие install scripts и distribution checks, bundle identity,
ad-hoc codesign и обе архитектуры. Допускается только payload внутри
`Applications/FlowBridgeExplicitBeta.app`; stable app, системные расширения,
службы и privileged helpers запрещены. После установки сравнивается полный
content fingerprint приложения с распакованным пакетом.

Launch-проверка означает, что процесс установленного SwiftUI-приложения прожил
четыре секунды. Она не доказывает исправность всех элементов окна или маршрута.
Upgrade сохраняет profile directory. Затем удаляется **только** app, отсутствовавшее
до этого запуска и сохранившее точный fingerprint, и его отдельный receipt.
Профиль beta остаётся. При ошибке скрипт записывает `cleanup_required` и не
выполняет широкую автоматическую очистку. `owned_cleanup_paths` в локальном
отчёте указывает только созданный этим запуском временный каталог, beta app
либо её uninstaller и отдельный receipt. Путей к пользовательским профилям
там нет. На Windows сначала закрывают оставшееся тестовое окно и используют
указанный beta uninstaller; stable приложение не удаляют. Временный QA-каталог
сохраняется для диагностики даже после успешного прогона.

Проверка entitlements следует документированному Apple способу
[`codesign -d --entitlements`](https://developer.apple.com/library/archive/technotes/tn2415/).
Успешная команда без plist означает отсутствие объявленных entitlements;
непустой вывод разбирается как plist. Неизвестный ненулевой exit code и сообщение
о повреждённых entitlements не принимаются как их отсутствие. В отчёте отдельно
сохраняется код завершения этой команды; подпись не меняется для прохождения теста.

## Результаты и границы принятия

| Результат | Что подтверждено |
|---|---|
| `VERIFIED_BYTES_NATIVE_NOT_RUN` | Совпали ожидаемые source/package/manifest/tool pins; native steps не запускались |
| `OWNER_NATIVE_AUTOMATED_CHECKS_PASS` | На указанном оператором non-CI хосте выполнены все шесть автоматических шагов; аппаратная идентичность не аттестована |
| `CI_AUTOMATED_CHECKS_PASS` | Те же шаги выполнены в обнаруженной CI-среде; это не owner-native evidence |
| `FAIL` | Есть отказ или неполный шаг; точный устойчивый код указан в `error_code` |

`native-acceptance.json` всегда сохраняет `release_accepted=false` и
`a3_a4_full_acceptance=false`. Независимая приёмка требует дополнительно
просмотреть исходные снимки, проверить интерактивные GUI/клавиатуру, реальный
управляемый SSH и профиль на целевой ОС. Пять Windows BMP дополняют JSON;
raw stdout, приватные ключи и содержимое user profiles в него не включаются.

Отчёт нельзя редактировать, чтобы закрыть недостающий тест. Проверяющий
сопоставляет `source_sha`, package/manifest/tool SHA и host metadata с candidate
index. После изменения пакета или исходников требуется новый запуск.

## Проверка самого инструмента

```bash
python3 -m unittest discover -s tests -p test_explicit_beta_acceptance.py -v
```

Эти тесты проверяют отказ при несовпадении SHA, traversal/duplicate payload,
подмене scope booleans, отсутствии harness, лишнем macOS payload, ошибочном
hostname/platform, утечке приватного текста в errors и попытке считать CI либо
проверку файлов native acceptance. Они не устанавливают приложение и не
подменяют Windows/macOS-проверку.
