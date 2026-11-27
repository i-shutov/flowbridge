# FlowBridge beta.3 — Win11 build host и отдельная Win10 приёмка

**27 ноября 2026.** Задание на локальную приватную сборку после проверки host
и CI выбранного source/tooling. Сборка не устанавливает драйвер, не изменяет
системную сеть и не является продуктовой приёмкой.

## Входы

- Product: `fix/windows-ssh-path-normalization-20261127`, [PR #91](https://github.com/i-shutov/flowbridge/pull/91).
- Полный product SHA: `PINNED_SOURCE` в принятом QA checkout, сверить с
  `RELEASE_EXECUTION_20261127.json`. Имя ветки не является pin.
- QA: `release/resume-internal-beta3-20261127`; зафиксировать полный SHA перед запуском.
  Product и QA должны находиться в разных каталогах.
- Локальный официальный `nsis-3.13.zip`, SHA-256
  `ba63dffc4410ee89193e1cb5a41989991bd77c61068da17e3156d136b7b0b3d8`.
  [Официальный каталог NSIS](https://sourceforge.net/projects/nsis/files/NSIS%203/3.13/).

## Preflight

Проверить Windows client x64, Python 3.13+, Rust stable, Git, CMake, MSVC x64 и
Windows SDK. Записать версии. Отсутствующий инструмент — prerequisite failure.
Не отключать Defender, UAC, подписи, сетевые фильтры или PowerShell policy.
Наличие инструмента в интерактивном профиле не доказывает доступность в службе.

Helper допускает Win10 build 19045 и Win11 build 22000+, требует нативную x64
среду и отклоняет Server/domain controller. Product acceptance target остаётся
Win10 Pro 22H2 x64 с `verified=false`.

## Ручной запуск через проверенный runner

В `main` доступен [Windows 11 private local beta.3 build](https://github.com/i-shutov/flowbridge/actions/workflows/win11-private-beta3-build.yml).
Запускать с ветки `main`: workflow закрепляет QA `86aace2a4696e9717bc2b4423b447a760946aa15`
и product `44f1fc0eba5ac1552df94f083342e25a1a764937`. Он проверяет стандартные
каталоги инструментов, нативную архитектуру и повышенную учётную запись,
активирует MSVC в дочернем процессе и выполняет пробную x64 компиляцию с SDK.

Результат сохраняется в новом `C:\FlowBridge\private-candidates\run-<run_id>-<attempt>`:
`private-build.log`, `runner-result.json`, `candidate-CHECKPOINT.json` и
`candidate\artifacts`. У каталога отдельные ACL; существующие кандидаты не
перезаписываются. Публичная сводка содержит ограниченные статусы и хеши,
пакет не загружается в GitHub Actions.

[Первая попытка](https://github.com/i-shutov/flowbridge/actions/runs/45984099025)
обнаружила Git, CMake, MSVC x64 и Windows SDK вне service PATH, но остановилась
с `PYTHON_3_13_OR_LATER_REQUIRED`. Rust/Cargo также не найдены. Для продолжения
нужны локальный Python 3.13+ и закреплённый Rust; уже найденные инструменты
переустанавливать не требуется. Проверка компиляции и сборка пакета ещё не
проходили. Действующая PowerShell Execution Policy остаётся `Restricted`.

## Подготовка и сборка

Подставить фактические локальные пути. Назначения должны быть новыми;
не использовать каталог старого кандидата. Пример для PowerShell:

```powershell
$ErrorActionPreference = 'Stop'
$qa = 'C:\FlowBridge\qa'
$product = 'C:\FlowBridge\product'
$nsisZip = 'C:\FlowBridge\toolchains\nsis-3.13.zip'
$privateRoot = 'C:\FlowBridge\private-candidates'

git -C $qa rev-parse HEAD
git -C $product rev-parse HEAD
git -C $product status --porcelain
Get-FileHash -LiteralPath $nsisZip -Algorithm SHA256

python "$qa\tools\stage_internal_beta3.py" `
  --source $product --out-dir "$privateRoot\beta3-source-review"
if ($LASTEXITCODE -ne 0) { throw 'Private source staging failed' }

# Новый каталог для настоящей сборки; подробный лог остаётся локально.
python "$qa\tools\stage_internal_beta3.py" `
  --source $product --out-dir "$privateRoot\beta3-native-build" `
  --build-windows --nsis-archive $nsisZip `
  *> "$privateRoot\beta3-native-build.log"
if ($LASTEXITCODE -ne 0) { throw 'Private native build failed; inspect local log' }
```

Нужны настроенные локальные `git user.name/user.email` для standalone commit.
Скрипт проверяет исходный SHA и чистоту, сохраняет точные blobs/modes, меняет
девять версионных файлов и семь собственных Cargo.lock packages.
Новый Git-репозиторий не имеет remotes.

SHA-256 всего ZIP проверяется до NSIS execution. Архив извлекается в новый
соседний каталог `beta3-native-build-nsis-toolchain`; запускается реальный
`Bin/makensis.exe`, `/VERSION` должен вернуть `v3.13`. Глобальный PATH не меняется.
Проверенный NSIS доступен только окружению дочернего builder.

## Выходы

Приватно сохранить checkpoint, installer и SHA256, package manifest, SBOM,
BUILD-METADATA, SHA GUI/CLI/FFI/harness, локальный build log и QA-tooling SHA.
Успех даёт `PRIVATE_LOCAL_INSTALLER_BUILT_QA_NOT_ACCEPTED`; Win10 A3, A5/A6 и A7
остаются false. Далее передать те же байты на Win10 по R6/R7 действующего плана.
В публичные Actions эти файлы не загружать.

## Что ещё не выполнено

Self-hosted smoke завершён PASS: Windows 11 Pro build 22631, native x64,
точный runner/host/account и повышенный token. Native build preflight выполнен
до проверки наличия Python; запуск NSIS и сборка beta.3 EXE пока не выполнялись.
Наличие runbook и успешный smoke не означают продуктовую приёмку.
