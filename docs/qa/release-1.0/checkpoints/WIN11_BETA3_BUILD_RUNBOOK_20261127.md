# FlowBridge beta.3 — Win11 build host и отдельная Win10 приёмка

> **Текущий объём 27 ноября: Win10 не трогать.** R5/R6 завершены, комплект
> сохранён; передача и R7 отложены владельцем. Codex на Win11 для сборки и
> ограниченной диагностики не требуется.

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

## Фактический результат

[Сборка #3](https://github.com/i-shutov/flowbridge/actions/runs/45986630920) на
`7d6597eb738d16839ff7a969c5ff6644194df975` завершена PASS 27 ноября 2026, 14:01 МСК.
Python 3.13.17 и Rust 1.100.0/rustup 1.29.3 подготовлены в отдельном каталоге
`C:\FlowBridge\private-candidates\toolchain-45986630920-1` из официальных пакетов
с проверкой SHA; Rust содержит необходимые для упаковки лицензии. Изменения PATH
ограничены заданием. Действующая PowerShell Execution Policy остаётся `Restricted`.

Оригинальный установщик:
`C:\FlowBridge\private-candidates\run-45986630920-1\candidate\artifacts\FlowBridge-0.3.0-beta.3-windows-x64-setup.exe`.
SHA-256: `6408c0bf595b0ae61a4fc05db17421dc4b03dcda241f3c1f1f997ab6583eec5b`.
Standalone source commit — `c6ead0f31de4c118453913d733f537ba421af616`, tree —
`19df7a94071f38be6b8aa3530e1ded7a954a02a8`. Это новый source cut из закреплённого
product `44f1fc0`, а не изменение исторической beta.2.

Workflow повторно сверил оригинальный installer, manifest и все 13 разрешённых
файлов payload, включая GUI/CLI/FFI. Полные результаты и хеши:
[нативный build evidence](../evidence/20261127/native-beta3-build.json).
Установщик не запускался. Публичных artifacts — 0; product acceptance не присвоена.

Готовый комплект передачи: `C:\FlowBridge\private-candidates\kit-45988214013-1\FlowBridge-0.3.0-beta.3-Win10-private-QA.zip`.
SHA-256: `60e13a2c9d35e441469c0b6e95b5115fa0d4e3212be8fd2f072e2c5d5baba085`.
[Упаковка PASS](https://github.com/i-shutov/flowbridge/actions/runs/45988214013),
[машинный результат](../evidence/20261127/private-beta3-kit.json). Он содержит
исходные байты этого build; заново собирать installer для R7 не требуется.

Предыдущие попытки сохранены в журнале истории: [#1](https://github.com/i-shutov/flowbridge/actions/runs/45984099025)
нашла Git/CMake/MSVC/SDK, но не Python/Rust; [#2](https://github.com/i-shutov/flowbridge/actions/runs/45985845724)
остановилась на `curl --compressed` (код 2). В #3 локальная проба подтвердила код 2,
загрузка без этого флага и ограниченная gzip-распаковка NuGet JSON прошли.

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
остаются false. Передача на Win10 и R7 отложены по последнему указанию владельца.
В публичные Actions эти файлы не загружать.

## Что ещё не выполнено

R5 и R6 выполнены на исходных байтах. Нативная Win10 A3 с install/upgrade/uninstall,
интерактивным GUI и реальным managed SSH ещё не запускалась. Win11 не получает
продуктовую приёмку автоматически. Приватный комплект готов; далее —
[задание локальному Codex на Win10](WIN10_BETA3_NATIVE_ACCEPTANCE_HANDOFF_20261127.md),
независимые A5/A6 и решение о внутреннем пилоте A7.
