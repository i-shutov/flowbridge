# FlowBridge 0.3.0-beta.3 — Win10 VM-910136, нативная приёмка R7 и архив V6

> **ОТЛОЖЕНО ВЛАДЕЛЬЦЕМ 27 ноября 2026. Win10 не трогать.**
> Этот документ сохранён как подготовленная процедура, но сейчас не является
> заданием на выполнение. Не передавать пакет и не запускать приведённые ниже
> команды на Win10. Текущие работы выполняются через Win11 runner и hosted CI.

**27 ноября 2026. Статус R7 — NOT_RUN.** Выполни согласованную per-user GUI/SSH
проверку в существующей интерактивной RDP-сессии локального Codex под
`Admin` на `VM-910136`, Windows 10 Pro 22H2 x64, build 19045. Проверь имя
хоста, версию ОС, архитектуру, учётную запись и наличие активного рабочего
стола. Зафиксируй номер сессии, DPI и размеры окна. GitHub runner доступен на
Win11 и используется для сборки. Действия GUI выполняет локальный Codex через
Win32/UI Automation в рабочем столе с проверкой foreground HWND/PID.

## 1. Прими и проверь исходные байты R6

Распакуй приватный QA kit по согласованному закрытому каналу в новый каталог
`C:\FlowBridge\ReleaseQA\beta3-kit`. Сохрани четыре исходных файла из одного
[Win11 build и R6](https://github.com/i-shutov/flowbridge/actions/runs/45986630920),
candidate index и `SHA256SUMS`. [Упаковка на Win11](https://github.com/i-shutov/flowbridge/actions/runs/45988214013)
прошла 27 ноября 2026, 14:10 МСК; исходные файлы повторно проверены, каждый
из шести участников ZIP прочитан с проверкой CRC и SHA-256. Артефактов Actions — 0.

Оригинальный ZIP на Win11:
`C:\FlowBridge\private-candidates\kit-45988214013-1\FlowBridge-0.3.0-beta.3-Win10-private-QA.zip`.
Размер — **2 057 147 байт**; SHA-256 —
`60e13a2c9d35e441469c0b6e95b5115fa0d4e3212be8fd2f072e2c5d5baba085`.
Перед распаковкой сравни ZIP с этим ожидаемым SHA. После распаковки проверь
`SHA256SUMS` для четырёх входов и `candidate-index.json`. SHA-256 index —
`dbc6b7b8150378e3ca44747ed9344a8a04efc2618196b9e27da4d72a045f5348`.
Сверь index и пины R6 ниже.
Подстановка SHA из полученного файла в качестве его ожидаемого SHA
не подтверждает происхождение.

| Предмет | Файл или pin |
|---|---|
| Product baseline, до staging | `44f1fc0eba5ac1552df94f083342e25a1a764937` |
| Standalone beta.3 commit | `c6ead0f31de4c118453913d733f537ba421af616` |
| Standalone beta.3 tree | `19df7a94071f38be6b8aa3530e1ded7a954a02a8` |
| Installer | `windows/FlowBridge-0.3.0-beta.3-windows-x64-setup.exe`, SHA-256 `6408c0bf595b0ae61a4fc05db17421dc4b03dcda241f3c1f1f997ab6583eec5b` |
| Исходный build manifest | `windows/explicit-beta-package.json`, SHA-256 `f6a94e5e8a87e571d63604ff3b2e417bf21e2e2758343171c587a43717318c99` |
| GUI | `8137a43a27eae62ba3988baeb5dffde0ee03fa983c96e8440480d77b1072b4d0` |
| CLI | `10182b2d58d9d0728f301afe3deb21be33b7aff9b99c627f4f37507bec7b70ab` |
| FFI | `cb933d0a0c312932d80c60ece25549a749f9664807e225dd339da2e57dad5b4e` |
| QA harness того же build | `windows/FlowBridgeNativeSmoke.exe`, 573 440 байт, SHA-256 `d41905fdcb2fc5f77e042d61c9aac5d640b23ca60ea0cf0965a4567dc9b105ff`; сверить также с `qa_harness` закреплённого manifest |
| Инструмент приёмки | `tools/explicit_beta_acceptance.py` из закреплённого исходного дерева, SHA-256 `faf62aabeea95ef316f5c0935177a65820ea4679ac94afe8b5461138dd17a33c` |

Упаковщик указал абсолютные пути Win11 в manifest. Сохрани его исходные
байты и передай фактические Win10 пути через `--package`, `--manifest` и
`--harness`. `--expected-source` получает новый standalone commit из R6.
Хеш инструмента проверяется **до его запуска**. Используй доступный локальный
Python 3.10+ x64. Если его нет, можно перенести проверенный официальный пакет
`python.nupkg` из каталога Win11 `toolchain-45986630920-1` в отдельный локальный
каталог, сверив SHA-512 из [R5 evidence](../evidence/20261127/native-beta3-build.json),
и распаковать весь каталог `tools/` с соседними DLL и стандартной библиотекой,
затем вызвать `tools/python.exe`. Этот Python не входит в шестикомпонентный QA ZIP.
Команды ниже можно выполнить в интерактивном PowerShell 5.1 с действующей ExecutionPolicy.

```powershell
$ErrorActionPreference = 'Stop'
$kit = 'C:\FlowBridge\ReleaseQA\beta3-kit'
$run = 'C:\FlowBridge\ReleaseQA\V6-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$python = 'C:\FlowBridge\toolchains\python\tools\python.exe' # Фактический доверенный Python.
$pins = @{
    new_private_git_commit = 'c6ead0f31de4c118453913d733f537ba421af616'
    new_private_git_tree = '19df7a94071f38be6b8aa3530e1ded7a954a02a8'
    installer_sha256 = '6408c0bf595b0ae61a4fc05db17421dc4b03dcda241f3c1f1f997ab6583eec5b'
    package_manifest_sha256 = 'f6a94e5e8a87e571d63604ff3b2e417bf21e2e2758343171c587a43717318c99'
    gui_sha256 = '8137a43a27eae62ba3988baeb5dffde0ee03fa983c96e8440480d77b1072b4d0'
    cli_sha256 = '10182b2d58d9d0728f301afe3deb21be33b7aff9b99c627f4f37507bec7b70ab'
    ffi_sha256 = 'cb933d0a0c312932d80c60ece25549a749f9664807e225dd339da2e57dad5b4e'
}
$package = Join-Path $kit 'windows\FlowBridge-0.3.0-beta.3-windows-x64-setup.exe'
$manifest = Join-Path $kit 'windows\explicit-beta-package.json'
$harness = Join-Path $kit 'windows\FlowBridgeNativeSmoke.exe'
$tool = Join-Path $kit 'tools\explicit_beta_acceptance.py'
$toolSha = 'faf62aabeea95ef316f5c0935177a65820ea4679ac94afe8b5461138dd17a33c'
function Assert-Sha256($path, $sha) {
    if ($sha -notmatch '^[0-9a-f]{64}$' -or
        (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine $sha) {
        throw 'Pin missing or SHA-256 mismatch'
    }
}
if ($env:COMPUTERNAME -ine 'VM-910136' -or
    (Get-CimInstance Win32_OperatingSystem).BuildNumber -ne '19045') {
    throw 'Wrong R7 host'
}
Assert-Sha256 $tool $toolSha
Assert-Sha256 $package $pins.installer_sha256
Assert-Sha256 $manifest $pins.package_manifest_sha256
Assert-Sha256 "$kit\candidate-index.json" 'dbc6b7b8150378e3ca44747ed9344a8a04efc2618196b9e27da4d72a045f5348'
Assert-Sha256 $harness 'd41905fdcb2fc5f77e042d61c9aac5d640b23ca60ea0cf0965a4567dc9b105ff'
$index = Get-Content -LiteralPath "$kit\candidate-index.json" -Raw -Encoding UTF8 | ConvertFrom-Json
if ($index.windows.source_sha -cne $pins.new_private_git_commit -or
    $index.windows.source_tree_sha -cne $pins.new_private_git_tree -or
    $index.windows.installer_sha256 -cne $pins.installer_sha256 -or
    $index.windows.manifest_sha256 -cne $pins.package_manifest_sha256 -or
    $index.acceptance_tool.sha256 -cne $toolSha) { throw 'Wrong candidate index' }
$m = Get-Content -LiteralPath $manifest -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-Sha256 $harness $m.qa_harness.sha256
if ($index.windows.harness_sha256 -cne $m.qa_harness.sha256) { throw 'Wrong harness pin' }
if ($m.candidate -cne '0.3.0-beta.3' -or
    $m.source_sha -cne $pins.new_private_git_commit -or
    $m.source_tree_sha -cne $pins.new_private_git_tree -or
    $m.driver_included -isnot [bool] -or $m.driver_included) { throw 'Wrong R6 manifest' }
$bins = [ordered]@{
    'FlowBridge.exe' = $pins.gui_sha256
    'flowbridge-cli.exe' = $pins.cli_sha256
    'flowbridge_ffi.dll' = $pins.ffi_sha256
}
foreach ($name in $bins.Keys) {
    $item = @($m.payload | Where-Object { $_.path -ceq $name })
    if ($item.Count -ne 1 -or $item[0].sha256 -cne $bins[$name]) {
        throw 'R6 payload pin mismatch'
    }
}
New-Item -ItemType Directory -Path $run | Out-Null
$common = @('-I', $tool, '--manifest', $manifest, '--package', $package, '--harness', $harness,
    '--expected-source', $pins.new_private_git_commit,
    '--expected-package-sha256', $pins.installer_sha256,
    '--expected-manifest-sha256', $pins.package_manifest_sha256,
    '--expected-tool-sha256', $toolSha, '--expected-computer', 'VM-910136')
& $python @common --output "$run\preflight"
if ($LASTEXITCODE -ne 0) { throw 'R7 pinned-byte preflight failed' }
```

Ожидаемый статус `VERIFIED_BYTES_NATIVE_NOT_RUN`. Сбой проверки хеша,
источника, платформы или объекта означает, что установка на этих входах
не начинается.

## 2. Выполни автоматический lifecycle 6/6

В рамках того же запуска зафиксируй исходное состояние stable и beta
profile, ярлыков, тестируемых HKCU ключей и связанных файлов. Используй
проверенный в V4/V5 способ сохранения предыдущего beta-профиля и оставшихся
ярлыков из теста через перенос на том же томе в новый доступный только
владельцу escrow. Проверь SHA/ACL до переноса и после восстановления.
`tools/explicit_beta_acceptance.py` отказывает при существующей регистрации,
beta-профиле, папке ярлыков или запущенном FlowBridge. Закрой FlowBridge
штатно на время изолированного теста и разбери существующую beta-регистрацию
по проверенному V4/V5 backup/restore.
Если её нельзя обратимо изолировать, сохрани её и зафиксируй конкретный
`existing_beta_refused`. Тест использует существующую учётную запись Admin.

После успешного preflight и сохранения beta baseline в том же сеансе:

```powershell
& $python @common --execute --output "$run\lifecycle"
if ($LASTEXITCODE -ne 0) { throw 'R7 lifecycle failed; inspect local native-acceptance.json' }
```

Ожидаются `OWNER_NATIVE_AUTOMATED_CHECKS_PASS` и шесть отдельных PASS для
`install`, `payload`, `launch`, `upgrade`, `uninstall`, `stable_preserved`.
Собери исходный `native-acceptance.json` и пять разных BMP. Сверь SHA
фактически установленных GUI/CLI/FFI с R6. Поведение сохранения файла
пользователя, отдельный HKCU namespace, отсутствие capture helper/драйвера,
и неизменность stable должны соответствовать проверкам инструмента.

## 3. Проверь GUI, настоящий SSH, отказы и восстановление

После автоматического uninstall установи **тот же** проверенный EXE в
отдельный новый тестовый каталог под `$run` для SSH. Используй этот же
тестовый beta-профиль, исходный профиль держи в escrow до общей очистки.
Для пути без пробелов можно запустить `Start-Process -FilePath $package
-ArgumentList '/S', "/D=$run\ssh-install" -Wait -PassThru` и сверить
`ExitCode`, `InstallDir`, SHA установленных GUI/CLI/FFI и `capabilities`.
При запуске GUI привяжи UIA к PID проверенного EXE. Зафиксируй Dashboard,
SSH, Journal, компактный режим и работу Tab/Enter, Apply/Save/Cancel,
Start/Stop. Записывай реальные операции в `actions.jsonl` с UTC, HWND/PID и
control ID. Сверь IDs исходного кода с живым окном. Managed Mode — 230,
Host/Port/User — 231/232/233, Key/known_hosts — 234/235, Backend — 286,
Save — 240, Start/Stop — 100/101, Health/Summary/Journal — 210/272/111.

Используй проверенный изолированный loopback fixture из приватного V4/V5
как рецепт. Запускай только его адаптированную к текущим pins версию.
Проверь Microsoft Authenticode `Valid` у локального `ssh.exe` и `sshd.exe`.
Запусти `sshd.exe` отдельным тестовым процессом на `127.0.0.1` со свободным
портом. Сгенерируй отдельные
одноразовые host/client ключи, `authorized_keys` и закреплённый `known_hosts`.
Подготовь отдельный loopback echo с счётчиком принятых соединений. Порт
ingress FlowBridge, локальный SOCKS порт клиента OpenSSH, SSHD и echo должны быть
различны. Настройки Windows SSH service, production SSH и сеть не нужны.

| Сценарий | Доказательство на тех же GUI/CLI/FFI |
|---|---|
| Healthy | Managed SSH Ready и фактический дочерний SSH PID. SOCKS5h с `ATYP=DOMAINNAME`, бинарный nonce совпадает побайтно, оба EOF. Зафиксируй подпись клиента и хеши исполненных файлов. |
| Ошибочный host key | Заменить только test `known_hosts` на другой корректный публичный ключ той же тестовой пары host/port. Нет Ready, передача отклонена, echo принимает 0 соединений. Вернуть верный pin. |
| Отсутствует private key | Абсолютный путь к отсутствующему тестовому файлу, остальные поля правильны. Нет Ready, echo принимает 0 соединений. Восстановить только правильный test key и подтвердить Ready и echo. |
| Backend trust и приватность | Проверенный Microsoft OpenSSH проходит positive control. Заведомо неподписанный тестовый файл выбран явно и отклонён; нет дочернего процесса этого файла и fallback. GUI Journal/health содержит безопасную категорию, без исходных SSH stderr, пути к тестовому ключу, имени пользователя или backend path. |
| All-down → recovery | Остановить только fixture sshd. Дождаться закрытия managed gate, проверить отказ нового SOCKS и 0 bypass accepts. Поднять тот же fixture с прежним host key и подтвердить новый бинарный echo. |
| Stop и cleanup | GUI Stop и закрытие окна. Повторный SOCKS probe не проходит; ни одного тестового дочернего SSH процесса или listener. Удаление только test beta через его `Uninstall.exe`, сохраняющее stable. |

Для каждого отрицательного теста записывай фактически наблюдаемый
результат. Отсутствующий listener означает connection refusal и `REP=null`.
Значение `REP=01` допустимо только при полученном ответе SOCKS. После каждого
отказа положительный контроль подтверждает, что сервер и fixture работают.
Тестирование выполняется в явном SOCKS режиме и не устанавливает драйвер,
службу или системный proxy.

## 4. Верни приватный V6 и восстанови исходное состояние

В `finally` останови только процессы fixture и test beta, убери test
установку её uninstaller и восстанови исходные beta и stable объекты, если
они были перемещены. Сверь SHA/ACL/registry и отсутствие тестовых listeners
и процессов. Не изменяй Defender, firewall, Windows Features, UAC, DNS,
маршруты, системный SSH service и ExecutionPolicy. Если восстановление
неполное, зафиксируй отказ и сохрани точный локальный журнал.

Создай оригинальный локальный `A3-Beta3-Codex-V6-Win10-<UTC>.zip` с
`CHECKPOINT.md`, preflight/lifecycle JSON, пятью BMP, исходными
скриншотами GUI тестовых состояний, `actions.jsonl`, результатами SSH
и `restore-checks.json`. Включи SHA-256 и длину каждого участника в
отдельный `sha256-manifest.json`, проверь CRC, совпадение файлов и SHA
самого ZIP. Исключи ключи, профили, raw stderr, production endpoints,
секреты и персональные пути. Верни ZIP по согласованному закрытому каналу,
снаружи передавай только архивный SHA и ограниченную сводку статусов.

`PASS_WIN10_BETA3_V6_NATIVE_QA` означает совпадение всех pins, lifecycle
6/6, действительный GUI/SSH на VM-910136, пройденные отрицательные проверки
и восстановление. Иначе верни `FAIL` либо `BLOCKED` с конкретным шагом и
сохрани имеющееся оригинальное доказательство. Независимое решение по
A5/A6, допуск A7 и WFP/G2 остаются отдельными.

