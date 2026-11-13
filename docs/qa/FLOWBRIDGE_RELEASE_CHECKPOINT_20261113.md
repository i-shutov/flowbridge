# FlowBridge — контрольная точка выпуска, 13 ноября 2026

## Результат и точная область

**1.0: NO-GO.** Промежуточная версия — **0.3.0-beta.1, explicit SOCKS only**.
**B0 hosted candidate: PASS.** Все 11 jobs общего workflow завершились успешно; original packages, QA reports и итоговый архив проверены независимо. Owner/release approval остаются открыты.

Пользователь вручную задаёт SOCKS5/5h в клиентском приложении. Эта поставка
не включает WFP/NDISRD helper/driver или Network Extension и не принимает
прозрачный перехват, системный kill switch, UDP/QUIC или общий DNS no-leak.
DNS через прокси относится к hostname, переданному клиентом через SOCKS5h.

| Привязка | Значение |
|---|---|
| Проверенный исходный commit | `f5ecd48d8f81c594f755a55e7969b57d20903020` |
| Git tree | `ac47b5292ec90e13572e88e9133b12d4dc1f77ac` |
| Unified workflow | [43407093536](https://github.com/i-shutov/flowbridge/actions/runs/43407093536) |
| Draft PR | [#59](https://github.com/i-shutov/flowbridge/pull/59) |
| Полный QA kit | [FlowBridge-0.3.0-beta.1-candidate-f5ecd48d8f81.zip](https://github.com/i-shutov/flowbridge/actions/runs/43407093536/artifacts/14028139291) — 5 697 502 bytes, вложен в Actions artifact вместе с source ZIP |
| SHA-256 QA kit | `4b51d4136878476b48946361ce1635cb6d630e62b50ca82c73df28a5902ed8b8` |
| Original Actions artifact | 14028139291 / `69e87b6ed4acd94b7abf59a4a825cfef49041004e5afea804e83d4787cf61d9f` |

Документальный commit этой контрольной точки не является новой принятой
бинарной сборкой. Все указанные пакеты и QA относятся к закреплённому
исходному commit выше; новая сборка требует собственного evidence.

## Что изменено в этом блоке

1. Единый контракт `packaging/explicit-beta.json` задаёт версию Cargo,
   Windows GUI/NSIS и macOS bundle/pkg. Два пакета и испытания теперь
   создаются одним workflow и связываются actual checkout SHA, tree и run ID.
2. Managed SSH испытывает release DLL и CLI из Windows installer.
   Исправлен реальный конфликт: установленный `flowbridge-cli.exe` ранее
   не проходил разрешённые имена experimental banner helper.
3. Windows beta получила отдельные mutex/window class, верный заголовок
   версии и читаемые scope/DNS пояснения в компактном окне. Выбор SSH
   обновляет пояснение режима, не переключая уже работающий маршрут.
4. Windows installer и macOS app включают source-pinned SBOM, metadata и
   тексты лицензий зависимостей. Проверены 71 и 37 компонентов соответственно.
   Это inventory resolved production/build inputs, а не заявление о точном
   составе linked binary или выполненном юридическом/уязвимостном аудите.
5. Строгий assembler отклоняет разные source/tree/run, лишние payload files,
   изменённые binaries, metadata и QA pins, а также неподтверждённый native PASS.
6. Подготовлен переносимый operator QA script с четырьмя независимыми pins,
   отказом при существующей beta и сохранением пользовательских данных.
   Его настоящий lifecycle проверен на свежих Windows/macOS hosted runners.

## Проверки и пределы результата

| Проверка | Наблюдение |
|---|---|
| Контракт, negative/integrity tests | 50 Python tests; версии и static macOS scope |
| Rust format / Clippy / workspace tests / DNS loopback | PASS на Linux, Windows и macOS одного source |
| Windows package | Release GUI/CLI/FFI, NSIS; 13 payload hashes и QA harness совпали |
| macOS package | Настоящий universal Mach-O x86_64 + arm64; Info.plist 0.3.0 / 3.0.1 / 0.3.0-beta.1 |
| Operator lifecycle Windows | Install / payload / launch / upgrade / uninstall / stable preservation: 6/6 PASS |
| Operator lifecycle macOS | Те же 6/6 PASS; launch означает процесс, проживший 4 секунды |
| Managed SSH на поставляемых DLL/CLI | PASS: 128 held / 1152 ожидаемых overload rejections / 10 000 TCP churn / 4 независимых workers; strict host-key, binary half-close, shutdown и recovery |
| Общий архив | PASS: 23 файла комплекта; source ZIP соответствует всем 301 Git blobs, включая имена, bytes, hashes и executable bit |
| Windows compact visual | Исправленные scope/DNS/Advanced строки полностью видны; тексты managed/external mode согласованы |
| Owner Win10/Win11/Mac | NOT_RUN на этих новых байтах |
| Подписи | Windows installer и macOS pkg unsigned; macOS app ad-hoc, без publisher/notarization acceptance |

Windows hosted среда — Server 2025 AMD64; macOS — arm64 / macOS 15.
Universal binary не заменяет отдельное исполнение на Intel.
Все исходные native QA reports сохраняют `owner_native=false`,
`release_accepted=false` и `a3_a4_full_acceptance=false`.

Локально перед публикацией кода выполнены 238 Rust tests в 19 suites,
format/Clippy и 50 Python tests. Локальный Rust — 1.91.0, hosted package —
1.100.0. Локальные working-tree результаты не подменяют итоговые
exact-source hosted reports.

### Контрольные суммы установщиков

| Пакет | Размер, bytes | SHA-256 |
|---|---:|---|
| `FlowBridge-0.3.0-beta.1-windows-x64-setup.exe` | 1797589 | `74ff309d2e8ae115083bed9c5d4f233fd02dc841a8084a22912f3430c1e4b504` |
| `FlowBridge-0.3.0-beta.1-macOS-universal-explicit-beta.pkg` | 3524634 | `7eb645e227442ba5a2d12bc1b9c5853212baf8a3d28e7215640f0e3e2ec0453c` |

Original Windows artifact: `14028351048`,
ZIP SHA `2c111798b117df2b0980a31db5262f20529ffb19619983aebfad2fa9ee6db535`.
Original macOS artifact: `14027658178`,
ZIP SHA `c90fffbc9681b44f2af0f3c5514d7e9f4cd65a63b7c7138063806f36e245cbb4`.

### Найденные и устранённые отказы сборки

- На `3f1ab43` Windows checkout преобразовывал исходные файлы в CRLF:
  исходные hashes расходились с Linux. `.gitattributes` теперь закрепляет LF
  для текстовых файлов; равенство подтверждено фактическими артефактами.
- На том же source XcodeGen создавал три известные Info.plist, из-за чего
  clean-source gate прерывал metadata generation. Исключены ровно эти
  объявленные outputs; произвольный новый файл остаётся видимым.
- На `1f5b55c` macOS собрал pkg, но строгая проверка отклонила bundle version.
  В beta Info.properties явно связаны short/build versions с build settings.
  Значения проверены в payload окончательного pkg.

Ни один из этих отказов не преобразован в PASS ослаблением соответствующего gate.

## Что остаётся до публичной beta и 1.0

| Gate | Состояние и требуемое доказательство |
|---|---|
| A3 owner Windows | Новые байты на Win10/Win11: lifecycle, ручной GUI/keyboard и реальный управляемый SSH |
| A4 owner macOS | Новые байты на целевых Mac; отдельно arm64 и Intel, GUI и SSH |
| A5 | Независимое license/native runtime distribution review; выбор лицензии собственного кода |
| A6 | Независимое выпускное решение по новым байтам, ограничениям и целевым ОС |
| A7 | NOT_RELEASED: tag/GitHub prerelease не создавались |
| B1 / native G2 | Нет принятого packet/flow → PID/epoch witness; native capture NO-GO |
| B1 / macOS NE | Нет принятого sign/install/approve/activate и native traffic evidence |
| B2–B4 | Containment, target OS/soak, publisher signing/notarization и RC1.0 зависят от B1 |

Файл [LICENSE](../../LICENSE) явно оставляет лицензию FlowBridge-specific
кода невыбранной. Тексты third-party licenses не решают этот отдельный вопрос.

### Текущий G2: исходный отказ сохранён

[Capture run 43407099791](https://github.com/i-shutov/flowbridge/actions/runs/43407099791)
на текущем source снова выдал `kernel_connection_id_missing`.
Проверен original artifact `14026914682`,
ZIP SHA `5e5e83a2c31db481d9317acb474192cdc04bfba45584f561b3349d64c24bc9d8`.
Его JSON имеет `packet_owner_bound=false`,
`native_packet_attribution_proved=false` и `release_accepted=false`.

Дополнительный raw OpenSSH job в
[43407099955](https://github.com/i-shutov/flowbridge/actions/runs/43407099955)
имеет PASS для минимальной baseline/recovery проверки, но
`raw_backend_512_stability_proved=false`. В этом конкретном пробном прогоне
наблюдался peak held 246; это не универсальный предел OpenSSH и не 512-channel
acceptance. Report выполнен на PR merge `961b5fa92dd3a00ae00546fab4e024db863948bd`
с тем же tree `ac47b529...`; это отдельное испытание debug FFI.

### B1: что установлено по независимому WFP research

Проверенный срез research — `ca72eee3d5dc422ad6894219f9b68e63cf731034`.
[R160](https://github.com/i-shutov/flowbridge/blob/ca72eee3d5dc422ad6894219f9b68e63cf731034/research/wfp-ale/r160/R160_DYNAMIC_BFE_NEGATIVE.md)
показывает разрыв между жизнью динамических BFE filters и kernel PING.
[R161](https://github.com/i-shutov/flowbridge/blob/ca72eee3d5dc422ad6894219f9b68e63cf731034/research/wfp-ale/r161/R161_TERMINAL_LEASE_RECOVERY.md)
фиксирует terminal lease/session state без безопасного повторного ARM.
[R162](https://github.com/i-shutov/flowbridge/blob/ca72eee3d5dc422ad6894219f9b68e63cf731034/research/wfp-ale/r162/R162_ALE_REAUTH_NO_GO.md)
описывает one-shot authorization, отвергающую reauthorization.

Это выводы по реальному коду, а не утверждение о наблюдавшихся на Windows
утечках либо разрывах соединений. Одна подпись драйвера не исправляет lifecycle.
До нового native positive evidence нужны корректные policy/session/generation,
reauthorization и physical SSH egress invariants, затем реально собранные
SYS/PDB/INF/CAB и испытание в предназначенном для этого контуре.

[Зафиксированная область владельца](https://github.com/i-shutov/flowbridge/issues/41#issuecomment-6702417257)
сохраняет NDISRD-only integration и отдельное WFP research. В этом блоке
research, `main` и принятие backend не изменялись.

## Следующее действие на VM-910136

Использовать только QA kit из этой контрольной точки. Закрыть FlowBridge
и работать из распакованного корня в интерактивном Windows desktop,
обычным пользователем с Python 3.10+. Существующие stable данные допускаются;
при существующей beta скрипт откажется. Не удалять свои данные для обхода отказа.

```powershell
$QaArgs = @(
    '.\tools\explicit_beta_acceptance.py',
    '--manifest', '.\windows\explicit-beta-package.json',
    '--package', '.\windows\FlowBridge-0.3.0-beta.1-windows-x64-setup.exe',
    '--harness', '.\windows\FlowBridgeNativeSmoke.exe',
    '--expected-source', 'f5ecd48d8f81c594f755a55e7969b57d20903020',
    '--expected-package-sha256', '74ff309d2e8ae115083bed9c5d4f233fd02dc841a8084a22912f3430c1e4b504',
    '--expected-manifest-sha256', '4a16dd710e468dd6e13e387fa4640c00102771758b4a5eb8c5f7bf9ec62bbf9a',
    '--expected-tool-sha256', 'faf62aabeea95ef316f5c0935177a65820ea4679ac94afe8b5461138dd17a33c',
    '--expected-computer', 'VM-910136'
)
py -3 @QaArgs --output '.\native-qa-preflight-20261113'
if ($LASTEXITCODE -ne 0) { throw 'Проверка закреплённых файлов не прошла' }
py -3 @QaArgs --execute --output '.\native-qa-windows-20261113'
if ($LASTEXITCODE -ne 0) { throw 'Native QA не пройдена; см. native-acceptance.json' }
```

Первый вызов только сверяет bytes. Второй выполняет install/GUI/TCP/upgrade/
uninstall; это намеренное действие оператора на указанной машине.
Результат — `native-qa-windows-20261113/native-acceptance.json` и BMP.
Он не заменяет последующие ручные SSH/host-key/SOCKS5h/Stop проверки.

Полный [operator protocol](EXPLICIT_BETA_NATIVE_ACCEPTANCE.md) содержит
macOS шаги и точные границы автоматизации. Pins для Mac:
package `7eb645e227442ba5a2d12bc1b9c5853212baf8a3d28e7215640f0e3e2ec0453c`,
manifest `ed00c3257a4b5f1db453169fc802c3ba85215265bb2dce783d79275cbb386a03`;
source и tool совпадают с Windows.

Исторические owner W0–W2b2 PASS относятся к `c339df2e` и не переносятся
на эти новые пакеты. Машинно читаемая сопутствующая запись:
[FLOWBRIDGE_RELEASE_CHECKPOINT_20261113.json](FLOWBRIDGE_RELEASE_CHECKPOINT_20261113.json).

