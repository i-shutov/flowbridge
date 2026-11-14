# FlowBridge beta A3 — Windows 10/11 no-Python native acceptance

Date: 2026-11-14. This is a focused operator option for the **same frozen**
v0.3.0-beta.1 candidate, with no new executable or installer build.

## Why this gate exists

Owner's Windows 10 Pro 22H2 (VM-910136) previously reported that neither
`python.exe` nor `py.exe` was installed. The pinned A3 script in Draft PR #58
uses Python to run the otherwise valid QA kit. It is inappropriate to impose
a new Python installation solely for release acceptance of this user-mode
product. This implementation uses stock Windows PowerShell 5.1 and .NET.

## Immutable input and safety boundary

- Original hosted candidate run: [43407093536](https://github.com/i-shutov/flowbridge/actions/runs/43407093536).
- Source: `f5ecd48d8f81c594f755a55e7969b57d20903020`.
- Inner ZIP `FlowBridge-0.3.0-beta.1-candidate-f5ecd48d8f81.zip`.
- Inner ZIP SHA256 `4b51d4136878476b48946361ce1635cb6d630e62b50ca82c73df28a5902ed8b8`.
- Windows installer SHA256 `74ff309d2e8ae115083bed9c5d4f233fd02dc841a8084a22912f3430c1e4b504`.
- Pinned original `explicit-beta-package.json`, original QA harness and
  `candidate-index.json`. Verifies all 21 indexed kit files and all 13
  installed package payload hashes; no provider-controlled hash discovery.

Script: `tools/windows/FlowBridge-ExplicitBeta-A3-NoPython.ps1`.

**Default**: expected host and OS checks, original ZIP SHA, extracted file
manifest/index/harness checks; no install, no Python, no driver.

**Explicit `-Execute` only**: refuses existing beta profile/registration,
checks stable settings/profile/known binaries before/after, executes
NSIS per-user install, JSON CLI capabilities, exact smoke harness with five
distinct BMP screenshots, second install/upgrade preserving test user file
and beta profile, then uninstall and preservation of stable data.

No changes to global DNS, proxy, firewall, Defender, WFP/NDISRD,
SecureBoot, Windows services, UAC, routing, or system certificates.
No user profiles or pre-existing installations are deleted to make a test pass.
Failures preserve evidence with `cleanup_required=true` for operator review.

## Commands on owner VM-910136, Windows PowerShell 5.1

Download the **original** Actions artifact to Windows. Its outer zip contains
the inner frozen candidate zip; extract only that inner zip for this test.
Keep the expected filename byte-for-byte.

```powershell
$Script = '.\tools\windows\FlowBridge-ExplicitBeta-A3-NoPython.ps1'
$Kit = 'C:\Temp\FlowBridge-0.3.0-beta.1-candidate-f5ecd48d8f81.zip'

# SHA preflight only. No installation or other OS modification.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Script -KitZip $Kit -ExpectedComputerName VM-910136

# On a clean dedicated normal-user interactive desktop only:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Script -KitZip $Kit -ExpectedComputerName VM-910136 -Execute
```

Results: a new timestamped folder under Documents/FlowBridge-A3, containing
`native-acceptance.json` and five BMPs. On owner Windows the automated
result is `OWNER_NATIVE_AUTOMATED_CHECKS_PASS` only after all six steps.

**Owner A3 is NOT yet accepted.** A positive automated result still needs
independent original JSON/BMP review, manual keyboard/GUI and real managed
SSH host-key, all-down and DNS tests. Windows 11 requires separate execution
on the same pinned source. The machine name is supplied and only checked,
not cryptographically attested.

## Hosted regression (disposable Windows Server 2025 only)

The workflow `flowbridge-beta-a3-no-python.yml` downloads the original
frozen GitHub artifact. It checks parse/negative guards, then performs
both byte-only and real user-mode NSIS/GUI/upgrade/uninstall steps with
the explicit `-AllowHostedCI` switch, which refuses non-GitHub-hosted
machines and is not an owner acceptance bypass.

Windows Server hosted success is an engineering reproducibility result
**not** a Win10/11 owner QA PASS. It does not run signed drivers or
publish a release. The Python-based runner remains the canonical
full operator protocol; this independent PowerShell implementation
provides equivalent six-step hosted behavior for Python-free owners.

## Release acceptance boundary

The JSON always retains `release_accepted=false`,
`a3_full_acceptance=false`, `wfp_g2_accepted=false` and
`transparent_interception_accepted=false`. R01 Windows kernel G2,
R02 signed macOS NE and A4/A5/A6/A7 remain separately open.


## Проверенная контрольная точка 14 ноября 2026

**Причина двух первоначальных hosted failures:** PowerShell function
`RunBounded` использовала параметр с именем `$args`. Это автоматическая
переменная PowerShell, из-за конфликта команда NSIS получала неправильные
параметры, и установщик не завершался в silent режиме. Первый прогон
ошибочно сравнивал также `qa_harness.path` (в исходном manifest это путь
сборочного CI, а не рабочая локальная ссылка), что устранено без
ослабления SHA256/size pins. Перемещение рабочего каталога в TEMP сохранено
для более безопасного и короткого пути, но само по себе timeout не исправило.

Функциональный фикс передачи аргументов:
`9d4bf34cee61b8446c33a6210ed59adeb6949e1d`.

- [Exact original kit CI #43637228155](https://github.com/i-shutov/flowbridge/actions/runs/43637228155)
  **2/2 jobs SUCCESS**: Windows PowerShell 5.1/7 AST, 0-driver frozen
  preflight, затем полный hosted NSIS install, payload, GUI/FFI,
  upgrade, uninstall, stable state preserved: **6/6 PASS**.
- Оригинал [artifact 14130800650](https://github.com/i-shutov/flowbridge/actions/runs/43637228155/artifacts/14130800650)
  скачан и независимо проверен: ZIP CRC PASS, девять файлов,
  SHA256 `ea2787f50870b7779529a04ed12dc219a90d4b9338cf63f53fff44b4ecb89a18`.
- Внутри два отчёта: `VERIFIED_BYTES_NATIVE_NOT_RUN` (только байты)
  и `CI_AUTOMATED_CHECKS_PASS` (все шесть проверок PASS).
- Пять самостоятельных BMP страниц (Dashboard, SSH, Proxy, Apps, Advanced)
  по 964×641 пиксель, уникальные SHA256 и визуально различимое содержание.
  Отдельные desktop/keyboard/SSH/operator tests ещё необходимы.
- В JSON: `python_required=false`, `cleanup_required=false`,
  `owner_native=false`, `a3_full_acceptance=false`,
  `release_accepted=false`, `wfp_g2_accepted=false`.

**A3 owner native остаётся NOT_RUN** на VM-910136 и отдельной Win11 Pro.
До проверки на реальной Win10 ссылаться на текущий QA как на hosted
и применять только закреплённый исходный ZIP. При ошибке скрипт сохраняет
отчёт и не удаляет существующие пользовательские установки.
