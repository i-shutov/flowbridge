# FlowBridge beta.2 — независимый технический A6-аудит только Windows 10

**Контрольная дата: 17 ноября 2026.** Статус: `A6_TECHNICAL_EVIDENCE_PASS_RELEASE_GO_BLOCKED`.

## Согласованный релизный контур

**Текущая ОС — только Windows 10 Pro 22H2 x64.** Windows 11 и macOS отложены решением владельца от 17.11 и не считаются пройденными. Проверяемый продукт — `0.3.0-beta.2`, **explicit SOCKS-only**, без перехвата произвольных EXE, WFP/NDISRD, system DNS no-leak или UDP-over-SSH.

- Оригинальный source `86583a1a0487b9d383c0122b24558e620bde5b9c`; tree `9f92e9e9e87725d127505c8ac415f37e42a8d148`.
- Original [11/11 GitHub candidate CI #43883696169 attempt 2](https://github.com/i-shutov/flowbridge/actions/runs/43883696169); complete original [artifact #14238314845](https://github.com/i-shutov/flowbridge/actions/runs/43883696169/artifacts/14238314845).
- Inner kit SHA256 `9980c786ceea82d2609b0229eca87b7f3ba044dc742466fedfa5e3b08e7585ae`; original source ZIP SHA256 `f37533b57453ecbc79efd014d9dbc405e6076b2c9b35f823ecae1e56684f3628`.
- Windows installer `0699bed4acaa1b9df9b63c658808b08fd65b5953cacdaaddb7a13953389e19f4`, GUI `0cf1749e7531659b1f5a42433818ecf31fe517d6815d11faeca6e04f9821325e`, FFI `23b62d54a89feea53331f3ac68fe7c3d348ca99ed72d816f3dcfbc94ef3fd2b4`.

## Новый контроль, реализованный в QA-ветке

- `tools/a6_win10_beta2_release_gate.py`: **стандартная библиотека Python, read-only**, не устанавливает EXE, не создаёт системные службы, не касается firewall/Defender/Win10, не исполняет пользовательские тестовые скрипты.
- Проверка оригинального immutable Actions artifact: SHA-source/kit и точные binary pins, 21 объявленный payload + 2 метафайла, ZIP-пути и защита от обхода каталога/симлинков/дубликатов, SHA256SUMS, `LICENSE` и запрет на ложный publisher/release/WFP `GO`.
- Опциональные **приватные** исходные ZIP владельца V4 и V5 передаются в параметрах `--v4-owner-zip` и `--v5-owner-zip` **только при локальном аудите**, не прикрепляются к GitHub Actions. Строго проверяются hash/size всех 100+26 original manifests, привязка к source/GUI/FFI/installer, Win10 lifecycle 6/6, SOCKS5h в обе стороны, no-DIRECT в тестируемом localhost, V5 отсутствие key-file, 12 неудачных TCP-открытий без открытого listener (`REP=null`, **не** `REP=01`), положительный 10-byte контроль и Stop/restore.
- `tests/test_a6_win10_beta2_release_gate.py`: adversarial ZIP traversal, path/duplicate/symlink, manifest tampering, false SOCKS positive, rollback и ложный release PASS.
- `.github/workflows/a6-win10-beta2-release-gate.yml`: Linux+Windows негативные тесты и независимая загрузка **оригинального** artifact #14238314845 из чужого неизменённого CI-запуска; в GitHub сохраняется только санитизированный JSON о source+packaging. Workflow **не имеет** оригинальных приватных V4/V5 и поэтому не делает вывод об их физическом прохождении. A6/A7 всегда остаются false.

## Фактически проведённый независимый локальный A6 pre-review

Имеющиеся в чате оригинальные **V4 ZIP SHA256 `23844631907f96063f0b13db73a835b92c386a4be3ed13a174c484c3139606e2`** и **V5 ZIP SHA256 `809dee21f0884e0d31dfa89a98033276cefaad859de1de64a87a2b90f454cb4c`** проверены офлайн на точных исходных байтах. Оригинальный комплект V4 **100/100**, V5 **26/26**, source/kit/binary pins, 17+6 GUI PNG, 23 Win32/UIA события V5, 6/6 lifecycle и узкие SSH сценарии согласованы. Это **аудит оригинальных записей Codex**, не независимая физическая переустановка или криптографическая аттестация Win10-хоста.

Независимый технический `A6_TECHNICAL_EVIDENCE_PASS_RELEASE_GO_BLOCKED` — **не** A6 release GO.

## Дополнительные открытые требования и риски

- **P0 A5:** собственная LICENSE ещё не выбрана, [Issue #78](https://github.com/i-shutov/flowbridge/issues/78). Технический A5 original-kit + SBOM/RustSec [PR #77](https://github.com/i-shutov/flowbridge/pull/77) 4/4 CI PASS, но не заменяет независимый юридический/native runtime security review.
- **A6 privacy:** экспорт diagnostics по исходнику `crates/flowbridge-ffi/src/diagnostics.rs` использует allowlist counters/enums; при этом **сырые GUI/SSH журналы и снимки могут содержать локальные пути**, поэтому приватные owner ZIP остаются только у владельца и проверяющего, никогда не публикуются в GitHub. Полного security audit C++/Win32 и защиты всей ОС эти проверки не дают.
- **A7:** unsigned engineering build, не подписана publisher-certificate, нет явного решения владельца на публикацию и релизного тега. Release notes должны исключить Windows 11/macOS, WFP/protected interception, global DNS guarantees и 512 raw SSH capacity.
- **Windows 10 EOL:** получение актуальных ESU/OS security updates на целевой VM не аттестовано; нельзя заявлять, что beta защищает всю Windows.
- **Полноценный 1.0** отдельно требует подписанного и физически испытанного WFP/G2, fail-closed/no-DIRECT, DNS/UDP, Win10 RC. Все WIN-00–09 accepted=false до доказательств.

### Строгий выпускной вывод

**A0–A3 Win10 технически приняты. A5 legal/native и A6 security/release остаются OPEN; A7 publisher GO отсутствует. `release_accepted=false`, `publisher_release_approved=false`, `wfp_g2_accepted=false`.** Не запускать Win11 QA, не изменять frozen beta.2 и не выпускать публичный GitHub Release до этих решений.

Приватные оригиналы V4/V5 и исходные диагностические файлы **не коммитить** в публичный репозиторий. Воспроизводимый офлайн A6-аудитор с контрольным JSON и оригинальными пользовательскими архивами передан владельцу отдельным ограниченным handoff-бандлом.
