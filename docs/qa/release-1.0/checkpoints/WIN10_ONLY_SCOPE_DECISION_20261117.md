# FlowBridge — решение владельца: текущий выпуск только Windows 10

**Дата:** 17 ноября 2026. **Статус:** `OWNER_CONFIRMED_WIN10_ONLY_NOW_WIN11_DEFERRED`.

## Точное изменение релизного контракта

Владелец прямо указал: **«на 11 пока не проверяем и не публикуем, это будут следующие релизы»**.

Это решение **заменяет** часть прежнего Windows-first решения от 15 ноября в отношении Windows 11. Оно не меняет принятые функциональные требования к защищённому режиму Windows 1.0 и не является разрешением на публикацию.

| Платформа | Текущий релиз beta.2 | Текущий Windows 1.0 | Следующие релизы |
| --- | --- | --- | --- |
| **Windows 10 Pro 22H2 x64** | **Единственная заявленная ОС**; A3 Win10 V4+V5 принят на основе независимо проверенных оригиналов | **Единственная целевая ОС**; WFP/G2 и остальные физические security gates пока NO-GO | Может поддерживаться при фактических обновлениях безопасности |
| **Windows 11 Pro x64** | **Не тестировать, не публиковать и не указывать как поддерживаемую**; отсутствие Win11 QA НЕ блокирует текущую beta.2 | **Не тестировать, не публиковать и не требовать Win11-native как текущий release gate** | Отдельный OS-support release и QA exact-new-frozen-SHA |
| macOS / Network Extension | Owner native QA deferred; bundled cross-platform CI is source/build evidence only | Deferred after Windows-first | Отдельные platform releases |

**Важная граница:** Windows 11 `DEFERRED_NOT_TESTED` — **не PASS** и не часть опубликованной совместимости. Историческое issue [#79](https://github.com/i-shutov/flowbridge/issues/79) сохранено как backlog будущего выпуска, но снято с критического пути текущего релиза. Не просить владельца запускать Codex на Win11 сейчас. Сохранять общий Rust core, портативный CI и исходный будущий Win11 test-runbook без исполнения.

## Точное наследование доказательств

- Frozen Windows beta.2 source `86583a1a0487b9d383c0122b24558e620bde5b9c`; original 11/11 CI [#43883696169](https://github.com/i-shutov/flowbridge/actions/runs/43883696169) attempt 2 SUCCESS; inner original kit ZIP SHA256 `9980c786ceea82d2609b0229eca87b7f3ba044dc742466fedfa5e3b08e7585ae`.
- У Win10 A3 действительно проверены оригиналы Codex V4 **100/100** и V5 **26/26**, финальный GUI `0cf1749e7531659b1f5a42433818ecf31fe517d6815d11faeca6e04f9821325e`, GUI/SSH отрицательные/положительные сценарии. [Независимый checkpoint V5](BETA2_WIN10_A3_V5_INDEPENDENT_REVIEW_20261117.md).
- **Решение по релизному A3 для текущей платформы Windows 10:** `A3_WIN10_SCOPE_PASS_ON_REVIEWED_ORIGINAL_EVIDENCE`. Это по-прежнему не независимый физический прогон на хосте и не криптографическая аттестация ОС.
- A0/A1/A2 остаются принятыми в ограниченном explicit SOCKS-объёме; A4/macOS и Win11 исключены из текущих платформенных обязательств, а не засчитаны PASS.

## Что всё ещё блокирует выпуск

1. **A5:** собственная лицензия FlowBridge не выбрана; [issue #78](https://github.com/i-shutov/flowbridge/issues/78). Хотя первичный original-kit/SBOM/RustSec-аудит [PR #77](https://github.com/i-shutov/flowbridge/pull/77) 4/4 PASS, независимые legal/native redistributables/security-review и разрешение на распространение остаются открыты.
2. **A6:** независимый итоговый аудит только Win10 beta.2: точный SHA, приватность и секреты, unsigned engineering prerelease ограничение, исходный отчет A3 и P0/critical список.
3. **A7:** отдельное явное GO владельца на публикацию; пока нет тега или GitHub Release. **Это решение о снятии Win11 с матрицы не даёт A7 GO.**
4. **Windows 1.0:** в текущей матрице только Win10, но **signed native WFP/G2, accepted socket authority, reauthorization, fail-closed, selected TCP, DNS/UDP, soak, signed RC и физический Win10 audit** по-прежнему NO-GO; не выдавать SOCKS-only beta за защищённый 1.0.
5. **Windows 10 security lifecycle:** стандартная поддержка Windows 10 закончилась в 2025; актуальный ESU/status patches на целевом стенде **не проверен**. Не делать обещаний об ОС без доказательств.

## Реализация в governance

- [Машинный A0–A7 beta.2](../BETA2_WINDOWS_A0_A7_20261116.json): `A3.accepted=true` **исключительно для Win10 current scope**, Win11 `DEFERRED_NOT_REQUIRED`; `A5/A6/A7.accepted=false`, `windows_beta2_release_accepted=false`.
- [Машинный Windows 1.0](../WINDOWS_FIRST_GATES_20261115.json): Windows 11 цель отложена и не является условием GO текущего Win10 1.0, **все WIN-00–09 accepted=false** до реальных 1.0 результатов.
- Документы с датой 15–16 ноября сохраняют исторические более широкие матрицы как свидетельство прежних планов; **это решение 17 ноября имеет приоритет**. В текущем A6-тексте и верхнеуровневом roadmap ссылки на Win11 помечаются как будущие, не как текущие блокеры.

**Никаких изменений frozen binaries, Win10 профилей/драйвера/сетевой защиты, main-ветки, публикации или лицензии сделано не было.**
