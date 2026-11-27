# FlowBridge beta.2 — пакет решения A5 по лицензии и нативной дистрибуции

**Дата:** 17 ноября 2026. **Продуктовый охват:** Windows 10 Pro 22H2 x64, `0.3.0-beta.2`, только explicit SOCKS. **Не юридическое заключение и не разрешение на публикацию**.

## Что реально доказано

Source `86583a1a0487b9d383c0122b24558e620bde5b9c`, immutable inner kit SHA256 `9980c786ceea82d2609b0229eca87b7f3ba044dc742466fedfa5e3b08e7585ae`, [CI #43883696169](https://github.com/i-shutov/flowbridge/actions/runs/43883696169) 11/11 PASS.

[Независимый A5 original-byte audit #77](https://github.com/i-shutov/flowbridge/pull/77) и [проверка #43936785163](https://github.com/i-shutov/flowbridge/actions/runs/43936785163) 4/4 PASS: Windows BOM **71** компонентов, macOS BOM **37** компонентов; у всех есть лицензионные **метаданные**, а notices присутствуют в поставке. В Windows BOM: 42 выражения `MIT OR Apache-2.0`, 15 `MIT`, 2 `Unlicense OR MIT`, 2 `Apache-2.0 OR MIT`, 1 `(MIT OR Apache-2.0) AND Unicode-3.0`, остальные девять содержат метаданные в другом формате (напр., SPDX license id, а не `expression`). **Никакого вывода о выполнении всех юридических обязанностей из этого не следует.**

Исходный собственный `LICENSE` буквально сообщает, что отдельная open-source лицензия коду FlowBridge **ещё не выбрана** и выбор нужен до публикации/перераспространения. Источник `native/windows/CMakeLists.txt` задаёт MSVC `MultiThreaded` runtime для GUI (статический CRT), но этот **source fact** не заменяет проверку содержимого/линковки окончательного EXE и лицензий SDK/MSVC. NSIS и собственные/сторонние license texts учтены в original build metadata. Пакет инженерный и **не подписан publisher-сертификатом**.

Оригинальный RustSec scan [#43935816560](https://github.com/i-shutov/flowbridge/actions/runs/43935816560) использовал `cargo-audit 0.23.0` против original `Cargo.lock`: 75 зависимостей, 0 известных advisories на версии базы 15.11.2026. Он не проверяет C++/Win32, внешние бинарники, неизвестные уязвимости или правовой статус.

## Что владелец должен выбрать (не выбирается агентом)

| Выбор | Последствие для собственного кода | Практическое действие |
| --- | --- | --- |
| **MIT** | Простая permissive лицензия, требует сохранения copyright + текста лицензии | Утвердить правообладателя/год, добавить точный `LICENSE`, сохранить THIRD_PARTY_NOTICES, выполнить отдельное legal/runtime review |
| **Apache-2.0** | Permissive лицензия с **явным патентным грантом**, условиями NOTICE и уведомлений об изменённых файлах | Утвердить владельцев авторских/патентных прав, точный `LICENSE`, при необходимости `NOTICE`, legal/runtime review |
| **Proprietary** | Собственные закрытые условия распространяются только на **код FlowBridge**, не отменяют прав сторонних компонентов | Утвердить точные EULA/redistribution terms, ownership/author rights, совместимость со сторонними лицензиями |
| **Internal-only** | Без публичной дистрибуции, до принятия правового решения | Сохранить verified candidate и внутренние контрольные суммы, никаких public Release/installer offers |

Источники требований и определения лицензий: [OSI — MIT](https://opensource.org/license/mit), [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0), [Microsoft — Redistribute Visual C++ files](https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files), [Microsoft — Visual Studio 2026 redistribution terms](https://learn.microsoft.com/en-us/visualstudio/releases/2026/redistribution). Их условия должны проверяться на реальной выбранной форме дистрибуции, не по одному списку зависимостей.

## Правовой/native security checklist до A5 GO

- [ ] Владелец явно выбрал MIT / Apache-2.0 / proprietary / internal-only, установил всех правообладателей и полномочия лицензировать собственный код (включая вклады соавторов).
- [ ] Независимо проверены все настоящие лицензии сторонних компонентов, `Unicode-3.0`, NSIS и нативные SDK/runtime/линковка **именно финального EXE**; все обязательные copyright/notice файлы включены и воспроизводимы.
- [ ] Проверены фактическая версия компилятора, оригинальный MSVC/SDK usage, условия его лицензии и необходимость/право дистрибуции любых Microsoft redistributable файлов — если они есть.
- [ ] Независимый P0 security/privacy review С++ Win32/FFI и пользовательских файлов/ACL/диагностического экспорта; не публиковать оригинальные приватные Win10 QA скриншоты, path/SSH журналы или test keys.
- [ ] Если решение — публичная несигнированная engineering prerelease: отдельно и явно подтвердить этот риск, не советовать отключать SmartScreen/Defender.
- [ ] Обновить исходный license и release notes **только после** согласования; это новая source/package ревизия и новые точные байты, прежние SHA `0.3.0-beta.2` не считать пересобранной опубликованной версией автоматически.

**Статус:** `A5_DEPENDENCY_PROVENANCE_AND_KNOWN_RUSTSEC_PASS`; `A5_LEGAL_OWN_CODE_LICENSE_AND_NATIVE_REDISTRIBUTION_OPEN`. [Решение владельца отслеживается в #78](https://github.com/i-shutov/flowbridge/issues/78). Сам факт подготовки этого мемо не устанавливает лицензию, не меняет исходный frozen binary и не даёт A6/A7 GO.
