# FlowBridge — генеральный план выхода в релиз

**Актуализация: 27 ноября 2026, МСК.** Цель текущей работы — проверенный
внутренний Windows-кандидат с явным SOCKS5 и управляемым SSH. Полный Windows
`1.0` с WFP/ALE требует отдельной нативной приёмки.

**Решение сейчас: к выпуску не готово.** Замороженная `0.3.0-beta.3` собрана,
её оригинальные файлы проверены. A3 отложен владельцем; A5/A6 и итоговый A7
открыты. Для полного `1.0` дополнительно открыты доверенный raw512 runtime,
G2, нативный lifecycle и подписанный RC.
[Машинный реестр](qa/release-1.0/RELEASE_EXECUTION_20261127.json) содержит точные
SHA, запуски и состояния. Накопленные подробности сохранены в
[истории до этой актуализации](RELEASE_1_0_PLAN_HISTORY_20261127.md) и
[истории до 17 ноября](RELEASE_1_0_PLAN_HISTORY_20261117.md).

## 1. Продуктовые результаты и действующие ограничения

| Результат | Состав и условия | Текущее состояние |
| --- | --- | --- |
| Внутренний explicit-SOCKS кандидат | GUI, CLI и FFI; без установки драйвера или службы; выбранный приложением SOCKS5 | Beta.3 заморожена; техническая сборка и сверка оригиналов выполнены; выпуск не принят |
| Следующий кандидат после исправлений состава | Обновлённые notices/SBOM и provenance; новые source/tree/installer hashes | Изолированное исправление генератора подготовлено; frozen beta.3 не перезаписывается |
| Полный Windows `1.0` | Перехват выбранных приложений через WFP/ALE, доказанное происхождение соединения, политика отказов, подписанная поставка | NO-GO; отдельный путь после G2 и нативных проверок |
| Win11 и macOS как поддерживаемые платформы | Самостоятельная приёмка конкретных бинарников на целевых ОС | Отложены; hosted CI и наличие runner их не заменяют |

Владелец исключил **любые работы на Win10**. Поэтому R7/A3 остаётся
`DEFERRED_BY_OWNER`: нет передачи комплекта, запуска GUI, установки, SSH
или работы Codex на этой машине. Новая Win11 используется для сборки и
инженерной QA. Её runner выполняет уже проверенные вручную запускаемые
workflow; локальный Codex для текущих задач не нужен.

Режим распространения — **внутренний**. Публичного Release, тега и публичных
исполняемых артефактов нет. На действующих QA/product workflow upload требует
private repository; результаты и отсутствие artifacts проверяются отдельно.
Политика Windows `Restricted`, проверка издателя SSH и защита загрузки драйвера
сохраняются. Публичность самого репозитория не изменена.

## 2. Опорные исходники и неизменяемый кандидат

| Объект | Точная опорная точка | Значение |
| --- | --- | --- |
| Product source | `44f1fc0eba5ac1552df94f083342e25a1a764937`, [PR #91](https://github.com/i-shutov/flowbridge/pull/91) | Проверка подписи/пути SSH, приватность и защита uploads; последующие QA commits не меняют этот frozen product |
| Frozen beta.3 | Source `c6ead0f31de4c118453913d733f537ba421af616`; tree `19df7a94071f38be6b8aa3530e1ded7a954a02a8` | Девять заданных version/staging изменений; сторонние lock-записи сохранены |
| Installer | SHA-256 `6408c0bf595b0ae61a4fc05db17421dc4b03dcda241f3c1f1f997ab6583eec5b` | Построен на Win11; не установлен и не принят как релиз |
| QA/source staging | [PR #92](https://github.com/i-shutov/flowbridge/pull/92) | План, проверка staging, fixtures и evidence; приёмка относится к указанному SHA |
| Строгая диагностика | `06c7d7d5cc005be092dd1c944b0c8dcd265d5726`, [PR #93](https://github.com/i-shutov/flowbridge/pull/93) | Отдельные raw512 и G2 проверки; 112 Python checks; production и frozen bytes не изменены |
| Private build | [run 45986630920](https://github.com/i-shutov/flowbridge/actions/runs/45986630920) | Оригинальные 13 файлов payload, installer, manifest и QA harness закреплены в реестре |

Прежняя приёмка beta.2 относится только к её оригинальным байтам и не
переносится на beta.3 либо будущую пересборку. Полные hashes GUI/CLI/FFI,
manifest и private kit хранятся в реестре и соответствующих evidence.

## 3. Генеральная последовательность

| Блок | Результат, необходимый для перехода дальше | Статус |
| --- | --- | --- |
| B0. Инфраструктура и происхождение | Защищённая сборка, воспроизводимое staging, точные hashes и чистая публикация | Завершено в инженерном объёме; R0–R6 зафиксированы |
| B1. Состав и качество кандидата | Полные notices/SBOM, проверенные зависимости и original-byte privacy/security review | В работе: статическая сверка и RustSec выполнены; подготовлено исправление метаданных; A5/A6 открыты |
| B2. Нативная приёмка explicit SOCKS | Install/upgrade/remove, GUI, настоящий SSH, отказы и восстановление на точном кандидате | R7/A3 отложен владельцем; никаких действий на Win10 |
| B3. Внутренний пилот | Один согласованный набор байтов, закрытые A3/A5/A6, ограничения и решение A7 | Ожидает B1/B2; новое решение о распространении ещё не принято |
| B4. Транспорт и kernel authority для 1.0 | Доверенная пара raw512; настоящий принятый WSK socket, проверяемый origin/epoch/policy и packet binding | Лабораторный raw512 PASS; подходящего официального runtime не найдено; WSK source/lifecycle продвинуты, G2 открыт |
| B5. Нативная WFP приёмка | IPv4/IPv6, anti-transplant, fail-closed, DNS/UDP/QUIC scope, cancel/unload/Verifier и восстановление | После B4 и готового подписанного изолированного стенда |
| B6. Подписанный RC и выпуск 1.0 | Оригиналы подписанных файлов, installer/rollback, независимая приёмка и разрешение на выпуск | После B5; Release/tag не создаются заранее |

B1 и инженерная часть B4 выполняются параллельно. B2 не является текущим
поручением. Открытый внешний барьер raw512 не мешает работе над составом
кандидата или WSK, но не становится PASS от успеха соседней ветки.

## 4. B1 — состав beta.3 и исправление следующего кандидата

### Уже проверено

- [Статическая инвентаризация](qa/release-1.0/evidence/20261127/frozen-beta3-static-inventory.json):
  все 13 payload-файлов; 71 SBOM-компонент, включая 68 Cargo; 61 внешний
  Cargo checksum; пять PE-файлов. Это анализ структуры, без выполнения кандидата.
- [Расширенный read-only аудит](qa/release-1.0/evidence/20261127/frozen-beta3-notice-coverage.json):
  [Win11 run 46025031777](https://github.com/i-shutov/flowbridge/actions/runs/46025031777)
  сверил **113 секций файлов лицензий** с hash-записями, project license,
  nlohmann header/license и NSIS COPYING. Проверены входные
  `System.dll`, `LangDLL.dll`, `nsDialogs.dll` из закреплённого NSIS ZIP.
  CMake 4.1.1, MSVC 19.44.35230.0, v143 и SDK 10.0.26100.0 наблюдались в
  оригинальных generated projects. Оба C++ target настроены на static runtime.
- [RustSec](qa/release-1.0/evidence/20261127/frozen-beta3-rustsec.json):
  точный lockfile из 75 записей проверен cargo-audit 0.23.0 по закреплённой
  официальной базе `c5279d0b`: 0 advisories и 0 warnings.
  Все 68 внешних lock-записей совпадают с продуктовым source. Yanked-проверка
  не выполнялась; этот результат не охватывает не-Cargo runtime.

### Конкретные оставшиеся работы

1. Внести в notices следующего кандидата дополнительные MIT attributions
   встроенных UTF-8/Grisu2 частей nlohmann; отдельно описать Hedley и Abseil scope.
   Замороженный notice содержит основной MIT-текст, но не все названные
   upstream attributions.
2. Явно отразить configured static MSVC runtime, версию компилятора/SDK,
   NSIS LZMA stub и три plugin input hashes, внешние OpenSSH/PowerShell
   зависимости. Input hash не доказывает identity сжатого члена installer,
   а флаг `/MT` не перечисляет фактически удержанные linker members.
3. Проверить лицензионные обязательства, выбор допустимых license options,
   включая составные условия, применимые права на runtime и упаковку.
   Техническая полнота notices не является юридическим заключением.
4. Завершить независимый privacy/security review нового точного набора:
   диагностика без сырых секретов/путей, доверие к исполняемому SSH, путь
   запуска и DLL/runtime provenance, поведение установщика и rollback.
5. После принятия source-исправлений создать новый кандидат с собственной
   версией и hashes; повторить затронутые checks. Не менять beta.3 на месте.

Изолированное исправление генератора опубликовано в [draft PR #94](https://github.com/i-shutov/flowbridge/pull/94)
на product `44f1fc0`; source `cc0106245d10e3e26ca3847c33397522db91b59f`.
Локальные проверки метаданных, сборки комплекта и приёмки: **51/51 PASS**;
независимая ревизия включена. [Точная область исправления](qa/release-1.0/evidence/20261127/next-candidate-native-metadata.json).
[CI этого source](qa/release-1.0/evidence/20261127/next-candidate-native-metadata-ci.json):
5/5 Rust/native и 3/3 capture integration прошли; G2 сохранил
`kernel_connection_id_missing`, общий итог 8/9, artifacts 0. Это generic native
CI; новый versioned explicit-beta installer с исправленными metadata ещё не
построен. A5/A6/A7 остаются открыты.

## 5. B4 — raw512: лабораторный результат и production-зависимость

[Лаборатория](qa/release-1.0/evidence/20261127/raw512-source-lab.json) собрала
клиент/сервер из официального OpenSSH source `274893f8` с единственным
upstream изменением `MAX_FDS: 256 → 1024`.
[Run 46007206276](https://github.com/i-shutov/flowbridge/actions/runs/46007206276):
**512 удержанных и проверенных по байтам каналов, затем 16/16 восстановлений**,
528 попыток. Это один backend без FlowBridge FFI/pooling; временный каталог
очищен, artifacts 0. Пара не подписана и не является production runtime.
Парного same-source stock-control не было; изолированная причинность изменения
и заполнение внутренней FD-таблицы отдельно не измерены.

[Проверка официальных runtime](qa/release-1.0/evidence/20261127/raw512-signed-runtime-review.json)
закрыла текущий поиск готовой замены конкретным отрицательным результатом:
точные x64 `ssh.exe` и `sshd-session.exe` из последнего
[10.4.0.0p1-Preview](https://github.com/PowerShell/Win32-OpenSSH/releases/tag/10.4.0.0p1-Preview)
имеют **256 slots**, что подтверждено PE-инструкциями и совпадающими PDB.
Проверенные ARM64 10.4 и x64 10.0 также не дают требуемой ёмкости.
Microsoft помечает этот preview как non-production. Это ограниченный
перечень проверенных файлов, а не утверждение о любых возможных сборках.

Встроенные Microsoft-подписи и PE digest проверены криптографически offline;
доверенная Windows-цепочка, revocation и product guard этим не проверены.
У продукта остаётся требование
[Authenticode Valid + Microsoft Corporation](https://github.com/i-shutov/flowbridge/blob/44f1fc0eba5ac1552df94f083342e25a1a764937/crates/flowbridge-tunnel/src/windows_backend_trust.rs).
Явный абсолютный `ssh_executable` допускает portable-клиент без замены
системного файла; reparse-защита и удержание файла действуют до запуска.

**Следующий исполняемый шаг для production raw512:** получить конкретную
Microsoft-signed пару с подтверждённым запасом descriptor capacity, закрепить
client/server/helper/DLL hashes, проверить Windows trust существующим guard,
затем повторить строгие 512+16 на этих байтах. Подходящая пара не найдена.
Повторять тот же stock preview ради того же результата не требуется.
Другой издатель или иной backend требует отдельного решения о доверии и
архитектуре; лабораторная подпись не подменяет текущую политику.

## 6. B4/B5 — G2, WSK и нативный lifecycle

[Win11 ETW](qa/release-1.0/evidence/20261127/native-win11-g2.json) увидел
четыре закреплённых соединения, но все нужные connection IDs были нулевыми.
[Own-socket ALE probe](qa/release-1.0/evidence/20261127/native-win11-ale-endpoint.json)
получил ненулевые стабильные distinct IDs двух собственных принятых сокетов.
Это ещё не доказательство происхождения произвольного перехваченного процесса
и связи с пакетами.

Tests-only WSK seam получает `PWSK_SOCKET` через `WskAccept`, запрашивает
redirect context/records того же объекта и проверяет epoch, policy generation
и одноразовый claim. User-supplied числовой socket не становится kernel authority.
[Первый WDK object compile](qa/release-1.0/evidence/20261127/wsk-accepted-socket-compile.json)
прошёл с нулём ошибок/предупреждений; driver не линковался и не загружался.

Новый lifecycle source `a7476671a5b9574dfe8d6f5a307148b5fe27ef11`
выносит cleanup за пределы ожидания accept/query:

- Один трёхсекундный budget на ожидания completion; при истечении возвращается
  отдельный cleanup handle, без bound authority.
- IRP, буферы и сокет сохраняются до завершения; cancel запрашивается один раз,
  поздний успешный accept собирается, close выдаётся один раз.
- Успешный binding освобождается через тот же сериализованный drain.
  Неуспешный close оставляет handle в quarantine и счётчик outstanding занятым.
- Stop закрывает admission. Для уже допущенной работы требуется отдельно
  disarm policy под authority lock. Нулевой счётчик не разрешает unload:
  ещё нужны listener close, worker/caller join, callback rundown, освобождение
  provider и завершённая WSK deregistration.

Девять authority и девять lifecycle fixtures и 20 структурных мутаций прошли
локально, у независимого ревизора и в hosted Windows.
[WDK run 46025550513](https://github.com/i-shutov/flowbridge/actions/runs/46025550513)
завершился PASS: SDK/WDK 10.0.28000.2526, `/W4 /WX`, 0 warnings/errors,
artifacts 0. [Результат и пределы доказательства](qa/release-1.0/evidence/20261127/wsk-accepted-socket-lifecycle.json).
Ограничен собственный completion wait, **не** синхронное время выполнения
WSK/provider/cancel и **не** полное время cleanup/unload.

Следующий блок интеграции: назвать владельцев listener/provider/policy и
worker/callback rundown; связать seam с kernel-owned redirect context;
подготовить точный подписанный isolated-lab package и rollback; проверить
настоящий redirected socket, перенос claim на другой объект, IPv4/IPv6,
packet lineage, cancel/close races, failed close, shutdown и Driver Verifier.
Подписанный стенд пока не готов. G2, origin binding и packet ownership — OPEN.

## 7. CI и достоверность результата

[Последний полностью наблюдённый QA head `f998127`](qa/release-1.0/evidence/20261127/qa-f998127-terminal-ci.json):
**5/6 workflow и 12/13 jobs**, все с первой попытки, artifacts 0.
Rust/native, DNS на трёх ОС, WDK и staging прошли. Managed SSH:
128 каналов, 1 152 корректных admission-отказа, 10 000 циклов без ошибки,
четыре независимых worker-процесса.

Единственный отказ этого head — штатный bare OpenSSH: 244 удержанных канала
из 245 попыток, recovery не выполнен; сервер сообщил notify-pipe EMFILE
и ppoll resource error. Этот отказ не меняется на PASS вслед за успешной
unsigned лабораторией. Исторические transient bind failures и cancelled
запуски сохраняются в evidence; они не считаются выполненными проверками.

[Текущий main `7ec261f`](qa/release-1.0/evidence/20261127/main-7ec261-terminal-ci.json)
прошёл 5/5 jobs с первой попытки, artifacts 0. Предшествующий launcher commit
`1a76621` был прерван новой ревизией: его частичные 3/5 не считаются PASS.

Все новые проверки связываются с source/tree, ОС, точными входными файлами,
командой, exit status и оригинальным журналом. Документный commit не наследует
результат запуска на другом SHA без проверки идентичности соответствующего дерева.

## 8. Критерии возобновления приёмки и выпуска

R7/A3 возобновляется только после изменения владельцем текущего ограничения
на Win10 либо отдельного согласования другой продуктовой цели. Затем на одном
наборе байтов нужны install/payload/launch/upgrade/uninstall/profile preservation,
интерактивный GUI, положительный реальный SSH/SOCKS5h, отрицательные сценарии,
Stop/recovery и сохранённые оригинальные доказательства.

Внутренний pilot A7 возможен после A3/A5/A6 и перечня известных ограничений.
Полный 1.0 дополнительно требует B4/B5 и signed RC. Непрерывность уже открытых
TCP через перезапуск SSH, универсальный DNS/no-leak, UDP/QUIC и macOS не
объявляются поддержанными без отдельных подтверждений.

[Исторический WIN-00…09](qa/release-1.0/WINDOWS_FIRST_GATES_20261115.json)
сохраняется как карта критериев и прежних решений. Текущее выполнение и
ограничение Win10 определяет этот план и реестр от 27 ноября.
