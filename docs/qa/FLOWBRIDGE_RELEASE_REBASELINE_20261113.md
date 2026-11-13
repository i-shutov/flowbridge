# FlowBridge 1.0 — актуализированный план выпуска (13.11.2026)

**Статус: RELEASE NO-GO / PLAN REBASELINED.** Это инженерный план в draft PR #58, а не разрешение выпускать продукт, включать системный перехват или менять защищённые настройки. Действующий 1.0 scope сохранён из [RELEASE_1_0_PLAN.md](../RELEASE_1_0_PLAN.md). Предыдущая оперативная хроника [10.11](FLOWBRIDGE_RELEASE_ROUTE_20261110.md) остаётся архивом наблюдений; численные PASS не переносятся на новые SHA.

## Обновление после B0 — 13 ноября 2026 (новые проверенные байты)

**Сведения ниже в исторических разделах 1, 3 и 5 фиксировали более ранний срез PR #59 и WFP research. Эта секция заменяет их для текущего решения; обязательства R00–R10 и NO-GO 1.0 не изменены.**

| Объект | Доказанный результат |
| --- | --- |
| PR #59 | Draft; HEAD документации `5dd6ca35d975e536cd8901ebd9cae158aef02797`, бинарный source `f5ecd48d8f81c594f755a55e7969b57d20903020`, tree `ac47b5292ec90e13572e88e9133b12d4dc1f77ac` |
| [Единый workflow](https://github.com/i-shutov/flowbridge/actions/runs/43407093536) | **11/11 SUCCESS**: пакет Windows, macOS universal, format/Clippy/tests/DNS, managed SSH, native hosted lifecycle и сборка QA kit |
| [QA kit artifact](https://github.com/i-shutov/flowbridge/actions/runs/43407093536/artifacts/14028139291) | Inner ZIP SHA256 `4b51d4136878476b48946361ce1635cb6d630e62b50ca82c73df28a5902ed8b8` |
| [Capture/G2](https://github.com/i-shutov/flowbridge/actions/runs/43407099791) | **FAIL** `kernel_connection_id_missing`; G2/native 1.0 **NO-GO** |
| Research WFP/ALE | Проверенный срез `ca72eee3d5dc422ad6894219f9b68e63cf731034`, R160–R162 — исходные lifecycle и re-auth ограничения, НЕ нативная приёмка |

### Actual beta gate verdict — не переносить hosted PASS на owner acceptance

- **A0:** HOSTED_PASS_OWNER_OPEN: пакет Windows содержит 13 разрешённых файлов, но нет capture helper/driver; macOS pkg не содержит NE. Protected controls отключены.
- **A1:** HOSTED_PASS_OWNER_OPEN: один binary source, 11/11 CI, 23 файла итогового комплекта, source ZIP проверен.
- **A2:** HOSTED_PASS_LIMITED: тесты поставляемых Windows DLL/CLI подтвердили 128 held / 1152 expected rejected / 10000 TCP churn / 4 workers, host-key, half-close, shutdown и recovery; raw 512-channel stability и owner SSH soak НЕ доказаны.
- **A3/A4:** NOT_RUN_NEW_BYTES: прежние owner W0–W2b2 PASS относятся к `c339df2e`, а не к новой сборке. На Win10/Win11 и Mac ARM64/Intel обязательны install, GUI/keyboard, реальный SSH, upgrade/uninstall, независимый аудит исходных отчётов.
- **A5:** PARTIAL: SBOM/third-party inventory проверены (Windows 71, macOS 37 components); лицензия FlowBridge-specific кода ещё не выбрана; unsigned PKG/installer и независимый license/runtime review открыты.
- **A6/A7:** OPEN / NOT_RUN. Никакого merge в main, тега или публичного релиза.

Проверяемый пакет, хеши и готовая Windows-команда: [checkpoint PR #59](https://github.com/i-shutov/flowbridge/blob/5dd6ca35d975e536cd8901ebd9cae158aef02797/docs/qa/FLOWBRIDGE_RELEASE_CHECKPOINT_20261113.md). Машинный обновлённый реестр всех 19 gates: [`gate_status_20261113.json`](release-1.0/gate_status_20261113.json). Значение `pr58` в JSON — предшествующий SHA ветки перед записью checkpoint, а не само-ссылка на коммит с JSON.

### Архитектурное решение Windows G2 (отдельный checkpoint)

Подробные варианты A/B/C, границы текущего разрешения NDISRD-only, перечень source blockers R158/R160–R162 и условия первого настоящего G2.1–G2.6 испытания оформлены в [WINDOWS_G2_BACKEND_DECISION_20261113.md](WINDOWS_G2_BACKEND_DECISION_20261113.md). Это **P0 decision packet**, а не разрешение на смену backend или driver load.

### Architecture blocker, который нельзя замаскировать новым CI

[Issue #41](https://github.com/i-shutov/flowbridge/issues/41#issuecomment-6702417257) сохраняет разрешённую NDISRD-only архитектуру продукта, тогда как R01 WFP/ALE остаётся **отдельной исследовательской альтернативой**. Нужен независимый kernel-owned packet→PID+epoch trust witness в рамках NDISRD либо отдельное явное решение о переходе на иной подписанный backend. Нельзя автоматически включить WFP в 1.0 лишь потому, что research прошёл source tests. На целевой Win10/11 запрещены незапрошенные driver/filter/BCD/Firewall/Defender изменения.

**Следующий крупный блок:** A3/A4 exact-package native QA + A5/A6 independent decision; параллельно B1 native lab readiness и архитектурный R01 decision, macOS NE signing/entitlement path, DNS R03/R04 threat model, SSH R05 и правила R06. Затем BETA-C с real selected app traffic → R07/R08 → R09 frozen RC и физические тесты/24h soak → R10 подписанный `v1.0.0` по отдельному GO.

---

## 1. Source-of-truth срез — на момент сверки

| Объект | SHA / состояние | Доказательная граница |
| --- | --- | --- |
| Product main | 5b5afc2feeda2195f302380e615ba003d4906e09 | Историческая 0.2.0, не интегрированная версия 1.0 |
| [PR #56](https://github.com/i-shutov/flowbridge/pull/56) | c339df2e4d20edf1d11d45786581a68451a71929, Draft | Интеграция Rust/NDISRD; G2 packet→owner NO-GO; не вливать в beta целиком |
| [PR #58](https://github.com/i-shutov/flowbridge/pull/58) | a390461e4dc12b9b6922214cb1f1f0b69f1091d6, Draft, исходная точка этого плана | Релизное управление и W0–W2b2; без изменения main |
| [PR #59](https://github.com/i-shutov/flowbridge/pull/59) | 173d8bc5df792fb6b36cf270c4603cfd089ad9b1, Draft, base=PR #56 | Изолированная explicit beta; новый SHA не наследует прежние native PASS |
| [WFP/ALE research](https://github.com/i-shutov/flowbridge/tree/071599f10bc4299b9313f2040e3b84125c4cb42b/research/wfp-ale) | 071599f10bc4299b9313f2040e3b84125c4cb42b, R158 | Модели/исходники, НЕ принятый kernel-driver или драйверный релиз |

**Действительное наблюдение:** на выделенной Windows 10 Pro 22H2 x64 пользователь сообщил W0/W1/W2a/W2b0/W2b1/W2b2 PASS на проверенном *старом* инженерном пакете c339df2e. W2b2 включал Win32 GUI, NSIS install/upgrade/uninstall; архив исходных отчётов W2b2 не принят независимым ревьюером. R140: пять source blobs и user-mode guard PASS по консоли, kernel classify НЕ выполнялся. Это ценно как стендовая готовность, но **не** подтверждает новый beta EXE/installer или WFP.

**Точное CI PR #59:** workflow «Explicit SOCKS-only beta engineering package (Windows)» SUCCESS (43022649018); Rust/native SUCCESS (43022658637); native DNS SUCCESS (43022658593); capture integration FAILURE (43022658629: g2-kernel-connection-owner). Нельзя ставить полный CI PASS. Для beta необходимо определить и отдельно проверить required checks explicit-only, не маскируя незакрытый G2 в релизе 1.0.

## 2. Два независимых маршрута, три выпуска

| Этап | Продуктовый контракт | GO только после |
| --- | --- | --- |
| **v0.3.0-beta.1** | Explicit SOCKS5; 1–4 реально контролируемых SSH worker; native GUI; отдельные Windows и macOS пакеты; без перехвата произвольного EXE, драйверов, системного DNS/no-DIRECT | A0–A6 PASS на **одном exact beta SHA**, A7 — решение владельца |
| **BETA-C (полнофункциональная внутренняя)** | Реальный прозрачный TCP IPv4/IPv6 по выбранному приложению на Win/macOS, визуальные правила, подтверждённые remote DNS и failure limits | R01–R06 native end-to-end PASS, подтверждение platform signing/activation |
| **RC-1.0 → v1.0.0** | BETA-C + UX, подпись/нотаризация, восстановление/удаление и независимая физическая безопасность | Все R00–R10 и P0 PASS на одном RC SHA; подписанные байты равны принятым |

Заявленная 1.0 поддержка: **Windows 10 22H2 / Windows 11 x64; macOS Apple Silicon и Intel на проверенных Xcode/OS версиях**. Linux используется для сборки и тестов, а не автоматически объявляется продуктовой платформой.

1.0 обязательное: TCP IPv4/IPv6 per-app, правила **App × Host/CIDR × Port → Proxy/Chain/Direct/Block** с приоритетом, понятным explain; SOCKS5/SOCKS4a/HTTP CONNECT и согласованные цепочки; строгие SSH host key, 1–4 owned OpenSSH, без скрытого DIRECT; разделённая/удалённая DNS-политика с ясными исключениями; компактный GUI и безопасные Apply/Stop, upgrade/rollback/uninstall, ключи в OS secure store.
**Не входящие в 1.0 обещания:** восстановление живых TCP после потери SSH, повтор application/AI запросов, UDP-over-SSH и полная замена всех функций Proxifier. UDP/QUIC и application DoH/DoT **не получают автоматическое «защищено»**: в защищённом режиме неподдержанное блокируется доказуемо или весь protected mode недоступен. Не подменять блокировку надписью «не защищено».

## 3. Beta A0–A7: немедленный выход готового user-mode продукта

| Gate | Состояние | Действие / критерий GO |
| --- | --- | --- |
| **A0** scope isolation | PARTIAL | Ревью PR #59: WFP/NDISRD элементы недоступны через GUI/CLI/IPC, в allowlist пакета нет Capture.exe/SYS/INF/служб; точный source SHA |
| **A1** exact-source CI | PARTIAL | Собрать **новые** beta байты, required CI for explicit path all green; G2 failure отдельно зафиксирован как системный NO-GO |
| **A2** managed SSH | PARTIAL | Pinned host-key + реальный SSH/echo, 1–4 owned workers, all-down denies, no fallback, 251/252 error classification, 10k churn с явными ограничениями/soak |
| **A3** Win10/11 GUI/install | OWNER PASS на старом SHA | Заново пройти native Win10 Pro и Win11 install→upgrade→uninstall/DPI для *точного финального PR #59* ZIP; независимый аудит оригиналов |
| **A4** macOS explicit pkg | OPEN | Отдельные ARM64/Intel native GUI/SSH, pkg, upgrade/uninstall, без NE/ентitlements claims |
| **A5** security/provenance | OPEN | Version/unsigned-beta limitation, permissions/IPC, приватные данные, SBOM/licenses, manifest binary allowlist, ZIP SHA |
| **A6** independent beta QA | OPEN | 0 P0 FAIL/SKIP/UNKNOWN, original ZIP/JSON, source→binary→installer hashes, reviewer verdict |
| **A7** prerelease/tag | NOT RUN | Только после A0–A6, отдельное решение владельца; не публиковать автоматически |

**Главное управленческое решение:** не задерживать SOCKS-only beta исследованием R159+. Один интегратор отвечает за PR #59, независимый ревьюер — за приёмку, WFP researcher не делает в beta параллельную интеграцию. Сохранить прежние тестовые результаты как исторические источники, а не как GO для новых байтов.

## 4. FlowBridge 1.0: критический путь R00–R10

| ID / поток | Приоритет | Проверяемый выход | Зависит от |
| --- | --- | --- | --- |
| **R00** freeze контракт | P0 | Единая QA-матрица, точные требования, OS/архитектура, источник истины, test IDs и независимые SHA | main/docs |
| **R01** Windows WFP/ALE | **P0 BLOCKED** | Signed/authorized driver на disposable Win10+Win11, оригинальный owner/epoch/AppId в native ALE, V4/V6 redirect→accepted socket records/context→one-use CLAIM→SSH; неназванные и sibling DIRECT blocked при потере сервиса | R00, лаборатория |
| **R02** macOS Network Extension | **P0 BLOCKED** | Действительное signing/entitlement/approve/activate, selected TCP V4/V6, fail-closed, restart/sleep/wake/uninstall на ARM64+Intel | R00, Apple Team/два Mac |
| **R03** Windows DNS | P0 | Сохранение hostname и remote DNS для выбранного EXE, SYSTEM resolver/split/LAN/DoH/DoT/IPv6/QUIC без скрытых утечек; pcap+JSON | R01 |
| **R04** macOS DNS | P0 | Native DNS/NE flow and packet capture, bootstrap/rollback, local vs remote resolution, no leak | R02 |
| **R05** SSH надёжность | P0 | 251/252 и tiers 64/128/192/256/512 с измеренным safe cap, 10k churn, 24h soak, 1–4 SSH worker, no-DIRECT on loss | R00; end-to-end с R01/02 |
| **R06** правила/GUI | P0 | Визуальные App/host/CIDR/port/action, chain, explain/active flows/log, atomic apply, happy/negative paths на Win+Mac | R00; интеграция R01/02 |
| **R07** интерфейс/доступность | P1→release gate | Win 1366×768 и DPI 100/125/150/200; Mac Retina/dark/light/keyboard/VoiceOver, атлас и ручная независимая приёмка | R06 |
| **R08** security/поставка | P0 | Windows production driver+installer signing, macOS Developer ID/NE notarization, безопасный upgrade/rollback/uninstall/keys/ACL | R01,R02,R06 |
| **R09** RC acceptance | P0 | Frozen RC SHA, 0 P0 FAIL/SKIP/UNKNOWN; physical IPv4/v6 app/SSH/DNS, broker/BFE crash, 10k/24h, независимые traces и поставки | R01–R08 |
| **R10** release | P0 | Подписанные байты точно совпадают с RC, документация, SHA/SBOM/licenses, explicit owner GO перед tag v1.0.0 | R09 |

Критическая зависимость: **R01 + R02 → R03 + R04 → BETA-C → R08/R09 → R10**. R05, R06, read-only аудит R07 и подготовка packaging могут идти параллельно. Не объявлять срок v1.0.0 до закрытия внешних лабораторных предпосылок.

## 5. Windows WFP: R158 — точные оставшиеся разрывы

Research R140–R143 и R156–R158 подтвердили/уточнили **исходные ограничения**, но не реальные WFP-пакеты:

1. **ACTION_WRITE / veto (R140/R156):** исправлен source guard, а R156 скорректировал прежний изолированный вывод R155 с учётом внешнего callback. **Нет native classify** с реальными правами и арбитражем.
2. **AppId BFE/ARM split (R158):** фильтры выбирают AppId A, ARM может получить B без строгого равенства; при A≠B четыре текущих фильтра B не матчят. Требуется единая каноническая byte identity: filename API → BFE readback → ARM → kernel process event. Это source NO-GO, **не заснятый DIRECT**.
3. **Покрытие политики (R157):** четыре dynamic TCP/6 фильтра не обеспечивают выбранному приложению UDP/QUIC/DNS/ICMP и не живут после исчезновения владельца динамической BFE-сессии. Они не гарантируют system no-DIRECT.
4. **Постоянная защита (R141/R143):** есть NON_INSTALLABLE blueprint; stored persistent object ≠ enabled/effective block. Boot-time и runtime BFE restart — разные испытания; hard BLOCK может перекрыть и разрешённый redirect.
5. **Сквозной trust:** исходный process+FileObject, epoch/start key, endpoint/compartment, ALE_REDIRECT/AUTH v4/v6, redirect records из реального accepted socket, terminal CLAIM, SET_RECORDS на исходящем SSH сокете **до connect**. PID/tuple/ETW догадки недостаточны.

**Stop rule для исследователя:** после source-level проверки конкретного WFP контракта требуется решение инженера об интеграции и **отдельно разрешённый стенд**. Бесконечные дополнительные синтетические R-номера без сдвига physical G2 запрещено использовать как «готовность к релизу». Старый signed NDISRD G1=10/10 на dd1ab3c существует только для своего SHA; G2 PacketBound не унаследован.

## 6. Порядок больших блоков работ

| Блок | Основной исполнитель | Выход, после которого идти дальше |
| --- | --- | --- |
| **B0 — beta cut (сразу)** | Beta integrator + independent QA | A0–A6 PASS для одного SHA PR #59; отдельно native Win10/Win11 и Mac pkg; решение о beta A7 |
| **B1 — native readiness параллельно** | WFP owner / Mac NE owner | Signed-driver/Apple entitlements + documented lab approval, snapshot, separate out-of-band VNC/SYSTEM rescue, tested rollback; без вмешательства в текущую Win10 |
| **B2 — исправление native trust** | Windows kernel / macOS | R158 AppId equality, callout action/veto, BFE loss model, WFP/NE real probes; accepted-socket receipt→SSH with physical observer |
| **B3 — DNS и product integration** | DNS+GUI+SSH owners | R03–R06 green and real app flow on BOTH platforms; BETA-C GO |
| **B4 — security and stress** | Security/release QA | R07–R08, signed packages, real 10k + 24h, resource budgets, failure/rollback matrix |
| **B5 — RC / release** | One release integrator; independent controller | R09 frozen SHA 0 P0 gaps → R10 owner signoff; no implicit public publish |

На каждом завершённом блоке: **исходный SHA → test IDs/команды → OS/build и binary SHA → первичные JSON/pcap/screenshot → независимый verdict → checkpoint**. Хеш без реального содержимого не равен приёмке. При изменении SHA затронутые тесты снова PENDING. Ревьюер контролирует, но не заменяет интегратора.

## 7. Непереходимые ограничения безопасности

- **Не изменять в ходе планирования:** main, PR #56, beta PR #59, исследовательский WFP трек, установленные драйверы, службы, runner, firewall/Defender/SecureBoot/Memory Integrity, DNS и системные маршруты.
- Никакого native filter/driver trial на пользовательской Win10 или Windows Server без явного отдельного допуска. Не запускать сценарий, способный оборвать RDP/SSH, без независимого канала восстановления и отката.
- Постоянные фильтры не устанавливать под предлогом исправления динамической сессии. Сначала formal arbitration, native source binding, rescue.
- До нативного packet observer: **kernel-origin proof=false, PacketBound/G2=false, no_DIRECT_proved=false, release_accepted=false**.
- Изменения релизных документов в draft [PR #58](https://github.com/i-shutov/flowbridge/pull/58) не равны merge в main и не разрешают выпуск. Публичный релиз отдельно подтверждает владелец.

## 8. Управление, незавершённые решения, немедленные задачи

**Один интегратор** закрывает продуктовый beta/1.0 backlog; отдельные исполнители делают Windows WFP, macOS NE, DNS и UX; независимый стратегический контролёр проверяет source SHA/физические доказательства и ставит STOP, но не запускает вторую интеграцию. Важные решения владельца, необходимые позднее, не симулировать: driver lab/подпись и out-of-band rescue; Apple entitlement/Developer ID; утверждение набора поддерживаемых версий macOS; согласие на beta/RC/v1.0.0 publish.

Немедленно: (1) вычистить A0/A1 beta и повторить CI на изолированном SHA, (2) закрыть A2/Win10/Win11/Mac user-mode beta acceptance с оригинальными пакетами, (3) выделить WFP/Mac независимые native prerequisites и блокер R158, (4) определить системную DNS/UDP/QUIC protected-mode политику, не обещая UDP-over-SSH, (5) завести единый machine-readable реестр [19 gates](release-1.0/gate_status_20261113.json). Этот план заменяет лишь оперативную оценку, но сохраняет историческую доказательную базу.

**Решение на 13.11.2026: beta NOT ACCEPTED, BETA-C NOT ACCEPTED, v1.0.0 NO-GO.**
