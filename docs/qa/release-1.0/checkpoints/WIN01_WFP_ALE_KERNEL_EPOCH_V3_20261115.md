# WIN-01 — WFP/ALE kernel provenance v3 + Rust non-DIRECT, 15.11.2026

**Решение владельца:** WFP/ALE для Windows 1.0 теперь **разрешён к разработке и испытаниям**. Первой платформой остаются Windows 10 Pro 22H2 x64 и Windows 11 Pro x64; общее Rust-ядро и macOS-код сохраняются. Разрешение на разработку **не эквивалентно** разрешению установить неподписанный драйвер или ослабить защиту ОС. WIN-01/G2 по-прежнему **NO-GO**.

## Продуктовая ветка и реальные изменения

Новый [Draft PR #69](https://github.com/i-shutov/flowbridge/pull/69),
стек над Windows PR #67, **exact head `d242c3726904eed1bf5b5eb9998bc37d02ac90ba`**.
В `main` (`5b5afc2feeda2195f302380e615ba003d4906e09`) и замороженном explicit beta (`f5ecd48d8f81c594f755a55e7969b57d20903020`) изменений нет.

- В настоящем WDK `FlowBridgeWfp.sys` реализован `PsSetCreateProcessNotifyRoutineEx`: callback ОС сохраняет `PID`, `PsGetProcessCreateTimeQuadPart`, `PsGetProcessStartKey`. Фиксированная spinlock-таблица на 4096 записей запрещает неопознанный PID, повторную живую инкарнацию, несогласованный exit и переполнение. Запущенные **до** регистрации драйвера процессы из отдельной PID-таблицы не «доверяются»; для protected mode потребуется их перезапуск либо независимо доказанная иная OS-аттестация.
- `ALE_CONNECT_REDIRECT` копирует kernel PID+epoch+start key+OS транспортный endpoint в socket-context **v3**, 2136 байт. Win32 `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` отвергает старый контекст и любой ноль в обязательном provenance. IOCTL device ABI повышен **2→3**, чтобы старые helper/driver не интерпретировали новый протокол.
- Старые source-level fail-open пути — выбранный фильтр при `gEnabled=FALSE`, перенаправление *другим* провайдером и иностранная previous-version local redirect — изменены на BLOCK. Наличие `FWPS_RIGHT_ACTION_WRITE`/конкурирующих BFE фильтров ещё требуется проверять на реальном драйвере.
- В существующем Rust FFI исправлен **критический DIRECT fallback**: WFP-record-bearing поток может выбрать только непустой `Proxy` или `Chain`. Отсутствующая/изменившаяся настройка выбранного приложения и `DIRECT` прерываются **до исходящего сокета**; обычный explicit SOCKS без WFP records сохраняет отдельную пользовательскую политику. Недостоверные redirect records в режиме Proxy дополнительно отклоняются до connect.
- WDK `.sys` имеет PE `FORCE_INTEGRITY`, необходимый для process notification. Это бит PE, **не цифровая подпись** и не доказательство OS Code Integrity. Бинарник не установлен и не загружен.

## Независимо подтверждённая матрица CI — последний source SHA

| Проверка | Итог |
| --- | --- |
| [WIN WFP epoch native #43713831922](https://github.com/i-shutov/flowbridge/actions/runs/43713831922) | **PASS 1/1**, реальный MSVC компилирует production C ledger, 6 сценариев рождения/смерти/PID reuse/overflow, 4 теста и 9 source-мутаций |
| [Original test ZIP #14161458866](https://github.com/i-shutov/flowbridge/actions/runs/43713831922/artifacts/14161458866) | SHA256 `49b0b932e9952728dc7785d9bfa7b371c8946a7d657bbc338877dafa251a00f4`, CRC PASS; JSON явно фиксирует `kernel_callback_executed=false`, `g2_native_pass=false` |
| [WDK #43713831976](https://github.com/i-shutov/flowbridge/actions/runs/43713831976) | **PASS 1/1**: unsigned 64-bit WDK `.sys` 27136 байт, PE `FORCE_INTEGRITY` есть |
| [Original WDK ZIP #14161284274](https://github.com/i-shutov/flowbridge/actions/runs/43713831976/artifacts/14161284274) | ZIP SHA256 `704fc5149a07c45a4f9db1dc88b25a89d7068abb3f6fe5f888ab7b2755d3fbc6`, CRC PASS; `.sys` SHA256 `51f931967ef32e84a9fc591235ca9bf22e29877851bbbf8d6879ef7ab95e2319` |
| [Rust/native Windows, Linux, macOS #43713831970](https://github.com/i-shutov/flowbridge/actions/runs/43713831970) | **PASS 5/5**: WFP DIRECT test and proxy-invalid-records checks; Windows GUI/installer, Rust 3 OS, macOS app |
| [Real Windows BFE scope #43713831985](https://github.com/i-shutov/flowbridge/actions/runs/43713831985) | **PASS 1/1**: реальный Windows BFE, без загрузки кастомного драйвера |
| [DNS regressions #43713832030](https://github.com/i-shutov/flowbridge/actions/runs/43713832030) | **PASS 3/3**, только source/network-fixture, не физическое отсутствие DNS утечек |

Первоначальные исходные версии PR проходили целевой epoch и WDK CI, но **Windows FFI тест показал новый (правильный) ранний отказ DIRECT вместо ожидаемой поздней ошибки `WSAIoctl`**. Тест разделён на два независимых сценария, не ослабляя требований. Ошибки rustfmt в рабочих коммитах также сохранены в истории; итоговые PASS относятся **только к последнему SHA**.

## Почему G2 всё ещё NO-GO

Новая kernel birth-epoch запись копируется в OS redirect context, но ни WDK build, ни тесты C-подсистемы не исполнили реальный kernel process callback на Win10/Win11. Для утверждения защищённого 1.0 нужны:

1. Реально подписанный WFP драйвер, кодовая целостность без ослабления ОС, изолированные Win10/Win11 VM с проверенными rollback и VNC/SYSTEM rescue.
2. Реальный `ALE_CONNECT_REDIRECT` + `ALE_AUTH_CONNECT` V4/V6 на выбранном EXE, независимые PID/start-key/epoch/endpoint и terminal one-use redirect-record CLAIM на принятом socket.
3. Отсутствие fail-open при BFE dynamic session loss, hard PERMIT в чужом sublayer, reauthorization, авторизованном stop/crash и процессе PID reuse.
4. Отдельный тест **R198**: распространяется ли выбранный `ALE_ORIGINAL_APP_ID` на физический SSH-сокет с redirect records, и не блокирует ли его AUTH. Запретить blanket-exemption для broker PID как замену доказательства.
5. Точный remote SSH → IPv4/v6 selected TCP/other-app DIRECT, DNS/UDP/QUIC/DoH, реальные pcap/JSON/logs до/после, исходный SHA и SHA подписанных бинарников; независимая приёмка.

**G2/R01/WIN-01 accepted=false.** Не было установки WFP/NDISRD, изменения BFE/Defender/SecureBoot/BCD/маршрутизации на пользовательских машинах или публикации beta/1.0. Нативное испытание без подписанного безопасного стенда не может быть заменено системной симуляцией.

Подробный технический контракт в продуктовой ветке: [WINDOWS_WFP_EPOCH_V3_PRODUCT_20261115.md](https://github.com/i-shutov/flowbridge/blob/feat/windows-wfp-ale-kernel-process-epoch-v3-20261115/docs/qa/WINDOWS_WFP_EPOCH_V3_PRODUCT_20261115.md).

Машинная запись: [WIN01_WFP_ALE_KERNEL_EPOCH_V3_20261115.json](WIN01_WFP_ALE_KERNEL_EPOCH_V3_20261115.json).
