# WIN-01 / G2 — terminal WFP AUTH CLAIM (ABI4), 15 ноября 2026

**Итог:** завершён реальный исходный код kernel ticket → accepted Winsock → обязательный CLAIM → Rust non-DIRECT. WDK, нативные security-тесты и кроссплатформенная матрица завершились **PASS**. **Подписанный/загруженный драйвер не испытывался; G2 и Windows 1.0 по-прежнему NO-GO.**

## Изоляция разработки и точный source

- [Draft PR #71](https://github.com/i-shutov/flowbridge/pull/71), HEAD **`391316368470f0a9f6fe85eb302d54a6afaeb5f8`**, stacked поверх [PR #70](https://github.com/i-shutov/flowbridge/pull/70), далее PR #69 и Windows GUI epoch PR #67.
- `main` `5b5afc2feeda2195f302380e615ba003d4906e09` и замороженная explicit SOCKS beta `f5ecd48d8f81c594f755a55e7969b57d20903020` **не изменены**. Никаких merge, tag, подписей, загрузок драйвера, модификаций BFE на машинах владельца или отключения защит ОС.
- Владелец ранее явно разрешил **разработку и испытания WFP/ALE** для Windows 1.0, при этом обязательность безопасного подписанного стенда, rollback/VNC/SYSTEM rescue и независимой native QA не отменял.

## Какой P0 исправлен

До PR #71 `native/windows/wfp/service.cpp::handle` читал WFP context и records при помощи OS `WSAIoctl` на принятом локальном TCP-сокете, затем **сразу** вызывал Rust `fb_native_stream_open_wfp_json`. Никакая проверка не требовала, чтобы одноразовая AUTH-запись *этого исходного процесса* дошла до `ALE_AUTH_CONNECT` и была терминально погашена до открытия исходящего сокета.

### Новый обязательный путь

1. WDK `ALE_CONNECT_REDIRECT` на kernel-origin PID/creation epoch/start key/endpoint выдаёт уникальную запись `FbAuthBook` (state `1`), а `ALE_AUTH_CONNECT` сопоставляет real OS original destination и broker/local redirect target и однократно переводит её в state `2`. Неизвестный PID или старый epoch не могут выдать права.
2. **Один принятый сокет:** helper вызывает `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` и `SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS` на *этом* Winsock `SOCKET`. Затем `getsockname(accepted)` должен подтвердить локальный `127.0.0.1`/`::1`, точный активный порт брокера и совпадение IP-семейства с WFP context. Иначе reject до Rust.
3. **`FB_IOCTL_CLAIM`** (`METHOD_BUFFERED`, `FILE_WRITE_DATA`) принимает строго фиксированный `FbWfpClaim`: 4 байта size, 4 байта ABI version, 2136-байтный WFP context (**2144 байта всего**). Driver проверяет эксклюзивный `FileObject`/PID повышенного helper, ABI4, поля OS process incarnation, origin destination, endpoint, flow ID и записанный terminal AUTH ticket. Только state `2` может стать state `3`; replay и ранний CLAIM отвергаются. При отсутствии записи, сбое процессной таблицы, отключённом драйвере или неизвестном origin — deny.
4. **Лишь после успеха `DeviceIoControl(FB_IOCTL_CLAIM)`** происходит Rust policy→outbound. Rust с WFP records может выбрать только ненулевой Proxy/Chain; DIRECT/empty/Block отклоняются **до** открытия исходящего TCP. Установку `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` на исходящий сокет Rust выполняет отдельно и не пропускает в случае ошибки.
5. **ABI повышен 3 → 4**: старый Windows helper, который ещё не вызывает CLAIM, не сможет успешно согласовать версию с новым kernel-driver. `Capture::claim` и `Capture::stop` сериализованы одним mutex, чтобы не читать закрытый драйверный дескриптор.

## Важная граница доверия (не объявлять native PASS)

Между фактом вызова OS `WSAIoctl` на принятом сокете и `FB_IOCTL_CLAIM` остаётся **пользовательская память доверенного повышенного helper**. В драйверный IOCTL передаётся копия v3 context, а **не OS kernel AFD/socket identity**. `getsockname` подтверждает правильную локальную конечную точку именно вызванного Winsock-сокета, но не является независимой kernel-связью ticket → socket object. При компрометации повышенного helper контекст может быть скопирован. Поэтому это **кодовый и owner-handle enforcement subgate**, а не окончательная kernel socket-origin аттестация.

Таблица `FbAuthBook` пока допускает только **512 non-reusable tickets**; исчерпание завершает сессию fail-closed. Нет generation-safe recycling и idempotent reauthorization. Внешнее физическое SSH-подключение с WFP records ещё может обнаружить R198 конфликт текущего/исходного AppId; требуется наблюдать его на реально подписанном загруженном драйвере.

## Точно проверенный CI на `391316368470`

| Исходное доказательство | Фактический результат |
| --- | --- |
| [WFP AUTH/CLAIM + epoch #43739267311](https://github.com/i-shutov/flowbridge/actions/runs/43739267311) | **1/1 SUCCESS**; production C **13 AUTH/CLAIM** сценариев, 6 epoch, 11 новых мутаций terminal-claim + 17 ранее существовавших source mutations |
| [Original source ZIP #14171931082](https://github.com/i-shutov/flowbridge/actions/runs/43739267311/artifacts/14171931082) | CRC PASS, SHA256 `8a8a851dca3bec2f40919e1f59144d198a43c3f039118eadb5b1dc16565dae6b`; JSON явно фиксирует `kernel_callbacks_executed=false`, `native_g2_accepted=false` |
| [WDK unsigned x64 #43739267383](https://github.com/i-shutov/flowbridge/actions/runs/43739267383) | **1/1 SUCCESS**; `FlowBridgeWfp.sys` **30 720 bytes**, SHA256 `0fae76a8336220d91ecb4cfba9e75357ece5e9dc9fd613673268f31dc3800528`, PE x64 `0x8664`, FORCE_INTEGRITY есть, сертификатная PE-directory = 0 |
| [Original WDK ZIP #14172175340](https://github.com/i-shutov/flowbridge/actions/runs/43739267383/artifacts/14172175340) | ZIP CRC PASS, SHA256 `e39694404a9e9dd0914f1a6b6ab41196c3e880fa9c1a06ee90a796acc28abcb3` |
| [Полный Rust/native #43739267354](https://github.com/i-shutov/flowbridge/actions/runs/43739267354) | **5/5 SUCCESS**: реальный Windows helper/GUI/installer; Rust Windows, Linux, macOS; macOS application |
| [Windows BFE #43739267305](https://github.com/i-shutov/flowbridge/actions/runs/43739267305) | **1/1 SUCCESS**: BFE scope на hosted Windows, FlowBridge kernel-driver не загружен |
| [Windows real GUI owner #43739267350](https://github.com/i-shutov/flowbridge/actions/runs/43739267350) | **1/1 SUCCESS**: фактический Win32 process epoch и три отрицательных мутации |
| [DNS regression #43739267519](https://github.com/i-shutov/flowbridge/actions/runs/43739267519) | **3/3 SUCCESS**; native физическая DNS leak-free не проверена |

**Независимая проверка:** скачаны оригинальные WDK и C-отчёты; ZIP CRC PASS, SHA256 рассчитаны заново; в одном WDK ZIP обе копии `.sys` имеют одинаковый SHA. Реальный PE-формат 64-bit, x64, FORCE_INTEGRITY; подписи нет. В C JSON `cases_pass=13` и нет никаких заявлений о kernel execution.

Первоначальная общая Windows CI на промежуточном SHA #43738736079 корректно выявила недостающий `<ws2tcpip.h>` в новом IPv6 socket guard. Исходная ошибка сохранена, header добавлен, **весь набор повторён** на `391316368470` до 5/5. Исторические FAILED не маркировались PASS.

## Следующий решающий инженерный блок

**WIN-01/G2 остаётся NO-GO.** Требуется либо отдельный kernel/AFD-observed socket-binding mechanism, либо строгое физическое доказательство целостности доверенного helper с исходным WSA контекстом и kernel ticket. Далее — real `ALE_AUTH_CONNECT` initial/reauthorization, original/current AppId для физического SSH сокета, redirect record propagation/replay, 512-ticket lifecycle, competing BFE filters, selected/nonselected dual-stack no-DIRECT и DNS/UDP/QUIC/DoH под независимым egress pcap. Все эти проверки должны быть выполнены на **подписанном**, rollback-capable **изолированном Win10 Pro/Win11 Pro**, без test-signing обхода защит на рабочих машинах.

Состояние выпуска: `WIN-01.accepted=false`, `R01/G2=NO_GO`, `windows_1_0_accepted=false`, `beta_release_accepted=false`.

Машинный реестр этой проверки: [WIN01_WFP_TERMINAL_CLAIM_ABI4_20261115.json](WIN01_WFP_TERMINAL_CLAIM_ABI4_20261115.json).
