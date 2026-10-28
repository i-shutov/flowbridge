# FlowBridge — платформы и выпуск 0.2

Дата: 2026-10-28. Точные результаты сборки/запуска: [VERIFICATION.md](VERIFICATION.md). Исходники системного перехвата не равны установленному и проверенному системному режиму.

## Windows x64

Поставляемый пакет: Win32 GUI `FlowBridge.exe`, Rust DLL `flowbridge_ffi.dll`, CLI `flowbridge-cli.exe`, примеры, notices и uninstaller. NSIS создаёт настоящий 64-bit PE installer. Режим пакета — explicit local SOCKS5. Win32 calls управляют общим Rust Engine через проверяемые registry handles и owned JSON. UI вызывает FFI на worker thread; snapshots обновляются примерно раз в секунду.

MinGW cross-build и запуск собственного GUI/DLL в Wine покрываются отдельным smoke harness. Wine не проверяет ядро Windows, WFP, работу Driver Verifier или поведение на чистой Windows 10/11. Кросс-сборка ARM64 Windows пока не предлагается.

MSVC/MinGW команды и payload layout: [BUILD.md](../packaging/windows/BUILD.md). Профиль хранится в AppData; установка per-user. Installer не включает системные фильтры/драйверы и не требует администратора. Release signing ещё не выполнялся.

### WFP

Собственные исходники: [WINDOWS_WFP.md](WINDOWS_WFP.md), `native/windows/wfp`. Driver сохраняет исходное назначение и наблюдаемый ALE app identity в проверяемом versioned context. Служба должна принимать только действительно redirected соединения с корректным контекстом/records. Opaque redirect records передаются в `fb_stream_open_wfp_json`, копируются с ограничением 64 KiB и устанавливаются на каждом новом outbound socket до connect. Ошибка подготовки не допускает повторной попытки без records. Это поведение транспортного hook проверено тестами, сам WFP IOCTL требует Windows [W1–W5].

Динамические filters привязаны к сессии службы. Системная политика при Stop/crash отличается от ошибки отдельного маршрута: восстановление обычной маршрутизации ОС не является kill switch. Требуются native WDK build, Microsoft signing для обычного распространения нового kernel driver, Driver Verifier, VM/реальное устройство, IPv4/IPv6, coexistence и crash/unload tests [W6]. Не включать исходники непроверенного драйвера в автоматическую активацию installer.

## macOS

Реализованы SwiftUI controls, профиль, engine worker, connection table и log; C ABI stream transport используется в `NETransparentProxyProvider`. `NEAppProxyTCPFlow` не приводится к POSIX socket: Swift bounded pumps читают/пишут NE flow и Rust stream handles, поддерживают partial writes, cancellation, idle deadlines и half-close.

Отдельные схемы: **FlowBridgeLocal** без Network Extension и **FlowBridge** с embedded system extension. Scripts собирают arm64+x86_64 Rust library, Xcode app и pkgbuild/productbuild installer. Полные команды и signing: [macOS README](../packaging/macos/README.md). В текущем Linux-окружении нет Apple SDK: Swift type checking, `.app`, `.pkg` и native runtime пока не выполнены.

Activation идёт через OSSystemExtensionRequest и NETransparentProxyManager. Состояние Active требует actual connection плюс успешный ping provider. Старые callbacks не могут менять состояние более новой операции. Entitlement XML сам по себе не даёт разрешений; нужны реальная подпись, provisioning, системное одобрение и для распространения appropriate notarization [A1–A4].

Native scope — выбранные destination TCP ports, по умолчанию 80/443; DNS port 53 не включается, UDP/QUIC/прочие порты direct. Loopback и IP upstream исключены для предотвращения самоперехвата. Native upstream hostnames отклоняются; explicit SOCKS их поддерживает. Direct возвращает `false`; Block закрывает claimed flow; proxy failure закрывает соединение без direct fallback [A5,A6].

## Identity, DNS и границы

- Explicit SOCKS не удостоверяет вызывающий процесс. Application criteria запрещают запуск этого режима, но доступны для hypothetical `explain` и native attested flows.
- Windows identity берётся из kernel WFP metadata, macOS — из наблюдаемого signing identifier. Правило basename Windows не превращается автоматически в bundle identity Mac.
- Connect redirection часто получает уже разрешённый IP. PTR и SNI-предположения не подменяют исходное hostname. CIDR/IP rules работают на наблюдаемых адресах; hostname rules нельзя обещать для каждого native flow.
- Передача hostname в SOCKS разрешает его upstream, только если клиент действительно передал hostname. Прозрачный NE не перенаправляет системный DNS посредством `NEDNSSettings`; документация Apple прямо различает эти режимы [A5].
- UDP, QUIC, системный kill switch, secret stores, profile import и автоматический update — дальнейшие задачи. Неохваченный трафик продолжает обычную маршрутизацию ОС.

## Что нужно проверить для следующего выпуска

1. Чистая Windows 10/11: установка/обновление/удаление GUI, proxy outage, IPv6, долгоживущие потоки, sleep/wake, перезапуск и профиль.
2. Windows WDK build/sign/native tests: validation context, fake local caller, records propagation, loop prevention, coexistence, filter cleanup, SCM crash и unload.
3. Mac M1/M4 и Intel: Xcode compile, local app/package; затем signed native app, approve/deny/restart states, Direct/Block/Proxy, exhaustion и stale callbacks.
4. Packet captures для DNS и UDP scope; никакие заявления об охвате «всего трафика» не делать без этих проверок.

## Official API references

Reviewed 2026-10-28. The design choices above are FlowBridge's proposed implementation, not vendor guarantees.

- **W1** Microsoft, Using Bind or Connect Redirection: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- **W2** Microsoft, FwpsQueryConnectionRedirectState0: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsqueryconnectionredirectstate0
- **W3** Microsoft, Using Proxied Connections Tracking: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- **W4** Microsoft, user-mode SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS: https://learn.microsoft.com/en-us/windows/win32/winsock/sio-query-wfp-connection-redirect-records
- **W5** Microsoft, SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/sio-query-wfp-connection-redirect-context
- **W6** Microsoft, Kernel-Mode Code Signing Requirements: https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-requirements--windows-vista-and-later-
- **A1** Apple, startSystemExtensionMode: https://developer.apple.com/documentation/networkextension/neprovider/startsystemextensionmode()
- **A2** Apple, NETransparentProxyManager: https://developer.apple.com/documentation/networkextension/netransparentproxymanager
- **A3** Apple, Network Extensions Entitlement: https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension
- **A4** Apple, TN3134 Network Extension provider deployment: https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment
- **A5** Apple, NETransparentProxyProvider: https://developer.apple.com/documentation/networkextension/netransparentproxyprovider
- **A6** Apple, Handling Flow Copying: https://developer.apple.com/documentation/networkextension/handling-flow-copying
- **A7** Apple, NEAppProxyFlow: https://developer.apple.com/documentation/networkextension/neappproxyflow
