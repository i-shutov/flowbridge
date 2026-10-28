from pathlib import Path

def edit(path, old, new, count=1):
    p=Path(path);s=p.read_text(encoding='utf-8')
    if s.count(old)!=count:raise RuntimeError(f'{path}: match count {s.count(old)}, expected {count}')
    p.write_text(s.replace(old,new),encoding='utf-8')

p='crates/flowbridge-ffi/src/native_dns.rs'
edit(p,'    query: Vec<u8>,\n}', '    query: Vec<u8>,\n    #[serde(default)]\n    udp: bool,\n    #[serde(default)]\n    reply_on_failure: bool,\n}')
edit(p,'        let answer = session.dns_exchange(request.query)?;', '''        let result = session.dns_exchange(request.query.clone());
        let failed = result.is_err();
        let mut answer = match result {
            Ok(answer) => answer,
            Err(_) if request.reply_on_failure => failure(&request.query),
            Err(error) => return Err(error),
        };
        if request.udp && answer.len() > 512 {
            answer = minimal_reply(&request.query, word(&answer, 2)? | 0x0200);
        }''')
edit(p,'"local_fallback":false}))','"local_fallback":false,"resolution_failed":failed}))')
p='native/macos/project.yml'
edit(p,'            com.apple.networkextension.app-proxy: $(PRODUCT_MODULE_NAME).TransparentProxyProvider','            com.apple.networkextension.app-proxy: $(PRODUCT_MODULE_NAME).TransparentProxyProvider\n            com.apple.networkextension.dns-proxy: $(PRODUCT_MODULE_NAME).DNSProxyProvider')
for p in ['native/macos/App/FlowBridge.entitlements','native/macos/Extension/FlowBridgeExtension.entitlements']:
    edit(p,'<array><string>app-proxy-provider-systemextension</string></array>','<array><string>app-proxy-provider-systemextension</string><string>dns-proxy-systemextension</string></array>')
p='native/macos/Extension/TransparentProxyProvider.swift'
edit(p,'                let nativeOptions: [String: Any] = [','                var nativeOptions: [String: Any] = [')
edit(p,'                    "ready": false, "ready_lease_ms": 5000, "pause_grace_ms": 30000]','''                    "ready": false, "ready_lease_ms": 5000, "pause_grace_ms": 30000]
                if let dns = proto.providerConfiguration?["remoteDNS"] as? [String: Any] { nativeOptions["dns"] = dns }''')
edit(p,'                    if self.ready { self.recordLocked("TCP capture ready; UDP/DNS direct. Upstream and loopback destinations excluded.") }','''                    if self.ready, let sessionID = self.sessionID {
                        SharedNativeSession.shared.publish(id:sessionID,handle:id.uint64Value,
                            dns:proto.providerConfiguration?["remoteDNS"] != nil)
                        self.recordLocked("TCP capture ready; DNS activation is confirmed separately.")
                    }
                    if error != nil && self.coreSession == id.uint64Value { self.coreSession = 0 }''')
edit(p,'                    completionHandler(error ?? (cancelled ? Bridge.error("Start cancelled") : nil))','''                    if error != nil || cancelled { fb_native_destroy(id.uint64Value) }
                    completionHandler(error ?? (cancelled ? Bridge.error("Start cancelled") : nil))''')
edit(p,'        fb_native_destroy(native)','        SharedNativeSession.shared.revoke(handle:native)\n        fb_native_destroy(native)')
edit(p,'            "status": core["status"] ?? [:], "managed_upstream": core["managed_upstream"] ?? NSNull()]','''            "status": core["status"] ?? [:], "managed_upstream": core["managed_upstream"] ?? NSNull(),
            "dns": SharedNativeSession.shared.snapshot(handle:native)]''')
p='native/macos/App/NativeController.swift'
edit(p,'    var upstreamReady = false','    var upstreamReady = false\n    var remoteDNS: [String: Any]?',2)
edit(p,'    private var manager: NETransparentProxyManager?','''    private var manager: NETransparentProxyManager?
    private var ownsSession = false
    private var dnsRequested: String?
    private var dnsStopComplete = true
    private var dnsStopError: Error?
    private lazy var dnsController = DNSController(identifier:extensionID)''')
edit(p,'    func start(_ profile: String) {\n        guard available, !busy else { return }','''    func start(_ profile: String) {
        guard available, !busy else { return }
        if manager?.connection.status == .connected && !ownsSession {
            message = "Обнаружен ранее запущенный перехват. Сначала нажмите Остановить; его SSH-сеанс не принадлежит этому запуску."; return
        }''')
edit(p,'        operation += 1; providerSessionID = nil; busy = true; active = false; stopping = false; pendingProfile = profile','''        operation += 1; providerSessionID = nil; busy = true; active = false; stopping = false; pendingProfile = profile
        ownsSession = true; dnsRequested = nil; dnsStopError = nil''')
edit(p,'            throw Bridge.error("Required system extension / Network Extension entitlements missing")\n        }','''            throw Bridge.error("Required system extension / Network Extension entitlements missing")
        }
        if remoteDNS != nil {
            guard (appEnt["com.apple.developer.networking.networkextension"] as? [String])?.contains("dns-proxy-systemextension") == true,
                  (extEnt["com.apple.developer.networking.networkextension"] as? [String])?.contains("dns-proxy-systemextension") == true else {
                throw Bridge.error("Подпись приложения и расширения должна разрешать DNS Proxy")
            }
        }''')
edit(p,'                    manager.protocolConfiguration = proto; manager.localizedDescription = "FlowBridge TCP capture"','''                    if let dns = self.remoteDNS { proto.providerConfiguration?["remoteDNS"] = dns }
                    manager.protocolConfiguration = proto; manager.localizedDescription = "FlowBridge TCP capture"''')
edit(p,'        pingSequence += 1; pingOutstanding = false\n        manager?.connection.stopVPNTunnel(); message = "Stopping TCP capture."','''        pingSequence += 1; pingOutstanding = false; ownsSession = false; dnsRequested = nil
        dnsStopComplete = false; dnsStopError = nil; let revision = operation
        dnsController.disable { error in
            guard self.operation == revision else { return }
            self.dnsStopComplete = true; self.dnsStopError = error
            if let error { self.message = "Не удалось отключить DNS: " + error.localizedDescription }
        }
        manager?.connection.stopVPNTunnel(); message = "Останавливаем TCP-перехват и DNS."''')
edit(p,'            if status == nil || status == .disconnected || status == .invalid { completion(true); return }','''            if self.dnsStopComplete && self.dnsStopError != nil { completion(false); return }
            if self.dnsStopComplete && (status == nil || status == .disconnected || status == .invalid) { completion(true); return }''')
start='    func deactivate() {';end='    private func submitDeactivation() {'
s=Path(p).read_text();a=s.index(start);b=s.index(end,a)
s=s[:a]+'''    func deactivate() {
        stopAndWait { success in
            guard success else { return }; self.busy = true
            guard let manager = self.manager else { self.submitDeactivation(); return }
            let revision = self.operation; manager.isEnabled = false
            manager.saveToPreferences { error in
                DispatchQueue.main.async {
                    guard self.operation == revision else { return }
                    if let error { self.fail(error) } else { self.submitDeactivation() }
                }
            }
        }
    }
'''+s[b:];Path(p).write_text(s)
edit(p,'        manager?.connection.stopVPNTunnel(); stopping = true; providerSessionID = nil\n        busy = false; active = false; pendingProfile = nil; message = error.localizedDescription','''        stop(); busy = false; active = false; pendingProfile = nil; message = error.localizedDescription''')
edit(p,'        guard let manager, !stopping else { return }','''        guard let manager, !stopping else { return }
        guard ownsSession else {
            if manager.connection.status == .connected { message = "Существует другой сеанс перехвата: сначала остановите его." }
            return
        }''')
edit(p,'                    self.providerSessionID = observedSession; self.snapshot = response; self.active = true; self.busy = false\n                    self.message = "TCP capture active on configured ports. UDP and system DNS remain direct."','''                    self.providerSessionID = observedSession; self.snapshot = response
                    if self.remoteDNS != nil {
                        if self.dnsRequested != observedSession {
                            self.dnsRequested = observedSession; let revision = self.operation
                            self.dnsController.enable(session:observedSession) { error in
                                guard self.operation == revision, !self.stopping else { return }
                                if let error { self.fail(error) }
                            }
                        }
                        let dns = response["dns"] as? [String:Any] ?? [:]
                        guard dns["active"] as? Bool == true else {
                            self.active = false; self.busy = true; self.message = "Ожидаем подтверждение системного DNS-провайдера…"; return
                        }
                    }
                    self.active = true; self.busy = false
                    self.message = self.remoteDNS == nil ? "TCP-перехват готов. Системный DNS не перехватывается." : "TCP и системный DNS через SSH готовы. Собственный DoH/DoT приложений не перехватывается."''')
p='native/macos/App/SSHController.swift'
edit(p,'    var appSelectionEnabled = false','''    var appSelectionEnabled = false
    // Optional fields preserve decoding of previously saved profiles.
    var remoteDNS: Bool? = true
    var remoteDNSResolver: String? = ""
''')
edit(p,'    private func poll() {','''    func discoverDNS(completion: @escaping (Result<[String],Error>) -> Void) {
        let version = revision
        queue.async {
            let id = self.handle
            // Do not block the supervisor queue: Stop must cancel discovery.
            DispatchQueue.global(qos:.utility).async {
                let result: Result<[String],Error>
                do {
                    let value = try Bridge.consume(fb_ssh_remote_dns_json(id))
                    guard let servers = value["servers"] as? [String], !servers.isEmpty else { throw Bridge.error("DNS-сервер не найден") }
                    result = .success(servers)
                } catch { result = .failure(error) }
                DispatchQueue.main.async {
                    guard self.revision == version else { return }; completion(result)
                }
            }
        }
    }
    private func poll() {''')
p='native/macos/App/DesktopController.swift'
edit(p,'import Foundation','import Foundation\nimport Darwin')
edit(p,'    func start() {','''    private func literalIP(_ value: String) -> Bool {
        var v4 = in_addr(); var v6 = in6_addr()
        return value.withCString { inet_pton(AF_INET,$0,&v4) } == 1 || value.withCString { inet_pton(AF_INET6,$0,&v6) } == 1
    }
    func start() {''')
edit(p,'            var profile = try configuredProfile()','''            var profile = try configuredProfile()
            native.remoteDNS = nil
            let remoteDNS = settings.mode == 1 && (settings.remoteDNS ?? true)
            if remoteDNS {
                guard settings.integratedSSH else { throw Bridge.error("Системный DNS через SSH требует встроенного SSH-подключения.") }
                guard literalIP(settings.sshHost) else { throw Bridge.error("Для DNS-режима этой беты укажите IP SSH-сервера, чтобы его повторное подключение не зависело от отключённого DNS-туннеля.") }
                let resolver = settings.remoteDNSResolver ?? ""
                guard resolver.isEmpty || literalIP(resolver) else { throw Bridge.error("Укажите IP DNS-сервера удалённой машины или оставьте поле пустым.") }
            }''')
edit(p,'                    if success { self.engine.setUpstreamGate(port: self.settings.localPort, ready: true); launch() }','''                    if success {
                        self.engine.setUpstreamGate(port:self.settings.localPort,ready:true)
                        let useResolver: (String) -> Void = { resolver in
                            guard self.revision == version else { return }
                            self.native.remoteDNS = ["resolver":["host":resolver,"port":53],"timeout_ms":5000]
                            launch()
                        }
                        if !remoteDNS { launch() }
                        else if let resolver = self.settings.remoteDNSResolver, !resolver.isEmpty { useResolver(resolver) }
                        else {
                            self.message = "Читаем DNS-настройки удалённого SSH-сервера…"
                            self.ssh.discoverDNS { result in
                                guard self.revision == version else { return }
                                switch result {
                                case .success(let servers): useResolver(servers[0])
                                case .failure(let error): self.stop { _ in self.message = "DNS не запущен: " + error.localizedDescription }
                                }
                            }
                        }
                    }''')
p='native/macos/App/FlowBridgeApp.swift'
edit(p,'                        TextField("TCP-порты для перехвата", text: $desktop.settings.capturePorts)','''                        TextField("TCP-порты для перехвата", text: $desktop.settings.capturePorts)
                        Toggle("Разрешать DNS на удалённом SSH-сервере", isOn:Binding(
                            get:{desktop.settings.remoteDNS ?? true},set:{desktop.settings.remoteDNS = $0}))
                        if desktop.settings.remoteDNS ?? true {
                            TextField("Удалённый DNS IP · пусто = авто",text:Binding(
                                get:{desktop.settings.remoteDNSResolver ?? ""},set:{desktop.settings.remoteDNSResolver = $0}))
                            Text("Меняется обработка стандартного DNS всей системы, не только выбранных приложений. Внутренние домены должны разрешаться на SSH-сервере. При сбое локального обхода нет. Собственный DoH/DoT не перехватывается.")
                                .font(.caption).foregroundStyle(.orange)
                        }''')
edit(p,'Нужно одобрение macOS. UDP, QUIC, DNS, остальные порты и исключённые адреса идут напрямую.','Нужно одобрение macOS. TCP — на выбранных портах; DNS управляется отдельной галочкой. UDP/QUIC и остальные порты пока не перехватываются.')
edit(p,'Watchdog восстанавливает SSH для новых подключений. В native-режиме ожидание новых потоков во время обрыва не реализовано; текущие TCP-сессии могут оборваться.','Watchdog восстанавливает SSH; новые потоки ждут в ограниченной очереди. Уже открытые TCP-сессии при разрыве SSH могут оборваться.')
print('macOS DNS provider, serialized manager lifecycle, persisted checkbox and resolver discovery integrated')
