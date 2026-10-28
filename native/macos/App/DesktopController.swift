import Foundation
import Darwin
import SwiftUI

final class DesktopController: ObservableObject {
    let engine = EngineController()
    let native = NativeController()
    let ssh = SSHController()
    let discovery = AppDiscovery()
    @Published var settings = DesktopSettings()
    @Published private(set) var busy = false
    @Published var message = "Настройте подключение и нажмите «Подключить»."
    private var revision: UInt64 = 0
    private var monitor: Timer?
    private var waitingForNative = false
    private var pendingNativeProfile: String?
    private var previousSSHState = ""
    private let file = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("FlowBridge/desktop.json")
    init() {
        if let text = try? EngineController.read(file), let saved = try? JSONDecoder().decode(DesktopSettings.self, from: Data(text.utf8)) { settings = saved }
        native.ports = settings.capturePorts
        monitor = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in self?.tick() }
        discovery.scan()
    }
    deinit { monitor?.invalidate() }
    @discardableResult func saveSettings() -> Bool {
        do {
            try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try JSONEncoder().encode(settings).write(to: file, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
            return true
        } catch { message = "Не удалось сохранить настройки: " + error.localizedDescription; return false }
    }
    private func configuredProfile() throws -> String {
        guard var object = try JSONSerialization.jsonObject(with: Data(engine.config.utf8)) as? [String: Any] else { throw Bridge.error("Некорректный профиль") }
        if let generated = (object["rules"] as? [[String: Any]])?.first(where: { $0["id"] as? String == "desktop-app-selection" }),
           let route = generated["action"] as? [String: Any] {
            object["default_action"] = route
            object["rules"] = (object["rules"] as? [[String: Any]] ?? []).filter { $0["id"] as? String != "desktop-app-selection" }
        }
        object["listen"] = engine.listen
        if settings.integratedSSH {
            guard Int(engine.listen.split(separator: ":").last ?? "") != settings.localPort else {
                throw Bridge.error("Порт SSH SOCKS должен отличаться от входного порта FlowBridge.")
            }
            var proxies = object["proxies"] as? [[String: Any]] ?? []
            proxies.removeAll { $0["id"] as? String == "flowbridge-ssh" }
            proxies.insert(["id": "flowbridge-ssh", "kind": "socks5", "endpoint": ["host": "127.0.0.1", "port": settings.localPort],
                            "username": NSNull(), "password_env": NSNull()], at: 0)
            object["proxies"] = proxies
            object["default_action"] = ["type": "proxy", "id": "flowbridge-ssh"]
        }
        // Generated app rules must never leak into explicit SOCKS mode, where
        // source application identity cannot be authenticated.
        if settings.mode == 0 {
            object["rules"] = (object["rules"] as? [[String: Any]] ?? []).filter { $0["id"] as? String != "desktop-app-selection" }
        }
        let text = try Bridge.text(object); try Bridge.validate(text); return text
    }
    private func appProfile(_ source: String) throws -> String {
        guard var object = try JSONSerialization.jsonObject(with: Data(source.utf8)) as? [String: Any] else { throw Bridge.error("Некорректный профиль") }
        let selected = discovery.applications.filter { settings.selectedApplications.contains($0.path) }
        let identities = Array(Set(selected.compactMap(\.policyIdentity))).sorted()
        guard !identities.isEmpty else { throw Bridge.error("Выберите найденные приложения с доступным signing ID.") }
        let action: [String: Any]
        if settings.integratedSSH { action = ["type": "proxy", "id": "flowbridge-ssh"] }
        else {
            guard let existing = object["default_action"] as? [String: Any],
                  ["proxy", "chain"].contains(existing["type"] as? String ?? "") else {
                throw Bridge.error("Для шаблона выберите прокси или цепочку в профиле.")
            }
            action = existing
        }
        object["rules"] = [["id": "desktop-app-selection", "enabled": true, "applications": identities,
                             "hosts": [], "networks": [], "ports": [], "action": action]]
        object["default_action"] = ["type": "direct"]
        let text = try Bridge.text(object); try Bridge.validate(text); return text
    }
    private func literalIP(_ value: String) -> Bool {
        var v4 = in_addr(); var v6 = in6_addr()
        return value.withCString { inet_pton(AF_INET,$0,&v4) } == 1 || value.withCString { inet_pton(AF_INET6,$0,&v6) } == 1
    }
    func start() {
        guard !busy, !engine.running, !native.active else { return }
        do {
            guard saveSettings() else { return }
            var profile = try configuredProfile()
            native.remoteDNS = nil
            let remoteDNS = settings.mode == 1 && (settings.remoteDNS ?? true)
            if remoteDNS {
                guard settings.integratedSSH else { throw Bridge.error("Системный DNS через SSH требует встроенного SSH-подключения.") }
                guard literalIP(settings.sshHost) else { throw Bridge.error("Для DNS-режима этой беты укажите IP SSH-сервера, чтобы его повторное подключение не зависело от отключённого DNS-туннеля.") }
                let resolver = settings.remoteDNSResolver ?? ""
                guard resolver.isEmpty || literalIP(resolver) else { throw Bridge.error("Укажите IP DNS-сервера удалённой машины или оставьте поле пустым.") }
            }
            var applicationProfile: String?
            if settings.mode == 1 {
                guard native.available else { throw Bridge.error("Прозрачный режим недоступен: нужен подписанный и одобренный Network Extension.") }
                if settings.integratedSSH {
                    guard let identity = InstalledApplication.systemSSHSigningID() else {
                        throw Bridge.error("Не удалось проверить signing ID /usr/bin/ssh для защиты от повторного перехвата SSH.")
                    }
                    native.bypassSigningIDs = [identity]
                } else { native.bypassSigningIDs = [] }
                if settings.appSelectionEnabled {
                    applicationProfile = try appProfile(profile)
                    guard var bootstrap = try JSONSerialization.jsonObject(with: Data(profile.utf8)) as? [String: Any] else { throw Bridge.error("Некорректный профиль") }
                    bootstrap["rules"] = []; bootstrap["default_action"] = ["type": "direct"]
                    profile = try Bridge.text(bootstrap) // no app interception claim before readiness
                }
            }
            revision += 1; let version = revision; busy = true
            pendingNativeProfile = applicationProfile
            let launch = {
                guard self.revision == version else { return }
                self.engine.config = profile; self.engine.syncQuick()
                if self.settings.mode == 0 {
                    self.engine.execute("start") { success in
                        guard self.revision == version else { return }; self.busy = false
                        self.message = success ? "Локальный SOCKS готов. Укажите его адрес в нужных приложениях." : self.engine.message
                        if !success && self.settings.integratedSSH { self.ssh.stop() }
                    }
                } else {
                    self.native.managedPort = self.settings.integratedSSH ? self.settings.localPort : nil
                    self.native.upstreamReady = !self.settings.integratedSSH || self.ssh.state == "ready"
                    self.native.ports = self.settings.capturePorts; self.waitingForNative = true
                    self.native.start(profile); self.message = "Ожидаем подтверждение готовности macOS…"
                }
            }
            if settings.integratedSSH {
                engine.setUpstreamGate(port: settings.localPort, ready: false)
                message = "Проверяем SSH и локальный SOCKS…"
                ssh.start(settings) { success in
                    guard self.revision == version else { return }
                    if success {
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
                    }
                    else { self.busy = false; self.message = self.ssh.message }
                }
            } else { engine.setUpstreamGate(port: nil, ready: true); launch() }
        } catch { message = error.localizedDescription; busy = false }
    }
    private func tick() {
        native.upstreamReady = !settings.integratedSSH || ssh.state == "ready"
        if ssh.state != previousSSHState {
            previousSSHState = ssh.state
            engine.setUpstreamGate(port: settings.integratedSSH ? settings.localPort : nil, ready: !settings.integratedSSH || ssh.state == "ready")
        }
        guard waitingForNative else { return }
        if native.active {
            waitingForNative = false
            if let profile = pendingNativeProfile {
                pendingNativeProfile = nil; let version = revision
                native.applyRules(profile) { success in
                    guard self.revision == version else { return }; self.busy = false
                    if success {
                        self.engine.config = profile; try? self.engine.persist(profile)
                        self.message = "Выбранные приложения направлены через прокси. Остальные — напрямую."
                    } else {
                        let failure = self.native.message
                        self.stop { _ in self.message = "Не удалось применить правила приложений: " + failure }
                    }
                }
            } else { busy = false; try? engine.persist(engine.config); message = "Прозрачный TCP-режим готов." }
        } else if !native.busy {
            waitingForNative = false; let failure = native.message
            stop { _ in self.message = failure }
        }
    }
    func stop(completion: ((Bool) -> Void)? = nil) {
        revision += 1; let version = revision; waitingForNative = false; pendingNativeProfile = nil; busy = true
        message = "Останавливаем маршрутизацию…"
        let stopSSH = { (success: Bool) in
            guard self.revision == version else { return }
            guard success else { self.busy = false; self.message = "Остановка маршрутизации не подтверждена. SSH сохранён."; completion?(false); return }
            self.ssh.stop { guard self.revision == version else { return }; self.busy = false; self.message = "Подключение остановлено."; completion?(true) }
        }
        native.stopAndWait { success in
            guard self.revision == version else { return }
            guard success else { stopSSH(false); return }
            self.engine.execute("stop", completion: stopSSH)
        }
    }
    func apply() {
        guard !busy, !engine.busy, !native.busy else { return }
        guard saveSettings() else { return }
        do {
            if settings.mode == 1 {
                guard native.active else { message = "Настройки сохранены. Правила приложений применятся после готовности macOS при подключении."; return }
                let profile = settings.appSelectionEnabled ? try appProfile(configuredProfile()) : try configuredProfile()
                let version = revision; busy = true
                native.applyRules(profile) { success in
                    guard self.revision == version else { return }; self.busy = false
                    if success { self.engine.config = profile; try? self.engine.persist(profile) }
                    self.message = self.native.message
                }
            } else {
                engine.config = try configuredProfile(); engine.syncQuick(); engine.execute("apply")
                message = "Локальный режим: выбор приложений не меняет маршрутизацию; используйте SOCKS-настройки самих приложений."
            }
        } catch { message = error.localizedDescription }
    }
    func selectPreset(_ id: String) {
        guard let preset = discovery.catalog?.presets.first(where: { $0.id == id }) else { return }
        settings.selectedPreset = id
        settings.selectedApplications = discovery.applications.filter { app in
            app.policyIdentity != nil && !Set(app.catalogIDs).isDisjoint(with: Set(preset.app_ids))
        }.map(\.path)
        saveSettings()
        message = "Шаблон выбрал \(settings.selectedApplications.count) установленных приложений. Проверьте список перед применением."
    }
}
