import Foundation
import SwiftUI

struct DesktopSettings: Codable {
    var integratedSSH = true
    var sshHost = ""
    var sshUser = ""
    var sshPort = 22
    var localPort = 1080
    // Optional field ensures older saved macOS DesktopSettings decode normally.
    var sshWorkers: Int? = 1
    var identityFile = ""
    var knownHostsFile = ""
    var compression = false
    var aliveInterval = 15
    var aliveCount = 3
    var connectTimeout = 10
    var healthInterval = 1000
    var healthTimeout = 1000
    var startupTimeout = 15000
    var restartInitial = 1000
    var restartMaximum = 30000
    var maxRestarts = 0
    var mode = 0
    var capturePorts = "80,443"
    var selectedApplications: [String] = []
    var selectedPreset = "ai_web"
    var appSelectionEnabled = false
    // Optional fields preserve decoding of previously saved profiles.
    var remoteDNS: Bool? = true
    var remoteDNSResolver: String? = ""


    func sshJSON(localPort overridePort: Int? = nil) throws -> String {
        guard !sshHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !sshUser.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Bridge.error("Укажите SSH-сервер и имя пользователя.")
        }
        return try Bridge.text([
            "host": sshHost, "user": sshUser, "port": sshPort, "local_port": overridePort ?? localPort,
            "identity_file": identityFile.isEmpty ? NSNull() : identityFile as Any,
            "known_hosts_file": knownHostsFile.isEmpty ? NSNull() : knownHostsFile as Any,
            "compression": compression, "server_alive_interval_secs": aliveInterval,
            "server_alive_count_max": aliveCount, "connect_timeout_secs": connectTimeout,
            "health_check_interval_ms": healthInterval, "health_check_timeout_ms": healthTimeout,
            "startup_timeout_ms": startupTimeout, "restart_initial_delay_ms": restartInitial,
            "restart_max_delay_ms": restartMaximum, "max_restarts": maxRestarts
        ])
    }
}

final class SSHController: ObservableObject {
    @Published private(set) var state = "stopped"
    @Published private(set) var status: [String: Any] = [:]
    @Published private(set) var events: [[String: Any]] = []
    @Published private(set) var message = "SSH остановлен"
    private let queue = DispatchQueue(label: "FlowBridge.ssh")
    private var handle: UInt64 = 0 // worker queue only
    private var timer: Timer?
    private var revision: UInt64 = 0 // main thread only
    private var pending: ((Bool) -> Void)?
    private var polling = false

    init() {
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in self?.poll() }
    }
    deinit { timer?.invalidate(); let id = handle; queue.async { fb_ssh_destroy(id) } }
    func start(_ settings: DesktopSettings, completion: @escaping (Bool) -> Void) {
        do {
            let json = try settings.sshJSON()
            revision += 1; let version = revision; pending = completion; state = "starting"; message = "Запуск SSH…"
            queue.async {
                do {
                    if self.handle != 0 { fb_ssh_destroy(self.handle); self.handle = 0 }
                    let created = try json.withCString { try Bridge.consume(fb_ssh_create_json($0)) }
                    guard let number = created["ssh_id"] as? NSNumber else { throw Bridge.error("SSH handle missing") }
                    self.handle = number.uint64Value
                    let response = try Bridge.consume(fb_ssh_start_json(self.handle))
                    DispatchQueue.main.async { guard self.revision == version else { return }; self.accept(response) }
                } catch {
                    DispatchQueue.main.async {
                        guard self.revision == version else { return }
                        self.state = "failed"; self.message = error.localizedDescription
                        let callback = self.pending; self.pending = nil; callback?(false)
                    }
                }
            }
        } catch { state = "failed"; message = error.localizedDescription; completion(false) }
    }
    func stop(completion: (() -> Void)? = nil) {
        revision += 1; pending = nil; let version = revision
        queue.async {
            var failure: String?
            if self.handle != 0 {
                do { _ = try Bridge.consume(fb_ssh_stop_json(self.handle)) }
                catch { failure = error.localizedDescription }
            }
            DispatchQueue.main.async {
                guard self.revision == version else { return }
                self.state = failure == nil ? "stopped" : "failed"
                self.message = failure ?? "SSH остановлен"; completion?()
            }
        }
    }
    func discoverDNS(completion: @escaping (Result<[String],Error>) -> Void) {
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
    private func poll() {
        guard !polling else { return }; polling = true; let version = revision
        queue.async {
            let response = self.handle == 0 ? nil : try? Bridge.consume(fb_ssh_snapshot_json(self.handle))
            DispatchQueue.main.async {
                self.polling = false
                guard self.revision == version, let response else { return }; self.accept(response)
            }
        }
    }
    private func accept(_ response: [String: Any]) {
        guard let value = response["status"] as? [String: Any] else { return }
        status = value; state = value["state"] as? String ?? "failed"
        events = response["events"] as? [[String: Any]] ?? events
        let descriptions = ["starting": "Подключение SSH…", "ready": "SSH готов", "reconnecting": "SSH переподключается", "degraded": "SSH: перегрузка или проверка доступности", "failed": "Ошибка SSH", "stopped": "SSH остановлен"]
        message = descriptions[state] ?? state
        if let error = value["last_error"] as? String, !error.isEmpty { message += ": " + error }
        if let count = value["resource_exhaustion_count"] as? NSNumber, count.uint64Value > 0 {
            message += " · ошибок ресурсов: \(count)"
        }
        if let backend = value["backend_version"] as? String { message += " · " + backend }
        if state == "ready" || state == "failed" || state == "stopped" {
            let callback = pending; pending = nil; callback?(state == "ready")
        }
    }
}
