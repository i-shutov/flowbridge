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
    @Published private(set) var workerStatuses: [[String: Any]] = []
    @Published private(set) var workerRevision: UInt64 = 0
    @Published private(set) var workerHandles: [UInt64] = [] // immutable main-thread publication
    @Published private(set) var events: [[String: Any]] = []
    @Published private(set) var message = "SSH остановлен"

    private let queue = DispatchQueue(label: "FlowBridge.ssh")
    private var handles: [UInt64] = [] // accessed on serial worker queue
    private var timer: Timer?
    private var revision: UInt64 = 0 // accessed on main thread
    private var pending: ((Bool) -> Void)?
    private var polling = false
    private var previousWorkerSignature = ""

    init() {
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in self?.poll() }
    }
    deinit {
        timer?.invalidate()
        // Deallocation happens after the desktop's Stop callback. Avoid
        // blocking the main thread on SSH shutdown in a deinitializer.
        let ids = handles
        queue.async { for id in ids { fb_ssh_destroy(id) } }
    }

    func start(_ settings: DesktopSettings, completion: @escaping (Bool) -> Void) {
        do {
            let count = settings.sshWorkers ?? 1
            guard (1...4).contains(count), settings.localPort > 0,
                  settings.localPort + 2 * (count - 1) <= 65535 else {
                throw Bridge.error("Пул SSH: 1–4 процесса; проверьте локальные SOCKS-порты.")
            }
            let configurations = try (0..<count).map {
                try settings.sshJSON(localPort: settings.localPort + 2 * $0)
            }
            revision += 1
            let version = revision
            pending = completion
            state = "starting"
            workerHandles = []
            message = "Запускаем \(count) независимых SSH-процессов…"
            workerStatuses = []
            queue.async {
                for id in self.handles { fb_ssh_destroy(id) }
                self.handles = []
                var created: [UInt64] = []
                do {
                    for config in configurations {
                        let value = try config.withCString {
                            try Bridge.consume(fb_ssh_create_json($0))
                        }
                        guard let number = value["ssh_id"] as? NSNumber else {
                            throw Bridge.error("Не получен идентификатор SSH worker.")
                        }
                        created.append(number.uint64Value)
                    }
                    self.handles = created
                    for id in created { _ = try Bridge.consume(fb_ssh_start_json(id)) }
                    let snapshots = try created.map {
                        try Bridge.consume(fb_ssh_snapshot_json($0))
                    }
                    DispatchQueue.main.async {
                        guard self.revision == version else { return }
                        self.workerHandles = created
                        self.acceptWorkers(snapshots)
                    }
                } catch {
                    // A partial pool must not leave child processes behind.
                    for id in created { fb_ssh_destroy(id) }
                    self.handles = []
                    DispatchQueue.main.async {
                        guard self.revision == version else { return }
                        self.workerHandles = []
                        self.state = "failed"
                        self.message = error.localizedDescription
                        let callback = self.pending
                        self.pending = nil
                        callback?(false)
                    }
                }
            }
        } catch {
            state = "failed"
            message = error.localizedDescription
            completion(false)
        }
    }

    func stop(completion: (() -> Void)? = nil) {
        revision += 1
        pending = nil
        let version = revision
        queue.async {
            var failure: String?
            // Attempt every stop even if one worker has already failed.
            for id in self.handles {
                do { _ = try Bridge.consume(fb_ssh_stop_json(id)) }
                catch { if failure == nil { failure = error.localizedDescription } }
            }
            DispatchQueue.main.async {
                guard self.revision == version else { return }
                self.state = failure == nil ? "stopped" : "failed"
                self.message = failure ?? "Все процессы SSH остановлены."
                self.workerStatuses = []
                self.workerHandles = []
                self.workerRevision &+= 1
                completion?()
            }
        }
    }

    func discoverDNS(completion: @escaping (Result<[String], Error>) -> Void) {
        let version = revision
        queue.async {
            let id = self.handles.first ?? 0
            // The actual DNS proxy is single-SSH only in this beta. Do not
            // block the serial supervisor queue: Stop must cancel discovery.
            DispatchQueue.global(qos: .utility).async {
                let result: Result<[String], Error>
                do {
                    let value = try Bridge.consume(fb_ssh_remote_dns_json(id))
                    guard let servers = value["servers"] as? [String], !servers.isEmpty else {
                        throw Bridge.error("DNS-сервер не найден")
                    }
                    result = .success(servers)
                } catch {
                    result = .failure(error)
                }
                DispatchQueue.main.async {
                    guard self.revision == version else { return }
                    completion(result)
                }
            }
        }
    }

    private func poll() {
        guard !polling else { return }
        polling = true
        let version = revision
        queue.async {
            let snapshots: [[String: Any]]
            if self.handles.isEmpty {
                snapshots = []
            } else {
                // Fail closed if any snapshot cannot be read. Never mark a
                // missing worker ready from stale data.
                snapshots = self.handles.map {
                    (try? Bridge.consume(fb_ssh_snapshot_json($0))) ?? [
                        "status": ["state": "failed", "last_error": "Нет ответа SSH worker"]
                    ]
                }
            }
            DispatchQueue.main.async {
                self.polling = false
                guard self.revision == version, !snapshots.isEmpty else { return }
                self.acceptWorkers(snapshots)
            }
        }
    }

    private func acceptWorkers(_ snapshots: [[String: Any]]) {
        let states = snapshots.map {
            $0["status"] as? [String: Any] ?? ["state": "failed"]
        }
        workerStatuses = states
        let newSignature = states.map { item in
            "\(item["state"] as? String ?? "failed"):" +
            "\((item["pid"] as? NSNumber)?.uint64Value ?? 0):" +
            "\((item["local_port"] as? NSNumber)?.intValue ?? 0)"
        }.joined(separator: "|")
        if previousWorkerSignature != newSignature {
            previousWorkerSignature = newSignature
            workerRevision &+= 1
        }
        let readyCount = states.filter { ($0["state"] as? String) == "ready" }.count
        let allFailed = states.allSatisfy { ($0["state"] as? String) == "failed" }
        let allStopped = states.allSatisfy { ($0["state"] as? String) == "stopped" }
        let anyDegraded = states.contains { ($0["state"] as? String) == "degraded" }
        let representative = states.first(where: { ($0["state"] as? String) == "ready" })
            ?? states.first ?? [:]
        var summary = representative
        summary["worker_count"] = states.count
        summary["ready_workers"] = readyCount
        status = summary
        if readyCount > 0 {
            state = "ready"
        } else if allFailed {
            state = "failed"
        } else if allStopped {
            state = "stopped"
        } else if anyDegraded {
            state = "degraded"
        } else {
            state = "reconnecting"
        }
        let restarts = states.reduce(UInt64(0)) {
            $0 + (($1["restarts"] as? NSNumber)?.uint64Value ?? 0)
        }
        let exhausted = states.reduce(UInt64(0)) {
            $0 + (($1["resource_exhaustion_count"] as? NSNumber)?.uint64Value ?? 0)
        }
        message = "SSH \(readyCount)/\(states.count) готово · перезапусков \(restarts)"
        if exhausted > 0 { message += " · ошибок ресурсов \(exhausted)" }
        if state == "failed", let error = representative["last_error"] as? String {
            message += ": " + error
        }
        events = snapshots.flatMap { $0["events"] as? [[String: Any]] ?? [] }.suffix(64).map { $0 }
        if state == "ready" || state == "failed" || state == "stopped" {
            let callback = pending
            pending = nil
            callback?(state == "ready")
        }
    }
}
