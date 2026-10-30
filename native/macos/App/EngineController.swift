import AppKit
import SwiftUI
import UniformTypeIdentifiers

final class EngineController: ObservableObject {
    @Published var config = Bridge.initial
    @Published var message = "Stopped. Configure your applications to use the local SOCKS5 listener."
    @Published var running = false
    @Published var busy = false
    @Published var snapshot: [String: Any] = [:]
    @Published var host = "127.0.0.1"
    @Published var port = "1080"
    @Published var kind = "socks5"
    @Published var listen = "127.0.0.1:1081"
    private let queue = DispatchQueue(label: "FlowBridge.engine")
    private var engine: UInt64 = 0 // accessed only on queue
    private var gateJSON = "{\"endpoint\":null,\"ready\":true,\"grace_ms\":30000}"
    private var ownedPoolJSON: String?
    private var timer: Timer?
    private let profile = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("FlowBridge/profile.json")

    init() {
        if let text = try? Self.read(profile) { config = text }
        syncQuick()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in self?.poll() }
    }
    deinit { timer?.invalidate(); let id = engine; queue.async { fb_engine_destroy(id) } }
    static func read(_ url: URL) throws -> String {
        let input = try FileHandle(forReadingFrom: url); defer { try? input.close() }
        let data = try input.read(upToCount: 1_048_577) ?? Data()
        guard data.count <= 1_048_576, let text = String(data: data, encoding: .utf8), !text.contains("\0") else {
            throw Bridge.error("Profile must be UTF-8 without NUL, at most 1 MiB")
        }
        return text
    }
    func syncQuick() {
        guard let object = try? JSONSerialization.jsonObject(with: Data(config.utf8)) as? [String: Any] else { return }
        listen = object["listen"] as? String ?? listen
        if let proxies = object["proxies"] as? [[String: Any]], let first = proxies.first,
           let endpoint = first["endpoint"] as? [String: Any] {
            host = endpoint["host"] as? String ?? host
            port = String(endpoint["port"] as? Int ?? 1080)
            kind = first["kind"] as? String ?? kind
        }
    }
    func updateQuick() {
        do {
            guard var object = try JSONSerialization.jsonObject(with: Data(config.utf8)) as? [String: Any],
                  let number = Int(port), (1...65535).contains(number) else { throw Bridge.error("Invalid profile or port") }
            var proxies = object["proxies"] as? [[String: Any]] ?? []
            var first = proxies.first ?? ["id": "quick", "username": NSNull(), "password_env": NSNull()]
            first["kind"] = kind; first["endpoint"] = ["host": host, "port": number]
            if proxies.isEmpty {
                proxies.append(first); object["default_action"] = ["type": "proxy", "id": "quick"]
            } else { proxies[0] = first }
            object["proxies"] = proxies; object["listen"] = listen
            let updated = try Bridge.text(object); try Bridge.validate(updated); config = updated
            message = "Quick settings updated in draft. Apply to use this profile."
        } catch { message = error.localizedDescription }
    }
    func execute(_ operation: String, completion: ((Bool) -> Void)? = nil) {
        guard !busy || operation == "stop" else { completion?(false); return }; busy = true
        let draft = config
        queue.async { [weak self] in
            guard let self else { return }
            do {
                if operation != "stop" { try Bridge.validate(draft) }
                if self.engine == 0 && operation != "stop" {
                    let result = try draft.withCString { try Bridge.consume(fb_engine_create_json($0)) }
                    guard let id = result["engine_id"] as? NSNumber else { throw Bridge.error("Missing engine handle") }
                    self.engine = id.uint64Value
                    if let pool = self.ownedPoolJSON {
                        _ = try pool.withCString {
                            try Bridge.consume(fb_engine_sync_owned_ssh_pool_json(self.engine, $0))
                        }
                    } else {
                        _ = try self.gateJSON.withCString {
                            try Bridge.consume(fb_engine_set_upstream_gate_json(self.engine, $0))
                        }
                    }
                }
                if operation == "stop" {
                    if self.engine != 0 { _ = try Bridge.consume(fb_engine_stop_json(self.engine)) }
                } else {
                    _ = try draft.withCString { try Bridge.consume(fb_engine_reload_json(self.engine, $0)) }
                    if operation == "start" { _ = try Bridge.consume(fb_engine_start_json(self.engine)) }
                    try self.persist(draft)
                }
                let snapshot = self.engine == 0 ? [:] : try Bridge.consume(fb_engine_snapshot_json(self.engine))
                DispatchQueue.main.async {
                    self.accept(snapshot); self.busy = false
                    self.message = operation == "stop" ? "Локальный SOCKS остановлен." : "Профиль применён и сохранён."
                    completion?(true)
                }
            } catch {
                if operation == "start", self.engine != 0 { _ = try? Bridge.consume(fb_engine_stop_json(self.engine)) }
                DispatchQueue.main.async { self.message = error.localizedDescription; self.busy = false; completion?(false) }
            }
        }
    }
    func setUpstreamGate(port: Int?, ready: Bool) {
        let endpoint: Any
        if let port { endpoint = ["host": "127.0.0.1", "port": port] } else { endpoint = NSNull() }
        guard let json = try? Bridge.text(["endpoint": endpoint, "ready": ready, "grace_ms": 30000]) else { return }
        queue.async {
            self.gateJSON = json
            self.ownedPoolJSON = nil
            guard self.engine != 0 else { return }
            do { _ = try json.withCString { try Bridge.consume(fb_engine_set_upstream_gate_json(self.engine, $0)) } }
            catch { DispatchQueue.main.async { self.message = error.localizedDescription } }
        }
    }
    /// Bind actual SSH supervisor handles. The FFI derives readiness and
    /// loopback ports from owned process snapshots; no readiness JSON is
    /// accepted from SwiftUI. Transparent NE stays single-worker.
    func setUpstreamPool(sshIDs: [UInt64]) {
        guard (2...4).contains(sshIDs.count), !sshIDs.contains(0),
              Set(sshIDs).count == sshIDs.count else {
            DispatchQueue.main.async {
                self.message = "Недопустимые или повторяющиеся SSH supervisor handles."
            }
            return
        }
        let perWorker = 128 / sshIDs.count
        let request: [String: Any] = [
            "ssh_ids": sshIDs,
            "limits": [
                "max_flows": perWorker, "max_opening": min(16, perWorker),
                "max_queued": 64 / sshIDs.count, "wait_timeout_ms": 10000
            ],
            "aggregate_max_flows": 128
        ]
        do {
            let json = try Bridge.text(request)
            queue.async {
                self.ownedPoolJSON = json
                guard self.engine != 0 else { return }
                do {
                    _ = try json.withCString {
                        try Bridge.consume(fb_engine_sync_owned_ssh_pool_json(self.engine, $0))
                    }
                } catch {
                    DispatchQueue.main.async {
                        self.message = "Ошибка SSH-пула: " + error.localizedDescription
                    }
                }
            }
        } catch {
            message = error.localizedDescription
        }
    }

    func persist(_ text: String) throws {
        try FileManager.default.createDirectory(at: profile.deletingLastPathComponent(), withIntermediateDirectories: true,
                                              attributes: [.posixPermissions: 0o700])
        try text.write(to: profile, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: profile.path)
    }
    private func poll() {
        guard !busy else { return }
        queue.async { [weak self] in
            guard let self, self.engine != 0, let value = try? Bridge.consume(fb_engine_snapshot_json(self.engine)) else { return }
            DispatchQueue.main.async { self.accept(value) }
        }
    }
    private func accept(_ value: [String: Any]) {
        snapshot = value; running = (value["status"] as? [String: Any])?["running"] as? Bool ?? false
    }
    func open() {
        let panel = NSOpenPanel(); panel.allowedContentTypes = [.json]; panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { config = try Self.read(url); syncQuick(); message = "Loaded draft. Apply when ready." }
        catch { message = error.localizedDescription }
    }
    func save() {
        let panel = NSSavePanel(); panel.allowedContentTypes = [.json]; panel.nameFieldStringValue = "flowbridge.json"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { try config.write(to: url, atomically: true, encoding: .utf8); message = "Saved draft." }
        catch { message = error.localizedDescription }
    }
}
