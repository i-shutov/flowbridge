import Foundation
import NetworkExtension
import Darwin

/// TCP-only transparent adapter. A false return means DIRECT, never BLOCK.
/// Socket I/O is confined to per-flow queues. Each direction holds at most one
/// NE buffer and one 64-KiB Rust buffer; the next read waits for the write callback.
final class TransparentProxyProvider: NETransparentProxyProvider {
    private let lock = NSLock()
    private var profile = ""
    private var coreSession: UInt64 = 0
    private var ready = false
    private var generation: UInt64 = 0
    private var sessionID: String?
    private var limit = 128
    private var idleSeconds: Double = 300
    private var bypassSigningIDs: Set<String> = []
    private var sessions: [UUID: TCPRelay] = [:]
    private var recent: [[String: Any]] = []
    private var events: [[String: Any]] = []
    private var sequence = 0
    private let setupQueue = DispatchQueue(label: "FlowBridge.provider.setup")

    static func ipPrefix(_ host: String) -> Int? {
        var v4 = in_addr(); var v6 = in6_addr()
        if host.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 { return 32 }
        if host.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 { return 128 }
        return nil
    }
    private static func rule(_ host: String, port: Int, prefix: Int) -> NENetworkRule {
        NENetworkRule(remoteNetwork: NWHostEndpoint(hostname: host, port: String(port)), remotePrefix: prefix,
                      localNetwork: nil, localPrefix: 0, protocol: .TCP, direction: .outbound)
    }
    override func startProxy(options: [String: Any]?, completionHandler: @escaping (Error?) -> Void) {
        lock.lock(); generation += 1; let revision = generation; sessionID = UUID().uuidString; ready = false; lock.unlock()
        setupQueue.async { [weak self] in
            guard let self else { completionHandler(Bridge.error("Provider released")); return }
            do {
                guard let proto = self.protocolConfiguration as? NETunnelProviderProtocol,
                      let source = proto.providerConfiguration?["profile"] as? String,
                      let ports = proto.providerConfiguration?["capturePorts"] as? [Int],
                      !ports.isEmpty, ports.count <= 64,
                      ports.allSatisfy({ (1...65535).contains($0) && $0 != 53 }) else {
                    throw Bridge.error("Missing profile or explicit capture TCP ports")
                }
                try Bridge.validate(source)
                guard let config = try JSONSerialization.jsonObject(with: Data(source.utf8)) as? [String: Any] else { throw Bridge.error("Invalid configuration") }
                let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
                // Apple's rules require a concrete port when using wildcard addresses.
                settings.includedNetworkRules = ports.flatMap { port in
                    [Self.rule("0.0.0.0", port: port, prefix: 0), Self.rule("::", port: port, prefix: 0)]
                }
                var exclusions = [Self.rule("127.0.0.1", port: 0, prefix: 8), Self.rule("::1", port: 0, prefix: 128)]
                for proxy in config["proxies"] as? [[String: Any]] ?? [] {
                    guard let endpoint = proxy["endpoint"] as? [String: Any], let host = endpoint["host"] as? String,
                          let port = endpoint["port"] as? Int, let prefix = Self.ipPrefix(host), port != 53 else {
                        throw Bridge.error("Transparent mode requires literal IP upstream proxy endpoints, excluding port 53, so egress can be excluded reliably. Local mode supports proxy hostnames.")
                    }
                    exclusions.append(Self.rule(host, port: port, prefix: prefix))
                }
                settings.excludedNetworkRules = exclusions
                self.lock.lock()
                guard self.generation == revision else { self.lock.unlock(); throw Bridge.error("Start cancelled") }
                self.bypassSigningIDs = Set(proto.providerConfiguration?["bypassSigningIDs"] as? [String] ?? [])
                let nativeOptions: [String: Any] = [
                    "managed_endpoint": proto.providerConfiguration?["managedEndpoint"] ?? NSNull(),
                    "ready": false, "ready_lease_ms": 5000, "pause_grace_ms": 30000]
                self.lock.unlock()
                let optionsJSON = try Bridge.text(nativeOptions)
                let created = try source.withCString { c in try optionsJSON.withCString { o in
                    try Bridge.consume(fb_native_create_json(c, o)) } }
                guard let id = created["session_id"] as? NSNumber else { throw Bridge.error("Missing native session") }
                self.lock.lock()
                guard self.generation == revision else { self.lock.unlock(); fb_native_destroy(id.uint64Value); throw Bridge.error("Start cancelled") }
                self.coreSession = id.uint64Value
                self.profile = source; self.limit = min(config["max_connections"] as? Int ?? 256, 128)
                self.idleSeconds = Double(config["idle_timeout_ms"] as? Int ?? 300000) / 1000
                self.lock.unlock()
                self.setTunnelNetworkSettings(settings) { error in
                    self.lock.lock()
                    let cancelled = self.generation != revision
                    self.ready = error == nil && !cancelled
                    if self.ready { self.recordLocked("TCP capture ready; UDP/DNS direct. Upstream and loopback destinations excluded.") }
                    self.lock.unlock()
                    completionHandler(error ?? (cancelled ? Bridge.error("Start cancelled") : nil))
                }
            } catch { completionHandler(error) }
        }
    }
    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        lock.lock(); ready = false; sessionID = nil; generation += 1; let all = Array(sessions.values)
        let native = coreSession; coreSession = 0; lock.unlock()
        fb_native_destroy(native)
        all.forEach { $0.cancel(Bridge.error("Capture stopped")) }
        // Cancellation marks all relays closed immediately; bounded Rust calls finish
        // on their worker queues. In-flight opens close their handle on completion.
        setTunnelNetworkSettings(nil) { _ in completionHandler() }
    }
    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let tcp = flow as? NEAppProxyTCPFlow else { return false } // UDP explicitly direct
        lock.lock(); let source = profile; let isReady = ready
        let timeout = idleSeconds; let bypass = bypassSigningIDs; let native = coreSession; lock.unlock()
        guard isReady else { reject(flow, "Provider not ready"); return true }
        guard let endpoint = tcp.remoteEndpoint as? NWHostEndpoint, let port = Int(endpoint.port) else {
            reject(flow, "Unknown TCP destination"); return true
        }
        // Only OS-observed signing identity. Never invent a path, PID, DNS name,
        // reverse-DNS result or resolved IP. Empty signing identity remains null.
        let signingID = flow.metaData.sourceAppSigningIdentifier
        // Managed OpenSSH transport must never re-enter its own local SOCKS.
        // IDs come from inspecting the actual /usr/bin/ssh code signature.
        if bypass.contains(signingID) { return false }
        let object: [String: Any] = ["application": signingID.isEmpty ? NSNull() : signingID as Any,
                                    "destination": ["host": endpoint.hostname, "port": port], "resolved_ip": NSNull()]
        do {
            let flowJSON = try Bridge.text(object)
            let evaluation = try source.withCString { c in try flowJSON.withCString { f in try Bridge.consume(fb_evaluate_json(c, f)) } }
            guard let decision = evaluation["decision"] as? [String: Any], let action = decision["action"] as? [String: Any],
                  let type = action["type"] as? String else { throw Bridge.error("No policy decision") }
            if type == "direct" { record("Direct: \(endpoint.hostname):\(port)"); return false }
            if type == "block" { reject(flow, "Blocked by policy"); return true }
            if !bypass.isEmpty && signingID.isEmpty {
                reject(flow, "Unknown source identity cannot be proxied while SSH transport exclusion is required"); return true
            }
            let id = UUID()
            let relay = TCPRelay(id: id, flow: tcp, nativeSession: native, flowJSON: flowJSON, idleSeconds: timeout,
                                 host: endpoint.hostname, port: port, application: signingID,
                                 route: type + ":" + (action["id"] as? String ?? "")) { [weak self] summary in
                guard let self else { return }; self.lock.lock()
                self.sessions.removeValue(forKey: id); self.recent.append(summary)
                if self.recent.count > 256 { self.recent.removeFirst(self.recent.count - 256) }
                self.recordLocked("Flow \(id.uuidString) \(summary["state"] ?? "closed")")
                self.lock.unlock()
            }
            lock.lock()
            guard ready, sessions.count < limit else { lock.unlock(); reject(flow, "Provider stopping or full"); return true }
            sessions[id] = relay; lock.unlock(); relay.start(); return true
        } catch { reject(flow, error.localizedDescription); return true }
    }
    override func handleNewUDPFlow(_ flow: NEAppProxyUDPFlow, initialRemoteEndpoint remoteEndpoint: NWEndpoint) -> Bool { false }
    private func reject(_ flow: NEAppProxyFlow, _ message: String) {
        let error = Bridge.error(message); flow.closeReadWithError(error); flow.closeWriteWithError(error); record(message)
    }
    private func record(_ message: String) { lock.lock(); recordLocked(message); lock.unlock() }
    private func recordLocked(_ message: String) {
        sequence += 1; events.append(["seq": sequence, "level": "info", "message": message])
        if events.count > 256 { events.removeFirst(events.count - 256) }
    }
    private func snapshotData() throws -> Data {
        lock.lock(); let all = Array(sessions.values); let history = recent; let log = events
        let isReady = ready; let currentSession = sessionID; let native = coreSession; lock.unlock()
        let core = (try? Bridge.consume(fb_native_snapshot_json(native))) ?? [:]
        let value: [String: Any] = ["ready": isReady, "session_id": currentSession as Any? ?? NSNull(),
            "connections": all.map { $0.snapshot() } + history, "events": log,
            "status": core["status"] ?? [:], "managed_upstream": core["managed_upstream"] ?? NSNull()]
        return try JSONSerialization.data(withJSONObject: value)
    }
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        setupQueue.async {
            do {
                if messageData == Data("snapshot".utf8) {
                    completionHandler?(try self.snapshotData()); return
                }
                guard messageData.count <= 1_048_576,
                      let request = try JSONSerialization.jsonObject(with: messageData) as? [String: Any],
                      let command = request["command"] as? String,
                      let expected = request["session_id"] as? String else { throw Bridge.error("Invalid provider command") }
                self.lock.lock(); let native = self.coreSession
                let matches = self.ready && self.sessionID == expected && native != 0; self.lock.unlock()
                guard matches else { throw Bridge.error("Provider session changed or not ready") }
                if command == "heartbeat" {
                    guard let upstreamReady = request["upstream_ready"] as? Bool else { throw Bridge.error("Missing upstream readiness") }
                    let gate = try Bridge.text(["ready":upstreamReady])
                    _ = try gate.withCString { try Bridge.consume(fb_native_set_gate_json(native, $0)) }
                    completionHandler?(try self.snapshotData())
                } else if command == "apply_rules", let updated = request["profile"] as? String {
                    _ = try updated.withCString { try Bridge.consume(fb_native_reload_json(native, $0)) }
                    self.lock.lock()
                    guard self.ready, self.sessionID == expected, self.coreSession == native else {
                        self.lock.unlock(); throw Bridge.error("Provider state changed")
                    }
                    self.profile = updated; self.recordLocked("Application policy applied to new TCP flows")
                    self.lock.unlock()
                    completionHandler?(try JSONSerialization.data(withJSONObject:["ok":true,"session_id":expected]))
                } else { throw Bridge.error("Unsupported provider command") }
            } catch {
                completionHandler?(try? JSONSerialization.data(withJSONObject:["ok":false,"error":error.localizedDescription]))
            }
        }
    }

}

private final class TCPRelay {
    private let id: UUID
    private let flow: NEAppProxyTCPFlow
    private let nativeSession: UInt64
    private let flowJSON: String
    private let idleSeconds: Double
    private let completion: ([String: Any]) -> Void
    private let up = DispatchQueue(label: "FlowBridge.relay.upload", qos: .utility)
    private let down = DispatchQueue(label: "FlowBridge.relay.download", qos: .utility)
    private let lock = NSLock()
    private var handle: UInt64 = 0
    private var closed = false
    private var uploadEOF = false
    private var downloadEOF = false
    private var lastActivity = ProcessInfo.processInfo.systemUptime
    private var timer: DispatchSourceTimer?
    private var row: [String: Any]

    init(id: UUID, flow: NEAppProxyTCPFlow, nativeSession: UInt64, flowJSON: String, idleSeconds: Double,
         host: String, port: Int, application: String, route: String, completion: @escaping ([String: Any]) -> Void) {
        self.id = id; self.flow = flow; self.nativeSession = nativeSession; self.flowJSON = flowJSON
        self.idleSeconds = idleSeconds; self.completion = completion
        row = ["id": id.uuidString, "host": host, "port": port, "application": application.isEmpty ? "unknown" : application,
               "action": route, "state": "connecting", "bytes_up": UInt64(0), "bytes_down": UInt64(0)]
    }
    func snapshot() -> [String: Any] { lock.lock(); defer { lock.unlock() }; return row }
    private func stream() -> UInt64 { lock.lock(); defer { lock.unlock() }; return closed ? 0 : handle }
    func start() {
        up.async {
            do {
                let response = try self.flowJSON.withCString { f in try Bridge.consume(fb_native_stream_open_json(self.nativeSession, f)) }
                guard let number = response["stream_id"] as? NSNumber else { throw Bridge.error("No stream handle") }
                let handle = number.uint64Value
                self.lock.lock()
                if self.closed { self.lock.unlock(); fb_stream_close(handle); return }
                self.handle = handle; self.row["state"] = "active"; self.lastActivity = ProcessInfo.processInfo.systemUptime
                self.lock.unlock()
                self.flow.open(withLocalEndpoint: nil) { error in
                    if let error { self.cancel(error); return }
                    guard self.stream() != 0 else { return }
                    self.beginTimer(); self.readUpload(); self.readDownload()
                }
            } catch { self.cancel(error) }
        }
    }
    private func beginTimer() {
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        timer.schedule(deadline: .now() + 1, repeating: 1)
        timer.setEventHandler { [weak self] in
            guard let self else { return }; self.lock.lock()
            let expired = !self.closed && ProcessInfo.processInfo.systemUptime - self.lastActivity > self.idleSeconds
            self.lock.unlock(); if expired { self.cancel(Bridge.error("Idle timeout")) }
        }
        lock.lock(); if closed { lock.unlock(); timer.resume(); timer.cancel(); return }
        self.timer = timer; timer.resume(); lock.unlock()
    }
    private func progress(_ count: Int, key: String) {
        lock.lock(); row[key] = (row[key] as? UInt64 ?? 0) + UInt64(count)
        lastActivity = ProcessInfo.processInfo.systemUptime; lock.unlock()
    }
    private func readUpload() {
        guard stream() != 0 else { return }
        flow.readData { data, error in
            if let error { self.cancel(error); return }
            guard let data else { self.cancel(Bridge.error("Missing flow data")); return }
            // NE controls read chunk size. Reject an oversized delivered chunk;
            // never enqueue an unbounded series of buffers or concurrent reads.
            guard data.count <= 1_048_576 else { self.cancel(Bridge.error("Flow read exceeds 1 MiB buffer limit")); return }
            self.writeUpload(data, offset: 0)
        }
    }
    private func writeUpload(_ data: Data, offset initialOffset: Int) {
        up.async {
            let handle = self.stream(); guard handle != 0 else { return }
            if data.isEmpty {
                let status = fb_stream_shutdown_write(handle)
                if status < 0 { self.cancel(Bridge.error("Stream half-close failed")); return }
                self.flow.closeReadWithError(nil); self.eof(upload: true); return
            }
            var offset = initialOffset
            while offset < data.count {
                guard self.stream() != 0 else { return }
                let count = data.withUnsafeBytes { raw in
                    fb_stream_write(handle, raw.baseAddress!.assumingMemoryBound(to: UInt8.self).advanced(by: offset), min(65536, data.count - offset))
                }
                if count == -2 {
                    // Release the worker between bounded timeouts; do not monopolize
                    // GCD's thread pool while another flow needs a writer.
                    let retryOffset = offset
                    self.up.asyncAfter(deadline: .now() + .milliseconds(10)) { self.writeUpload(data, offset: retryOffset) }
                    return
                }
                guard count > 0 else { self.cancel(Bridge.error("Upstream write failed")); return }
                offset += Int(count); self.progress(Int(count), key: "bytes_up")
            }
            self.readUpload()
        }
    }

    private func readDownload() {
        down.async {
            var buffer = [UInt8](repeating: 0, count: 65536)
            while true {
                let handle = self.stream(); guard handle != 0 else { return }
                let count = buffer.withUnsafeMutableBufferPointer { fb_stream_read(handle, $0.baseAddress, $0.count) }
                if count == -2 {
                    self.down.asyncAfter(deadline: .now() + .milliseconds(10)) { self.readDownload() }
                    return
                }
                if count == 0 { self.flow.closeWriteWithError(nil); self.eof(upload: false); return }
                guard count > 0 else { self.cancel(Bridge.error("Upstream read failed")); return }
                let data = Data(buffer.prefix(Int(count)))
                self.flow.write(data) { error in
                    if let error { self.cancel(error); return }
                    self.progress(data.count, key: "bytes_down"); self.readDownload()
                }
                return // only the write completion schedules the next read
            }
        }
    }
    private func eof(upload: Bool) {
        lock.lock(); if upload { uploadEOF = true } else { downloadEOF = true }
        let finished = uploadEOF && downloadEOF; lock.unlock()
        if finished { cancel(nil) }
    }
    func cancel(_ error: Error?) {
        lock.lock(); guard !closed else { lock.unlock(); return }
        closed = true; let handle = self.handle; self.handle = 0
        let timer = self.timer; self.timer = nil
        row["state"] = error == nil ? "completed" : "failed"
        if let error { row["error"] = error.localizedDescription }
        let result = row; lock.unlock()
        timer?.cancel(); flow.closeReadWithError(error); flow.closeWriteWithError(error)
        // A third queue wakes both directions even if either worker is in I/O.
        DispatchQueue.global(qos: .utility).async { if handle != 0 { fb_stream_close(handle) } }
        completion(result)
    }
}
