// Compile the REAL EngineController + Rust FFI on macOS. No system extension,
// production profile, SSH credentials or remote destination is used.
import Foundation
import Darwin

private func require(_ condition: Bool, _ message: String) throws {
    if !condition { throw Bridge.error(message) }
}
private func until(_ predicate: () -> Bool) throws {
    let deadline = Date().addingTimeInterval(10)
    while !predicate() {
        try require(Date() < deadline, "Controller completion timed out")
        _ = RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.01))
    }
}
private final class Listener {
    let fd: Int32
    let port: Int
    init() throws {
        let socketFD = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        try require(socketFD >= 0, "socket")
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(socketFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if bound != 0 || Darwin.listen(socketFD, 8) != 0 {
            Darwin.close(socketFD); throw Bridge.error("bind/listen")
        }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let result = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.getsockname(socketFD, $0, &length)
            }
        }
        if result != 0 { Darwin.close(socketFD); throw Bridge.error("getsockname") }
        fd = socketFD
        port = Int(UInt16(bigEndian: address.sin_port))
    }
    deinit { Darwin.close(fd) }
}
private func profile(ingress: Int, upstream: Int) throws -> String {
    var object = try JSONSerialization.jsonObject(with: Data(Bridge.initial.utf8)) as! [String: Any]
    object["listen"] = "127.0.0.1:\(ingress)"
    object["rules"] = [] // no DIRECT exception may mask the fail-closed test
    object["proxies"] = [["id":"ssh", "kind":"socks5", "endpoint":["host":"127.0.0.1", "port":upstream]]]
    return try Bridge.text(object)
}
private func execute(_ controller: EngineController, _ operation: String, success: Bool = true) throws {
    var completed: Bool?
    controller.execute(operation) { completed = $0 }
    try until { completed != nil }
    try require(completed == success, "\(operation): \(controller.message)")
}
@main
private struct NativeEnginePoolLifecycle {
    static func main() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("FlowBridge-controller-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let reservations = try (0..<4).map { _ in try Listener() }
        var ingressReservation: Listener? = try Listener()
        let ingress = ingressReservation!.port
        ingressReservation = nil
        let engine = EngineController(profileURL: root.appendingPathComponent("profile.json"))
        var handles: [UInt64] = []
        defer {
            try? execute(engine, "stop")
            for id in handles { fb_ssh_destroy(id) }
        }
        for reservation in reservations {
            let text = try Bridge.text(["host":"qa.invalid", "user":"qa", "local_port":reservation.port])
            let created = try text.withCString { try Bridge.consume(fb_ssh_create_json($0)) }
            handles.append((created["ssh_id"] as! NSNumber).uint64Value)
        }
        // A cached gate is intentionally set before each pool, exactly as the
        // DesktopController start path does. No default budget may survive it.
        for count in [1,2,4,3,2,1] {
            engine.config = try profile(ingress: ingress, upstream: reservations[0].port)
            engine.setUpstreamGate(port: reservations[0].port, ready: false)
            if count > 1 { engine.setUpstreamPool(sshIDs: Array(handles.prefix(count))) }
            try execute(engine, "start")
            try require(engine.running, "start did not bind actual SOCKS listener")
            if count > 1 {
                let pool = engine.snapshot["managed_pool"] as? [String: Any]
                let workers = pool?["workers"] as? [[String: Any]]
                try require(workers?.count == count, "pool missing after stopped engine restart")
                try require((pool?["ready_workers"] as? NSNumber)?.intValue == 0, "stopped children reported ready")
                for worker in workers ?? [] {
                    let admission = worker["admission"] as? [String: Any]
                    let limits = admission?["limits"] as? [String: Any]
                    try require((limits?["max_flows"] as? NSNumber)?.intValue == 128/count, "wrong live budget")
                }
            }
            try execute(engine, "stop")
            try require(!engine.running, "stop left engine running")
            try require(engine.snapshot["managed_pool"] is NSNull, "stop retained old pool budget")
        }
        // Existing handle + changed PRIMARY endpoint must apply only after the
        // new profile is loaded, not to the prior stopped engine's config.
        engine.config = try profile(ingress: ingress, upstream: reservations[1].port)
        engine.setUpstreamGate(port: reservations[1].port, ready: false)
        engine.setUpstreamPool(sshIDs: [handles[1],handles[2]])
        try execute(engine, "start")
        try execute(engine, "stop")
        let destroyed = handles.removeLast()
        fb_ssh_destroy(destroyed)
        engine.setUpstreamPool(sshIDs: [handles[1],destroyed])
        try execute(engine, "start", success: false)
        try require(!engine.running, "invalid owned pool still started a healthy listener")
        // Invalid refresh while running must also stop routing, not leave a
        // cached healthy pool active behind an error message.
        engine.setUpstreamPool(sshIDs: [handles[1],handles[2]])
        try execute(engine, "start")
        engine.setUpstreamPool(sshIDs: [handles[1],destroyed])
        try until { !engine.running }
        try require(engine.message.contains("Маршрут остановлен"), "refresh error did not stop route")
        let evidence: [String: Any] = [
            "passed":true, "actual_swift_controller":true, "actual_rust_ffi":true,
            "worker_count_transitions":[1,2,4,3,2,1], "changed_primary_restart":true,
            "stale_start_rejected":true, "stale_live_refresh_stops_engine":true,
            "native_network_extension_activated":false, "real_ssh_processes":false
        ]
        print(try Bridge.text(evidence))
    }
}
