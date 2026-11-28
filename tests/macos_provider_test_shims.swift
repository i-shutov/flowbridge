// Test-only Apple/FFI substitutes. No Network Extension, driver or network is used.
import Foundation
#if os(Linux)
import Glibc
#else
import Darwin
#endif

final class TestRuntime {
    static let shared = TestRuntime()
    private let lock = NSLock()
    private var sequence: UInt64 = 100
    private var destroyed: [UInt64] = []
    var beforeEvaluate: (() -> Void)?
    var beforeReload: (() -> Void)?
    var rejectReload = false
    var beforeCreate: (() -> Void)?
    var action = "proxy"
    var zeroHandle = false
    func reset() { lock.lock(); destroyed = []; sequence = 100; lock.unlock(); beforeEvaluate = nil; beforeReload = nil; rejectReload = false; beforeCreate = nil; action = "proxy"; zeroHandle = false }
    func create() -> UInt64 { beforeCreate?(); if zeroHandle { return 0 }; lock.lock(); defer { lock.unlock() }; sequence += 1; return sequence }
    func destroy(_ id: UInt64) { lock.lock(); destroyed.append(id); lock.unlock() }
    func destructionCount(_ id: UInt64) -> Int { lock.lock(); defer { lock.unlock() }; return destroyed.filter { $0 == id }.count }
}
class NWEndpoint {}
class NWHostEndpoint: NWEndpoint {
    let hostname: String
    let port: String
    init(hostname: String, port: String) { self.hostname = hostname; self.port = port }
}
class NENetworkRule {
    enum IPProtocol { case TCP }
    enum Direction { case outbound }
    init(remoteNetwork: NWHostEndpoint, remotePrefix: Int, localNetwork: NWHostEndpoint?, localPrefix: Int,
         protocol: IPProtocol, direction: Direction) {}
}
class NETransparentProxyNetworkSettings {
    var includedNetworkRules: [NENetworkRule] = []
    var excludedNetworkRules: [NENetworkRule] = []
    init(tunnelRemoteAddress: String) {}
}
class NETunnelProviderProtocol { var providerConfiguration: [String: Any]? }
enum NEProviderStopReason { case userInitiated }
struct FlowMetadata { var sourceAppSigningIdentifier = "test.application" }
class NEAppProxyFlow {
    var metaData = FlowMetadata()
    private(set) var readError: Error?
    private(set) var writeError: Error?
    func closeReadWithError(_ error: Error?) { readError = error }
    func closeWriteWithError(_ error: Error?) { writeError = error }
    func open(withLocalEndpoint: NWEndpoint?, completionHandler: (Error?) -> Void) { completionHandler(nil) }
}
class NEAppProxyTCPFlow: NEAppProxyFlow {
    var remoteEndpoint: NWEndpoint = NWHostEndpoint(hostname: "203.0.113.20", port: "443")
    func readData(completionHandler: (Data?, Error?) -> Void) { completionHandler(Data(), nil) }
    func write(_ data: Data, completionHandler: (Error?) -> Void) { completionHandler(nil) }
}
class NEAppProxyUDPFlow: NEAppProxyFlow {}
class NETransparentProxyProvider {
    var protocolConfiguration: Any = NETunnelProviderProtocol()
    var settingsHook: ((NETransparentProxyNetworkSettings?, @escaping (Error?) -> Void) -> Void)?
    func setTunnelNetworkSettings(_ settings: NETransparentProxyNetworkSettings?, completionHandler: @escaping (Error?) -> Void) {
        if let hook = settingsHook { hook(settings, completionHandler) } else { completionHandler(nil) }
    }
    func startProxy(options: [String: Any]?, completionHandler: @escaping (Error?) -> Void) {}
    func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {}
    func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool { false }
    func handleNewUDPFlow(_ flow: NEAppProxyUDPFlow, initialRemoteEndpoint remoteEndpoint: NWEndpoint) -> Bool { false }
    func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {}
}
enum Bridge {
    static func error(_ text: String) -> NSError { NSError(domain: "FlowBridgeTests", code: 1, userInfo: [NSLocalizedDescriptionKey: text]) }
    static func validate(_ source: String) throws { _ = try JSONSerialization.jsonObject(with: Data(source.utf8)) }
    static func text(_ object: Any) throws -> String { String(data: try JSONSerialization.data(withJSONObject: object, options: .sortedKeys), encoding: .utf8)! }
    static func consume(_ value: [String: Any]) throws -> [String: Any] {
        if value["ok"] as? Bool == false { throw error(value["error"] as? String ?? "Simulated FFI error") }
        return value
    }
}
func fb_native_create_json(_ config: UnsafePointer<CChar>, _ options: UnsafePointer<CChar>) -> [String: Any] { ["session_id": NSNumber(value: TestRuntime.shared.create())] }
func fb_native_destroy(_ handle: UInt64) { TestRuntime.shared.destroy(handle) }
func fb_evaluate_json(_ config: UnsafePointer<CChar>, _ flow: UnsafePointer<CChar>) -> [String: Any] {
    let action = TestRuntime.shared.action
    TestRuntime.shared.beforeEvaluate?()
    return ["decision": ["action": ["type": action, "id": "proxy"]]]
}
func fb_native_snapshot_json(_ handle: UInt64) -> [String: Any] { ["status": ["test_handle": handle]] }
func fb_native_set_gate_json(_ handle: UInt64, _ gate: UnsafePointer<CChar>) -> [String: Any] { [:] }
func fb_native_reload_json(_ handle: UInt64, _ profile: UnsafePointer<CChar>) -> [String: Any] {
    TestRuntime.shared.beforeReload?()
    if TestRuntime.shared.rejectReload { return ["ok": false, "error": "Injected native reload rejection"] }
    return ["ok": true]
}
func fb_native_stream_open_json(_ handle: UInt64, _ flow: UnsafePointer<CChar>) -> [String: Any] { ["stream_id": NSNumber(value: handle + 1000)] }
func fb_stream_close(_ handle: UInt64) {}
func fb_stream_shutdown_write(_ handle: UInt64) -> Int { 0 }
func fb_stream_write(_ handle: UInt64, _ bytes: UnsafePointer<UInt8>, _ count: Int) -> Int { count }
func fb_stream_read(_ handle: UInt64, _ bytes: UnsafeMutablePointer<UInt8>?, _ count: Int) -> Int { 0 }
