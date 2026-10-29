import Foundation

/// Providers in this signed System Extension share one process, not an IPC socket.
/// A UUID lease prevents a DNS provider from attaching to a stale capture session.
final class SharedNativeSession {
    static let shared = SharedNativeSession()
    private let lock = NSLock()
    private var identifier = ""
    private var handle: UInt64 = 0
    private var dnsEnabled = false
    private var dnsAttached = false
    func publish(id: String, handle: UInt64, dns: Bool) {
        lock.lock(); defer { lock.unlock() }
        identifier = id; self.handle = handle; dnsEnabled = dns; dnsAttached = false
    }
    func revoke(handle: UInt64) {
        lock.lock(); defer { lock.unlock() }
        guard self.handle == handle else { return }
        self.handle = 0; identifier = ""; dnsEnabled = false; dnsAttached = false
    }
    func attach(id: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard identifier == id, handle != 0, dnsEnabled else { return false }
        dnsAttached = true; return true
    }
    func detach(id: String) {
        lock.lock(); defer { lock.unlock() }
        if identifier == id { dnsAttached = false }
    }
    func context(id: String) -> UInt64? {
        lock.lock(); defer { lock.unlock() }
        return identifier == id && dnsEnabled && dnsAttached && handle != 0 ? handle : nil
    }
    func snapshot(handle: UInt64) -> [String: Any] {
        lock.lock(); defer { lock.unlock() }
        let matching = self.handle == handle && handle != 0
        return ["enabled":matching && dnsEnabled, "active":matching && dnsAttached,
                "scope":"system_standard_dns", "encrypted_dns_intercepted":false]
    }
}
