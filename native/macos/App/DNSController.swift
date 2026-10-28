import Foundation
#if FLOWBRIDGE_NATIVE
import NetworkExtension

/// Main-thread serialized preference writes; never replace another DNS provider.
final class DNSController {
    private let identifier: String
    private var operations: [(@escaping () -> Void) -> Void] = []
    private var running = false
    init(identifier: String) { self.identifier = identifier }
    func enable(session: String, completion: @escaping (Error?) -> Void) {
        change(enabled: true, session: session, completion: completion)
    }
    func disable(completion: @escaping (Error?) -> Void) {
        change(enabled: false, session: nil, completion: completion)
    }
    private func change(enabled: Bool, session: String?, completion: @escaping (Error?) -> Void) {
        precondition(Thread.isMainThread)
        operations.append { finish in
            let manager = NEDNSProxyManager.shared()
            manager.loadFromPreferences { error in
                DispatchQueue.main.async {
                    func complete(_ error: Error?) { completion(error); finish() }
                    if let error { complete(error); return }
                    if let owner = manager.providerProtocol?.providerBundleIdentifier,
                       owner != self.identifier {
                        if enabled { complete(Bridge.error("Настроен другой DNS-провайдер. FlowBridge не будет заменять его настройки.")) }
                        else { complete(nil) }
                        return
                    }
                    if !enabled && manager.providerProtocol == nil { complete(nil); return }
                    if enabled {
                        guard let session, !session.isEmpty else { complete(Bridge.error("DNS session is missing")); return }
                        let proto = NEDNSProxyProviderProtocol()
                        proto.providerBundleIdentifier = self.identifier
                        proto.providerConfiguration = ["session_id":session]
                        manager.providerProtocol = proto
                        manager.localizedDescription = "FlowBridge: DNS через SSH"
                    }
                    manager.isEnabled = enabled
                    manager.saveToPreferences { error in
                        DispatchQueue.main.async {
                            if let error { complete(error); return }
                            manager.loadFromPreferences { error in
                                DispatchQueue.main.async {
                                    if let error { complete(error) }
                                    else if manager.isEnabled != enabled {
                                        complete(Bridge.error("macOS did not confirm the requested DNS configuration"))
                                    } else { complete(nil) }
                                }
                            }
                        }
                    }
                }
            }
        }
        next()
    }
    private func next() {
        guard !running, !operations.isEmpty else { return }
        running = true
        let operation = operations.removeFirst()
        operation { self.running = false; self.next() }
    }
}
#endif
