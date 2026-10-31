import Foundation
import NetworkExtension

/// Standard UDP/TCP DNS captured by macOS. Never returns DIRECT on failure.
/// Encrypted app-owned DoH/DoT is explicitly outside this provider's coverage.
final class DNSProxyProvider: NEDNSProxyProvider {
    private let lock = NSLock()
    private var token = ""
    private var running = false
    private var flows: [UUID: DNSFlow] = [:]
    private let work: OperationQueue = {
        let queue = OperationQueue(); queue.name = "FlowBridge.DNS.work"
        queue.maxConcurrentOperationCount = 16; return queue
    }()
    override func startProxy(options: [String: Any]?, completionHandler: @escaping (Error?) -> Void) {
        guard let id = options?["session_id"] as? String,
              !id.isEmpty, SharedNativeSession.shared.attach(id: id) else {
            completionHandler(Bridge.error("DNS requires the matching active native SSH session")); return
        }
        lock.lock(); token = id; running = true; lock.unlock()
        completionHandler(nil)
    }
    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        lock.lock(); running = false; let id = token; token = ""
        let pending = Array(flows.values); flows.removeAll(); lock.unlock()
        SharedNativeSession.shared.detach(id: id)
        pending.forEach { $0.cancel() }; completionHandler()
    }
    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        lock.lock()
        guard running, flows.count < 64,
              SharedNativeSession.shared.context(id: token) != nil,
              flow is NEAppProxyUDPFlow || flow is NEAppProxyTCPFlow else {
            lock.unlock()
            let error = Bridge.error("DNS unavailable or capacity exhausted; no local fallback")
            flow.closeReadWithError(error); flow.closeWriteWithError(error)
            return true
        }
        let id = UUID()
        let relay = DNSFlow(flow: flow, token: token, workers: work) { [weak self] in
            guard let self else { return }
            self.lock.lock(); self.flows.removeValue(forKey: id); self.lock.unlock()
        }
        flows[id] = relay; lock.unlock()
        relay.start(); return true
    }
}

private final class DNSFlow {
    private let flow: NEAppProxyFlow
    private let token: String
    private let workers: OperationQueue
    private let done: () -> Void
    private let queue = DispatchQueue(label: "FlowBridge.DNS.flow")
    private var closed = false
    private var input = Data()
    private var queries = 0
    init(flow: NEAppProxyFlow, token: String, workers: OperationQueue, done: @escaping () -> Void) {
        self.flow = flow; self.token = token; self.workers = workers; self.done = done
    }
    func start() {
        queue.async {
            self.flow.open(withLocalEndpoint: nil) { error in
                self.queue.async {
                    guard !self.closed else { return }
                    if let error { self.finish(error); return }
                    if let udp = self.flow as? NEAppProxyUDPFlow { self.readUDP(udp) }
                    else if let tcp = self.flow as? NEAppProxyTCPFlow { self.readTCP(tcp) }
                    else { self.finish(Bridge.error("Unsupported DNS flow")) }
                }
            }
            // Bounds open callbacks, idle clients, pending work and TCP reuse.
            self.queue.asyncAfter(deadline: .now() + 30) {
                self.finish(Bridge.error("DNS flow deadline reached"))
            }
        }
    }
    func cancel() { queue.async { self.finish(Bridge.error("DNS stopped")) } }
    private func finish(_ error: Error?) {
        guard !closed else { return }; closed = true; input.removeAll()
        flow.closeReadWithError(error); flow.closeWriteWithError(error); done()
    }
    private func resolve(_ packet: Data, udp: Bool, completion: @escaping (Data?) -> Void) {
        guard !closed, (12...4096).contains(packet.count), queries < 64 else {
            finish(Bridge.error("Invalid or excessive DNS queries")); completion(nil); return
        }
        queries += 1
        workers.addOperation { [weak self] in
            guard let self else { return }
            let result: Result<Data, Error>
            do {
                guard let handle = SharedNativeSession.shared.context(id: self.token) else {
                    throw Bridge.error("Native DNS session expired")
                }
                let request = try Bridge.text(["query":Array(packet), "udp":udp, "reply_on_failure":true])
                let value = try request.withCString { try Bridge.consume(fb_native_dns_exchange_json(handle, $0)) }
                guard let bytes = value["response"] as? [UInt8] else { throw Bridge.error("DNS response missing") }
                result = .success(Data(bytes))
            } catch { result = .failure(error) }
            self.queue.async {
                guard !self.closed else { return }
                switch result {
                case .success(let answer): completion(answer)
                case .failure(let error): self.finish(error); completion(nil)
                }
            }
        }
    }
    private func readUDP(_ udp: NEAppProxyUDPFlow) {
        guard !closed else { return }
        udp.readDatagrams { packets, endpoints, error in
            self.queue.async {
                guard !self.closed else { return }
                if let error { self.finish(error); return }
                guard let packets, let endpoints, packets.count == endpoints.count,
                      !packets.isEmpty, packets.count <= 32,
                      packets.allSatisfy({ (12...4096).contains($0.count) }) else {
                    self.finish(Bridge.error("Invalid DNS datagram batch")); return
                }
                // Retain the exact NE endpoint objects returned with each query.
                // Do not reconstruct endpoints; replies must preserve their identity.
                self.replyUDP(udp, packets: packets, endpoints: endpoints, index: 0)
            }
        }
    }
    private func replyUDP(_ udp: NEAppProxyUDPFlow, packets: [Data], endpoints: [NWEndpoint], index: Int) {
        guard !closed else { return }
        guard index < packets.count else { readUDP(udp); return }
        resolve(packets[index], udp: true) { answer in
            guard let answer, !self.closed else { return }
            udp.writeDatagrams([answer], sentBy: [endpoints[index]]) { error in
                self.queue.async {
                    guard !self.closed else { return }
                    if let error { self.finish(error) }
                    else { self.replyUDP(udp, packets: packets, endpoints: endpoints, index: index + 1) }
                }
            }
        }
    }
    private func readTCP(_ tcp: NEAppProxyTCPFlow) {
        guard !closed else { return }
        if input.count >= 2 {
            let size = Int(input[input.startIndex]) * 256 + Int(input[input.startIndex + 1])
            guard (12...4096).contains(size) else { finish(Bridge.error("Invalid DNS TCP frame")); return }
            if input.count >= size + 2 {
                let packet = Data(input.dropFirst(2).prefix(size)); input.removeFirst(size + 2)
                resolve(packet, udp: false) { answer in
                    guard let answer, !self.closed else { return }
                    var framed = Data([UInt8(answer.count >> 8), UInt8(answer.count & 255)])
                    framed.append(answer)
                    tcp.write(framed) { error in
                        self.queue.async {
                            guard !self.closed else { return }
                            if let error { self.finish(error) } else { self.readTCP(tcp) }
                        }
                    }
                }
                return
            }
        }
        tcp.readData { data, error in
            self.queue.async {
                guard !self.closed else { return }
                if let error { self.finish(error); return }
                guard let data, !data.isEmpty else { self.finish(nil); return }
                guard data.count <= 65536, self.input.count + data.count <= 69632 else {
                    self.finish(Bridge.error("DNS TCP input exceeds bounded buffer")); return
                }
                self.input.append(data); self.readTCP(tcp)
            }
        }
    }
}
