import Foundation

/// Serializes asynchronous apply/clear operations, not merely their submission.
/// NetworkExtension completions can be asynchronous; a serial DispatchQueue alone
/// does not prevent a later clear from racing an earlier settings apply.
final class ProviderLifecycleQueue {
    typealias Operation = (@escaping () -> Void) -> Void
    private let queue = DispatchQueue(label: "FlowBridge.provider.lifecycle")
    private var pending: [Operation] = []
    private var active: UUID?

    func enqueue(_ operation: @escaping Operation) {
        queue.async {
            self.pending.append(operation)
            self.startNext()
        }
    }

    private func startNext() {
        guard active == nil, !pending.isEmpty else { return }
        let token = UUID()
        active = token
        let operation = pending.removeFirst()
        operation { [weak self] in
            guard let owner = self else { return }
            owner.queue.async {
                // A duplicate completion must not finish the next operation.
                guard owner.active == token else { return }
                owner.active = nil
                owner.startNext()
            }
        }
    }
}
