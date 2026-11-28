// Deterministic interleavings against the real provider body, with test-only OS/FFI shims.
import Foundation

struct Failure: Error { let text: String }
func expect(_ value: @autoclosure () throws -> Bool, _ message: String) throws { if try !value() { throw Failure(text: message) } }
func wait(_ semaphore: DispatchSemaphore, _ message: String) throws {
    try expect(semaphore.wait(timeout: .now() + 5) == .success, message)
}
final class SettingsProbe {
    private let lock = NSLock()
    private var calls: [(Bool, (Error?) -> Void)] = []
    private let arrived = DispatchSemaphore(value: 0)
    func call(_ settings: NETransparentProxyNetworkSettings?, _ completion: @escaping (Error?) -> Void) {
        lock.lock(); calls.append((settings != nil, completion)); lock.unlock(); arrived.signal()
    }
    func next() throws -> (Bool, (Error?) -> Void) {
        try wait(arrived, "settings operation did not arrive")
        lock.lock(); defer { lock.unlock() }; return calls.removeFirst()
    }
    var count: Int { lock.lock(); defer { lock.unlock() }; return calls.count }
}
final class Completion {
    private let lock = NSLock()
    private var errors: [Error?] = []
    let done = DispatchSemaphore(value: 0)
    func call(_ error: Error?) { lock.lock(); errors.append(error); lock.unlock(); done.signal() }
    var succeeded: Bool { lock.lock(); defer { lock.unlock() }; return errors.count == 1 && errors[0] == nil }
    var failed: Bool { lock.lock(); defer { lock.unlock() }; return errors.count == 1 && errors[0] != nil }
    var count: Int { lock.lock(); defer { lock.unlock() }; return errors.count }
}
func provider(_ probe: SettingsProbe) throws -> TransparentProxyProvider {
    let p = TransparentProxyProvider()
    let config = NETunnelProviderProtocol()
    config.providerConfiguration = ["profile": try Bridge.text(["proxies": [], "max_connections": 128]), "capturePorts": [443], "remoteDNS": [:]]
    p.protocolConfiguration = config
    p.settingsHook = { settings, completion in probe.call(settings, completion) }
    return p
}
func snapshot(_ p: TransparentProxyProvider) throws -> [String: Any] {
    let done = DispatchSemaphore(value: 0)
    var result: [String: Any] = [:]
    p.handleAppMessage(Data("snapshot".utf8)) { data in
        if let data, let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] { result = dict }
        done.signal()
    }
    try wait(done, "snapshot timed out"); return result
}
func start(_ p: TransparentProxyProvider, _ probe: SettingsProbe) throws -> Completion {
    let completion = Completion(); p.startProxy(options: nil, completionHandler: completion.call)
    let (isApply, callback) = try probe.next(); try expect(isApply, "expected apply")
    callback(nil); try wait(completion.done, "start callback missing")
    try expect(completion.succeeded, "start failed")
    return completion
}
func stop(_ p: TransparentProxyProvider, _ probe: SettingsProbe, error: Error? = nil) throws {
    let done = DispatchSemaphore(value: 0)
    p.stopProxy(with: .userInitiated) { done.signal() }
    let (isApply, callback) = try probe.next(); try expect(!isApply, "expected clear")
    callback(error); try wait(done, "stop completion missing")
}
func duplicateStart() throws {
    let probe = SettingsProbe(); let p = try provider(probe)
    _ = try start(p, probe)
    let second = Completion(); p.startProxy(options: nil, completionHandler: second.call)
    // Rejection must be immediate; no settings operation must begin.
    try wait(second.done, "duplicate start did not reject")
    try expect(second.failed, "duplicate start accepted")
    try expect(probe.count == 0, "duplicate start changed OS settings")
    try expect((try snapshot(p))["ready"] as? Bool == true, "duplicate start damaged current ready")
    try stop(p, probe)
}
func cancelPendingStart() throws {
    let probe = SettingsProbe(); let p = try provider(probe)
    let begun = Completion(); p.startProxy(options: nil, completionHandler: begun.call)
    let (apply, oldCallback) = try probe.next(); try expect(apply, "apply missing")
    let stopped = DispatchSemaphore(value: 0)
    p.stopProxy(with: .userInitiated) { stopped.signal() }
    oldCallback(nil)
    try wait(begun.done, "cancelled start completion missing")
    try expect(begun.failed, "cancelled start succeeded")
    let (clear, callback) = try probe.next(); try expect(!clear, "clear missing")
    callback(nil); try wait(stopped, "stop completion missing")
    try expect(TestRuntime.shared.destructionCount(101) == 1, "native handle destroyed more than once")
    try expect((try snapshot(p))["ready"] as? Bool == false, "cancelled provider ready")
}
func restartDuringClear() throws {
    let probe = SettingsProbe(); let p = try provider(probe)
    _ = try start(p, probe)
    let done = DispatchSemaphore(value: 0); p.stopProxy(with: .userInitiated) { done.signal() }
    let (isApply, clear) = try probe.next(); try expect(!isApply, "clear missing")
    let early = Completion(); p.startProxy(options: nil, completionHandler: early.call)
    try wait(early.done, "restart during clear did not reject")
    try expect(early.failed, "restart accepted before clear")
    clear(nil); try wait(done, "stop completion missing")
    _ = try start(p, probe)
    try expect((try snapshot(p))["ready"] as? Bool == true, "fresh restart not ready")
    try stop(p, probe)
}
func staleDirectDecision() throws {
    let probe = SettingsProbe(); let p = try provider(probe)
    _ = try start(p, probe)
    TestRuntime.shared.action = "direct"
    TestRuntime.shared.beforeEvaluate = { p.stopProxy(with: .userInitiated) {} }
    let flow = NEAppProxyTCPFlow()
    let handled = p.handleNewFlow(flow)
    TestRuntime.shared.beforeEvaluate = nil
    try expect(handled, "stale decision released flow DIRECT after stop")
    try expect(flow.readError != nil && flow.writeError != nil, "stale flow not rejected")
    let (_, clear) = try probe.next(); clear(nil)
}

func normalLifecycleAndDNS() throws {
    let probe = SettingsProbe(); let p = try provider(probe)
    _ = try start(p, probe)
    let state = try snapshot(p)
    try expect(state["ready"] as? Bool == true, "normal start not ready")
    let token = state["session_id"] as? String ?? ""
    try expect(!token.isEmpty && SharedNativeSession.shared.attach(id: token), "DNS lease not published")
    try expect(SharedNativeSession.shared.context(id: token) == 101, "DNS lease wrong handle")
    try stop(p, probe)
    try expect(SharedNativeSession.shared.context(id: token) == nil, "DNS lease survived stop")
    try expect(TestRuntime.shared.destructionCount(101) == 1, "normal stop destroy count")
    try expect(TestRuntime.shared.destructionCount(0) == 0, "zero handle was destroyed")
}
func duplicatePendingStart() throws {
    let probe = SettingsProbe(); let p = try provider(probe)
    let original = Completion(); p.startProxy(options: nil, completionHandler: original.call)
    let (_, apply) = try probe.next()
    let other = Completion(); p.startProxy(options: nil, completionHandler: other.call)
    try wait(other.done, "duplicate pending start did not reject")
    try expect(other.failed && probe.count == 0, "pending duplicate created settings")
    apply(nil); try wait(original.done, "original pending completion missing")
    try expect(original.succeeded, "original pending start was damaged")
    try stop(p, probe)
}
func cancelDuringCreation() throws {
    let probe = SettingsProbe(); let p = try provider(probe)
    let stopped = DispatchSemaphore(value: 0)
    TestRuntime.shared.beforeCreate = { p.stopProxy(with: .userInitiated) { stopped.signal() } }
    let started = Completion(); p.startProxy(options: nil, completionHandler: started.call)
    try wait(started.done, "creation cancellation missing start completion")
    try expect(started.failed, "cancelled creation accepted")
    let (isApply, clear) = try probe.next()
    try expect(!isApply, "cancelled creation applied settings")
    clear(nil); try wait(stopped, "cancel during create missed stop")
    try expect(TestRuntime.shared.destructionCount(101) == 1, "unpublished created handle leaked or destroyed twice")
}
func clearWaitsForApply() throws {
    let probe = SettingsProbe(); let p = try provider(probe)
    let started = Completion(); p.startProxy(options: nil, completionHandler: started.call)
    let (_, apply) = try probe.next()
    let stopped = DispatchSemaphore(value: 0); p.stopProxy(with: .userInitiated) { stopped.signal() }
    // The clear is asynchronous in the fix. Give an incorrectly unsequenced
    // implementation time to submit it; this is a bounded negative wait.
    Thread.sleep(forTimeInterval: 0.05)
    try expect(probe.count == 0, "settings clear raced outstanding apply")
    apply(nil); try wait(started.done, "cancelled apply completion missing")
    let (isApply, clear) = try probe.next(); try expect(!isApply, "expected queued clear")
    clear(nil); try wait(stopped, "queued clear never finished stop")
}
func duplicateStopCoalesces() throws {
    let probe = SettingsProbe(); let p = try provider(probe)
    _ = try start(p, probe)
    let first = DispatchSemaphore(value: 0); let second = DispatchSemaphore(value: 0)
    p.stopProxy(with: .userInitiated) { first.signal() }
    let (_, clear) = try probe.next()
    p.stopProxy(with: .userInitiated) { second.signal() }
    try expect(probe.count == 0, "duplicate stop submitted another clear")
    clear(nil); try wait(first, "first stop callback missing"); try wait(second, "second stop callback missing")
    try expect(TestRuntime.shared.destructionCount(101) == 1, "duplicate stop destroyed twice")
}
func failedApplyWaitsForCleanup() throws {
    let probe = SettingsProbe(); let p = try provider(probe)
    let startResult = Completion(); p.startProxy(options: nil, completionHandler: startResult.call)
    let (_, apply) = try probe.next(); apply(Bridge.error("injected apply failure"))
    let (isApply, clear) = try probe.next(); try expect(!isApply, "failed apply did not clear settings")
    try expect(startResult.count == 0, "start failure completed before cleanup")
    let early = Completion(); p.startProxy(options: nil, completionHandler: early.call)
    try wait(early.done, "early restart not rejected"); try expect(early.failed, "early restart accepted")
    clear(nil); try wait(startResult.done, "failed start did not complete")
    try expect(startResult.failed, "failed apply reported success")
    try expect(TestRuntime.shared.destructionCount(101) == 1, "failed apply leaked/destroyed twice")
    _ = try start(p, probe); try stop(p, probe)
}
func failedClearBlocksRestart() throws {
    let probe = SettingsProbe(); let p = try provider(probe)
    _ = try start(p, probe); try stop(p, probe, error: Bridge.error("injected cleanup failure"))
    let next = Completion(); p.startProxy(options: nil, completionHandler: next.call)
    try wait(next.done, "cleanup failure did not block restart")
    try expect(next.failed && probe.count == 0, "restart after failed cleanup changed settings")
    try expect((try snapshot(p))["ready"] as? Bool == false, "failed cleanup exposed ready")
}
func cleanupRetryRestoresStart() throws {
    let probe = SettingsProbe(); let p = try provider(probe)
    _ = try start(p, probe); try stop(p, probe, error: Bridge.error("injected cleanup failure"))
    try stop(p, probe)
    _ = try start(p, probe); try stop(p, probe)
    try expect(TestRuntime.shared.destructionCount(101) == 1 && TestRuntime.shared.destructionCount(102) == 1, "cleanup retry ownership mismatch")
}
func directCurrentPolicyWorks() throws {
    let probe = SettingsProbe(); let p = try provider(probe)
    _ = try start(p, probe); TestRuntime.shared.action = "direct"
    let flow = NEAppProxyTCPFlow()
    try expect(p.handleNewFlow(flow) == false && flow.readError == nil, "current direct policy was overblocked")
    try stop(p, probe)
}
func staleProxyAcrossRestart() throws {
    let probe = SettingsProbe(); let p = try provider(probe)
    _ = try start(p, probe)
    var interleavingError: Error?
    TestRuntime.shared.beforeEvaluate = {
        do { try stop(p, probe); _ = try start(p, probe) }
        catch { interleavingError = error }
    }
    let flow = NEAppProxyTCPFlow()
    let handled = p.handleNewFlow(flow)
    TestRuntime.shared.beforeEvaluate = nil
    if let error = interleavingError { throw error }
    try expect(handled && flow.readError != nil, "stale proxy decision admitted into a new native session")
    try stop(p, probe)
}
func stalePolicyReloadIsRejected() throws {
    let probe = SettingsProbe(); let p = try provider(probe)
    _ = try start(p, probe); TestRuntime.shared.action = "direct"
    let token = try snapshot(p)["session_id"] as! String
    let updated = try Bridge.text(["proxies": [], "max_connections": 64])
    let command = try JSONSerialization.data(withJSONObject: ["command": "apply_rules", "session_id": token, "profile": updated])
    let completed = DispatchSemaphore(value: 0)
    TestRuntime.shared.beforeEvaluate = {
        p.handleAppMessage(command) { _ in completed.signal() }
        _ = completed.wait(timeout: .now() + 5)
    }
    let flow = NEAppProxyTCPFlow()
    let handled = p.handleNewFlow(flow)
    TestRuntime.shared.beforeEvaluate = nil
    try expect(handled && flow.readError != nil, "pre-reload policy decision released flow DIRECT")
    try stop(p, probe)
}
func synchronousCallbacksAreSupported() throws {
    let probe = SettingsProbe(); let p = try provider(probe)
    p.settingsHook = { _, completion in completion(nil) }
    let started = Completion(); p.startProxy(options: nil, completionHandler: started.call)
    try wait(started.done, "synchronous start completion deadlocked")
    try expect(started.succeeded, "synchronous start failed")
    let stopped = DispatchSemaphore(value: 0); p.stopProxy(with: .userInitiated) { stopped.signal() }
    try wait(stopped, "synchronous stop completion deadlocked")
}
func zeroHandleCannotStart() throws {
    let probe = SettingsProbe(); let p = try provider(probe)
    TestRuntime.shared.zeroHandle = true
    let result = Completion(); p.startProxy(options: nil, completionHandler: result.call)
    try wait(result.done, "zero native handle not rejected")
    try expect(result.failed && probe.count == 0, "zero handle reached settings apply")
}
func invalidConfigurationCanBeRetried() throws {
    let probe = SettingsProbe(); let p = try provider(probe)
    let config = p.protocolConfiguration as! NETunnelProviderProtocol
    let saved = config.providerConfiguration
    config.providerConfiguration = [:]
    let result = Completion(); p.startProxy(options: nil, completionHandler: result.call)
    try wait(result.done, "invalid config did not complete")
    try expect(result.failed && probe.count == 0, "invalid config reached apply")
    config.providerConfiguration = saved
    _ = try start(p, probe); try stop(p, probe)
}
func stoppedProviderDeniesFlow() throws {
    let probe = SettingsProbe(); let p = try provider(probe)
    let flow = NEAppProxyTCPFlow()
    try expect(p.handleNewFlow(flow) && flow.readError != nil, "idle provider released TCP")
}
func repeatedLifecycleNoOwnershipLeak() throws {
    let probe = SettingsProbe(); let p = try provider(probe)
    for i in 0..<50 {
        _ = try start(p, probe); try stop(p, probe)
        try expect(TestRuntime.shared.destructionCount(UInt64(101 + i)) == 1, "handle lifecycle mismatch")
    }
}


func applyBarrierRejectsCapturedAndArrivingDirect() throws {
    let probe = SettingsProbe(); let p = try provider(probe)
    _ = try start(p, probe)
    TestRuntime.shared.action = "direct"
    let token = try snapshot(p)["session_id"] as! String
    let updated = try Bridge.text(["proxies": [], "max_connections": 128, "default_action": ["type": "block"]])
    let command = try JSONSerialization.data(withJSONObject:
        ["command": "apply_rules", "session_id": token, "profile": updated])
    let entered = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    let completed = DispatchSemaphore(value: 0)
    var response: [String: Any] = [:]
    TestRuntime.shared.beforeReload = {
        entered.signal()
        _ = release.wait(timeout: .now() + 5)
    }
    // This evaluates the old DIRECT policy while a competing Apply is
    // deliberately blocked inside the native reload, after its admission
    // barrier must already have been installed in the provider.
    TestRuntime.shared.beforeEvaluate = {
        p.handleAppMessage(command) { data in
            if let data, let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                response = value
            }
            completed.signal()
        }
        _ = entered.wait(timeout: .now() + 5)
    }
    let captured = NEAppProxyTCPFlow()
    let handled = p.handleNewFlow(captured)
    TestRuntime.shared.beforeEvaluate = nil
    try expect(handled && captured.readError != nil,
               "in-flight old DIRECT decision escaped during Apply")
    let arriving = NEAppProxyTCPFlow()
    try expect(p.handleNewFlow(arriving) && arriving.readError != nil,
               "new DIRECT flow escaped during pending Apply")
    release.signal()
    try wait(completed, "native Apply never completed")
    TestRuntime.shared.beforeReload = nil
    try expect(response["ok"] as? Bool == true, "valid rule update was not committed")
    try expect((try snapshot(p))["ready"] as? Bool == true, "rule update damaged provider readiness")
    try stop(p, probe)
}

func rejectedApplyRestoresOldPolicyAdmission() throws {
    let probe = SettingsProbe(); let p = try provider(probe)
    _ = try start(p, probe)
    TestRuntime.shared.action = "direct"
    TestRuntime.shared.rejectReload = true
    let token = try snapshot(p)["session_id"] as! String
    let updated = try Bridge.text(["proxies": [], "max_connections": 128, "default_action": ["type": "block"]])
    let command = try JSONSerialization.data(withJSONObject:
        ["command": "apply_rules", "session_id": token, "profile": updated])
    let failed = DispatchSemaphore(value: 0)
    var reply: [String: Any] = [:]
    p.handleAppMessage(command) { data in
        if let data, let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            reply = value
        }
        failed.signal()
    }
    try wait(failed, "failed reload completion missing")
    try expect(reply["ok"] as? Bool == false, "rejected native rule change was accepted")
    TestRuntime.shared.rejectReload = false
    let direct = NEAppProxyTCPFlow()
    try expect(p.handleNewFlow(direct) == false && direct.readError == nil,
               "rejected Apply left provider locked or modified old direct decision")
    let succeeded = DispatchSemaphore(value: 0)
    p.handleAppMessage(command) { data in
        if let data, let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            reply = value
        }
        succeeded.signal()
    }
    try wait(succeeded, "rule retry completion missing")
    try expect(reply["ok"] as? Bool == true, "valid retry did not recover after failure")
    try stop(p, probe)
}

func stopDuringNativeRuleReloadCannotReopenProvider() throws {
    let probe = SettingsProbe(); let p = try provider(probe)
    _ = try start(p, probe)
    let token = try snapshot(p)["session_id"] as! String
    let updated = try Bridge.text(["proxies": [], "max_connections": 128, "default_action": ["type": "block"]])
    let command = try JSONSerialization.data(withJSONObject:
        ["command": "apply_rules", "session_id": token, "profile": updated])
    let stopComplete = DispatchSemaphore(value: 0)
    let applyComplete = DispatchSemaphore(value: 0)
    var response: [String: Any] = [:]
    TestRuntime.shared.beforeReload = {
        p.stopProxy(with: .userInitiated) { stopComplete.signal() }
    }
    p.handleAppMessage(command) { data in
        if let data, let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            response = value
        }
        applyComplete.signal()
    }
    try wait(applyComplete, "stopped Apply completion missing")
    TestRuntime.shared.beforeReload = nil
    try expect(response["ok"] as? Bool == false,
               "native Apply response was acknowledged after Stop")
    let (isApply, clear) = try probe.next()
    try expect(!isApply, "Stop during Apply must clear settings")
    clear(nil); try wait(stopComplete, "Stop cleanup completion missing")
    let flow = NEAppProxyTCPFlow()
    try expect(p.handleNewFlow(flow) && flow.readError != nil,
               "stopped provider accepted a flow after Apply returned")
    try expect((try snapshot(p))["ready"] as? Bool == false, "Apply resurrected readiness")
}

@main enum Runner {
    static func main() {
        let selected = CommandLine.arguments.dropFirst().first
        let tests: [(String, () throws -> Void)] = [
            ("duplicate_start", duplicateStart),
            ("cancel_pending_start", cancelPendingStart),
            ("restart_during_clear", restartDuringClear),
            ("stale_direct_after_stop", staleDirectDecision),
            ("normal_lifecycle_dns", normalLifecycleAndDNS),
            ("duplicate_pending_start", duplicatePendingStart),
            ("cancel_during_creation", cancelDuringCreation),
            ("clear_waits_for_apply", clearWaitsForApply),
            ("duplicate_stop", duplicateStopCoalesces),
            ("failed_apply_cleanup", failedApplyWaitsForCleanup),
            ("failed_clear_blocks_restart", failedClearBlocksRestart),
            ("cleanup_retry", cleanupRetryRestoresStart),
            ("direct_current_policy", directCurrentPolicyWorks),
            ("stale_proxy_across_restart", staleProxyAcrossRestart),
            ("stale_policy_reload", stalePolicyReloadIsRejected),
            ("synchronous_callbacks", synchronousCallbacksAreSupported),
            ("zero_native_handle", zeroHandleCannotStart),
            ("invalid_configuration_retry", invalidConfigurationCanBeRetried),
            ("stopped_provider_denies", stoppedProviderDeniesFlow),
            ("fifty_lifecycles", repeatedLifecycleNoOwnershipLeak),
            ("apply_barrier_direct", applyBarrierRejectsCapturedAndArrivingDirect),
            ("apply_reject_restore", rejectedApplyRestoresOldPolicyAdmission),
            ("apply_stop_race", stopDuringNativeRuleReloadCannotReopenProvider)
        ]
        var failed = 0; var count = 0
        for (name, test) in tests where selected == nil || selected == name {
            count += 1; TestRuntime.shared.reset()
            do { try test(); print("PASS \(name)") }
            catch { failed += 1; print("FAIL \(name): \(error)") }
        }
        print("TESTS=\(count) FAILED=\(failed) NATIVE_NE_ACTIVATION=false")
        if failed != 0 || count == 0 { exit(1) }
    }
}
