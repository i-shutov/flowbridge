import Foundation
import SwiftUI
#if FLOWBRIDGE_NATIVE
import NetworkExtension
import SystemExtensions
import Security

final class NativeController: NSObject, ObservableObject, OSSystemExtensionRequestDelegate {
    @Published var message = "Transparent capture unavailable until a signed extension is verified and approved."
    @Published var available = false
    @Published var active = false
    @Published var busy = false
    @Published var snapshot: [String: Any] = [:]
    @Published var ports = "80,443"
    var bypassSigningIDs: [String] = []
    var managedPort: Int?
    var upstreamReady = false
    private var manager: NETransparentProxyManager?
    private var pendingProfile: String?
    private var activation: OSSystemExtensionRequest?
    private var timer: Timer?
    private var operation: UInt64 = 0
    private var stopping = false
    private var providerSessionID: String?
    private var pingOutstanding = false
    private var pingSequence = 0
    private let extensionID = Bundle.main.bundleIdentifier! + ".extension"

    override init() {
        super.init()
        do { try verifyEmbedded(); available = true; message = "Signed extension found. Start requests macOS approval and starts TCP capture." }
        catch { message = "Transparent capture unavailable: \(error.localizedDescription)" }
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in self?.poll() }
        if available {
            NETransparentProxyManager.loadAllFromPreferences { [weak self] managers, _ in
                DispatchQueue.main.async {
                    guard let self, !self.busy, self.manager == nil else { return }
                    self.manager = managers?.first { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == self.extensionID }
                    if let saved = (self.manager?.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["capturePorts"] as? [Int] {
                        self.ports = saved.map(String.init).joined(separator: ",")
                    }
                    self.poll()
                }
            }
        }
    }
    deinit { timer?.invalidate() }
    private func signedInfo(_ url: URL) throws -> [String: Any] {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code else { throw Bridge.error("Code signature missing") }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString("anchor apple generic" as CFString, [], &requirement) == errSecSuccess,
              SecStaticCodeCheckValidity(code, [], requirement) == errSecSuccess else { throw Bridge.error("A valid Apple-issued signing identity is required") }
        var result: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &result) == errSecSuccess,
              let info = result as? [String: Any] else { throw Bridge.error("Cannot inspect code signing") }
        return info
    }
    private func verifyEmbedded() throws {
        let url = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/SystemExtensions/\(extensionID).systemextension")
        guard let bundle = Bundle(url: url), bundle.bundleIdentifier == extensionID else { throw Bridge.error("No embedded system extension in this build") }
        let app = try signedInfo(Bundle.main.bundleURL), ext = try signedInfo(url)
        guard let team = app[kSecCodeInfoTeamIdentifier as String] as? String, !team.isEmpty,
              ext[kSecCodeInfoTeamIdentifier as String] as? String == team else { throw Bridge.error("App and extension must share a signing team") }
        let appEnt = app[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]
        let extEnt = ext[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]
        guard appEnt["com.apple.developer.system-extension.install"] as? Bool == true,
              (appEnt["com.apple.developer.networking.networkextension"] as? [String])?.contains("app-proxy-provider-systemextension") == true,
              (extEnt["com.apple.developer.networking.networkextension"] as? [String])?.contains("app-proxy-provider-systemextension") == true else {
            throw Bridge.error("Required system extension / Network Extension entitlements missing")
        }
    }
    func start(_ profile: String) {
        guard available, !busy else { return }
        do { try Bridge.validate(profile); try verifyEmbedded(); _ = try capturePorts() }
        catch { message = error.localizedDescription; return }
        operation += 1; providerSessionID = nil; busy = true; active = false; stopping = false; pendingProfile = profile
        message = "Requesting extension activation; macOS may require approval in System Settings."
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: extensionID, queue: .main)
        request.delegate = self; activation = request
        OSSystemExtensionManager.shared.submitRequest(request)
    }
    private func capturePorts() throws -> [Int] {
        let pieces = ports.split(separator: ","); let result = pieces.compactMap { Int($0.trimmingCharacters(in: .whitespaces)) }
        guard !result.isEmpty, result.count == pieces.count, result.count <= 64,
              result.allSatisfy({ (1...65535).contains($0) && $0 != 53 }) else { throw Bridge.error("Choose 1–64 TCP ports, excluding DNS port 53") }
        return Array(Set(result)).sorted()
    }
    private func configure(_ profile: String) {
        let revision = operation
        NETransparentProxyManager.loadAllFromPreferences { [weak self] managers, error in
            DispatchQueue.main.async {
                guard let self, self.operation == revision, !self.stopping else { return }; if let error { self.fail(error); return }
                do {
                    let manager = managers?.first { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == self.extensionID } ?? NETransparentProxyManager()
                    let proto = NETunnelProviderProtocol(); proto.providerBundleIdentifier = self.extensionID
                    proto.serverAddress = "FlowBridge TCP proxy"
                    proto.providerConfiguration = ["profile": profile, "capturePorts": try self.capturePorts(), "bypassSigningIDs": self.bypassSigningIDs]
                    if let port = self.managedPort {
                        proto.providerConfiguration?["managedEndpoint"] = ["host":"127.0.0.1","port":port]
                    }
                    manager.protocolConfiguration = proto; manager.localizedDescription = "FlowBridge TCP capture"
                    manager.isEnabled = true; manager.isOnDemandEnabled = false
                    self.manager = manager
                    manager.saveToPreferences { error in
                        DispatchQueue.main.async {
                            guard self.operation == revision, !self.stopping else { return }
                            if let error { self.fail(error); return }
                            manager.loadFromPreferences { error in
                                DispatchQueue.main.async {
                                    guard self.operation == revision, !self.stopping else { return }
                                    if let error { self.fail(error); return }
                                    do {
                                        try manager.connection.startVPNTunnel()
                                        self.message = "Starting TCP capture; waiting for provider readiness."
                                        DispatchQueue.main.asyncAfter(deadline: .now() + 30) { [weak self] in
                                            guard let self, self.operation == revision, self.busy, !self.active, self.activation == nil else { return }
                                            self.stop(); self.message = "Provider did not become ready within 30 seconds. Check signing, approval and profile errors in macOS Console."
                                        }
                                    }
                                    catch { self.fail(error) }
                                }
                            }
                        }
                    }
                } catch { self.fail(error) }
            }
        }
    }
    func stop() {
        operation += 1; activation = nil; providerSessionID = nil
        pendingProfile = nil; active = false; busy = false; stopping = true
        pingSequence += 1; pingOutstanding = false
        manager?.connection.stopVPNTunnel(); message = "Stopping TCP capture."
    }
    func stopAndWait(completion: @escaping (Bool) -> Void) {
        stop(); let revision = operation
        func check(_ remaining: Int) {
            guard self.operation == revision else { completion(false); return }
            let status = self.manager?.connection.status
            if status == nil || status == .disconnected || status == .invalid { completion(true); return }
            guard remaining > 0 else { self.message = "Capture stop has not been confirmed; SSH remains running."; completion(false); return }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { check(remaining - 1) }
        }
        check(40)
    }
    func applyRules(_ profile: String, completion: @escaping (Bool) -> Void) {
        guard active, !stopping, let expectedSession = providerSessionID, let session = manager?.connection as? NETunnelProviderSession else {
            message = "Native capture must be ready before applying app selection."; completion(false); return
        }
        do {
            try Bridge.validate(profile)
            let request = try JSONSerialization.data(withJSONObject: ["command": "apply_rules", "profile": profile, "session_id": expectedSession])
            let revision = operation
            var answered = false
            try session.sendProviderMessage(request) { data in
                DispatchQueue.main.async {
                    guard !answered else { return }; answered = true
                    guard self.operation == revision, !self.stopping, self.active, self.providerSessionID == expectedSession,
                          let data, let response = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { completion(false); return }
                    let ok = response["ok"] as? Bool == true && response["session_id"] as? String == expectedSession
                    self.message = ok ? "Application policy applied to new TCP flows." : (response["error"] as? String ?? "Native Apply failed")
                    completion(ok)
                }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
                guard !answered else { return }; answered = true
                guard self.operation == revision, !self.stopping, self.active, self.providerSessionID == expectedSession else {
                    completion(false); return
                }
                self.message = "Native Apply acknowledgment timed out."; completion(false)
            }
        } catch { message = error.localizedDescription; completion(false) }
    }
    func deactivate() {
        stop(); busy = true
        let revision = operation
        // Disable the saved configuration before removing the extension.
        guard let manager else { submitDeactivation(); return }
        manager.isEnabled = false
        manager.saveToPreferences { [weak self] error in
            DispatchQueue.main.async {
                guard let self, self.operation == revision else { return }; if let error { self.fail(error); return }; self.submitDeactivation()
            }
        }
    }
    private func submitDeactivation() {
        let request = OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: extensionID, queue: .main)
        request.delegate = self; activation = request; OSSystemExtensionManager.shared.submitRequest(request)
    }
    private func fail(_ error: Error) {
        manager?.connection.stopVPNTunnel(); stopping = true; providerSessionID = nil
        busy = false; active = false; pendingProfile = nil; message = error.localizedDescription
    }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) { guard request === activation else { return }; message = "Approval required in macOS System Settings. Capture is not active." }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) { guard request === activation else { return }; activation = nil; fail(error) }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        guard request === activation else { return }
        activation = nil
        guard result == .completed else { pendingProfile = nil; busy = false; message = "macOS requires a restart before the extension can be used."; return }
        if let profile = pendingProfile { pendingProfile = nil; configure(profile) }
        else { active = false; busy = false; message = "Extension request completed. Capture is stopped." }
    }
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .replace }
    private func poll() {
        guard let manager, !stopping else { return }
        guard manager.connection.status == .connected else {
            if active { message = "TCP capture disconnected." }
            active = false; providerSessionID = nil
            return
        }
        guard !pingOutstanding, let session = manager.connection as? NETunnelProviderSession else { return }
        pingOutstanding = true; pingSequence += 1; let sequence = pingSequence
        do {
            let request: Data
            if let expected = providerSessionID {
                request = try JSONSerialization.data(withJSONObject:["command":"heartbeat","session_id":expected,
                    "upstream_ready": managedPort == nil || upstreamReady])
            } else { request = Data("snapshot".utf8) }
            try session.sendProviderMessage(request) { [weak self] data in
                DispatchQueue.main.async {
                    guard let self, self.pingSequence == sequence, !self.stopping, manager.connection.status == .connected else { return }; self.pingOutstanding = false
                    guard let data, let response = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                          response["ready"] as? Bool == true, let observedSession = response["session_id"] as? String,
                          !observedSession.isEmpty else { self.providerSessionID = nil; self.active = false; self.busy = true; self.message = "Provider readiness not confirmed. Stop capture to cancel."; return }
                    self.providerSessionID = observedSession; self.snapshot = response; self.active = true; self.busy = false
                    self.message = "TCP capture active on configured ports. UDP and system DNS remain direct."
                }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in
                guard let self, self.pingOutstanding, self.pingSequence == sequence else { return }
                self.pingOutstanding = false; self.providerSessionID = nil; self.active = false; self.busy = true; self.message = "Provider readiness timed out. Stop capture to cancel."
            }
        } catch { pingOutstanding = false; fail(error) }
    }
}
#else
final class NativeController: ObservableObject {
    @Published var message = "Transparent capture unavailable in this local SOCKS build. Requires a separately signed and provisioned system extension."
    @Published var available = false
    @Published var active = false
    @Published var busy = false
    @Published var snapshot: [String: Any] = [:]
    @Published var ports = "80,443"
    var bypassSigningIDs: [String] = []
    var managedPort: Int?
    var upstreamReady = false
    func start(_ profile: String) {}
    func stop() {}
    func deactivate() {}
    func stopAndWait(completion: @escaping (Bool) -> Void) { completion(true) }
    func applyRules(_ profile: String, completion: @escaping (Bool) -> Void) { completion(false) }
}
#endif
