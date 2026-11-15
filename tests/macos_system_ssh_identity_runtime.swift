// Read-only runtime assertion against the REAL macOS /usr/bin/ssh and Apple
// Security.framework. The exact production SystemSSHCarrierIdentity.swift
// module is compiled into this command; no test-only flag or mock identity.
import Foundation
import Darwin

@main enum VerifySystemSSHCarrier {
    static func main() {
        let architecture = ProcessInfo.processInfo.environment["EXPECTED_ARCH"] ?? ""
        var system = utsname()
        guard uname(&system) == 0 else {
            fputs("HOST_KERNEL_UNAVAILABLE\n", stderr); exit(1)
        }
        let actual = withUnsafePointer(to: &system.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: system.machine)) {
                String(cString: $0)
            }
        }
        guard ["arm64", "x86_64"].contains(actual), actual == architecture else {
            fputs("WRONG_NATIVE_ARCH\n", stderr); exit(1)
        }
        guard let identity = SystemSSHCarrierIdentity.verifiedIdentifier() else {
            fputs("APPLE_SYSTEM_SSH_CODE_SIGNATURE_NOT_ACCEPTED\n", stderr)
            exit(1)
        }
        let result: [String: Any] = [
            "schema":"flowbridge-macos-carrier-signature-hosted-v1",
            "status":"APPLE_SYSTEM_SSH_ANCHORED_SIGNER_VERIFIED",
            "architecture":actual,
            "system_binary":"/usr/bin/ssh",
            "signing_id":identity,
            "requirement":"anchor apple",
            "real_security_framework_executed":true,
            "network_extension_activated":false,
            "owner_native_accepted":false,
            "owned_ssh_process_instance_proved":false,
            "physical_no_direct_proved":false,
            "release_accepted":false,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]),
              let text = String(data: data, encoding: .utf8) else {
            fputs("RUNTIME_REPORT_SERIALIZATION_FAILED\n", stderr)
            exit(1)
        }
        print(text)
    }
}
