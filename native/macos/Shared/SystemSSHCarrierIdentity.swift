import Foundation
#if !FLOWBRIDGE_PROVIDER_TEST
import Security
#endif

/// Trust anchor for the ONLY permitted managed SSH transport carrier.
///
/// The application and its signed system extension use the SAME production
/// verifier. A user-editable providerConfiguration signing ID cannot authorize
/// a different binary or a wildcard traffic exclusion.
///
/// No process-instance attestation is implied; the actual NE process audit
/// token and owned-SSH PID/epoch still require physical operator acceptance.
enum SystemSSHCarrierIdentity {
    static func verifiedIdentifier() -> String? {
        #if FLOWBRIDGE_PROVIDER_TEST
        return TestRuntime.shared.systemSSHSigningID
        #else
        let url = URL(fileURLWithPath: "/usr/bin/ssh")
        var code: SecStaticCode?
        var requirement: SecRequirement?
        var info: CFDictionary?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code,
              SecRequirementCreateWithString("anchor apple" as CFString, [], &requirement) == errSecSuccess,
              let requirement,
              SecStaticCodeCheckValidity(code, [], requirement) == errSecSuccess,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let attributes = info as? [String: Any],
              let identity = attributes[kSecCodeInfoIdentifier as String] as? String,
              !identity.isEmpty, identity.utf8.count <= 1024,
              !identity.contains("*"), !identity.contains("?"),
              !identity.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
        else { return nil }
        return identity
        #endif
    }
}
