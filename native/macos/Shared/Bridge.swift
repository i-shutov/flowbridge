import Foundation

enum Bridge {
    static func error(_ message: String) -> NSError {
        NSError(domain: "FlowBridge", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
    static func consume(_ pointer: UnsafeMutablePointer<CChar>?) throws -> [String: Any] {
        guard let pointer else { throw error("Engine returned no response") }
        defer { fb_string_free(pointer) }
        guard let data = String(cString: pointer).data(using: .utf8),
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw error("Invalid engine response")
        }
        guard object["ok"] as? Bool == true else { throw error(object["error"] as? String ?? "Engine error") }
        return object
    }
    static func text(_ value: Any) throws -> String {
        String(decoding: try JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys]), as: UTF8.self)
    }
    static func validate(_ text: String) throws {
        guard text.utf8.count <= 1_048_576, !text.contains("\0") else { throw error("Profile exceeds 1 MiB or contains NUL") }
        _ = try text.withCString { try consume(fb_validate_json($0)) }
    }
    static let initial = """
    {"version":1,"listen":"127.0.0.1:1081","proxies":[{"id":"ssh","kind":"socks5","endpoint":{"host":"127.0.0.1","port":1080},"username":null,"password_env":null}],"chains":[],"rules":[{"id":"loopback","enabled":true,"applications":[],"hosts":[],"networks":["127.0.0.0/8","::1/128"],"ports":[],"action":{"type":"direct"}}],"default_action":{"type":"proxy","id":"ssh"},"connect_timeout_ms":10000,"handshake_timeout_ms":10000,"idle_timeout_ms":300000,"max_connections":256}
    """
}
