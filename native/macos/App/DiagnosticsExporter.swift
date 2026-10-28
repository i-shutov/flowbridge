import AppKit
import Foundation
import UniformTypeIdentifiers

enum DiagnosticsExporter {
    static func save(engine: [String: Any], ssh: [String: Any]) {
        do {
            let minimal: [String: Any] = ["status": engine["status"] ?? [:], "managed_upstream": engine["managed_upstream"] ?? NSNull()]
            let input = try Bridge.text(["engine": minimal, "ssh": ssh])
            let result = try input.withCString { try Bridge.consume(fb_diagnostic_report_json($0)) }
            guard let report = result["report"] as? [String: Any] else {
                throw Bridge.error("Диагностический отчёт не получен.")
            }
            let panel = NSSavePanel()
            panel.allowedContentTypes = [.json]
            panel.nameFieldStringValue = "FlowBridge-diagnostics.json"
            panel.message = "Только состояния и счётчики. Ключи, адреса, пути и сырые журналы не включаются."
            guard panel.runModal() == .OK, let url = panel.url else { return }
            let data = try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
            try data.write(to: url, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch {
            let alert = NSAlert()
            alert.messageText = "Не удалось сохранить диагностику"
            alert.informativeText = error.localizedDescription
            alert.runModal()
        }
    }
}
