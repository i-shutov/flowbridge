import AppKit
import UniformTypeIdentifiers
import Security
import SwiftUI

struct ApplicationCatalog: Decodable {
    struct Preset: Decodable, Identifiable { let id: String; let name: String; let description: String; let app_ids: [String] }
    struct Hint: Decodable, Identifiable {
        let id: String; let name: String; let categories: [String]
        let mac_app_names: [String]; let mac_bundle_ids: [String]
    }
    let schema_version: Int
    let presets: [Preset]
    let apps: [Hint]
}
struct InstalledApplication: Identifiable {
    var id: String { path }
    let name: String
    let bundleID: String
    let signingID: String?
    let path: String
    let catalogIDs: [String]
    var policyIdentity: String? {
        guard let signingID, !signingID.isEmpty, !signingID.contains("*"), !signingID.contains("?"),
              signingID.utf8.count <= 1024, !signingID.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else { return nil }
        return signingID
    }
    static func systemSSHSigningID() -> String? {
        var code: SecStaticCode?; var information: CFDictionary?
        let url = URL(fileURLWithPath: "/usr/bin/ssh")
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, [], nil) == errSecSuccess,
              SecCodeCopySigningInformation(code, [], &information) == errSecSuccess,
              let info = information as? [String: Any], let identity = info[kSecCodeInfoIdentifier as String] as? String,
              !identity.isEmpty else { return nil }
        return identity
    }
}
final class AppDiscovery: ObservableObject {
    @Published private(set) var applications: [InstalledApplication] = []
    @Published private(set) var scanning = false
    @Published private(set) var message = "Поиск ещё не выполнен"
    let catalog: ApplicationCatalog?
    init() {
        if let url = Bundle.main.url(forResource: "presets", withExtension: "json"),
           let data = try? Data(contentsOf: url) { catalog = try? JSONDecoder().decode(ApplicationCatalog.self, from: data) }
        else { catalog = nil }
    }
    func scan() {
        guard !scanning else { return }; scanning = true; message = "Поиск установленных приложений…"
        let hints = catalog?.apps ?? []
        // LaunchServices queries use known IDs only as lookup hints. The resulting
        // bundle is inspected; a catalog hint never becomes an observed identity.
        let launchURLs = hints.flatMap { $0.mac_bundle_ids }.compactMap { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) }
        DispatchQueue.global(qos: .utility).async {
            let fm = FileManager.default
            var found: [String: InstalledApplication] = [:]
            var inspected = 0
            func inspect(_ url: URL) {
                guard found.count < 500, url.pathExtension.lowercased() == "app",
                      let bundle = Bundle(url: url), let bundleID = bundle.bundleIdentifier, !bundleID.isEmpty else { return }
                let path = url.resolvingSymlinksInPath().standardizedFileURL.path
                let name = bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
                    ?? bundle.object(forInfoDictionaryKey: "CFBundleName") as? String ?? url.deletingPathExtension().lastPathComponent
                let matches = hints.filter { hint in
                    hint.mac_bundle_ids.contains(bundleID) || hint.mac_app_names.contains {
                        name.localizedCaseInsensitiveContains($0.replacingOccurrences(of: ".app", with: ""))
                        || url.lastPathComponent.localizedCaseInsensitiveContains($0)
                    }
                }.map(\.id)
                var staticCode: SecStaticCode?
                var information: CFDictionary?
                var signingID: String?
                if SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode) == errSecSuccess, let staticCode,
                   SecCodeCopySigningInformation(staticCode, [], &information) == errSecSuccess,
                   let info = information as? [String: Any] {
                    signingID = info[kSecCodeInfoIdentifier as String] as? String
                }
                found[path] = InstalledApplication(name: name, bundleID: bundleID, signingID: signingID,
                                                   path: path, catalogIDs: matches)
            }
            func walk(_ directory: URL, depth: Int) {
                guard depth <= 2, inspected < 3000,
                      let urls = try? fm.contentsOfDirectory(at: directory, includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey], options: [.skipsHiddenFiles]) else { return }
                for url in urls {
                    guard inspected < 3000, found.count < 500 else { break }; inspected += 1
                    if url.pathExtension.lowercased() == "app" { inspect(url); continue }
                    let values = try? url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
                    if values?.isDirectory == true && values?.isSymbolicLink != true { walk(url, depth: depth + 1) }
                }
            }
            launchURLs.forEach(inspect)
            walk(URL(fileURLWithPath: "/Applications", isDirectory: true), depth: 0)
            walk(fm.homeDirectoryForCurrentUser.appendingPathComponent("Applications", isDirectory: true), depth: 0)
            let result = found.values.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
            DispatchQueue.main.async {
                self.applications = result; self.scanning = false
                self.message = "Найдено: \(result.count). Совпадения шаблонов — подсказки; проверьте выбранные приложения."
            }
        }
    }
    func chooseFile() {
        let panel = NSOpenPanel(); panel.canChooseDirectories = false; panel.canChooseFiles = true
        panel.allowedContentTypes = [.applicationBundle]
        guard panel.runModal() == .OK, let url = panel.url, let bundle = Bundle(url: url), let bundleID = bundle.bundleIdentifier else { return }
        var code: SecStaticCode?; var information: CFDictionary?; var signingID: String?
        if SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code,
           SecCodeCopySigningInformation(code, [], &information) == errSecSuccess,
           let info = information as? [String: Any] { signingID = info[kSecCodeInfoIdentifier as String] as? String }
        let item = InstalledApplication(name: bundle.object(forInfoDictionaryKey: "CFBundleName") as? String ?? url.deletingPathExtension().lastPathComponent,
                                        bundleID: bundleID, signingID: signingID, path: url.standardizedFileURL.path, catalogIDs: [])
        applications.removeAll { $0.path == item.path }; applications.append(item)
    }
}
