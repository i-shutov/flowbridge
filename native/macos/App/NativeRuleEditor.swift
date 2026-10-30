import SwiftUI
import Foundation

// Local, native draft editor. There is deliberately no routing side effect:
// the parent Apply button runs the existing atomic engine/NE reload.
private struct RuleRoute: Identifiable {
    let type: String
    let identifier: String
    let label: String
    var id: String { type + ":" + identifier }
    var object: [String: Any] {
        var value: [String: Any] = ["type": type]
        if !identifier.isEmpty { value["id"] = identifier }
        return value
    }
}

private struct RuleFields {
    var identifier = ""
    var apps = ""
    var hosts = ""
    var networks = ""
    var ports = ""
    var enabled = false
    var route = "direct:"
}

struct NativeRuleEditor: View {
    @Binding var config: String
    @Environment(\.dismiss) private var dismiss
    @State private var draft: [String: Any] = [:]
    @State private var selected: Int? = nil
    @State private var fields = RuleFields()
    @State private var routes: [RuleRoute] = []
    @State private var defaultRoute = "direct:"
    @State private var ready = false
    @State private var message = ""

    private var rules: [[String: Any]] { draft["rules"] as? [[String: Any]] ?? [] }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Визуальные правила").font(.title2.bold())
                    Text("Первое совпадение · маршруты изменяются только после «Применить профиль»")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button("Отмена") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Сохранить черновик") { finish() }
                    .buttonStyle(.borderedProminent).disabled(!ready)
            }
            Divider()
            HStack(alignment: .top, spacing: 14) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Правила — сверху вниз").font(.headline)
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 4) {
                            ForEach(rules.indices, id: \.self) { index in
                                Button { choose(index) } label: {
                                    HStack(spacing: 8) {
                                        Image(systemName: (rules[index]["enabled"] as? Bool ?? false)
                                              ? "checkmark.circle.fill" : "circle")
                                        Text(rules[index]["id"] as? String ?? "?")
                                            .lineLimit(1).truncationMode(.middle)
                                        Spacer(minLength: 2)
                                        Text((rules[index]["action"] as? [String: Any])?["type"] as? String ?? "")
                                            .font(.caption).foregroundStyle(.secondary)
                                    }
                                    .padding(.horizontal, 10).padding(.vertical, 9)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .background(selected == index ? Color.accentColor.opacity(0.16) :
                                                Color(nsColor: .controlBackgroundColor),
                                                in: RoundedRectangle(cornerRadius: 8))
                                }.buttonStyle(.plain)
                            }
                        }
                    }
                    .frame(minHeight: 240)
                    HStack(spacing: 6) {
                        Button("Добавить") { change(.add) }
                        Button("Копия") { change(.duplicate) }.disabled(selected == nil)
                        Button("Удалить") { change(.remove) }.disabled(selected == nil)
                    }
                    HStack(spacing: 6) {
                        Button("↑ Выше") { change(.up) }.disabled(selected == nil || selected == 0)
                        Button("↓ Ниже") { change(.down) }
                            .disabled(selected == nil || selected == rules.count - 1)
                    }
                }.frame(minWidth: 250, idealWidth: 285, maxWidth: 320)
                Divider()
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Выбранное правило").font(.headline)
                        Group {
                            TextField("ID правила", text: $fields.identifier)
                            Toggle("Правило включено", isOn: $fields.enabled)
                            TextField("Приложения · через ;", text: $fields.apps)
                            TextField("Хосты и wildcard · через ;", text: $fields.hosts)
                            TextField("IPv4/IPv6 CIDR · через ;", text: $fields.networks)
                            TextField("Порты: 443; 8000-8010", text: $fields.ports)
                            Picker("Действие", selection: $fields.route) {
                                ForEach(routes) { route in Text(route.label).tag(route.id) }
                            }
                            Button("Проверить правило") { storeCurrent() }
                                .disabled(selected == nil)
                        }.disabled(selected == nil)
                        Divider()
                        Text("Маршрут по умолчанию").font(.headline)
                        Picker("Если правила не подошли", selection: $defaultRoute) {
                            ForEach(routes) { route in Text(route.label).tag(route.id) }
                        }.disabled(!ready)
                        Text("Добавленные и скопированные правила выключены. Пустой список приложений — любой процесс, когда это допускает режим перехвата.")
                            .font(.caption).foregroundStyle(.secondary)
                        if !message.isEmpty {
                            Text(message).font(.caption)
                                .foregroundStyle(message.hasPrefix("Ошибка") ? .red : .secondary)
                                .textSelection(.enabled)
                        }
                    }.textFieldStyle(.roundedBorder).frame(maxWidth: .infinity, alignment: .leading)
                }
            }.frame(maxHeight: .infinity)
        }
        .padding(18).frame(minWidth: 840, minHeight: 570)
        .onAppear(perform: load)
    }

    private func key(_ value: [String: Any]) -> String {
        (value["type"] as? String ?? "") + ":" + (value["id"] as? String ?? "")
    }
    private func tokens(_ text: String) -> [String] {
        text.components(separatedBy: CharacterSet(charactersIn: ";\r\n"))
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }
    private func joined(_ raw: Any?) -> String {
        (raw as? [String] ?? []).joined(separator: "; ")
    }
    private func showPorts(_ raw: Any?) -> String {
        (raw as? [[String: Any]] ?? []).compactMap { item -> String? in
            guard let start = item["start"] as? Int, let end = item["end"] as? Int else { return nil }
            return start == end ? String(start) : "\(start)-\(end)"
        }.joined(separator: "; ")
    }
    private func parsePorts(_ raw: String) throws -> [[String: Int]] {
        try tokens(raw).map { item in
            let edges = item.split(separator: "-", omittingEmptySubsequences: false)
            guard edges.count == 1 || edges.count == 2,
                  let start = Int(edges[0].trimmingCharacters(in: .whitespaces)),
                  let end = Int(edges[edges.count - 1].trimmingCharacters(in: .whitespaces)),
                  (1...65535).contains(start), (1...65535).contains(end),
                  start <= end else {
                throw Bridge.error("Порты: допустимы 1–65535 и диапазоны вида 8000-8010.")
            }
            return ["start": start, "end": end]
        }
    }
    private func validated(_ candidate: [String: Any]) throws -> String {
        let text = try Bridge.text(candidate)
        try Bridge.validate(text) // Rust FFI, same authority as Apply.
        return text
    }
    private func load() {
        do {
            try Bridge.validate(config)
            guard let object = try JSONSerialization.jsonObject(with: Data(config.utf8)) as? [String: Any],
                  object["rules"] is [[String: Any]],
                  let proxies = object["proxies"] as? [[String: Any]],
                  let chains = object["chains"] as? [[String: Any]] else {
                throw Bridge.error("Профиль не содержит корректный список правил, прокси и цепочек.")
            }
            draft = object
            routes = [RuleRoute(type: "direct", identifier: "", label: "Direct"),
                      RuleRoute(type: "block", identifier: "", label: "Block")]
            for proxy in proxies {
                if let id = proxy["id"] as? String {
                    routes.append(RuleRoute(type: "proxy", identifier: id, label: "Proxy · " + id))
                }
            }
            for chain in chains {
                if let id = chain["id"] as? String {
                    routes.append(RuleRoute(type: "chain", identifier: id, label: "Chain · " + id))
                }
            }
            defaultRoute = key(object["default_action"] as? [String: Any] ?? [:])
            guard routes.contains(where: { $0.id == defaultRoute }) else {
                throw Bridge.error("Действие по умолчанию не существует в профиле.")
            }
            ready = true
            if !rules.isEmpty { fill(0) }
            message = "Редактируется копия профиля. Отмена не изменяет приложение."
        } catch {
            ready = false
            message = "Ошибка: " + error.localizedDescription
        }
    }
    private func fill(_ index: Int) {
        guard rules.indices.contains(index) else { selected = nil; fields = RuleFields(); return }
        let value = rules[index]
        fields = RuleFields(
            identifier: value["id"] as? String ?? "",
            apps: joined(value["applications"]),
            hosts: joined(value["hosts"]),
            networks: joined(value["networks"]),
            ports: showPorts(value["ports"]),
            enabled: value["enabled"] as? Bool ?? false,
            route: key(value["action"] as? [String: Any] ?? [:]))
        selected = index
    }
    @discardableResult private func storeCurrent() -> Bool {
        guard ready, let index = selected else { return ready }
        do {
            guard let action = routes.first(where: { $0.id == fields.route }) else {
                throw Bridge.error("Неизвестный маршрут.")
            }
            var next = rules
            var edited = next[index]
            edited["id"] = fields.identifier.trimmingCharacters(in: .whitespacesAndNewlines)
            edited["enabled"] = fields.enabled
            edited["applications"] = tokens(fields.apps)
            edited["hosts"] = tokens(fields.hosts)
            edited["networks"] = tokens(fields.networks)
            edited["ports"] = try parsePorts(fields.ports)
            edited["action"] = action.object
            next[index] = edited
            var candidate = draft
            candidate["rules"] = next
            _ = try validated(candidate)
            draft = candidate
            message = "Правило принято Rust-валидатором; маршрут пока не применён."
            return true
        } catch {
            message = "Ошибка: " + error.localizedDescription
            return false
        }
    }
    private func choose(_ index: Int) {
        guard selected != index, storeCurrent() else { return }
        fill(index)
    }
    private func uniqueId(_ prefix: String) -> String {
        let used = Set(rules.compactMap { $0["id"] as? String })
        for number in 1...99999 {
            let id = prefix + String(number)
            if !used.contains(id) { return id }
        }
        return ""
    }
    private enum Mutation { case add, duplicate, remove, up, down }
    private func change(_ operation: Mutation) {
        guard storeCurrent() else { return }
        do {
            var next = rules
            let newSelection: Int
            switch operation {
            case .add:
                newSelection = next.count
                next.append(["id": uniqueId("rule-"), "enabled": false,
                             "applications": [], "hosts": [], "networks": [], "ports": [],
                             "action": ["type": "direct"]])
            case .duplicate:
                guard let index = selected else { return }
                var copy = next[index]
                copy["id"] = uniqueId((copy["id"] as? String ?? "rule") + "-copy-")
                copy["enabled"] = false
                newSelection = index + 1
                next.insert(copy, at: newSelection)
            case .remove:
                guard let index = selected else { return }
                next.remove(at: index)
                newSelection = min(index, next.count - 1)
            case .up, .down:
                guard let index = selected else { return }
                let target = index + (operation == .up ? -1 : 1)
                guard next.indices.contains(target) else { return }
                next.swapAt(index, target)
                newSelection = target
            }
            var candidate = draft
            candidate["rules"] = next
            _ = try validated(candidate)
            draft = candidate
            if newSelection >= 0 { fill(newSelection) } else { selected = nil; fields = RuleFields() }
            message = "Изменён только черновик; порядок правил учитывает первое совпадение."
        } catch {
            message = "Ошибка: " + error.localizedDescription
        }
    }
    private func finish() {
        guard storeCurrent() else { return }
        do {
            guard let chosen = routes.first(where: { $0.id == defaultRoute }) else {
                throw Bridge.error("Неизвестное действие по умолчанию.")
            }
            var candidate = draft
            candidate["default_action"] = chosen.object
            config = try validated(candidate) // only mutation of parent; Cancel never writes.
            dismiss()
        } catch {
            message = "Ошибка: " + error.localizedDescription
        }
    }
}
