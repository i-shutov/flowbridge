import SwiftUI
import AppKit

@main
struct FlowBridgeApp: App {
    @StateObject private var desktop = DesktopController()
    @NSApplicationDelegateAdaptor(FlowBridgeDelegate.self) private var delegate
    var body: some Scene {
        WindowGroup("FlowBridge") {
            Dashboard(desktop: desktop, engine: desktop.engine, native: desktop.native,
                      ssh: desktop.ssh, discovery: desktop.discovery).frame(minWidth: 1080, minHeight: 760)
                .onAppear { delegate.desktop = desktop }
        }.windowStyle(.titleBar)
    }
}
private final class FlowBridgeDelegate: NSObject, NSApplicationDelegate {
    weak var desktop: DesktopController?
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let desktop else { return .terminateNow }
        desktop.stop { stopped in sender.reply(toApplicationShouldTerminate: stopped) }
        return .terminateLater
    }
}
private enum Page: String, CaseIterable, Identifiable {
    case connection = "Подключение", apps = "Приложения", activity = "Активность", advanced = "Дополнительно"
    var id: String { rawValue }
    var icon: String {
        switch self { case .connection: return "network"; case .apps: return "square.grid.2x2"; case .activity: return "waveform.path.ecg"; case .advanced: return "slider.horizontal.3" }
    }
}
private struct Dashboard: View {
    @ObservedObject var desktop: DesktopController
    @ObservedObject var engine: EngineController
    @ObservedObject var native: NativeController
    @ObservedObject var ssh: SSHController
    @ObservedObject var discovery: AppDiscovery
    @State private var page: Page? = .connection
    @State private var showSSHOptions = false
    @State private var showLog = false
    private var routing: Bool { engine.running || native.active }
    private var locked: Bool { desktop.busy || routing || engine.busy || native.busy || ["starting", "ready", "reconnecting", "degraded"].contains(ssh.state) }
    private var healthy: Bool { !desktop.busy && routing && (!desktop.settings.integratedSSH || ssh.state == "ready") }
    private var statusTitle: String {
        if ssh.state == "degraded" { return "SSH: требуется диагностика" }
        if ssh.state == "reconnecting" { return "Восстанавливаем SSH" }
        if healthy { return "Подключено" }
        if desktop.busy { return "Подключение…" }
        if ssh.state == "failed" { return "Требуется внимание" }
        return "Не подключено"
    }
    var body: some View {
        NavigationSplitView {
            VStack(alignment: .leading, spacing: 18) {
                HStack(spacing: 10) {
                    Image(systemName: "arrow.triangle.branch").font(.title).foregroundStyle(.cyan)
                    VStack(alignment: .leading) { Text("FlowBridge").font(.title3.bold()); Text("PRIVATE CONNECTION").font(.system(size: 9, weight: .semibold)).tracking(1.4).foregroundStyle(.secondary) }
                }.padding(.horizontal, 16).padding(.top, 20)
                List(Page.allCases, selection: $page) { item in Label(item.rawValue, systemImage: item.icon).tag(item).padding(.vertical, 7) }.listStyle(.sidebar)
                VStack(alignment: .leading, spacing: 6) {
                    Label(healthy ? "Маршрут готов" : "Вы управляете подключением", systemImage: healthy ? "checkmark.shield.fill" : "shield.lefthalf.filled")
                    Text("Без автозапуска · macOS 13+").font(.caption).foregroundStyle(.secondary)
                }.font(.caption).padding(16)
            }.navigationSplitViewColumnWidth(min: 210, ideal: 225, max: 260)
        } detail: {
            VStack(spacing: 0) {
                HStack(alignment: .center, spacing: 20) {
                    VStack(alignment: .leading, spacing: 5) {
                        Text((page ?? .connection).rawValue).font(.system(size: 28, weight: .bold))
                        Text(subtitle).font(.callout).foregroundStyle(.secondary)
                    }
                    Spacer()
                    HStack(spacing: 7) { Circle().fill(healthy ? Color.green : (desktop.busy || ssh.state == "reconnecting" || ssh.state == "degraded" ? Color.orange : Color.secondary)).frame(width: 7, height: 7); Text(statusTitle).font(.callout.weight(.medium)) }
                        .padding(.horizontal, 12).padding(.vertical, 8).background(.quaternary, in: Capsule())
                }.padding(28)
                Divider()
                Group {
                    switch page ?? .connection {
                    case .connection: connection
                    case .apps: applications
                    case .activity: activity
                    case .advanced: advanced
                    }
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
                Divider()
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "info.circle").foregroundStyle(.secondary)
                    Text(desktop.message).font(.caption).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                    Text("v0.2.0").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                }.padding(14)
            }.background(Color(nsColor: .windowBackgroundColor))
        }.tint(.cyan)
    }
    private var subtitle: String {
        switch page ?? .connection {
        case .connection: return "SSH, контроль соединения и локальный прокси — в одном окне"
        case .apps: return "Шаблоны AI / Web и реальные приложения на этом Mac"
        case .activity: return "Состояние туннеля, соединения и события"
        case .advanced: return "Профили, правила, цепочки и системное расширение"
        }
    }
    private var connection: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    Picker("Источник прокси", selection: $desktop.settings.integratedSSH) {
                        Text("Встроенный SSH + watchdog").tag(true)
                        Text("Существующий прокси").tag(false)
                    }.pickerStyle(.segmented)
                    if desktop.settings.integratedSSH {
                        HStack { TextField("SSH-сервер", text: $desktop.settings.sshHost, prompt: Text("server.example.com")); TextField("Порт", value: $desktop.settings.sshPort, format: .number).frame(width: 125) }
                        TextField("Пользователь", text: $desktop.settings.sshUser, prompt: Text("Имя на SSH-сервере"))
                        fileField("Приватный ключ", path: $desktop.settings.identityFile, placeholder: "SSH agent / стандартные ключи")
                        fileField("known_hosts", path: $desktop.settings.knownHostsFile, placeholder: "Стандартный файл OpenSSH")
                        TextField("Локальный порт SSH SOCKS", value: $desktop.settings.localPort, format: .number)
                        Text("Ключ или SSH agent; парольные запросы отключены. Новый сервер должен присутствовать в проверенном known_hosts. Ключ хоста не принимается автоматически.")
                            .font(.caption).foregroundStyle(.secondary)
                        DisclosureGroup("Устойчивость и параметры SSH", isExpanded: $showSSHOptions) {
                            Toggle("Сжатие SSH", isOn: $desktop.settings.compression)
                            HStack { TextField("Keepalive, сек", value: $desktop.settings.aliveInterval, format: .number); TextField("Пропуски keepalive", value: $desktop.settings.aliveCount, format: .number) }
                            HStack { TextField("Таймаут соединения, сек", value: $desktop.settings.connectTimeout, format: .number); TextField("Таймаут запуска, мс", value: $desktop.settings.startupTimeout, format: .number) }
                            HStack { TextField("Проверка SOCKS каждые, мс", value: $desktop.settings.healthInterval, format: .number); TextField("Таймаут проверки, мс", value: $desktop.settings.healthTimeout, format: .number) }
                            HStack { TextField("Начальная задержка повтора, мс", value: $desktop.settings.restartInitial, format: .number); TextField("Максимальная задержка, мс", value: $desktop.settings.restartMaximum, format: .number) }
                            TextField("Максимум перезапусков (0 — без ограничения)", value: $desktop.settings.maxRestarts, format: .number)
                        }
                    } else {
                        Picker("Протокол", selection: $engine.kind) { Text("SOCKS5").tag("socks5"); Text("SOCKS4a").tag("socks4a"); Text("HTTP CONNECT").tag("http_connect") }
                        HStack { TextField("Адрес прокси", text: $engine.host); TextField("Порт", text: $engine.port).frame(width: 125) }
                        Button("Обновить прокси в профиле") { engine.updateQuick(); desktop.message = engine.message }
                    }
                } header: { Label("Подключение", systemImage: "server.rack") }
                Section {
                    Picker("Режим", selection: $desktop.settings.mode) {
                        Text("Локальный SOCKS5").tag(0); Text("Прозрачный TCP · Network Extension").tag(1)
                    }
                    TextField("Локальный адрес FlowBridge", text: $engine.listen)
                        .onSubmit { engine.updateQuick() }
                    if desktop.settings.mode == 0 {
                        Text("Работают только клиенты, в которых указан SOCKS FlowBridge. Выбор приложений не перехватывает их трафик в этом режиме.")
                            .font(.caption).foregroundStyle(.secondary)
                    } else {
                        TextField("TCP-порты для перехвата", text: $desktop.settings.capturePorts)
                        Text(native.available ? "Нужно одобрение macOS. UDP, QUIC, DNS, остальные порты и исключённые адреса идут напрямую." : native.message)
                            .font(.caption).foregroundStyle(native.available ? Color.secondary : Color.orange)
                    }
                } header: { Label("Маршрутизация", systemImage: "point.3.connected.trianglepath.dotted") }
            }.formStyle(.grouped).disabled(locked)
            VStack(alignment: .leading, spacing: 12) {
                if desktop.settings.integratedSSH {
                    Label(ssh.message, systemImage: ssh.state == "ready" ? "checkmark.circle.fill" : "arrow.clockwise.circle")
                        .font(.callout).foregroundStyle(ssh.state == "ready" ? Color.green : Color.secondary)
                    Text(desktop.settings.mode == 0
                         ? "При обрыве SSH локальный адрес остаётся прежним; новые проксируемые подключения ждут восстановления до 30 секунд. Уже открытые TCP-сессии могут оборваться."
                         : "Watchdog восстанавливает SSH для новых подключений. В native-режиме ожидание новых потоков во время обрыва не реализовано; текущие TCP-сессии могут оборваться.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                HStack {
                    Button { if !desktop.settings.integratedSSH { engine.updateQuick() }; desktop.start() } label: { Label("Подключить", systemImage: "power") }.buttonStyle(.borderedProminent).controlSize(.large).disabled(locked)
                    Button("Остановить") { desktop.stop() }.controlSize(.large).disabled(!locked && ssh.state == "stopped")
                    Spacer()
                    Button("Сохранить настройки") { if desktop.saveSettings() { desktop.message = "Настройки сохранены." } }
                }
            }.padding(24)
        }
    }
    private func fileField(_ title: String, path: Binding<String>, placeholder: String) -> some View {
        HStack {
            TextField(title, text: path, prompt: Text(placeholder))
            Button { let panel = NSOpenPanel(); panel.canChooseFiles = true; panel.canChooseDirectories = false; if panel.runModal() == .OK, let url = panel.url { path.wrappedValue = url.path } } label: { Image(systemName: "folder") }
                .help("Выбрать файл")
        }
    }
    private var applications: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                HStack(spacing: 12) {
                    ForEach(discovery.catalog?.presets ?? []) { preset in
                        Button { desktop.selectPreset(preset.id) } label: {
                            VStack(alignment: .leading, spacing: 9) {
                                Image(systemName: preset.id == "ai" ? "sparkles" : preset.id == "web" ? "globe" : "square.stack.3d.up").font(.title2)
                                Text(preset.name).font(.headline)
                                Text(preset.description).font(.caption).foregroundStyle(.secondary).lineLimit(3)
                            }.frame(maxWidth: .infinity, minHeight: 105, alignment: .leading).padding(16)
                                .background(desktop.settings.selectedPreset == preset.id ? Color.cyan.opacity(0.12) : Color.secondary.opacity(0.06), in: RoundedRectangle(cornerRadius: 14))
                                .overlay(RoundedRectangle(cornerRadius: 14).stroke(desktop.settings.selectedPreset == preset.id ? Color.cyan : Color.clear))
                        }.buttonStyle(.plain).disabled(discovery.scanning)
                    }
                }
                Toggle("Направлять через прокси только выбранные приложения", isOn: $desktop.settings.appSelectionEnabled)
                    .font(.headline)
                Text(desktop.settings.mode == 0
                     ? "Список — только подготовка профиля. Локальный SOCKS не знает, какое приложение открыло соединение. Для перехвата выбранных приложений нужен готовый Network Extension."
                     : "Выбранные signing ID получают прокси, остальные приложения — Direct. Шаблон заменяет правила профиля. Перехватываются только выбранные TCP-порты; UDP, QUIC и DNS остаются напрямую.")
                    .font(.callout).foregroundStyle(desktop.settings.mode == 0 ? Color.orange : Color.secondary)
                HStack { Text(discovery.message).font(.caption).foregroundStyle(.secondary); Spacer(); Button("Добавить .app…") { discovery.chooseFile() }; Button("Найти приложения") { discovery.scan() }.disabled(discovery.scanning) }
                if discovery.scanning { ProgressView().frame(maxWidth: .infinity) }
                LazyVStack(spacing: 8) {
                    ForEach(discovery.applications) { app in
                        HStack(spacing: 12) {
                            Image(nsImage: NSWorkspace.shared.icon(forFile: app.path)).resizable().frame(width: 36, height: 36)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(app.name).font(.headline)
                                Text(app.signingID ?? "Signing ID не найден — правило не создаётся").font(.caption.monospaced()).foregroundStyle(.secondary)
                                Text(app.path).font(.caption2).foregroundStyle(.tertiary).lineLimit(1).truncationMode(.middle)
                            }
                            Spacer()
                            Toggle("Выбрать \(app.name)", isOn: Binding(get: { desktop.settings.selectedApplications.contains(app.path) }, set: { checked in
                                desktop.settings.selectedApplications.removeAll { $0 == app.path }; if checked { desktop.settings.selectedApplications.append(app.path) }; desktop.saveSettings()
                            })).labelsHidden().disabled(app.policyIdentity == nil)
                        }.padding(12).background(Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 10))
                    }
                }
                Text("Поиск ограничен /Applications, ~/Applications, двумя уровнями подпапок и LaunchServices. Названия шаблонов — эвристика. В правила попадают только прочитанные signing ID; проверьте их по активности native-провайдера.")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    Text("Выбрано: \(desktop.settings.selectedApplications.count)").font(.callout)
                    Spacer()
                    Button("Применить к готовому native-захвату") { desktop.apply() }.buttonStyle(.borderedProminent)
                        .disabled(desktop.settings.mode != 1 || !native.active || desktop.busy)
                }
            }.padding(28)
        }
    }
    private var activity: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 12) {
                metric("SSH", ssh.state == "ready" ? "Готов" : ssh.state, "bolt.horizontal.circle")
                metric("Перезапуски", String(describing: ssh.status["restarts"] ?? 0), "arrow.clockwise")
                metric("Потоки", String((selectedSnapshot["connections"] as? [Any] ?? []).count), "arrow.up.arrow.down")
            }
            Text(ssh.message).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            Button("Сохранить диагностику…") {
                DiagnosticsExporter.save(engine: selectedSnapshot, ssh: ["status":ssh.status])
            }.help("Сохраняются только состояния и счётчики; ключи, адреса и сырые журналы исключены.")
            ConnectionTable(value: selectedSnapshot)
            DisclosureGroup("Журнал SSH и маршрутизации", isExpanded: $showLog) {
                ScrollView {
                    Text(eventText).font(.system(size: 11, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                }.frame(height: 190).padding(10).background(.quaternary, in: RoundedRectangle(cornerRadius: 10))
            }
        }.padding(28)
    }
    private var selectedSnapshot: [String: Any] { desktop.settings.mode == 0 ? engine.snapshot : native.snapshot }
    private var eventText: String {
        let all = ssh.events + (selectedSnapshot["events"] as? [[String: Any]] ?? [])
        return all.suffix(256).map { "[\($0["level"] ?? "info")] \($0["message"] ?? "")" }.joined(separator: "\n")
    }
    private func metric(_ title: String, _ value: String, _ icon: String) -> some View {
        VStack(alignment: .leading, spacing: 8) { Label(title, systemImage: icon).font(.caption).foregroundStyle(.secondary); Text(value).font(.title2.bold()).lineLimit(1) }
            .frame(maxWidth: .infinity, alignment: .leading).padding(18).background(.quaternary, in: RoundedRectangle(cornerRadius: 12))
    }
    private var advanced: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack { Button("Открыть JSON…") { engine.open() }; Button("Сохранить JSON…") { engine.save() }; Spacer(); Button("Применить профиль") { engine.syncQuick(); desktop.apply() }.disabled(desktop.busy || engine.busy) }
            Text("Полный профиль правил и цепочек. Режим встроенного SSH использует управляемый SOCKS-прокси flowbridge-ssh. Шаблон приложений заменяет список правил; настройки соединения меняйте после остановки.").font(.caption).foregroundStyle(.secondary)
            TextEditor(text: $engine.config).font(.system(.body, design: .monospaced)).padding(6).background(.quaternary, in: RoundedRectangle(cornerRadius: 10))
            Text(engine.message).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            Divider()
            HStack { Label("Network Extension", systemImage: "puzzlepiece.extension").font(.headline); Spacer(); Button("Деактивировать расширение") { native.deactivate() }.disabled(!native.available || desktop.busy || native.busy || routing) }
            Text(native.message).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            Text("Native: proxy endpoints должны быть IP-адресами. Доменные правила могут не сработать, когда macOS передаёт только IP. Обход DNS не предотвращается. При выходе FlowBridge сначала останавливает маршрутизацию, затем свой SSH.").font(.caption).foregroundStyle(.secondary)
        }.padding(28)
    }
}
private struct ConnectionRow: Identifiable {
    let id: String; let host: String; let application: String; let route: String; let state: String; let traffic: String
}
private struct ConnectionTable: View {
    let value: [String: Any]
    var rows: [ConnectionRow] {
        (value["connections"] as? [[String: Any]] ?? []).enumerated().map { index, row in
            ConnectionRow(id: String(describing: row["id"] ?? index), host: "\(row["host"] ?? "unknown"):\(row["port"] ?? "?")",
                          application: row["application"] as? String ?? "неизвестно",
                          route: String(describing: row["action"] ?? "unknown"), state: String(describing: row["state"] ?? "unknown"),
                          traffic: "↑ \(row["bytes_up"] ?? 0)  ↓ \(row["bytes_down"] ?? 0)")
        }
    }
    var body: some View {
        Table(rows) { TableColumn("Назначение", value: \.host); TableColumn("Приложение", value: \.application); TableColumn("Маршрут", value: \.route); TableColumn("Состояние", value: \.state); TableColumn("Байты", value: \.traffic) }
    }
}
