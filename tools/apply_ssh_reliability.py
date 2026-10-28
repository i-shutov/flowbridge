from pathlib import Path

def edit(path, old, new):
    p=Path(path); s=p.read_text(encoding='utf-8')
    if s.count(old)!=1: raise RuntimeError(f'{path}: match count {s.count(old)}')
    p.write_text(s.replace(old,new),encoding='utf-8')

def write(path,text):
    p=Path(path)
    if p.exists(): raise RuntimeError(f'{path} already exists')
    p.write_text(text,encoding='utf-8')

write('crates/flowbridge-ffi/src/diagnostics.rs',r'''//! Allowlist-only, offline diagnostic export. Never include arbitrary raw logs.
use serde_json::{json, Map, Value};
fn numeric(source: &Value, keys: &[&str]) -> Value {
    let mut output = Map::new();
    for key in keys {
        if let Some(value) = source.get(*key).filter(|v| v.is_u64() || v.is_boolean()) {
            output.insert((*key).into(), value.clone());
        }
    }
    Value::Object(output)
}
fn choice(value: &Value, allowed: &[&str]) -> Value {
    value.as_str().filter(|s| allowed.contains(s)).map_or(Value::Null, |s| json!(s))
}
pub(super) fn report(request: &Value) -> Value {
    let engine = &request["engine"];
    let ssh = &request["ssh"]["status"];
    let mut ssh_summary = numeric(ssh, &["restarts", "attempt", "resource_exhaustion_count", "last_resource_error_unix_ms", "health_failures"]);
    ssh_summary["state"] = choice(&ssh["state"], &["stopped", "starting", "ready", "degraded", "reconnecting", "failed"]);
    ssh_summary["diagnostic_code"] = choice(&ssh["diagnostic_code"], &["ssh_resource_exhausted", "ssh_health_unresponsive"]);
    // Record only the program's version token, never a path or arbitrary stderr.
    ssh_summary["backend_version"] = ssh["backend_version"].as_str()
        .and_then(|v| v.split([',', ' ']).next())
        .filter(|v| v.starts_with("OpenSSH_") && v.len() <= 80
            && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)))
        .map_or(Value::Null, |v| json!(v));
    let upstream = &engine["managed_upstream"];
    let managed = if upstream.is_object() {
        let mut value = numeric(upstream, &["active_including_opening", "opening", "queued", "rejected"]);
        value["limits"] = numeric(&upstream["limits"], &["max_flows", "max_opening", "max_queued", "wait_timeout_ms"]);
        value
    } else { Value::Null };
    json!({
        "schema_version": 1,
        "product": "FlowBridge",
        "version": env!("CARGO_PKG_VERSION"),
        "platform": std::env::consts::OS,
        "architecture": std::env::consts::ARCH,
        "generated_unix_ms": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis().min(u128::from(u64::MAX)) as u64,
        "ssh": ssh_summary,
        "engine": numeric(&engine["status"], &["running", "generation", "active", "accepted", "completed", "failed", "bytes_up", "bytes_down", "transparent"]),
        "managed_upstream": managed,
        "redaction": "Allowlisted counters only: no keys, profile, usernames, paths, hostnames, destinations or raw logs.",
        "coverage": {"snapshot_only": true, "remote_network_probe_performed": false,
            "os_descriptor_count_measured": false, "transparent_dns_verified": false}
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sensitive_and_unknown_fields_are_never_exported() {
        let input = json!({
            "engine": {"status": {"active": 7, "listen": "PRIVATE_ADDRESS", "secret":"PRIVATE_PASSWORD"},
                "connections":[{"host":"PRIVATE_DOMAIN"}], "events":[{"message":"PRIVATE_LOG"}],
                "managed_upstream":{"queued":2,"limits":{"max_flows":128,"password":"PRIVATE_LIMIT"}}},
            "ssh":{"status":{"state":"degraded","restarts":1,"resource_exhaustion_count":12,
                "diagnostic_code":"ssh_resource_exhausted", "backend_path":"PRIVATE_PATH",
                "backend_version":"OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2", "last_error":"PRIVATE_ERROR"},
                "stderr":["PRIVATE_STDERR"]}, "identity_file":"PRIVATE_KEY"});
        let result=report(&input);
        assert!(!result.to_string().contains("PRIVATE_"));
        assert_eq!(result["engine"]["active"],7);
        assert_eq!(result["ssh"]["resource_exhaustion_count"],12);
        assert_eq!(result["ssh"]["backend_version"],"OpenSSH_for_Windows_9.5p1");
        assert_eq!(result["managed_upstream"]["limits"]["max_flows"],128);
    }
    #[test]
    fn nested_injection_and_empty_snapshots_are_safe() {
        let input=json!({"ssh":{"status":{"state":"PRIVATE_STATE", "backend_version":"PRIVATE_VERSION",
            "restarts":{"secret":"PRIVATE_NESTED"}, "diagnostic_code":"PRIVATE_DIAG"}},
            "engine":{"managed_upstream":{"limits":{"max_flows":"PRIVATE_STRING"}}}});
        assert!(!report(&input).to_string().contains("PRIVATE_"));
        assert!(report(&Value::Null)["managed_upstream"].is_null());
        assert_eq!(report(&Value::Null)["coverage"]["remote_network_probe_performed"],false);
    }
}
''')
F='crates/flowbridge-ffi/src/lib.rs'
edit(F,'const MAX_INPUT_BYTES: usize = 1024 * 1024;','mod diagnostics;\n\nconst MAX_INPUT_BYTES: usize = 1024 * 1024;')
edit(F,'/// Validate a profile. Returns an owned JSON string, released with `fb_string_free`.','''/// Produce a redacted, offline report from cached UI snapshots.
///
/// # Safety
/// `snapshot_json` must reference a live NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn fb_diagnostic_report_json(snapshot_json: *const c_char) -> *mut c_char {
    guarded(|| {
        let request: Value = serde_json::from_str(unsafe { input(snapshot_json) }?).map_err(|e| e.to_string())?;
        Ok(json!({"ok":true,"report":diagnostics::report(&request)}))
    })
}

/// Validate a profile. Returns an owned JSON string, released with `fb_string_free`.''')
edit('native/include/flowbridge.h','char *fb_validate_json(const char *config_json);','''/* Offline, allowlist-redacted report from {engine:<snapshot>,ssh:<snapshot>}.
 * Contains no raw logs, profile, keys, paths or destination names. */
char *fb_diagnostic_report_json(const char *snapshot_json);
char *fb_validate_json(const char *config_json);''')
W='native/windows/main.cpp'
edit(W,'RetryMax=246, Banner=280 };','RetryMax=246, Banner=280, ExportDiagnostics=281 };')
edit(W,'Json draft;','Json draft;\nJson latestEngineSnapshot=Json::object(),latestSshSnapshot=Json::object();')
edit(W,'void showSnapshot(const Json& snap) {','void showSnapshot(const Json& snap) {\n    latestEngineSnapshot=snap;')
edit(W,'void showSsh(const Json& ssh,bool waiting){','void showSsh(const Json& ssh,bool waiting){\n    latestSshSnapshot=ssh;')
edit(W,'void browseApplication(){','''void exportDiagnostics(){
    auto engine=latestEngineSnapshot.is_object()?latestEngineSnapshot:Json::object();
    auto ssh=latestSshSnapshot.is_object()?latestSshSnapshot:Json::object();
    auto request=Json{{"engine",{{"status",engine.value("status",Json::object())},{"managed_upstream",engine.value("managed_upstream",Json())}}},{"ssh",{{"status",ssh.value("status",Json::object())}}}}.dump();
    auto report=response(fb_diagnostic_report_json(request.c_str())).at("report");
    auto path=chooseFile(L"Диагностический JSON\\0*.json\\0",true);
    if(path.empty())return;
    writeFile(path,report.dump(2));
    note("Диагностический отчёт сохранён: без ключей, адресов, путей и сырых журналов.");
}
void browseApplication(){''')
edit(W,'    move(Theme,16,height-74,180,42);','    move(Theme,16,height-74,180,42);move(ExportDiagnostics,16,height-126,180,42);')
edit(W,'        add(L"BUTTON",L"Подключить",WS_TABSTOP,Start,-1);','        add(L"BUTTON",L"Диагностика…",WS_TABSTOP,ExportDiagnostics,-1);\n        add(L"BUTTON",L"Подключить",WS_TABSTOP,Start,-1);')
edit(W,'                else if(!busy){','                else if(id==ExportDiagnostics){exportDiagnostics();}\n                else if(!busy){')
M='native/macos/App/FlowBridgeApp.swift'
edit(M,'            ConnectionTable(value: selectedSnapshot)','''            Button("Сохранить диагностику…") {
                DiagnosticsExporter.save(engine: selectedSnapshot, ssh: ["status":ssh.status])
            }.help("Сохраняются только состояния и счётчики; ключи, адреса и сырые журналы исключены.")
            ConnectionTable(value: selectedSnapshot)''')
write('native/macos/App/DiagnosticsExporter.swift','''import AppKit
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
''')
p=Path('docs/SSH_RELIABILITY.md')
p.write_text(p.read_text()+'\nNative UIs provide a redacted diagnostic JSON export. An allowlist in Rust excludes profiles, keys, usernames, full executable paths, destination hosts and arbitrary errors/logs. The report marks unmeasured OS descriptor counts and unverified transparent DNS explicitly. It uses cached status and performs no network probes.\n')
print('Diagnostic export code and privacy regression tests applied')
