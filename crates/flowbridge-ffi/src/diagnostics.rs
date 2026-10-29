//! Allowlist-only, offline diagnostic export. Never include arbitrary raw logs.
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
    value
        .as_str()
        .filter(|s| allowed.contains(s))
        .map_or(Value::Null, |s| json!(s))
}
pub(super) fn report(request: &Value) -> Value {
    let engine = &request["engine"];
    let ssh = &request["ssh"]["status"];
    let mut ssh_summary = numeric(
        ssh,
        &[
            "restarts",
            "attempt",
            "resource_exhaustion_count",
            "last_resource_error_unix_ms",
            "health_failures",
            "worker_count",
            "ready_workers",
        ],
    );
    ssh_summary["state"] = choice(
        &ssh["state"],
        &[
            "stopped",
            "starting",
            "ready",
            "degraded",
            "reconnecting",
            "failed",
        ],
    );
    ssh_summary["diagnostic_code"] = choice(
        &ssh["diagnostic_code"],
        &[
            "ssh_resource_exhausted",
            "ssh_health_unresponsive",
            "ssh_server_unresponsive",
        ],
    );
    // Record only the program's version token, never a path or arbitrary stderr.
    ssh_summary["backend_version"] = ssh["backend_version"]
        .as_str()
        .and_then(|v| v.split([',', ' ']).next())
        .filter(|v| {
            v.starts_with("OpenSSH_")
                && v.len() <= 80
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
        .map_or(Value::Null, |v| json!(v));
    let upstream = &engine["managed_upstream"];
    let managed = if upstream.is_object() {
        let mut value = numeric(
            upstream,
            &["active_including_opening", "opening", "queued", "rejected"],
        );
        value["limits"] = numeric(
            &upstream["limits"],
            &["max_flows", "max_opening", "max_queued", "wait_timeout_ms"],
        );
        value
    } else {
        Value::Null
    };
    let pool = &engine["managed_pool"];
    // Do not expose upstream endpoints, hostnames or executable paths.
    // Each bounded ordinal record holds only numerical admission counters.
    let safe_pool = if pool.is_object() {
        let mut record = numeric(pool, &["aggregate_max_flows", "ready_workers"]);
        let mut workers = Vec::new();
        if let Some(entries) = pool["workers"].as_array() {
            for (index, worker) in entries.iter().take(4).enumerate() {
                let mut item = json!({"index":index});
                if let Some(ready) = worker["ready"].as_bool() {
                    item["ready"] = json!(ready);
                }
                let admission = &worker["admission"];
                let mut counters = numeric(admission, &[
                    "active_including_opening", "opening", "queued", "rejected"]);
                counters["limits"] = numeric(&admission["limits"], &[
                    "max_flows", "max_opening", "max_queued", "wait_timeout_ms"]);
                item["admission"] = counters;
                workers.push(item);
            }
        }
        record["workers"] = json!(workers);
        record
    } else {
        Value::Null
    };
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
        "managed_pool": safe_pool,
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
                "managed_upstream":{"queued":2,"limits":{"max_flows":128,"password":"PRIVATE_LIMIT"}},
                "managed_pool":{"aggregate_max_flows":128,"ready_workers":1,
                    "workers":[{"endpoint":{"host":"PRIVATE_ENDPOINT","port":1080},"ready":true,
                        "admission":{"active_including_opening":5,"queued":2,
                            "limits":{"max_flows":64,"password":"PRIVATE_LIMIT"}}}]}},
            "ssh":{"status":{"state":"degraded","restarts":1,"resource_exhaustion_count":12,
                "diagnostic_code":"ssh_resource_exhausted", "backend_path":"PRIVATE_PATH",
                "backend_version":"OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2", "last_error":"PRIVATE_ERROR"},
                "stderr":["PRIVATE_STDERR"]}, "identity_file":"PRIVATE_KEY"});
        let result = report(&input);
        assert!(!result.to_string().contains("PRIVATE_"));
        assert_eq!(result["engine"]["active"], 7);
        assert_eq!(result["ssh"]["resource_exhaustion_count"], 12);
        assert_eq!(
            result["ssh"]["backend_version"],
            "OpenSSH_for_Windows_9.5p1"
        );
        assert_eq!(result["managed_upstream"]["limits"]["max_flows"], 128);
        assert_eq!(result["managed_pool"]["ready_workers"], 1);
        assert_eq!(
            result["managed_pool"]["workers"][0]["admission"]["active_including_opening"],
            5
        );
        assert_eq!(result["managed_pool"]["workers"][0]["admission"]["limits"]["max_flows"], 64);
        assert!(result["managed_pool"]["workers"][0].get("endpoint").is_none());
    }
    #[test]
    fn nested_injection_and_empty_snapshots_are_safe() {
        let input = json!({"ssh":{"status":{"state":"PRIVATE_STATE", "backend_version":"PRIVATE_VERSION",
            "restarts":{"secret":"PRIVATE_NESTED"}, "diagnostic_code":"PRIVATE_DIAG"}},
            "engine":{"managed_upstream":{"limits":{"max_flows":"PRIVATE_STRING"}}}});
        assert!(!report(&input).to_string().contains("PRIVATE_"));
        assert!(report(&Value::Null)["managed_upstream"].is_null());
        assert_eq!(
            report(&Value::Null)["coverage"]["remote_network_probe_performed"],
            false
        );
    }
}
