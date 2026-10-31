//! Foreground, explicit SOCKS control plane. It is deliberately NOT an SCM
//! service, NDISRD protected routing or a substitute for packet/PID attestation.
//! No arbitrary paths, process identities, driver modes or secrets travel over IPC.
#[cfg(any(windows, test))]
use flowbridge_core::Config;
#[cfg(any(windows, test))]
use flowbridge_runtime::Engine;
#[cfg(any(windows, test))]
use serde::Deserialize;
#[cfg(any(windows, test))]
use serde_json::json;
use serde_json::Value;
#[cfg(any(windows, test))]
use std::io::Read;
#[cfg(any(windows, test))]
use std::path::{Path, PathBuf};

#[cfg(any(windows, test))]
const MAX_CONFIG: u64 = 1024 * 1024;

#[cfg(any(windows, test))]
#[derive(Debug, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Status {},
    Reload {},
    Stop {},
}

#[cfg(any(windows, test))]
fn load_explicit_profile(path: &Path) -> Result<Config, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("configuration open failed: {e}"))?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("configuration read failed: {e}"))?;
    if bytes.len() as u64 > MAX_CONFIG {
        return Err("configuration exceeds 1 MiB".into());
    }
    let json = std::str::from_utf8(&bytes).map_err(|_| "configuration is not UTF-8")?;
    let profile = Config::from_json(json).map_err(|e| e.to_string())?;
    if profile
        .rules
        .iter()
        .any(|rule| rule.enabled && !rule.applications.is_empty())
    {
        return Err(
            "explicit SOCKS cannot authenticate application identity; app-specific rules require unimplemented native owner proof".into(),
        );
    }
    Ok(profile)
}

#[cfg(any(windows, test))]
pub(crate) struct Controller {
    engine: Engine,
    config_path: PathBuf,
}

#[cfg(any(windows, test))]
impl Controller {
    fn open(config_path: PathBuf) -> Result<Self, String> {
        let config = load_explicit_profile(&config_path)?;
        let engine = Engine::new(config).map_err(|e| e.to_string())?;
        engine.start().map_err(|e| e.to_string())?;
        Ok(Self {
            engine,
            config_path,
        })
    }

    pub(crate) fn status(&self) -> Value {
        let s = self.engine.snapshot().status;
        json!({
            "ok": true,
            "mode": "foreground_explicit_socks_only",
            "scm_service_installed": false,
            "driver_capture_active": false,
            "native_process_proof": false,
            "protected_redirect_available": false,
            "dns_leak_free": false,
            "release_accepted": false,
            "engine": {
                "running": s.running,
                "listen": s.listen,
                "generation": s.generation,
                "active": s.active,
                "accepted": s.accepted,
                "completed": s.completed,
                "failed": s.failed
            }
        })
    }

    /// Only a strictly framed local pipe request reaches this handler. Even
    /// an authorized client cannot set a driver flag, change a process owner,
    /// supply a different config path or stop an unrelated Windows service.
    pub(crate) fn execute(&mut self, input: &[u8]) -> (Value, bool) {
        let request: Request = match serde_json::from_slice(input) {
            Ok(request) => request,
            Err(_) => {
                return (
                    json!({"ok":false,"error":"invalid bounded control request","release_accepted":false}),
                    false,
                )
            }
        };
        match request {
            Request::Status {} => (self.status(), false),
            Request::Reload {} => {
                // Validate before touching live state; Engine.reload additionally
                // rejects changes to listener/capacity without stopping it.
                let result = load_explicit_profile(&self.config_path)
                    .and_then(|config| self.engine.reload(config).map_err(|e| e.to_string()));
                match result {
                    Ok(_) => (self.status(), false),
                    Err(e) => (
                        json!({"ok":false,"error":e,"config_unchanged":true,"release_accepted":false}),
                        false,
                    ),
                }
            }
            Request::Stop {} => {
                let result = self.engine.stop();
                match result {
                    Ok(_) => (self.status(), true),
                    Err(e) => (
                        json!({"ok":false,"error":e.to_string(),"release_accepted":false}),
                        true,
                    ),
                }
            }
        }
    }
}

/// Starts a same-user foreground proxy/control process. No driver IOCTLs.
#[cfg(windows)]
pub fn serve_foreground(path: &str) -> Result<Value, String> {
    if path.is_empty() || path.len() > 4096 {
        return Err("control-serve requires one bounded config file path".into());
    }
    let controller = Controller::open(PathBuf::from(path))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(crate::windows_control_pipe::serve(controller))
}

#[cfg(not(windows))]
pub fn serve_foreground(_path: &str) -> Result<Value, String> {
    Err("restricted control IPC requires Windows; no listener started".into())
}

#[cfg(windows)]
pub fn command(action: &str) -> Result<Value, String> {
    if !matches!(action, "status" | "reload" | "stop") {
        return Err("Only status, reload or stop is accepted".into());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(crate::windows_control_pipe::client(action))
}

#[cfg(not(windows))]
pub fn command(_action: &str) -> Result<Value, String> {
    Err("restricted control IPC requires Windows".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowbridge_core::{Action, Rule};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    static SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn config() -> Config {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listen = socket.local_addr().unwrap();
        drop(socket);
        Config {
            version: 1,
            listen,
            proxies: vec![],
            chains: vec![],
            rules: vec![],
            default_action: Action::Block,
            connect_timeout_ms: 1000,
            handshake_timeout_ms: 1000,
            idle_timeout_ms: 1000,
            max_connections: 8,
            remote_dns_via_ssh: true,
        }
    }

    struct ConfigFile(PathBuf);
    impl ConfigFile {
        fn new(config: &Config) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "flowbridge-control-{}-{}-{}.json",
                std::process::id(),
                nanos,
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            let file = Self(path);
            file.write(config);
            file
        }
        fn write(&self, config: &Config) {
            std::fs::write(&self.0, serde_json::to_vec(config).unwrap()).unwrap();
        }
    }
    impl Drop for ConfigFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[tokio::test]
    async fn real_tcp_listener_status_atomic_reload_stop_and_no_secrets() {
        let config = config();
        let file = ConfigFile::new(&config);
        let mut controller = Controller::open(file.0.clone()).unwrap();
        let status = controller.execute(br#"{"command":"status"}"#).0;
        assert_eq!(status["engine"]["running"], true);
        assert_eq!(status["engine"]["generation"], 1);
        assert_eq!(status["protected_redirect_available"], false);
        assert!(!status.to_string().contains("password"));

        // This is a genuine TCP listener, not a mock engine. No network
        // destination is contacted because the default policy blocks.
        let mut socket = tokio::net::TcpStream::connect(config.listen).await.unwrap();
        socket.write_all(&[5, 1, 0]).await.unwrap();
        let mut response = [0_u8; 2];
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            socket.read_exact(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response, [5, 0]);
        drop(socket);

        let mut invalid = config.clone();
        invalid.rules.push(Rule {
            id: "no-implicit-app-identity".into(),
            enabled: true,
            applications: vec![r"C:\Apps\Browser.exe".into()],
            hosts: vec![],
            networks: vec![],
            ports: vec![],
            action: Action::Block,
        });
        file.write(&invalid);
        let denied = controller.execute(br#"{"command":"reload"}"#).0;
        assert_eq!(denied["ok"], false);
        assert_eq!(denied["config_unchanged"], true);
        assert_eq!(controller.status()["engine"]["generation"], 1);
        assert_eq!(controller.status()["engine"]["running"], true);

        // Attempting to switch ports cannot detach the live listener.
        invalid = config.clone();
        invalid.listen = "127.0.0.1:1".parse().unwrap();
        file.write(&invalid);
        let denied = controller.execute(br#"{"command":"reload"}"#).0;
        assert_eq!(denied["ok"], false);
        assert_eq!(controller.status()["engine"]["generation"], 1);

        let mut revised = config.clone();
        revised.rules.push(Rule {
            id: "deny-all".into(),
            enabled: true,
            applications: vec![],
            hosts: vec![],
            networks: vec![],
            ports: vec![],
            action: Action::Block,
        });
        file.write(&revised);
        let accepted = controller.execute(br#"{"command":"reload"}"#).0;
        assert_eq!(accepted["ok"], true);
        assert_eq!(accepted["engine"]["generation"], 2);

        let (stopped, exit) = controller.execute(br#"{"command":"stop"}"#);
        assert!(exit);
        assert_eq!(stopped["engine"]["running"], false);
        assert!(std::net::TcpStream::connect_timeout(
            &config.listen,
            std::time::Duration::from_millis(100)
        )
        .is_err());
    }

    #[test]
    fn strict_command_and_bounded_config_fail_closed() {
        let file = ConfigFile::new(&config());
        let mut ctl = Controller::open(file.0.clone()).unwrap();
        for request in [
            br#"{"command":"protected"}"#.as_slice(),
            br#"{"command":"status","driver_mode":3}"#,
            br#"{"command":"reload","config_path":"C:\\evil.json"}"#,
            br#"{"command":"stop","force":true}"#,
            br#"{"command":"status","command":"stop"}"#,
            b"{}",
            b"",
        ] {
            let (reply, exit) = ctl.execute(request);
            assert_eq!(reply["ok"], false);
            assert!(!exit);
            assert!(ctl.engine.snapshot().status.running);
        }
        let mut incompatible = config();
        incompatible.rules.push(Rule {
            id: "app".into(),
            enabled: true,
            applications: vec![r"C:\Apps\A.exe".into()],
            hosts: vec![],
            networks: vec![],
            ports: vec![],
            action: Action::Block,
        });
        file.write(&incompatible);
        assert!(load_explicit_profile(&file.0).is_err());
        std::fs::write(&file.0, vec![b'a'; MAX_CONFIG as usize + 1]).unwrap();
        assert!(load_explicit_profile(&file.0).is_err());
        ctl.engine.stop().unwrap();
    }
}
