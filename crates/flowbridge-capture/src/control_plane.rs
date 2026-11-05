//! Foreground, explicit SOCKS control plane. It is deliberately NOT an SCM
//! service, NDISRD protected routing or a substitute for packet/PID attestation.
//! No arbitrary paths, process identities, driver modes or secrets travel over IPC.
#[cfg(any(windows, test))]
use flowbridge_core::{Action, Config, Endpoint, ProxyKind};
#[cfg(any(windows, test))]
use flowbridge_runtime::Engine;
#[cfg(any(windows, test))]
use flowbridge_tunnel::{Config as SshConfig, Supervisor};
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
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
#[cfg(any(windows, test))]
use std::{thread, time::Duration};

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
#[derive(Debug)]
#[cfg(any(windows, test))]
struct LoadedProfile {
    engine: Config,
    ssh: Option<SshConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(any(windows, test))]
struct ManagedEnvelope {
    consent: String,
    engine: Config,
    ssh: SshConfig,
}

/// Two strictly separate formats: legacy explicit SOCKS configuration or
/// opt-in Rust-owned SSH + SOCKS. No implicit SSH process or route fallback.
#[cfg(any(windows, test))]
fn load_explicit_profile(path: &Path) -> Result<LoadedProfile, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("configuration open failed: {e}"))?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("configuration read failed: {e}"))?;
    if bytes.len() as u64 > MAX_CONFIG {
        return Err("configuration exceeds 1 MiB".into());
    }
    let data = std::str::from_utf8(&bytes).map_err(|_| "configuration is not UTF-8")?;
    let raw: serde_json::Value =
        serde_json::from_str(data).map_err(|_| "invalid strict control profile JSON")?;
    if raw.get("engine").is_none() {
        let engine = Config::from_json(data).map_err(|e| e.to_string())?;
        reject_unattested_app_rules(&engine)?;
        return Ok(LoadedProfile { engine, ssh: None });
    }
    let envelope: ManagedEnvelope =
        serde_json::from_value(raw).map_err(|_| "invalid strict managed SSH envelope")?;
    if envelope.consent != "RUST_MANAGED_SSH_SOCKS_CANDIDATE" {
        return Err("Rust-managed SSH requires exact explicit consent".into());
    }
    envelope.engine.validate().map_err(|e| e.to_string())?;
    envelope.ssh.validate().map_err(|e| e.to_string())?;
    reject_unattested_app_rules(&envelope.engine)?;
    validate_managed_route(&envelope.engine, &envelope.ssh)?;
    Ok(LoadedProfile {
        engine: envelope.engine,
        ssh: Some(envelope.ssh),
    })
}

#[cfg(any(windows, test))]
fn reject_unattested_app_rules(profile: &Config) -> Result<(), String> {
    if profile
        .rules
        .iter()
        .any(|rule| rule.enabled && !rule.applications.is_empty())
    {
        return Err(
            "explicit SOCKS cannot authenticate application identity; app-specific rules require unimplemented native owner proof".into(),
        );
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn validate_managed_route(engine: &Config, ssh: &SshConfig) -> Result<(), String> {
    let executable = ssh
        .ssh_executable
        .as_deref()
        .ok_or("managed SSH requires an explicit absolute local OpenSSH executable")?;
    let identity = ssh
        .identity_file
        .as_deref()
        .ok_or("managed SSH requires an explicit key path; no implicit agent fallback")?;
    let known = ssh
        .known_hosts_file
        .as_deref()
        .ok_or("managed SSH requires an explicit pinned known_hosts path")?;
    if ![executable, identity, known]
        .iter()
        .all(|p| Path::new(p).is_absolute())
    {
        return Err("managed SSH executable, key and host-key paths must be absolute".into());
    }
    if engine.proxies.len() != 1
        || !engine.rules.is_empty()
        || !engine.chains.is_empty()
        || !engine.remote_dns_via_ssh
        || engine.max_connections > 128
        || engine.listen.port() == ssh.local_port
        || !matches!(&engine.default_action,
            Action::Proxy { id } if id == &engine.proxies[0].id)
        || !matches!(&engine.proxies[0].kind, ProxyKind::Socks5)
        || engine.proxies[0].endpoint.host != "127.0.0.1"
        || engine.proxies[0].endpoint.port != ssh.local_port
        || engine.proxies[0].username.is_some()
        || engine.proxies[0].password_env.is_some()
    {
        return Err("managed SSH requires one pinned local SOCKS5 hop, default PROXY, no DIRECT/rules/chains, remote DNS and <=128 connections".into());
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn validate_scm_profile(path: &Path) -> Result<(), String> {
    let path_str = path.to_str().ok_or("SCM config path must be Unicode")?;
    crate::windows_service_management::validate_local_file(path_str)?;
    let config = load_explicit_profile(path)?;
    if !config.engine.listen.ip().is_loopback() {
        return Err("SCM candidate refuses non-loopback SOCKS listeners".into());
    }
    // A demand-start SCM service may run as LocalSystem. A mutable config
    // must never permit that service to launch an arbitrary SSH executable.
    // The SSH-owned candidate is foreground same-user only until a secure
    // identity/ACL/privilege model and upgrade isolation are independently proven.
    if config.ssh.is_some() {
        return Err(
            "SCM candidate refuses SSH process launch pending secure service-account identity and configuration ACLs".into(),
        );
    }
    Ok(())
}

#[cfg(any(windows, test))]
pub(crate) struct Controller {
    engine: Arc<Engine>,
    config_path: PathBuf,
    scm_mode: bool,
    ssh: Option<Arc<Supervisor>>,
    ssh_config: Option<SshConfig>,
    gate_worker: Mutex<Option<GateWorker>>,
    gate_ready: Arc<AtomicBool>,
}

#[cfg(any(windows, test))]
struct GateWorker {
    stop: Arc<AtomicBool>,
    task: thread::JoinHandle<()>,
}

#[cfg(any(windows, test))]
impl Controller {
    fn open(config_path: PathBuf) -> Result<Self, String> {
        Self::open_with_mode(config_path, false)
    }

    fn open_with_mode(config_path: PathBuf, scm_mode: bool) -> Result<Self, String> {
        #[cfg(windows)]
        if scm_mode {
            crate::windows_service_management::validate_local_file(
                config_path
                    .to_str()
                    .ok_or("SCM config path must be Unicode")?,
            )?;
        }
        let profile = load_explicit_profile(&config_path)?;
        if scm_mode && (!config_path.is_absolute() || !profile.engine.listen.ip().is_loopback()) {
            return Err(
                "SCM candidate requires an absolute config path and loopback-only SOCKS listener"
                    .into(),
            );
        }
        if scm_mode && profile.ssh.is_some() {
            return Err(
                "SCM candidate refuses managed SSH until secure service-account identity and configuration ACLs are proven".into(),
            );
        }
        let engine = Arc::new(Engine::new(profile.engine).map_err(|e| e.to_string())?);
        let mut ssh = None;
        let mut worker = None;
        let gate_ready = Arc::new(AtomicBool::new(false));
        if let Some(config) = profile.ssh.clone() {
            let endpoint = Endpoint {
                host: "127.0.0.1".into(),
                port: config.local_port,
            };
            // Gate must be CLOSED before the SOCKS listener becomes reachable.
            engine
                .set_upstream_gate(Some(endpoint.clone()), false, 0)
                .map_err(|e| e.to_string())?;
            let supervisor = Arc::new(Supervisor::new(config).map_err(|e| e.to_string())?);
            engine.start().map_err(|e| e.to_string())?;
            if let Err(error) = supervisor.start() {
                let _ = engine.stop();
                return Err(error.to_string());
            }
            let stop = Arc::new(AtomicBool::new(false));
            let signal = stop.clone();
            let watched = supervisor.clone();
            let gated = engine.clone();
            let tracked = gate_ready.clone();
            let task = thread::Builder::new()
                .name("flowbridge-managed-ssh-gate".into())
                .spawn(move || {
                    let mut previous = false;
                    while !signal.load(Ordering::Acquire) {
                        let state = watched.snapshot().status;
                        let ready = state.state == "ready" && state.pid.is_some();
                        if ready != previous {
                            if gated
                                .set_upstream_gate(Some(endpoint.clone()), ready, 0)
                                .is_err()
                            {
                                let _ = gated.stop();
                                break;
                            }
                            tracked.store(ready, Ordering::Release);
                            previous = ready;
                        }
                        thread::sleep(Duration::from_millis(50));
                    }
                    let _ = gated.set_upstream_gate(Some(endpoint), false, 0);
                    tracked.store(false, Ordering::Release);
                });
            match task {
                Ok(task) => worker = Some(GateWorker { stop, task }),
                Err(error) => {
                    let _ = engine.stop();
                    let _ = supervisor.stop();
                    return Err(format!("managed SSH gate worker failed: {error}"));
                }
            }
            ssh = Some(supervisor);
        } else {
            engine.start().map_err(|e| e.to_string())?;
        }
        Ok(Self {
            engine,
            config_path,
            scm_mode,
            ssh,
            ssh_config: profile.ssh,
            gate_worker: Mutex::new(worker),
            gate_ready,
        })
    }

    pub(crate) fn stop_engine(&self) -> Result<(), String> {
        // Shutdown is a best-effort sequence of INDEPENDENT cleanup operations,
        // not a chain of short-circuiting Results. A failed gate close, engine
        // join, or worker join must not skip terminating our managed SSH child.
        // Preserve every cleanup failure for the caller and SCM exit status.
        let worker = self
            .gate_worker
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take();
        let joined = if let Some(worker) = worker {
            worker.stop.store(true, Ordering::Release);
            worker.task.join().is_ok()
        } else {
            true
        };
        self.gate_ready.store(false, Ordering::Release);
        let mut failures = Vec::new();
        if !joined {
            failures.push("managed SSH gate worker panicked".to_owned());
        }
        if let Some(config) = &self.ssh_config {
            let endpoint = Endpoint {
                host: "127.0.0.1".into(),
                port: config.local_port,
            };
            if let Err(error) = self.engine.set_upstream_gate(Some(endpoint), false, 0) {
                failures.push(format!("managed SSH gate close failed: {error}"));
            }
        }
        if let Err(error) = self.engine.stop() {
            failures.push(format!("SOCKS engine stop failed: {error}"));
        }
        if let Some(supervisor) = &self.ssh {
            if let Err(error) = supervisor.stop() {
                failures.push(format!("managed SSH stop failed: {error}"));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }

    pub(crate) fn status(&self) -> Value {
        let s = self.engine.snapshot().status;
        let ssh = self.ssh.as_ref().map(|supervisor| {
            let state = supervisor.snapshot().status;
            json!({
                "state": state.state,
                "socks_ready_observed": state.state == "ready" && state.pid.is_some(),
                "local_port": state.local_port,
                "restarts": state.restarts,
                "diagnostic_code": state.diagnostic_code,
                "host_key_or_credentials_reported": false
            })
        });
        json!({
            "ok": true,
            "mode": if self.ssh.is_some() {
                if self.scm_mode { "scm_rust_owned_ssh_socks_candidate" } else { "foreground_rust_owned_ssh_socks_candidate" }
            } else if self.scm_mode { "scm_explicit_socks_only" } else { "foreground_explicit_socks_only" },
            "managed_ssh": ssh,
            "managed_ssh_gate_ready": self.gate_ready.load(Ordering::Acquire),
            "scm_service_installed": self.scm_mode,
            "scm_service_running": self.scm_mode,
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
                let result = load_explicit_profile(&self.config_path).and_then(|next| {
                    match (
                        serde_json::to_value(&next.ssh),
                        serde_json::to_value(&self.ssh_config),
                    ) {
                        (Ok(next), Ok(current)) if next == current => {}
                        _ => return Err(
                            "SSH profile changes require a stopped replacement and revalidation"
                                .into(),
                        ),
                    }
                    self.engine.reload(next.engine).map_err(|e| e.to_string())
                });
                match result {
                    Ok(_) => (self.status(), false),
                    Err(e) => (
                        json!({"ok":false,"error":e,"config_unchanged":true,"release_accepted":false}),
                        false,
                    ),
                }
            }
            Request::Stop {} => {
                let result = self.stop_engine();
                match result {
                    Ok(()) => (self.status(), true),
                    // Do not report a clean control/SCM termination when any
                    // resource failed to stop. The control service will either
                    // allow a retry or fail its engine health check visibly.
                    Err(e) => (
                        json!({"ok":false,"error":e,"release_accepted":false}),
                        false,
                    ),
                }
            }
        }
    }
}

#[cfg(any(windows, test))]
impl Drop for Controller {
    fn drop(&mut self) {
        let _ = self.stop_engine();
    }
}

/// Starts a same-user foreground proxy/control process. No driver IOCTLs.
#[cfg(windows)]
pub fn serve_foreground(path: &str) -> Result<Value, String> {
    if path.is_empty() || path.len() > 4096 {
        return Err("control-serve requires one bounded config file path".into());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    // A competing or unauthorized pipe instance must prevent SOCKS startup.
    let waiting = crate::windows_control_pipe::reserve_first()?;
    let controller = Controller::open(PathBuf::from(path))?;
    runtime.block_on(crate::windows_control_pipe::serve(controller, waiting))
}

#[cfg(windows)]
pub(crate) fn serve_scm(path: &Path) -> Result<Value, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    // Reserve the first restricted control-pipe instance before exposing even
    // a transient SOCKS listener. No SCM RUNNING before both are ready.
    let waiting = crate::windows_control_pipe::reserve_first()?;
    let controller = Controller::open_with_mode(path.to_path_buf(), true)?;
    runtime.block_on(crate::windows_control_pipe::serve(controller, waiting))
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
    fn scm_candidate_rejects_non_loopback_and_has_no_native_authority() {
        let mut invalid = config();
        invalid.listen = "0.0.0.0:0".parse().unwrap();
        let file = ConfigFile::new(&invalid);
        assert!(Controller::open_with_mode(file.0.clone(), true).is_err());
        let valid = config();
        file.write(&valid);
        let scm = Controller::open_with_mode(file.0.clone(), true).unwrap();
        let report = scm.status();
        assert_eq!(report["mode"], "scm_explicit_socks_only");
        assert_eq!(report["scm_service_running"], true);
        assert_eq!(report["driver_capture_active"], false);
        assert_eq!(report["protected_redirect_available"], false);
        assert_eq!(report["dns_leak_free"], false);
        assert_eq!(report["release_accepted"], false);
        scm.stop_engine().unwrap();
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
    #[test]
    fn gate_worker_failure_does_not_skip_engine_stop_or_claim_clean_exit() {
        let cfg = config();
        let file = ConfigFile::new(&cfg);
        let mut controller = Controller::open(file.0.clone()).unwrap();
        assert!(controller.status()["engine"]["running"].as_bool().unwrap());

        // A real SOCKS listener is active. Inject only a gate-worker join
        // failure; cleanup must still close the listener and decline the
        // success/exit signal sent to the SCM/control transport.
        let task = std::thread::spawn(|| panic!("intentional gate worker failure"));
        *controller.gate_worker.lock().unwrap() = Some(GateWorker {
            stop: Arc::new(AtomicBool::new(false)),
            task,
        });
        let (report, clean_exit) = controller.execute(br#"{"command":"stop"}"#);
        assert_eq!(report["ok"], false);
        assert_eq!(report["release_accepted"], false);
        assert!(!clean_exit);
        assert_eq!(controller.status()["engine"]["running"], false);
        assert!(std::net::TcpStream::connect_timeout(
            &cfg.listen,
            std::time::Duration::from_millis(100)
        )
        .is_err());
        // The resources remain idempotently stoppable after the fault.
        controller.stop_engine().unwrap();
    }

    #[test]
    fn managed_ssh_envelope_refuses_direct_identity_and_mutable_carrier() {
        use flowbridge_core::{Endpoint, Proxy, ProxyKind};
        let mut engine = config();
        let ssh = SshConfig {
            host: "127.0.0.1".into(),
            user: "testuser".into(),
            local_port: 17415,
            ssh_executable: Some(if cfg!(windows) {
                r"C:\Windows\System32\OpenSSH\ssh.exe".into()
            } else {
                "/usr/bin/ssh".into()
            }),
            identity_file: Some(if cfg!(windows) {
                r"C:\flowbridge-test\id_ed25519".into()
            } else {
                "/tmp/flowbridge-test/id_ed25519".into()
            }),
            known_hosts_file: Some(if cfg!(windows) {
                r"C:\flowbridge-test\known_hosts".into()
            } else {
                "/tmp/flowbridge-test/known_hosts".into()
            }),
            ..Default::default()
        };
        engine.proxies.push(Proxy {
            id: "owned".into(),
            kind: ProxyKind::Socks5,
            endpoint: Endpoint {
                host: "127.0.0.1".into(),
                port: ssh.local_port,
            },
            username: None,
            password_env: None,
        });
        engine.default_action = Action::Proxy { id: "owned".into() };
        assert!(validate_managed_route(&engine, &ssh).is_ok());
        let file = ConfigFile::new(&engine);
        let valid = serde_json::json!({
            "consent": "RUST_MANAGED_SSH_SOCKS_CANDIDATE",
            "engine": engine,
            "ssh": ssh
        });
        std::fs::write(&file.0, valid.to_string()).unwrap();
        assert!(load_explicit_profile(&file.0).unwrap().ssh.is_some());
        // SCM paths are administrative, possibly LocalSystem. Never let an
        // owner-writable SSH executable/key path cross that privilege boundary.
        assert!(Controller::open_with_mode(file.0.clone(), true).is_err());

        let mut denied = valid.clone();
        denied["consent"] = "UNSAFE".into();
        std::fs::write(&file.0, denied.to_string()).unwrap();
        assert!(load_explicit_profile(&file.0).is_err());
        let mut denied = valid.clone();
        denied["engine"]["default_action"] = serde_json::json!({"type": "direct"});
        std::fs::write(&file.0, denied.to_string()).unwrap();
        assert!(load_explicit_profile(&file.0).is_err());
        let mut denied = valid.clone();
        denied["engine"]["proxies"][0]["endpoint"]["port"] = 12345.into();
        std::fs::write(&file.0, denied.to_string()).unwrap();
        assert!(load_explicit_profile(&file.0).is_err());
        let mut denied = valid.clone();
        denied["ssh"]["known_hosts_file"] = serde_json::Value::Null;
        std::fs::write(&file.0, denied.to_string()).unwrap();
        assert!(load_explicit_profile(&file.0).is_err());
        let mut denied = valid.clone();
        denied["engine"]["rules"] = serde_json::json!([{
            "id":"hidden-direct","enabled":true,"applications":[],
            "hosts":[],"networks":[],"ports":[],"action":{"type":"direct"}
        }]);
        std::fs::write(&file.0, denied.to_string()).unwrap();
        assert!(load_explicit_profile(&file.0).is_err());
    }
}
