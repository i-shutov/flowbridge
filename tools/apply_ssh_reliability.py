"""One-shot exact-match migration, run only on the isolated working branch.
No user keys, settings or external destinations are used.
"""
from pathlib import Path

def edit(path, old, new, count=1):
    p = Path(path)
    text = p.read_text(encoding='utf-8')
    if text.count(old) != count:
        raise RuntimeError(f'{path}: expected {count} occurrences; found {text.count(old)}')
    p.write_text(text.replace(old, new), encoding='utf-8')

def write(path, text):
    p = Path(path)
    if p.exists(): raise RuntimeError(f'Already exists: {path}')
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding='utf-8')

T = 'crates/flowbridge-tunnel/src/lib.rs'
edit(T, '    pub health_check_timeout_ms: u64,', '''    pub health_check_timeout_ms: u64,
    pub health_failure_threshold: u32,
    pub overload_quiet_ms: u64,''')
edit(T, '            health_check_timeout_ms: 1000,', '''            health_check_timeout_ms: 1000,
            health_failure_threshold: 3,
            overload_quiet_ms: 5000,''')
edit(T, '            ("startup_timeout_ms", self.startup_timeout_ms, 1000, 120000),', '''            ("health_failure_threshold", u64::from(self.health_failure_threshold), 1, 20),
            ("overload_quiet_ms", self.overload_quiet_ms, 100, 300000),
            ("startup_timeout_ms", self.startup_timeout_ms, 1000, 120000),''')
edit(T, "    pub parent_exit_cleanup: &'static str,", '''    pub parent_exit_cleanup: &'static str,
    pub backend_path: Option<String>,
    pub backend_version: Option<String>,
    pub diagnostic_code: Option<String>,
    pub resource_exhaustion_count: u64,
    pub last_resource_error_unix_ms: Option<u64>,
    pub health_failures: u32,''')
edit(T, '    fatal: Option<String>,', '''    fatal: Option<String>,
    last_resource_error: Option<Instant>,
    last_resource_event: Option<Instant>,
    recovery_checks: u32,''')
edit(T, '''                let executable = if cfg!(target_os = "macos") {
                    "/usr/bin/ssh"
                } else {
                    "ssh"
                };
                let mut command = Command::new(executable);''', '''                let mut command = Command::new(resolve_ssh()?);''')
edit(T, '            parent_exit_cleanup: if cfg!(windows) {', '''            backend_path: None,
            backend_version: None,
            diagnostic_code: None,
            resource_exhaustion_count: 0,
            last_resource_error_unix_ms: None,
            health_failures: 0,
            parent_exit_cleanup: if cfg!(windows) {''')
edit(T, '                fatal: None,', '''                fatal: None,
                last_resource_error: None,
                last_resource_event: None,
                recovery_checks: 0,''')
edit(T, '                "starting" | "ready" | "reconnecting"', '                "starting" | "ready" | "reconnecting" | "degraded"')
edit(T, '''            s.fatal = None;
            s.event("info", "starting managed OpenSSH dynamic forwarding");''', '''            s.fatal = None;
            s.last_resource_error = None;
            s.last_resource_event = None;
            s.recovery_checks = 0;
            s.status.diagnostic_code = None;
            s.status.health_failures = 0;
            s.event("info", "starting managed OpenSSH dynamic forwarding");''')
edit(T, '''            s.status.last_error = None;
            s.event("info", "managed SSH stopped; restart disabled");''', '''            s.status.last_error = None;
            s.status.diagnostic_code = None;
            s.status.health_failures = 0;
            s.last_resource_error = None;
            s.recovery_checks = 0;
            s.event("info", "managed SSH stopped; restart disabled");''')
edit(T, '''    let mut s = lock(state);
    if let Some(fatal) = fatal {''', '''    let mut s = lock(state);
    if lower.contains("too many open files") || lower.contains("no buffer space available") {
        let now = Instant::now();
        s.status.resource_exhaustion_count = s.status.resource_exhaustion_count.saturating_add(1);
        s.status.last_resource_error_unix_ms = Some(
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_millis().min(u128::from(u64::MAX)) as u64);
        s.status.diagnostic_code = Some("ssh_resource_exhausted".into());
        s.status.state = "degraded".into();
        s.status.last_error = Some("SSH resources exhausted: new connections paused; existing streams retained. Reduce concurrency or select a tested backend. No automatic restart while overloaded.".into());
        s.last_resource_error = Some(now);
        s.recovery_checks = 0;
        // Count every occurrence; bound repetitive diagnostics independently.
        if s.last_resource_event.is_some_and(|last| last.elapsed() < Duration::from_secs(1)) {
            return;
        }
        s.last_resource_event = Some(now);
        let total = s.status.resource_exhaustion_count;
        s.event("error", format!("SSH resource exhaustion ({total} occurrences): {text}"));
    }
    if let Some(fatal) = fatal {''')
edit(T, '        let mut child = match launcher(&config).and_then(ChildGuard::spawn) {', '''        let launched = launcher(&config).and_then(|command| {
            let executable = command.get_program().to_owned();
            let version = backend_version(&executable, &control);
            {
                let mut s = lock(&state);
                s.status.backend_path = Some(executable.to_string_lossy().into_owned());
                s.status.backend_version = version;
                s.status.health_failures = 0;
                s.status.diagnostic_code = None;
                s.last_resource_error = None;
                s.recovery_checks = 0;
            }
            if control.cancelled() {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "SSH start cancelled"));
            }
            ChildGuard::spawn(command)
        });
        let mut child = match launched {''')
edit(T, '''                if healthy && matches!(child.child.try_wait(), Ok(None)) {
                    if !was_ready {
                        let mut s = lock(&state);
                        s.status.state = "ready".into();
                        s.status.last_error = None;
                        s.event("info","OpenSSH is alive and local SOCKS5 greeting is ready; existing TCP sessions do not survive a later SSH restart");
                        was_ready = true;
                        failures = 0;
                    }
                } else if was_ready {
                    break Some("local SOCKS health check failed".into());
                } else if started.elapsed() >= Duration::from_millis(config.startup_timeout_ms) {
                    break Some("SSH startup deadline expired before SOCKS readiness".into());
                }''', '''                let mut s = lock(&state);
                if healthy && matches!(child.child.try_wait(), Ok(None)) {
                    s.status.health_failures = 0;
                    let overload_recent = s.last_resource_error.is_some_and(|last|
                        last.elapsed() < Duration::from_millis(config.overload_quiet_ms));
                    if s.last_resource_error.is_some() {
                        if overload_recent { s.recovery_checks = 0; }
                        else { s.recovery_checks = s.recovery_checks.saturating_add(1); }
                    }
                    if s.last_resource_error.is_some() && s.recovery_checks < 2 {
                        s.status.state = "degraded".into();
                    } else {
                        if s.status.state != "ready" {
                            s.event("info", "SSH local SOCKS greeting ready; destination reachability is checked per connection, not by this probe");
                        }
                        s.last_resource_error = None;
                        s.recovery_checks = 0;
                        s.status.state = "ready".into();
                        s.status.last_error = None;
                        s.status.diagnostic_code = None;
                    }
                    was_ready = true;
                    failures = 0;
                } else if s.last_resource_error.is_some() {
                    // Do not destroy existing streams merely because an overloaded
                    // but live process cannot accept another health connection.
                    s.status.state = "degraded".into();
                    s.status.health_failures = s.status.health_failures.saturating_add(1);
                    s.recovery_checks = 0;
                } else if was_ready {
                    s.status.health_failures = s.status.health_failures.saturating_add(1);
                    s.status.state = "degraded".into();
                    s.status.diagnostic_code = Some("ssh_health_unresponsive".into());
                    s.status.last_error = Some("SOCKS health probe failed; confirming before restarting SSH".into());
                    if s.status.health_failures >= config.health_failure_threshold {
                        break Some("consecutive local SOCKS health checks failed".into());
                    }
                } else if started.elapsed() >= Duration::from_millis(config.startup_timeout_ms) {
                    break Some("SSH startup deadline expired before SOCKS readiness".into());
                }
                drop(s);''')
edit(T, 'fn supervise(config: Config,', '''fn resolve_ssh() -> io::Result<std::path::PathBuf> {
    if cfg!(target_os = "macos") {
        return std::fs::canonicalize("/usr/bin/ssh");
    }
    let name = if cfg!(windows) { "ssh.exe" } else { "ssh" };
    for directory in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        if !directory.is_absolute() { continue; }
        let path = directory.join(name);
        if path.is_file() { return std::fs::canonicalize(path); }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "OpenSSH was not found in an absolute PATH directory"))
}

fn backend_version(executable: &std::ffi::OsStr, control: &Control) -> Option<String> {
    let mut command = Command::new(executable);
    command.arg("-V");
    let mut child = ChildGuard::spawn(command).ok()?;
    let mut pipe = child.child.stderr.take()?;
    prepare_stderr(&pipe).ok()?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut output = Vec::new();
    let mut chunk = [0u8; 512];
    while !control.cancelled() && Instant::now() < deadline && output.len() < 4096 {
        match read_stderr(&mut pipe, &mut chunk) {
            Ok(0) => break,
            Ok(n) => output.extend_from_slice(&chunk[..n]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if matches!(child.child.try_wait(), Ok(Some(_))) { break; }
                if control.wait(Duration::from_millis(20)) { break; }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    child.terminate();
    String::from_utf8_lossy(&output).lines()
        .find(|line| line.starts_with("OpenSSH_"))
        .map(|line| line.chars().filter(|c| !c.is_control()).take(256).collect())
}

fn supervise(config: Config,''')
edit(T, '    #[test]\n    fn strict_config_and_arguments_do_not_allow_shell_or_host_key_overrides()', '''    #[test]
    fn overload_is_reported_coalesced_and_recovers_without_restarting() {
        let mut cfg = config();
        cfg.overload_quiet_ms = 300;
        let supervisor = supervisor(cfg, "ready");
        supervisor.start().unwrap();
        let ready = wait(&supervisor, |s| s.status.state == "ready");
        for _ in 0..10000 { stderr_line(&supervisor.state, b"accept: Too many open files"); }
        let overloaded = supervisor.snapshot();
        assert_eq!(overloaded.status.state, "degraded");
        assert_eq!(overloaded.status.diagnostic_code.as_deref(), Some("ssh_resource_exhausted"));
        assert_eq!(overloaded.status.resource_exhaustion_count, 10000);
        assert!(overloaded.events.len() < 20);
        assert_eq!(supervisor.start().unwrap().status.pid, ready.status.pid);
        let recovered = wait(&supervisor, |s| s.status.state == "ready");
        assert_eq!(recovered.status.pid, ready.status.pid);
        assert_eq!(recovered.status.restarts, 0);
        assert_eq!(recovered.status.resource_exhaustion_count, 10000);
        assert!(recovered.status.last_resource_error_unix_ms.is_some());
        supervisor.stop().unwrap();
    }

    #[test]
    fn overloaded_live_child_is_not_killed_when_health_probes_fail() {
        let mut cfg = config();
        cfg.overload_quiet_ms = 100;
        let supervisor = supervisor(cfg, "ready_then_stall");
        supervisor.start().unwrap();
        let ready = wait(&supervisor, |s| s.status.state == "ready");
        stderr_line(&supervisor.state, b"accept: Too many open files");
        thread::sleep(Duration::from_millis(900));
        let degraded = supervisor.snapshot();
        assert_eq!(degraded.status.state, "degraded");
        assert_eq!(degraded.status.pid, ready.status.pid);
        assert_eq!(degraded.status.restarts, 0);
        assert!(degraded.status.health_failures >= 1);
        let started = Instant::now();
        assert_eq!(supervisor.stop().unwrap().status.state, "stopped");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn strict_config_and_arguments_do_not_allow_shell_or_host_key_overrides()''')
W = 'native/windows/main.cpp'
edit(W, 'state=="reconnecting"?"Восстанавливается":state=="failed"', 'state=="reconnecting"?"Восстанавливается":state=="degraded"?"Перегрузка / диагностика":state=="failed"')
edit(W, '    setText(GetDlgItem(window,SshHealth),text);', '''    text+="\\nОшибок ресурсов: "+std::to_string(status.value("resource_exhaustion_count",uint64_t(0)));
    if(status.contains("backend_path")&&!status["backend_path"].is_null())text+=" · "+status["backend_path"].get<std::string>();
    if(status.contains("backend_version")&&!status["backend_version"].is_null())text+=" · "+status["backend_version"].get<std::string>();
    setText(GetDlgItem(window,SshHealth),text);''')
edit(W, 'setText(GetDlgItem(window,Badge),"●  SSH восстанавливается · SOCKS ждёт upstream");', 'setText(GetDlgItem(window,Badge),state=="degraded"?"●  SSH перегружен / проверяется · новые соединения ждут":"●  SSH восстанавливается · SOCKS ждёт upstream");')
S = 'native/macos/App/SSHController.swift'
edit(S, '"failed": "Ошибка SSH",', '"degraded": "SSH: перегрузка или проверка доступности", "failed": "Ошибка SSH",')
edit(S, '        if state == "ready" || state == "failed" || state == "stopped" {', '''        if let count = value["resource_exhaustion_count"] as? NSNumber, count.uint64Value > 0 {
            message += " · ошибок ресурсов: \\(count)"
        }
        if let backend = value["backend_version"] as? String { message += " · " + backend }
        if state == "ready" || state == "failed" || state == "stopped" {''')
A = 'native/macos/App/FlowBridgeApp.swift'
edit(A, '["starting", "ready", "reconnecting"]', '["starting", "ready", "reconnecting", "degraded"]')
edit(A, '        if ssh.state == "reconnecting" {', '        if ssh.state == "degraded" { return "SSH: требуется диагностика" }\n        if ssh.state == "reconnecting" {')
edit(A, 'desktop.busy || ssh.state == "reconnecting" ?', 'desktop.busy || ssh.state == "reconnecting" || ssh.state == "degraded" ?')
I = 'tests/ssh_real_integration.py'
edit(I, "        require(exact(client, 10) == b'\\x05\\x00\\x00\\x01' + bytes(6), 'SOCKS CONNECT failed')", '''        reply = exact(client, 10)
        require(reply == b'\\x05\\x00\\x00\\x01' + bytes(6),
                'SOCKS CONNECT failed; reply=' + reply.hex())''')
edit(I, "'health_check_interval_ms': 100,", "'health_check_interval_ms': 1000,")
edit(I, "'health_check_timeout_ms': 200,", "'health_check_timeout_ms': 3000,")
edit(I, "            report['error'] = str(error)\n            raise", '''            report['error'] = str(error)
            for label, handle, function in [
                ('ssh', supervisor, 'fb_ssh_snapshot_json'),
                ('untrusted_ssh', bad_supervisor, 'fb_ssh_snapshot_json'),
                ('engine', engine, 'fb_engine_snapshot_json'),
            ]:
                if handle:
                    try: report[label] = abi.call(function, handle)
                    except Exception as snapshot_error: report[label] = str(snapshot_error)
            raise''')
write('crates/flowbridge-runtime/src/admission.rs', r'''//! Shared per-loopback-upstream admission. Applies to explicitly managed routes;
//! external clients of the same SSH listener are outside this budget.
use flowbridge_core::Endpoint;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::{IpAddr, SocketAddr}, sync::{Arc, Mutex, OnceLock, Weak, atomic::{AtomicU64, Ordering}}, time::Duration};
use tokio::{sync::{OwnedSemaphorePermit, Semaphore}, time::Instant};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_flows: usize,
    pub max_opening: usize,
    pub max_queued: usize,
    pub wait_timeout_ms: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self { max_flows: 128, max_opening: 16, max_queued: 64, wait_timeout_ms: 10000 }
    }
}
impl Limits {
    fn validate(&self) -> Result<(), String> {
        if !(1..=4096).contains(&self.max_flows)
            || !(1..=self.max_flows).contains(&self.max_opening)
            || !(1..=4096).contains(&self.max_queued)
            || !(10..=120000).contains(&self.wait_timeout_ms) {
            return Err("invalid managed SSH admission limits".into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub limits: Limits,
    pub active_including_opening: usize,
    pub opening: usize,
    pub queued: usize,
    pub rejected: u64,
}
pub(crate) struct Budget {
    limits: Limits,
    active: Arc<Semaphore>,
    opening: Arc<Semaphore>,
    queued: Arc<Semaphore>,
    rejected: AtomicU64,
}
impl Budget {
    fn new(limits: Limits) -> Self {
        Self { active: Arc::new(Semaphore::new(limits.max_flows)),
            opening: Arc::new(Semaphore::new(limits.max_opening)),
            queued: Arc::new(Semaphore::new(limits.max_queued)),
            rejected: AtomicU64::new(0), limits }
    }
    pub(crate) fn shared(endpoint: &Endpoint, limits: Limits) -> Result<Arc<Self>, String> {
        limits.validate()?;
        let ip: IpAddr = endpoint.host.parse().map_err(|_| "managed upstream must be an IP literal")?;
        let ip = match ip { IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip), _ => ip };
        let key = SocketAddr::new(ip, endpoint.port);
        static REGISTRY: OnceLock<Mutex<BTreeMap<SocketAddr, Weak<Budget>>>> = OnceLock::new();
        let mut registry = REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock().unwrap_or_else(|e| e.into_inner());
        registry.retain(|_, weak| weak.strong_count() > 0);
        if let Some(existing) = registry.get(&key).and_then(Weak::upgrade) {
            if existing.limits != limits {
                return Err("the shared SSH upstream already has different limits; detach all engines using it before changing limits".into());
            }
            return Ok(existing);
        }
        if registry.len() >= 1024 { return Err("managed upstream registry is full".into()); }
        let budget = Arc::new(Self::new(limits));
        registry.insert(key, Arc::downgrade(&budget));
        Ok(budget)
    }
    pub(crate) fn snapshot(&self) -> Snapshot {
        Snapshot { limits: self.limits.clone(),
            active_including_opening: self.limits.max_flows - self.active.available_permits(),
            opening: self.limits.max_opening - self.opening.available_permits(),
            queued: self.limits.max_queued - self.queued.available_permits(),
            rejected: self.rejected.load(Ordering::Relaxed) }
    }
    pub(crate) fn enqueue(self: &Arc<Self>) -> Result<Waiter, String> {
        match self.queued.clone().try_acquire_owned() {
            Ok(permit) => Ok(Waiter { budget: self.clone(), _queued: permit,
                deadline: Instant::now() + Duration::from_millis(self.limits.wait_timeout_ms) }),
            Err(_) => {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                Err("managed SSH queue is full; no direct fallback".into())
            }
        }
    }
}
pub(crate) struct Waiter {
    budget: Arc<Budget>,
    _queued: OwnedSemaphorePermit,
    pub(crate) deadline: Instant,
}
pub(crate) struct Admission {
    _budget: Arc<Budget>,
    _active: OwnedSemaphorePermit,
    opening: Option<OwnedSemaphorePermit>,
}
impl Admission {
    pub(crate) fn connected(&mut self) { self.opening.take(); }
}
impl Waiter {
    pub(crate) async fn admit(self) -> Result<Admission, String> {
        let result = tokio::time::timeout_at(self.deadline, async {
            let active = self.budget.active.clone().acquire_owned().await.map_err(|_| "SSH budget closed")?;
            let opening = self.budget.opening.clone().acquire_owned().await.map_err(|_| "SSH opening budget closed")?;
            Ok(Admission { _budget: self.budget.clone(), _active: active, opening: Some(opening) })
        }).await;
        match result {
            Ok(result) => result,
            Err(_) => {
                self.budget.rejected.fetch_add(1, Ordering::Relaxed);
                Err("managed SSH capacity deadline expired; no direct fallback".into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn opening_active_queue_and_timeout_are_independently_bounded() {
        let budget = Arc::new(Budget::new(Limits { max_flows: 2, max_opening: 1, max_queued: 1, wait_timeout_ms: 30 }));
        let mut first = budget.enqueue().unwrap().admit().await.unwrap();
        assert_eq!(budget.snapshot().opening, 1);
        let waiting = budget.enqueue().unwrap();
        assert!(budget.enqueue().is_err());
        assert!(waiting.admit().await.is_err());
        first.connected();
        let second = budget.enqueue().unwrap().admit().await.unwrap();
        assert_eq!(budget.snapshot().active_including_opening, 2);
        drop(first); drop(second);
        let status = budget.snapshot();
        assert_eq!((status.active_including_opening, status.opening, status.queued), (0, 0, 0));
        assert_eq!(status.rejected, 2);
    }
    #[tokio::test]
    async fn cancellation_returns_all_permits() {
        let budget = Arc::new(Budget::new(Limits { max_flows: 2, max_opening: 1, max_queued: 2, wait_timeout_ms: 10000 }));
        let first = budget.enqueue().unwrap().admit().await.unwrap();
        let pending = tokio::spawn(budget.enqueue().unwrap().admit());
        for _ in 0..10 { tokio::task::yield_now().await; }
        pending.abort(); let _ = pending.await;
        drop(first);
        let status = budget.snapshot();
        assert_eq!((status.active_including_opening, status.opening, status.queued), (0, 0, 0));
    }
    #[test]
    fn engines_share_canonical_endpoint_and_reject_conflicting_limits() {
        let endpoint = Endpoint { host: "127.0.0.1".into(), port: 17419 };
        let first = Budget::shared(&endpoint, Limits::default()).unwrap();
        let mapped = Endpoint { host: "::ffff:127.0.0.1".into(), port: 17419 };
        assert!(Arc::ptr_eq(&first, &Budget::shared(&mapped, Limits::default()).unwrap()));
        assert!(Budget::shared(&endpoint, Limits { max_flows: 64, ..Limits::default() }).is_err());
        drop(first);
        assert!(Budget::shared(&endpoint, Limits { max_flows: 64, ..Limits::default() }).is_ok());
    }
    #[test]
    fn malformed_limits_fail_closed() {
        assert!(Limits { max_flows: 0, ..Limits::default() }.validate().is_err());
        assert!(Limits { max_queued: 100000, ..Limits::default() }.validate().is_err());
        assert!(serde_json::from_str::<Limits>(r#"{"unlimited":true}"#).is_err());
    }
}
''')
R = 'crates/flowbridge-runtime/src/lib.rs'
edit(R, 'use flowbridge_core::{', 'pub mod admission;\nuse flowbridge_core::{')
edit(R, '''pub struct Snapshot {
    pub status: Status,''', '''pub struct Snapshot {
    pub status: Status,
    pub managed_upstream: Option<admission::Snapshot>,''')
edit(R, '''    grace: Duration,
}''', '''    grace: Duration,
    budget: Option<Arc<admission::Budget>>,
}''')
edit(R, '                grace: Duration::ZERO,\n', '                grace: Duration::ZERO,\n                budget: None,\n')
edit(R, '''        Snapshot {
            status: s.status.clone(),''', '''        Snapshot {
            status: s.status.clone(),
            managed_upstream: self.upstream_gate.borrow().budget.as_ref().map(|b| b.snapshot()),''')
edit(R, '''        mut endpoint: Option<Endpoint>,
        ready: bool,
        grace_ms: u64,
    ) -> Result<Status, RuntimeError> {
        if grace_ms''', '''        endpoint: Option<Endpoint>,
        ready: bool,
        grace_ms: u64,
    ) -> Result<Status, RuntimeError> {
        self.set_upstream_gate_with_limits(endpoint, ready, grace_ms, admission::Limits::default())
    }
    pub fn set_upstream_gate_with_limits(
        &self,
        mut endpoint: Option<Endpoint>,
        ready: bool,
        grace_ms: u64,
        limits: admission::Limits,
    ) -> Result<Status, RuntimeError> {
        if grace_ms''')
edit(R, '''        self.upstream_gate.send_replace(UpstreamGate {
            endpoint,
            ready,
            grace: Duration::from_millis(grace_ms),
''', '''        let budget = endpoint.as_ref().map(|e| admission::Budget::shared(e, limits))
            .transpose().map_err(RuntimeError)?;
        self.upstream_gate.send_replace(UpstreamGate {
            endpoint,
            ready,
            grace: Duration::from_millis(grace_ms),
            budget,
''')
edit(R, '''    if let Some(first) = route.first() {
        let initial = upstream_gate.borrow().clone();''', '''    let mut waiter = None;
    if let Some(first) = route.first() {
        let initial = upstream_gate.borrow().clone();
        if initial.matches(&first.endpoint) {
            if let Some(budget) = &initial.budget {
                match budget.enqueue() {
                    Ok(value) => waiter = Some(value),
                    Err(error) => { let _ = reply_socks5(&mut client, 1).await; return Err(error); }
                }
            }
        }''')
edit(R, '            let deadline = Instant::now() + initial.grace;', '''            let deadline = waiter.as_ref().map(|w| w.deadline)
                .unwrap_or(Instant::now() + initial.grace)
                .min(Instant::now() + initial.grace);''')
edit(R, '    let upstream = match connect_route_guarded(', '''    let mut admission = if let Some(waiter) = waiter {
        if let Some(connection) = lock(&guard.state).connections.get_mut(&guard.id) {
            connection.state = "waiting_for_capacity".into();
        }
        match waiter.admit().await {
            Ok(value) => Some(value),
            Err(error) => { let _ = reply_socks5(&mut client, 1).await; return Err(error); }
        }
    } else { None };
    let paused = route.first().is_some_and(|first| upstream_gate.borrow().pauses(&first.endpoint));
    if paused {
        let _ = reply_socks5(&mut client, 1).await;
        return Err("managed SSH became unavailable while awaiting capacity".into());
    }
    let upstream = match connect_route_guarded(''')
edit(R, '    reply_socks5(&mut client, 0)\n', '    if let Some(admission) = &mut admission { admission.connected(); }\n    reply_socks5(&mut client, 0)\n')
edit(R, '''    fn pauses(&self, first_hop: &Endpoint) -> bool {
        !self.ready
            && self.endpoint.as_ref().is_some_and(|endpoint| {
                endpoint.port == first_hop.port
                    && endpoint.host.parse::<IpAddr>().ok() == first_hop.host.parse::<IpAddr>().ok()
            })
    }''', '''    fn matches(&self, first_hop: &Endpoint) -> bool {
        fn normalized(host: &str) -> Option<IpAddr> {
            host.parse::<IpAddr>().ok().map(|ip| match ip {
                IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
                _ => ip,
            })
        }
        self.endpoint.as_ref().is_some_and(|endpoint|
            endpoint.port == first_hop.port && normalized(&endpoint.host).is_some()
                && normalized(&endpoint.host) == normalized(&first_hop.host))
    }
    fn pauses(&self, first_hop: &Endpoint) -> bool {
        !self.ready && self.matches(first_hop)
    }''')
F = 'crates/flowbridge-ffi/src/lib.rs'
edit(F, '''    grace_ms: u64,
}
fn default_gate_grace()''', '''    grace_ms: u64,
    #[serde(default)]
    limits: flowbridge_runtime::admission::Limits,
}
fn default_gate_grace()''')
edit(F, 'engine.set_upstream_gate(gate.endpoint,gate.ready,gate.grace_ms)', 'engine.set_upstream_gate_with_limits(gate.endpoint,gate.ready,gate.grace_ms,gate.limits)')
write('docs/SSH_RELIABILITY.md', '''# SSH diagnostics and managed admission

Implementation checkpoint, not a production-release claim.

SSH status reports the resolved executable, a bounded ssh -V probe, resource-error count/time, diagnostic code and consecutive health failures. Resource exhaustion places the supervisor in degraded. Native UIs close the existing new-flow gate for every state except ready. Repeated errors are counted but rate-limited in logs. An overloaded live SSH child is not killed for failed health probes. Two successful checks after the quiet interval reopen the gate; user Stop still terminates the owned child. Existing streams cannot be migrated or resumed after actual SSH death.

health_failure_threshold (default 3, 1..20) and overload_quiet_ms (default 5000, 100..300000) are accepted in SSH JSON. A SOCKS greeting does not prove remote connectivity.

The explicit SOCKS runtime shares an admission budget across engines using the same managed loopback endpoint. Gate JSON accepts limits: max_flows (128), max_opening (16), max_queued (64), wait_timeout_ms (10000). Permits return on cancellation, timeout and disconnect. No DIRECT or local-DNS fallback. Conflicting active limits are rejected. Counts appear as managed_upstream in the engine snapshot. Defaults are conservative, not a measured universal capacity.

Remaining release gates: native WFP/NE path budget integration, selected Windows backend stress/soak tests, fair per-application admission, independent SSH pool, DNS capture for applications resolving before CONNECT, signing and small-screen/DPI acceptance. Unmanaged external clients of the SSH listener are outside this process-local budget. Issue #7 remains open.
''')
print('Exact source changes applied successfully')
