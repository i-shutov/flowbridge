//! Managed OpenSSH dynamic forwarding. No shell, password storage, terminal or
//! implicit host-key enrollment. Unix callers must explicitly stop: abrupt parent
//! process death can leave OpenSSH running. Windows uses a kill-on-close job.
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Child, ChildStderr, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex, MutexGuard,
    },
    thread,
    time::{Duration, Instant},
};

const MAX_EVENTS: usize = 256;
const MAX_STDERR_LINES: usize = 32;
const MAX_LINE: usize = 2048;
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct TunnelError(pub String);
impl From<io::Error> for TunnelError {
    fn from(e: io::Error) -> Self {
        Self(e.to_string())
    }
}
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub host: String,
    pub user: String,
    pub port: u16,
    pub local_port: u16,
    pub identity_file: Option<String>,
    pub known_hosts_file: Option<String>,
    /// Opt-in, absolute path to a user-reviewed OpenSSH-compatible client.
    /// Never auto-switch to another backend after authentication or overload.
    pub ssh_executable: Option<String>,
    pub compression: bool,
    pub verbose_diagnostics: bool,
    pub server_alive_interval_secs: u64,
    pub server_alive_count_max: u32,
    pub connect_timeout_secs: u64,
    pub health_check_interval_ms: u64,
    pub health_check_timeout_ms: u64,
    pub health_failure_threshold: u32,
    pub overload_quiet_ms: u64,
    pub startup_timeout_ms: u64,
    pub restart_initial_delay_ms: u64,
    pub restart_max_delay_ms: u64,
    pub max_restarts: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            host: String::new(),
            user: String::new(),
            port: 22,
            local_port: 1080,
            identity_file: None,
            known_hosts_file: None,
            ssh_executable: None,
            compression: false,
            verbose_diagnostics: false,
            server_alive_interval_secs: 15,
            server_alive_count_max: 3,
            connect_timeout_secs: 10,
            health_check_interval_ms: 1000,
            health_check_timeout_ms: 1000,
            health_failure_threshold: 3,
            overload_quiet_ms: 5000,
            startup_timeout_ms: 15000,
            restart_initial_delay_ms: 1000,
            restart_max_delay_ms: 30000,
            max_restarts: 0,
        }
    }
}
impl Config {
    pub fn from_json(text: &str) -> Result<Self, TunnelError> {
        if text.len() > 65536 {
            return Err(TunnelError("SSH configuration exceeds64KiB".into()));
        }
        let config: Self = serde_json::from_str(text).map_err(|e| TunnelError(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<(), TunnelError> {
        if self.host.is_empty()
            || self.host.len() > 253
            || self.host.starts_with('-')
            || !self
                .host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-:_[]%".contains(&b))
        {
            return Err(TunnelError(
                "SSH host must be an ASCII hostname or IP without whitespace, options, or a URI"
                    .into(),
            ));
        }
        if self.user.is_empty()
            || self.user.len() > 128
            || self.user.starts_with('-')
            || !self
                .user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(TunnelError(
                "SSH user must contain1..128 ASCII letters, digits, dots, underscores or hyphens"
                    .into(),
            ));
        }
        if self.port == 0 || self.local_port == 0 {
            return Err(TunnelError(
                "SSH and local SOCKS ports must be nonzero".into(),
            ));
        }
        for path in [&self.identity_file, &self.known_hosts_file]
            .into_iter()
            .flatten()
        {
            if path.is_empty()
                || path.len() > 4096
                || path.chars().any(char::is_control)
                || path.contains('"')
            {
                return Err(TunnelError(
                    "SSH file paths must be bounded and contain no controls or quotes".into(),
                ));
            }
        }
        if let Some(path) = &self.ssh_executable {
            let executable = std::path::Path::new(path);
            // Rust canonicalize on Windows uses the local drive device prefix
            // \\?\C:\... . Distinguish this explicitly from a UNC
            // \\server\share or \\?\UNC\server\share path; the old
            // prefix-only test rejected our own canonical absolute local exe.
            let local_extended_drive = cfg!(windows)
                && path.strip_prefix("\\\\?\\").is_some_and(|value| {
                    let bytes = value.as_bytes();
                    bytes.len() >= 3
                        && bytes[0].is_ascii_alphabetic()
                        && bytes[1] == b':'
                        && bytes[2] == b'\\'
                });
            if path.is_empty()
                || path.len() > 4096
                || path.chars().any(char::is_control)
                || path.contains('"')
                || !executable.is_absolute()
                || path.starts_with("//")
                || (path.starts_with("\\\\") && !local_extended_drive)
                || (cfg!(windows)
                    && !executable
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("exe")))
            {
                return Err(TunnelError(
                    "SSH executable must be an absolute local executable path, not an option, URI or network share".into(),
                ));
            }
            if cfg!(target_os = "macos") && executable != std::path::Path::new("/usr/bin/ssh") {
                return Err(TunnelError(
                    "macOS native capture requires /usr/bin/ssh for its verified signing-ID bypass"
                        .into(),
                ));
            }
        }
        for (name, value, min, max) in [
            (
                "server_alive_interval_secs",
                self.server_alive_interval_secs,
                1,
                3600,
            ),
            (
                "server_alive_count_max",
                u64::from(self.server_alive_count_max),
                1,
                100,
            ),
            ("connect_timeout_secs", self.connect_timeout_secs, 1, 120),
            (
                "health_check_interval_ms",
                self.health_check_interval_ms,
                100,
                60000,
            ),
            (
                "health_check_timeout_ms",
                self.health_check_timeout_ms,
                100,
                10000,
            ),
            (
                "health_failure_threshold",
                u64::from(self.health_failure_threshold),
                1,
                20,
            ),
            ("overload_quiet_ms", self.overload_quiet_ms, 100, 300000),
            ("startup_timeout_ms", self.startup_timeout_ms, 1000, 120000),
            (
                "restart_initial_delay_ms",
                self.restart_initial_delay_ms,
                100,
                60000,
            ),
            (
                "restart_max_delay_ms",
                self.restart_max_delay_ms,
                self.restart_initial_delay_ms,
                300000,
            ),
            ("max_restarts", self.max_restarts, 0, 100000),
        ] {
            if value < min || value > max {
                return Err(TunnelError(format!("{name} must be between{min} and{max}")));
            }
        }
        Ok(())
    }
    fn dns_discovery_arguments(&self) -> Vec<String> {
        let mut source = self.arguments().into_iter();
        let mut args = Vec::new();
        while let Some(arg) = source.next() {
            if arg == "-N" {
                continue;
            }
            if arg == "-D" {
                source.next();
                continue;
            }
            args.push(arg);
        }
        args.push("printf 'FLOWBRIDGE_DNS_BEGIN\\n' >&2; cat /etc/resolv.conf >&2; printf '\\nFLOWBRIDGE_DNS_END\\n' >&2".into());
        args
    }
    /// Arguments are passed directly to OpenSSH; no command shell is involved.
    pub fn arguments(&self) -> Vec<String> {
        let mut args = vec![
            "-F".into(),
            "none".into(),
            "-N".into(),
            "-T".into(),
            "-n".into(),
            "-a".into(),
            "-x".into(),
            "-D".into(),
            format!("127.0.0.1:{}", self.local_port),
            "-p".into(),
            self.port.to_string(),
            "-l".into(),
            self.user.clone(),
        ];
        for option in [
            "BatchMode=yes".into(),
            "StrictHostKeyChecking=yes".into(),
            "ExitOnForwardFailure=yes".into(),
            "PreferredAuthentications=publickey".into(),
            "PasswordAuthentication=no".into(),
            "KbdInteractiveAuthentication=no".into(),
            "ControlMaster=no".into(),
            "ControlPath=none".into(),
            format!("ServerAliveInterval={}", self.server_alive_interval_secs),
            format!("ServerAliveCountMax={}", self.server_alive_count_max),
            format!("ConnectTimeout={}", self.connect_timeout_secs),
            "ConnectionAttempts=1".into(),
            format!(
                "LogLevel={}",
                if self.verbose_diagnostics {
                    "DEBUG3"
                } else {
                    "INFO"
                }
            ),
            format!(
                "Compression={}",
                if self.compression { "yes" } else { "no" }
            ),
        ] {
            args.push("-o".into());
            args.push(option);
        }
        if let Some(path) = &self.identity_file {
            args.extend(["-i".into(), path.clone()]);
        }
        if let Some(path) = &self.known_hosts_file {
            // -o values still use OpenSSH configuration grammar even though
            // Command avoids the shell. Quote spaces and protect backslashes.
            let path = if cfg!(windows) {
                path.replace('\\', "/")
            } else {
                path.replace('\\', "\\\\")
            };
            args.extend(["-o".into(), format!("UserKnownHostsFile=\"{path}\"")]);
        }
        args.push(self.host.clone());
        args
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub state: String,
    pub pid: Option<u32>,
    pub local_port: u16,
    pub restarts: u64,
    pub attempt: u64,
    pub last_error: Option<String>,
    pub next_retry_ms: u64,
    pub parent_exit_cleanup: &'static str,
    pub backend_path: Option<String>,
    pub backend_version: Option<String>,
    pub diagnostic_code: Option<String>,
    pub resource_exhaustion_count: u64,
    pub last_resource_error_unix_ms: Option<u64>,
    pub health_failures: u32,
}
#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub seq: u64,
    pub level: String,
    pub message: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub status: Status,
    pub events: Vec<Event>,
    pub stderr: Vec<String>,
}
struct State {
    status: Status,
    events: VecDeque<Event>,
    stderr: VecDeque<String>,
    next_seq: u64,
    fatal: Option<String>,
    last_resource_error: Option<Instant>,
    last_resource_event: Option<Instant>,
    recovery_checks: u32,
}
impl State {
    fn event(&mut self, level: &str, message: impl Into<String>) {
        if self.events.len() == MAX_EVENTS {
            self.events.pop_front();
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.events.push_back(Event {
            seq,
            level: level.into(),
            message: message.into(),
        });
    }
    fn failed(&mut self, error: impl Into<String>) {
        let error = error.into();
        self.status.state = "failed".into();
        self.status.pid = None;
        self.status.next_retry_ms = 0;
        self.status.last_error = Some(error.clone());
        self.event("error", error);
    }
}
struct Control {
    stop: AtomicBool,
    mutex: Mutex<bool>,
    changed: Condvar,
}
impl Control {
    fn new() -> Self {
        Self {
            stop: AtomicBool::new(false),
            mutex: Mutex::new(false),
            changed: Condvar::new(),
        }
    }
    fn cancelled(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }
    fn cancel(&self) {
        self.stop.store(true, Ordering::Release);
        *lock(&self.mutex) = true;
        self.changed.notify_all();
    }
    fn wait(&self, duration: Duration) -> bool {
        let guard = lock(&self.mutex);
        let _ = self
            .changed
            .wait_timeout_while(guard, duration, |stopped| !*stopped)
            .unwrap_or_else(|e| e.into_inner());
        self.cancelled()
    }
}
type Launcher = Arc<dyn Fn(&Config) -> io::Result<Command> + Send + Sync>;
struct Running {
    control: Arc<Control>,
    thread: thread::JoinHandle<()>,
}
pub struct Supervisor {
    config: Config,
    state: Arc<Mutex<State>>,
    operation: Mutex<()>,
    running: Mutex<Option<Running>>,
    launcher: Launcher,
}
impl Supervisor {
    pub fn new(config: Config) -> Result<Self, TunnelError> {
        Self::with_launcher(
            config,
            Arc::new(|config| {
                // Native macOS capture exempts the observed code-signing ID of
                // this exact system client; PATH lookup could select a different
                // binary and invalidate that loop-prevention rule.
                let mut command = Command::new(resolve_ssh(config)?);
                command.args(config.arguments());
                Ok(command)
            }),
        )
    }
    fn with_launcher(config: Config, launcher: Launcher) -> Result<Self, TunnelError> {
        config.validate()?;
        let status = Status {
            state: "stopped".into(),
            pid: None,
            local_port: config.local_port,
            restarts: 0,
            attempt: 0,
            last_error: None,
            next_retry_ms: 0,
            backend_path: None,
            backend_version: None,
            diagnostic_code: None,
            resource_exhaustion_count: 0,
            last_resource_error_unix_ms: None,
            health_failures: 0,
            parent_exit_cleanup: if cfg!(windows) {
                "windows_job_object"
            } else {
                "explicit_stop_only"
            },
        };
        Ok(Self {
            config,
            state: Arc::new(Mutex::new(State {
                status,
                events: VecDeque::new(),
                stderr: VecDeque::new(),
                next_seq: 1,
                fatal: None,
                last_resource_error: None,
                last_resource_event: None,
                recovery_checks: 0,
            })),
            operation: Mutex::new(()),
            running: Mutex::new(None),
            launcher,
        })
    }
    pub fn from_json(text: &str) -> Result<Self, TunnelError> {
        Self::new(Config::from_json(text)?)
    }
    /// Read the remote POSIX resolver configuration through authenticated SSH.
    /// This is a fixed read-only command, not a shell command supplied by the UI.
    pub fn remote_dns_servers(&self) -> Result<Vec<String>, TunnelError> {
        let snapshot = self.snapshot();
        if snapshot.status.state != "ready" {
            return Err(TunnelError("SSH must be ready before DNS discovery".into()));
        }
        let executable = snapshot
            .status
            .backend_path
            .ok_or_else(|| TunnelError("SSH executable is unknown".into()))?;
        let control = lock(&self.running)
            .as_ref()
            .map(|worker| worker.control.clone())
            .ok_or_else(|| TunnelError("SSH is stopped".into()))?;
        let mut command = Command::new(executable);
        command.args(self.config.dns_discovery_arguments());
        let mut child = ChildGuard::spawn(command)?;
        let mut pipe = child
            .child
            .stderr
            .take()
            .ok_or_else(|| TunnelError("DNS discovery output unavailable".into()))?;
        prepare_stderr(&pipe)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut output = Vec::new();
        let mut chunk = [0; 1024];
        loop {
            if control.cancelled() {
                return Err(TunnelError("DNS discovery cancelled".into()));
            }
            if Instant::now() >= deadline {
                return Err(TunnelError("Remote DNS discovery timed out".into()));
            }
            match read_stderr(&mut pipe, &mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    output.extend_from_slice(&chunk[..n]);
                    if output.len() > 32768 {
                        return Err(TunnelError(
                            "Remote DNS configuration exceeds 32 KiB".into(),
                        ));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if matches!(child.child.try_wait(), Ok(Some(_))) {
                        break;
                    }
                    control.wait(Duration::from_millis(20));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => break,
                Err(e) => return Err(e.into()),
            }
        }
        let result = parse_resolvers(&String::from_utf8_lossy(&output));
        child.terminate();
        result
    }
    pub fn snapshot(&self) -> Snapshot {
        let s = lock(&self.state);
        Snapshot {
            status: s.status.clone(),
            events: s.events.iter().cloned().collect(),
            stderr: s.stderr.iter().cloned().collect(),
        }
    }
    pub fn start(&self) -> Result<Snapshot, TunnelError> {
        let _operation = lock(&self.operation);
        {
            let s = lock(&self.state);
            if matches!(
                s.status.state.as_str(),
                "starting" | "ready" | "reconnecting" | "degraded"
            ) {
                drop(s);
                return Ok(self.snapshot());
            }
        }
        if let Some(previous) = lock(&self.running).take() {
            previous.control.cancel();
            let _ = previous.thread.join();
        }
        {
            let mut s = lock(&self.state);
            s.status.state = "starting".into();
            s.status.pid = None;
            s.status.attempt = 0;
            s.status.restarts = 0;
            s.status.last_error = None;
            s.status.next_retry_ms = 0;
            s.fatal = None;
            s.last_resource_error = None;
            s.last_resource_event = None;
            s.recovery_checks = 0;
            s.status.diagnostic_code = None;
            s.status.health_failures = 0;
            s.event("info", "starting managed OpenSSH dynamic forwarding");
            if self
                .config
                .server_alive_interval_secs
                .saturating_mul(u64::from(self.config.server_alive_count_max))
                < 10
            {
                s.event("warn", "SSH keepalive budget is below 10 seconds; server login or load delays can cause premature disconnects");
            }
        }
        let config = self.config.clone();
        let state = self.state.clone();
        let control = Arc::new(Control::new());
        let task_control = control.clone();
        let launcher = self.launcher.clone();
        let worker = thread::Builder::new()
            .name("flowbridge-ssh".into())
            .spawn(move || {
                let failure_state = state.clone();
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    supervise(config, state, task_control, launcher)
                }))
                .is_err()
                {
                    lock(&failure_state).failed("SSH supervisor worker panicked");
                }
            });
        match worker {
            Ok(worker) => {
                *lock(&self.running) = Some(Running {
                    control,
                    thread: worker,
                })
            }
            Err(error) => {
                lock(&self.state).failed(format!("could not launch SSH supervisor: {error}"));
                return Err(error.into());
            }
        }
        Ok(self.snapshot())
    }
    pub fn stop(&self) -> Result<Snapshot, TunnelError> {
        let _operation = lock(&self.operation);
        if let Some(worker) = lock(&self.running).take() {
            worker.control.cancel();
            if worker.thread.join().is_err() {
                lock(&self.state).failed("SSH supervisor panicked");
                return Err(TunnelError("SSH supervisor panicked".into()));
            }
        }
        {
            let mut s = lock(&self.state);
            s.status.state = "stopped".into();
            s.status.pid = None;
            s.status.next_retry_ms = 0;
            s.status.last_error = None;
            s.status.diagnostic_code = None;
            s.status.health_failures = 0;
            s.last_resource_error = None;
            s.recovery_checks = 0;
            s.event("info", "managed SSH stopped; restart disabled");
        }
        Ok(self.snapshot())
    }
}
impl Drop for Supervisor {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn stderr_line(state: &Arc<Mutex<State>>, bytes: &[u8]) {
    let mut text = String::from_utf8_lossy(bytes)
        .chars()
        .filter(|c| !c.is_control() || *c == '\t')
        .take(MAX_LINE)
        .collect::<String>();
    if text.len() > MAX_LINE {
        let mut boundary = MAX_LINE;
        while !text.is_char_boundary(boundary) {
            boundary -= 1;
        }
        text.truncate(boundary);
    }
    if text.is_empty() {
        return;
    }
    let lower = text.to_ascii_lowercase();
    let fatal = if lower.contains("host key verification failed")
        || lower.contains("remote host identification has changed")
        || lower.contains("strict checking")
    {
        Some("SSH host key is missing or changed. Verify the server fingerprint through a trusted channel, then enroll it in the selected known_hosts file (or ~/.ssh/known_hosts) before starting again.")
    } else if lower.contains("permission denied (")
        || lower.contains("no supported authentication methods")
    {
        Some("SSH public-key authentication failed. Select an enrolled identity file or load its key into the SSH agent; password prompts are disabled.")
    } else {
        None
    };
    let mut s = lock(state);
    // OpenSSH on Windows may report Winsock resource exhaustion as WSAENOBUFS
    // or "No buffer space available"; POSIX reports EMFILE/ENFILE. Do not
    // infer a specific descriptor ceiling from these diagnostic strings.
    let exhausted = lower.contains("too many open files")
        || lower.contains("no buffer space available")
        || lower.contains("wsaenobufs")
        || lower.contains("error 10055")
        || lower.contains("resource temporarily unavailable");
    if exhausted {
        let now = Instant::now();
        s.status.resource_exhaustion_count = s.status.resource_exhaustion_count.saturating_add(1);
        s.status.last_resource_error_unix_ms = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .min(u128::from(u64::MAX)) as u64,
        );
        s.status.diagnostic_code = Some("ssh_resource_exhausted".into());
        s.status.state = "degraded".into();
        s.status.last_error = Some("SSH resources exhausted: new connections paused; existing streams retained. Reduce concurrency or select a tested backend. No automatic restart while overloaded.".into());
        s.last_resource_error = Some(now);
        s.recovery_checks = 0;
        // Count every occurrence; bound repetitive diagnostics independently.
        if s.last_resource_event
            .is_some_and(|last| last.elapsed() < Duration::from_secs(1))
        {
            return;
        }
        s.last_resource_event = Some(now);
        let total = s.status.resource_exhaustion_count;
        // A child can spam tens of thousands of identical resource errors per
        // second. Preserve only aggregate totals and a fixed, path-free code,
        // not its arbitrary stderr payload or one warning per failed accept.
        s.event(
            "error",
            format!(
                "SSH resource exhaustion observed ({total} occurrences); new connections paused"
            ),
        );
        return;
    }
    if lower.contains("timeout, server ") && lower.contains("not responding") {
        s.status.diagnostic_code = Some("ssh_server_unresponsive".into());
        s.status.last_error = Some("SSH server did not answer keepalive requests. Check the network, server load and keepalive budget; a local SOCKS greeting alone does not prove remote readiness.".into());
    }
    if let Some(fatal) = fatal {
        s.fatal = Some(fatal.into());
        s.status.last_error = Some(fatal.into());
    }
    if s.stderr.len() == MAX_STDERR_LINES {
        s.stderr.pop_front();
    }
    s.stderr.push_back(text.clone());
    s.event("warn", format!("ssh: {text}"));
}
#[cfg(unix)]
fn prepare_stderr(pipe: &ChildStderr) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let fd = pipe.as_raw_fd();
    // Only this reader owns the read end. Nonblocking mode bounds cancellation
    // even when a descendant retains the child's inherited write end.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
#[cfg(windows)]
fn prepare_stderr(_pipe: &ChildStderr) -> io::Result<()> {
    Ok(())
}
#[cfg(unix)]
fn read_stderr(pipe: &mut ChildStderr, buffer: &mut [u8]) -> io::Result<usize> {
    pipe.read(buffer)
}
#[cfg(windows)]
fn read_stderr(pipe: &mut ChildStderr, buffer: &mut [u8]) -> io::Result<usize> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;
    let mut available = 0;
    if unsafe {
        PeekNamedPipe(
            pipe.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut available,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if available == 0 {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    // This is the only pipe reader; bytes observed by Peek remain available.
    let length = buffer.len().min(available as usize);
    pipe.read(&mut buffer[..length])
}
fn capture_stderr(mut pipe: ChildStderr, state: Arc<Mutex<State>>, cancel: Arc<AtomicBool>) {
    let mut chunk = [0u8; 1024];
    let mut line = Vec::with_capacity(MAX_LINE);
    let mut final_bytes = 0;
    loop {
        let cancelled = cancel.load(Ordering::Acquire);
        // Preserve final authentication/host-key errors already in the pipe,
        // but never let a still-writing descendant postpone Stop indefinitely.
        if cancelled && final_bytes >= 65536 {
            break;
        }
        match read_stderr(&mut pipe, &mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if cancelled {
                    final_bytes += n;
                }
                for &byte in &chunk[..n] {
                    if byte == b'\n' || line.len() == MAX_LINE {
                        stderr_line(&state, &line);
                        line.clear();
                    }
                    if byte != b'\n' {
                        line.push(byte);
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if cancelled {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
    if !line.is_empty() {
        stderr_line(&state, &line);
    }
}
fn health(config: &Config, control: &Control, max_deadline: Instant) -> bool {
    let deadline =
        (Instant::now() + Duration::from_millis(config.health_check_timeout_ms)).min(max_deadline);
    let address = SocketAddr::from(([127, 0, 0, 1], config.local_port));
    while Instant::now() < deadline && !control.cancelled() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let slice = remaining.min(Duration::from_millis(100));
        if slice.is_zero() {
            break;
        }
        if let Ok(mut stream) = TcpStream::connect_timeout(&address, slice) {
            let result = (|| -> io::Result<bool> {
                stream.set_read_timeout(Some(slice))?;
                stream.set_write_timeout(Some(slice))?;
                stream.write_all(&[5, 1, 0])?;
                let mut response = [0; 2];
                stream.read_exact(&mut response)?;
                Ok(response == [5, 0])
            })();
            if matches!(result, Ok(true)) {
                return !control.cancelled();
            }
            // Always discard a failed health socket; Windows timeout state is
            // indeterminate and must never be reused.
        }
        if control.wait(Duration::from_millis(20)) {
            break;
        }
    }
    false
}

#[cfg(windows)]
struct Job(usize);
#[cfg(windows)]
impl Job {
    fn attach(child: &Child) -> io::Result<Self> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::{
            Foundation::CloseHandle,
            System::JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
                SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
        };
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&info) as u32,
            )
        } == 0
            || unsafe { AssignProcessToJobObject(handle, child.as_raw_handle()) } == 0
        {
            let error = io::Error::last_os_error();
            unsafe { CloseHandle(handle) };
            return Err(error);
        }
        Ok(Self(handle as usize))
    }
}
#[cfg(windows)]
impl Drop for Job {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0 as _) };
    }
}
struct ChildGuard {
    child: Child,
    #[cfg(windows)]
    job: Option<Job>,
}
impl ChildGuard {
    fn spawn(mut command: Command) -> io::Result<Self> {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .env("LC_ALL", "C")
            .env("SSH_ASKPASS_REQUIRE", "never");
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        #[allow(unused_mut)] // Windows job-assignment failure must terminate it.
        let mut child = command.spawn()?;
        #[cfg(windows)]
        let job = match Job::attach(&child) {
            Ok(job) => job,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        Ok(Self {
            child,
            #[cfg(windows)]
            job: Some(job),
        })
    }
    fn terminate(&mut self) {
        // Kill all processes in our own job before waiting for diagnostics:
        // descendants can otherwise keep stderr open after ssh has exited.
        #[cfg(windows)]
        drop(self.job.take());
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.terminate();
    }
}
fn parse_resolvers(output: &str) -> Result<Vec<String>, TunnelError> {
    let data = output.split_once("FLOWBRIDGE_DNS_BEGIN\n")
        .and_then(|(_,tail)| tail.split_once("FLOWBRIDGE_DNS_END"))
        .map(|(data,_)|data).ok_or_else(|| TunnelError("Remote host did not return a POSIX resolver file; configure its DNS resolver IP explicitly".into()))?;
    let mut result = Vec::new();
    for line in data.lines() {
        let mut words = line.split_whitespace();
        if words.next() != Some("nameserver") {
            continue;
        }
        let Some(ip) = words
            .next()
            .and_then(|v| v.parse::<std::net::IpAddr>().ok())
        else {
            continue;
        };
        if ip.is_unspecified() || ip.is_multicast() {
            continue;
        }
        let address = ip.to_string();
        if !result.contains(&address) {
            result.push(address);
        }
        if result.len() == 3 {
            break;
        }
    }
    if result.is_empty() {
        return Err(TunnelError(
            "No supported IP DNS resolvers in remote /etc/resolv.conf".into(),
        ));
    }
    Ok(result)
}
fn resolve_ssh(config: &Config) -> io::Result<std::path::PathBuf> {
    if let Some(explicit) = &config.ssh_executable {
        let path = std::fs::canonicalize(explicit)?;
        if !path.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "The explicitly selected OpenSSH client is not a file",
            ));
        }
        if cfg!(target_os = "macos") && path != std::fs::canonicalize("/usr/bin/ssh")? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "macOS selected SSH backend does not match signed native capture bypass",
            ));
        }
        return Ok(path);
    }
    if cfg!(target_os = "macos") {
        return std::fs::canonicalize("/usr/bin/ssh");
    }
    let name = if cfg!(windows) { "ssh.exe" } else { "ssh" };
    for directory in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        if !directory.is_absolute() {
            continue;
        }
        let path = directory.join(name);
        if path.is_file() {
            return std::fs::canonicalize(path);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "OpenSSH was not found in an absolute PATH directory",
    ))
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
                if matches!(child.child.try_wait(), Ok(Some(_))) {
                    break;
                }
                if control.wait(Duration::from_millis(20)) {
                    break;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    child.terminate();
    String::from_utf8_lossy(&output)
        .lines()
        .find(|line| line.starts_with("OpenSSH_"))
        .map(|line| line.chars().filter(|c| !c.is_control()).take(256).collect())
}

fn supervise(config: Config, state: Arc<Mutex<State>>, control: Arc<Control>, launcher: Launcher) {
    // Refuse an existing service rather than falsely identifying its SOCKS reply
    // as readiness for our own child. OpenSSH also uses ExitOnForwardFailure.
    match TcpListener::bind(("127.0.0.1", config.local_port)) {
        Ok(probe) => drop(probe),
        Err(error) => {
            lock(&state).failed(format!(
                "local SOCKS port {} is unavailable: {error}; choose a free port",
                config.local_port
            ));
            return;
        }
    }
    let mut failures = 0u32;
    while !control.cancelled() {
        {
            let mut s = lock(&state);
            s.status.attempt = s.status.attempt.saturating_add(1);
            s.status.next_retry_ms = 0;
            s.fatal = None;
        }
        let launched = launcher(&config).and_then(|command| {
            let executable = command.get_program().to_owned();
            let version = backend_version(&executable, &control);
            if config.ssh_executable.is_some() && version.is_none() {
                return Err(io::Error::new(io::ErrorKind::InvalidData,
                    "Explicit SSH backend did not identify itself as OpenSSH from -V; no fallback backend was launched"));
            }
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
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "SSH start cancelled",
                ));
            }
            ChildGuard::spawn(command)
        });
        let mut child = match launched {
            Ok(child) => child,
            Err(error) => {
                lock(&state).failed(format!("could not start OpenSSH: {error}. Install the OpenSSH client and make ssh available on PATH."));
                return;
            }
        };
        {
            let mut s = lock(&state);
            s.status.pid = Some(child.child.id());
            s.event(
                "info",
                format!("OpenSSH child {} launched", child.child.id()),
            );
        }
        let output_cancel = Arc::new(AtomicBool::new(false));
        let output = if let Some(pipe) = child.child.stderr.take() {
            if let Err(error) = prepare_stderr(&pipe) {
                child.terminate();
                lock(&state).failed(format!("could not prepare SSH diagnostics: {error}"));
                return;
            }
            match thread::Builder::new()
                .name("flowbridge-ssh-stderr".into())
                .spawn({
                    let state = state.clone();
                    let cancel = output_cancel.clone();
                    move || capture_stderr(pipe, state, cancel)
                }) {
                Ok(worker) => Some(worker),
                Err(error) => {
                    child.terminate();
                    lock(&state).failed(format!("could not capture SSH diagnostics: {error}"));
                    return;
                }
            }
        } else {
            None
        };
        let started = Instant::now();
        let mut was_ready = false;
        let mut next_check = Instant::now();
        let error = loop {
            if control.cancelled() {
                break None;
            }
            match child.child.try_wait() {
                Ok(Some(exit)) => break Some(format!("OpenSSH exited with {exit}")),
                Err(error) => break Some(format!("could not inspect SSH child: {error}")),
                Ok(None) => {}
            }
            if Instant::now() >= next_check {
                let health_deadline = if was_ready {
                    Instant::now() + Duration::from_millis(config.health_check_timeout_ms)
                } else {
                    started + Duration::from_millis(config.startup_timeout_ms)
                };
                let healthy = health(&config, &control, health_deadline);
                if control.cancelled() {
                    break None;
                }
                let mut s = lock(&state);
                if healthy && matches!(child.child.try_wait(), Ok(None)) {
                    s.status.health_failures = 0;
                    let overload_recent = s.last_resource_error.is_some_and(|last| {
                        last.elapsed() < Duration::from_millis(config.overload_quiet_ms)
                    });
                    if s.last_resource_error.is_some() {
                        if overload_recent {
                            s.recovery_checks = 0;
                        } else {
                            s.recovery_checks = s.recovery_checks.saturating_add(1);
                        }
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
                    s.status.last_error =
                        Some("SOCKS health probe failed; confirming before restarting SSH".into());
                    if s.status.health_failures >= config.health_failure_threshold {
                        break Some("local SOCKS health check failed repeatedly".into());
                    }
                } else if started.elapsed() >= Duration::from_millis(config.startup_timeout_ms) {
                    break Some("SSH startup deadline expired before SOCKS readiness".into());
                }
                drop(s);
                next_check =
                    Instant::now() + Duration::from_millis(config.health_check_interval_ms);
            }
            if control.wait(Duration::from_millis(25)) {
                break None;
            }
        };
        child.terminate();
        output_cancel.store(true, Ordering::Release);
        if let Some(output) = output {
            let _ = output.join();
        }
        drop(child);
        {
            lock(&state).status.pid = None;
        }
        if control.cancelled() {
            break;
        }
        let mut s = lock(&state);
        let diagnosed = s
            .status
            .diagnostic_code
            .as_deref()
            .filter(|code| *code == "ssh_server_unresponsive")
            .and(s.status.last_error.clone());
        let error = s
            .fatal
            .clone()
            .or(diagnosed)
            .or(error)
            .unwrap_or_else(|| "SSH stopped unexpectedly".into());
        if s.fatal.is_some()
            || (config.max_restarts > 0 && s.status.restarts >= config.max_restarts)
        {
            s.failed(error);
            return;
        }
        let delay = config
            .restart_initial_delay_ms
            .saturating_mul(1u64 << failures.min(20))
            .min(config.restart_max_delay_ms);
        failures = failures.saturating_add(1);
        s.status.state = "reconnecting".into();
        s.status.last_error = Some(error.clone());
        s.status.next_retry_ms = delay;
        s.event("warn", format!("{error}; restarting in {delay}ms"));
        drop(s);
        if control.wait(Duration::from_millis(delay)) {
            break;
        }
        let mut s = lock(&state);
        s.status.restarts = s.status.restarts.saturating_add(1);
    }
    let mut s = lock(&state);
    s.status.state = "stopped".into();
    s.status.pid = None;
    s.status.next_retry_ms = 0;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    fn config() -> Config {
        // Keep listener ports below the platform's client ephemeral range:
        // health probes in parallel tests otherwise can consume a just-released
        // temporary listener port before its fake child binds it.
        // GitHub-hosted macOS can reuse a fixed test port (18000+) from
        // another concurrently running test executable or service, between
        // our bind probe and the fake child startup. Use a per-test-process
        // distinct non-ephemeral (on macOS/Windows) port range rather than
        // reusing the same low 16 ports on every CI invocation.
        static NEXT: std::sync::OnceLock<AtomicUsize> = std::sync::OnceLock::new();
        let next = NEXT
            .get_or_init(|| AtomicUsize::new(16_000 + (std::process::id() as usize % 1800) * 8));
        let local_port = loop {
            let port = next.fetch_add(1, Ordering::SeqCst) as u16;
            assert!(port < 32_000, "test-only SSH listener port range exhausted");
            if TcpListener::bind(("127.0.0.1", port)).is_ok() {
                break port;
            }
        };
        Config {
            host: "server.example".into(),
            user: "alice".into(),
            local_port,
            health_check_interval_ms: 100,
            health_check_timeout_ms: 100,
            startup_timeout_ms: 1000,
            restart_initial_delay_ms: 100,
            restart_max_delay_ms: 200,
            max_restarts: 2,
            ..Config::default()
        }
    }
    fn command(config: &Config, mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "tests::fake_child_entry", "--nocapture"])
            .env("FLOWBRIDGE_FAKE_SSH_MODE", mode)
            .env("FLOWBRIDGE_FAKE_SSH_PORT", config.local_port.to_string());
        command
    }
    fn supervisor(config: Config, mode: &'static str) -> Supervisor {
        Supervisor::with_launcher(config, Arc::new(move |config| Ok(command(config, mode))))
            .unwrap()
    }
    fn wait(supervisor: &Supervisor, mut check: impl FnMut(&Snapshot) -> bool) -> Snapshot {
        let deadline = Instant::now() + Duration::from_secs(6);
        loop {
            let snapshot = supervisor.snapshot();
            if check(&snapshot) {
                return snapshot;
            }
            assert!(
                Instant::now() < deadline,
                "state did not settle: {snapshot:?}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
    // GitHub-hosted macOS may give a port to another process between
    // config()'s bind/release probe and the mock child's preflight bind.
    // Only retry a failed *pre-child* bind. Real SSH failures, health failures,
    // authentication and a lost running child must never be retried here.
    fn mock_preflight_bind_collision(snapshot: &Snapshot, port: u16) -> bool {
        snapshot.status.state == "failed"
            && snapshot.status.pid.is_none()
            && snapshot.status.attempt == 0
            && snapshot.status.restarts == 0
            && snapshot.status.last_error.as_deref().is_some_and(|error| {
                error.starts_with(&format!("local SOCKS port {port} is unavailable: "))
                    && (error.contains("Address already in use")
                        || error.contains("os error 48")
                        || error.contains("os error 98")
                        || error.contains("os error 10048"))
            })
    }

    fn started_mock_with_preflight_retry(
        mut cfg: Config,
        mode: &'static str,
    ) -> (Supervisor, usize) {
        const MAX_PREFLIGHT_RETRIES: usize = 3;
        for retries in 0..=MAX_PREFLIGHT_RETRIES {
            let candidate = supervisor(cfg.clone(), mode);
            candidate.start().unwrap();
            let snapshot = wait(&candidate, |s| {
                s.status.state == "ready" || s.status.state == "failed"
            });
            if snapshot.status.state == "ready" {
                return (candidate, retries);
            }
            assert!(
                mock_preflight_bind_collision(&snapshot, cfg.local_port),
                "unrelated mock SSH failure must not be retried: {snapshot:?}"
            );
            assert!(
                retries < MAX_PREFLIGHT_RETRIES,
                "mock SSH preflight port collisions exhausted {MAX_PREFLIGHT_RETRIES} retries: {snapshot:?}"
            );
            // Dropping the failed supervisor joins its worker. Retry only the
            // test fixture on another checked port, never production routing.
            drop(candidate);
            cfg.local_port = config().local_port;
        }
        unreachable!("bounded preflight loop returns or fails")
    }

    #[test]
    fn mock_preflight_collision_retries_before_spawning_child() {
        let cfg = config();
        let occupied = cfg.local_port;
        let held = TcpListener::bind(("127.0.0.1", occupied)).unwrap();
        let (candidate, retries) = started_mock_with_preflight_retry(cfg, "ready");
        let ready = candidate.snapshot();
        assert_eq!(retries, 1);
        assert_eq!(ready.status.state, "ready");
        assert_eq!(ready.status.attempt, 1);
        assert_eq!(ready.status.restarts, 0);
        assert_ne!(ready.status.local_port, occupied);
        assert!(ready.status.pid.is_some());
        candidate.stop().unwrap();
        drop(held);
    }

    #[test]
    fn mock_preflight_collision_filter_rejects_unrelated_failures() {
        let cfg = config();
        let mut snapshot = Supervisor::new(cfg.clone()).unwrap().snapshot();
        snapshot.status.state = "failed".into();
        snapshot.status.last_error = Some(format!(
            "local SOCKS port {} is unavailable: Address already in use (os error 48); choose a free port",
            cfg.local_port
        ));
        assert!(mock_preflight_bind_collision(&snapshot, cfg.local_port));
        snapshot.status.attempt = 1;
        assert!(!mock_preflight_bind_collision(&snapshot, cfg.local_port));
        snapshot.status.attempt = 0;
        snapshot.status.pid = Some(42);
        assert!(!mock_preflight_bind_collision(&snapshot, cfg.local_port));
        snapshot.status.pid = None;
        snapshot.status.last_error = Some(format!(
            "local SOCKS port {} is unavailable: Permission denied",
            cfg.local_port
        ));
        assert!(!mock_preflight_bind_collision(&snapshot, cfg.local_port));
        snapshot.status.last_error =
            Some("SOCKS health probe failed; confirming before restarting SSH".into());
        assert!(!mock_preflight_bind_collision(&snapshot, cfg.local_port));
        snapshot.status.last_error = Some(format!(
            "local SOCKS port {} is unavailable: Address already in use (os error 48)",
            cfg.local_port + 1
        ));
        assert!(!mock_preflight_bind_collision(&snapshot, cfg.local_port));
    }

    #[test]
    fn fake_child_entry() {
        let Ok(mode) = std::env::var("FLOWBRIDGE_FAKE_SSH_MODE") else {
            return;
        };
        if mode == "held_stderr" {
            eprintln!("descendant diagnostic writer is alive");
            thread::sleep(Duration::from_millis(1500));
            return;
        }
        if mode == "descendant_stderr" {
            // The grandchild inherits only this fake child's diagnostic pipe.
            // It outlives its parent without involving any unrelated process.
            let mut descendant = Command::new(std::env::current_exe().unwrap());
            descendant
                .args(["--exact", "tests::fake_child_entry", "--nocapture"])
                .env("FLOWBRIDGE_FAKE_SSH_MODE", "held_stderr")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit());
            // Intentionally outlive this fake parent: the regression requires
            // an inherited writer after parent exit. It exits in 1.5 seconds.
            #[allow(clippy::zombie_processes)]
            let _child = descendant.spawn().unwrap();
            thread::sleep(Duration::from_millis(200));
            return;
        }
        if mode == "hostkey" {
            eprintln!("Host key verification failed.");
            std::process::exit(255);
        }
        if mode == "auth" {
            eprintln!("alice@server: Permission denied (publickey).");
            std::process::exit(255);
        }
        if mode == "exit" {
            eprintln!("network connection closed");
            std::process::exit(75);
        }
        if mode == "sleep" {
            thread::sleep(Duration::from_secs(30));
            return;
        }
        if mode == "spam" {
            for _ in 0..600 {
                eprintln!("{}", "diagnostic".repeat(300));
            }
        }
        let port: u16 = std::env::var("FLOWBRIDGE_FAKE_SSH_PORT")
            .unwrap()
            .parse()
            .unwrap();
        let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        let mut count = 0;
        for accepted in listener.incoming() {
            let mut stream = accepted.unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut greeting = [0; 3];
            if stream.read_exact(&mut greeting).is_err() {
                continue;
            }
            assert_eq!(greeting, [5, 1, 0]);
            count += 1;
            if mode == "ready_then_stall" && count > 2 {
                let _ = stream.write_all(&[5, 255]);
            } else {
                let _ = stream.write_all(&[5, 0]);
            }
            // Health sockets close after reading the greeting. Wait for that
            // EOF so the mock server does not accumulate listener-port TIME_WAIT
            // entries; real OpenSSH also configures server socket reuse.
            let mut eof = [0u8; 1];
            let _ = stream.read(&mut eof);
            if mode == "exit_after_ready" && count >= 3 {
                std::process::exit(76);
            }
        }
    }
    #[test]
    fn overload_is_reported_coalesced_and_recovers_without_restarting() {
        let mut cfg = config();
        cfg.overload_quiet_ms = 300;
        let supervisor = supervisor(cfg, "ready");
        supervisor.start().unwrap();
        let ready = wait(&supervisor, |s| s.status.state == "ready");
        for _ in 0..10000 {
            stderr_line(&supervisor.state, b"accept: Too many open files");
        }
        let overloaded = supervisor.snapshot();
        assert_eq!(overloaded.status.state, "degraded");
        assert_eq!(
            overloaded.status.diagnostic_code.as_deref(),
            Some("ssh_resource_exhausted")
        );
        assert_eq!(overloaded.status.resource_exhaustion_count, 10000);
        assert!(overloaded.events.len() < 20);
        assert!(
            overloaded.stderr.len() < 20,
            "Repeated EMFILE must not flood stderr history"
        );
        assert!(
            overloaded
                .events
                .iter()
                .any(|e| e.message.contains("10000 occurrences"))
                || overloaded.status.resource_exhaustion_count == 10000
        );
        assert_eq!(supervisor.start().unwrap().status.pid, ready.status.pid);
        let recovered = wait(&supervisor, |s| s.status.state == "ready");
        assert_eq!(recovered.status.pid, ready.status.pid);
        assert_eq!(recovered.status.restarts, 0);
        assert_eq!(recovered.status.resource_exhaustion_count, 10000);
        assert!(recovered.status.last_resource_error_unix_ms.is_some());
        supervisor.stop().unwrap();
    }

    #[test]
    fn windows_and_unix_resource_errors_are_privacy_bounded_and_nonfatal() {
        let supervisor = Supervisor::new(config()).unwrap();
        let examples = [
            b"accept: too many open files C:\\Users\\private\\ssh".as_slice(),
            b"accept: No buffer space available".as_slice(),
            b"WSAENOBUFS: exhausted SOCKET handles".as_slice(),
            b"connect: error 10055".as_slice(),
            b"open failed: Resource temporarily unavailable".as_slice(),
        ];
        for message in examples {
            stderr_line(&supervisor.state, message);
        }
        let snap = supervisor.snapshot();
        assert_eq!(snap.status.resource_exhaustion_count, examples.len() as u64);
        assert_eq!(
            snap.status.diagnostic_code.as_deref(),
            Some("ssh_resource_exhausted")
        );
        assert_eq!(snap.status.state, "degraded");
        assert!(
            snap.stderr.is_empty(),
            "Private paths and resource spam must not be retained"
        );
        let serialized = serde_json::to_string(&snap).unwrap();
        assert!(!serialized.contains("private") && !serialized.contains("10055"));
        assert!(
            snap.events.len() <= 1,
            "Resource warnings must be coalesced"
        );
    }

    #[test]
    fn overloaded_live_child_is_not_killed_when_health_probes_fail() {
        let mut cfg = config();
        cfg.overload_quiet_ms = 100;
        let (supervisor, _) = started_mock_with_preflight_retry(cfg, "ready_then_stall");
        let ready = supervisor.snapshot();
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
    fn keepalive_timeout_reason_is_actionable_and_info_logging_is_preserved() {
        let supervisor = Supervisor::new(config()).unwrap();
        stderr_line(
            &supervisor.state,
            b"Timeout, server synthetic.invalid not responding.",
        );
        let snapshot = supervisor.snapshot();
        assert_eq!(
            snapshot.status.diagnostic_code.as_deref(),
            Some("ssh_server_unresponsive")
        );
        assert!(snapshot
            .status
            .last_error
            .as_deref()
            .unwrap()
            .contains("keepalive"));
        assert!(!snapshot
            .status
            .last_error
            .as_deref()
            .unwrap()
            .contains("synthetic.invalid"));
        assert!(config()
            .arguments()
            .iter()
            .any(|arg| arg == "LogLevel=INFO"));
        assert_eq!(snapshot.status.resource_exhaustion_count, 0);
    }

    #[test]
    fn remote_dns_discovery_is_fixed_bounded_and_keeps_strict_ssh_options() {
        let args = config().dns_discovery_arguments();
        assert!(!args.iter().any(|v| v == "-D" || v == "-N"));
        assert!(args.iter().any(|v| v == "StrictHostKeyChecking=yes"));
        assert!(args.last().unwrap().contains("cat /etc/resolv.conf"));
        let response="untrusted banner nameserver 192.0.2.2\nFLOWBRIDGE_DNS_BEGIN\nnameserver 127.0.0.53\nnameserver ::1\nnameserver 127.0.0.53\nFLOWBRIDGE_DNS_END\n";
        assert_eq!(
            parse_resolvers(response).unwrap(),
            vec!["127.0.0.53", "::1"]
        );
        assert!(parse_resolvers("nameserver 127.0.0.53").is_err());
        assert!(
            parse_resolvers("FLOWBRIDGE_DNS_BEGIN\nnameserver 0.0.0.0\nFLOWBRIDGE_DNS_END")
                .is_err()
        );
    }
    #[test]
    fn explicit_ssh_backend_requires_absolute_local_path_without_auto_fallback() {
        let mut cfg = config();
        cfg.ssh_executable = Some("ssh.exe".into());
        assert!(
            cfg.validate().is_err(),
            "Relative PATH resolution must not override OpenSSH"
        );
        cfg.ssh_executable = Some("//remote/share/ssh.exe".into());
        assert!(
            cfg.validate().is_err(),
            "Network-share backend must be refused"
        );
        cfg.ssh_executable = Some("".into());
        assert!(
            cfg.validate().is_err(),
            "Empty SSH override must not become PATH lookup"
        );
        let current = std::env::current_exe().unwrap().canonicalize().unwrap();
        cfg.ssh_executable = Some(current.to_string_lossy().into_owned());
        if cfg!(target_os = "macos") {
            assert!(
                cfg.validate().is_err(),
                "macOS must not silently change the signing-ID bypassed SSH binary"
            );
        } else {
            cfg.validate().unwrap();
            assert_eq!(resolve_ssh(&cfg).unwrap(), current);
            // This test executable does NOT report an OpenSSH_ version. It
            // must be rejected rather than launched as a dynamic SOCKS client.
            let supervisor = Supervisor::new(cfg).unwrap();
            supervisor.start().unwrap();
            let failed = wait(&supervisor, |s| s.status.state == "failed");
            assert!(failed
                .status
                .last_error
                .as_deref()
                .is_some_and(|message| message.contains("did not identify itself as OpenSSH")));
            assert_eq!(failed.status.restarts, 0);
            assert_eq!(failed.status.pid, None);
        }
    }

    #[test]
    fn strict_config_and_arguments_do_not_allow_shell_or_host_key_overrides() {
        let config=Config::from_json(r#"{"host":"server.example","user":"alice","identity_file":"/keys/with space/key","known_hosts_file":"/keys/known hosts","compression":true}"#).unwrap();
        assert_eq!(config.port, 22);
        assert_eq!(config.local_port, 1080);
        assert_eq!(config.max_restarts, 0);
        let args = config.arguments();
        for option in [
            "StrictHostKeyChecking=yes",
            "BatchMode=yes",
            "ExitOnForwardFailure=yes",
            "PreferredAuthentications=publickey",
            "PasswordAuthentication=no",
            "ServerAliveInterval=15",
            "ServerAliveCountMax=3",
            "Compression=yes",
        ] {
            assert!(args.iter().any(|arg| arg == option));
        }
        assert!(args.windows(2).any(|pair| pair == ["-F", "none"]));
        assert!(args
            .windows(2)
            .any(|pair| pair == ["-i", "/keys/with space/key"]));
        assert!(args
            .iter()
            .any(|arg| arg == "UserKnownHostsFile=\"/keys/known hosts\""));
        assert_eq!(args.last().unwrap(), "server.example");
        for text in [
            r#"{"host":"server","user":"alice","password":"secret"}"#,
            r#"{"host":"-oProxyCommand=x","user":"alice"}"#,
            r#"{"host":"server;touch /tmp/x","user":"alice"}"#,
            r#"{"host":"server","user":"user\nmalformed"}"#,
            r#"{"host":"server","user":"alice","local_port":0}"#,
            r#"{"host":"server","user":"alice","restart_initial_delay_ms":5000,"restart_max_delay_ms":100}"#,
        ] {
            assert!(Config::from_json(text).is_err(), "must reject {text}");
        }
    }
    #[test]
    fn readiness_requires_child_and_socks_and_stop_reaps_without_restart() {
        let config = config();
        let port = config.local_port;
        let supervisor = supervisor(config, "healthy");
        let start = supervisor.start().unwrap();
        assert!(matches!(start.status.state.as_str(), "starting" | "ready"));
        let ready = wait(&supervisor, |s| s.status.state == "ready");
        assert_eq!(ready.status.attempt, 1);
        assert_eq!(ready.status.restarts, 0);
        let pid = ready.status.pid.unwrap();
        let started = Instant::now();
        assert_eq!(supervisor.stop().unwrap().status.state, "stopped");
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(TcpListener::bind(("127.0.0.1", port)).is_ok());
        thread::sleep(Duration::from_millis(250));
        assert_eq!(supervisor.snapshot().status.attempt, 1);
        #[cfg(target_os = "linux")]
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "child must be reaped"
        );
        #[cfg(not(target_os = "linux"))]
        let _ = pid;
    }
    #[test]
    fn dead_child_reconnects_and_new_child_becomes_ready() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let supervisor = Supervisor::with_launcher(
            config(),
            Arc::new(move |config| {
                let mode = if count.fetch_add(1, Ordering::SeqCst) == 0 {
                    "exit_after_ready"
                } else {
                    "healthy"
                };
                Ok(command(config, mode))
            }),
        )
        .unwrap();
        supervisor.start().unwrap();
        let first = wait(&supervisor, |s| {
            s.status.state == "ready" && s.status.attempt == 1
        });
        let second = wait(&supervisor, |s| {
            s.status.state == "ready" && s.status.attempt == 2
        });
        assert_ne!(first.status.pid, second.status.pid);
        assert_eq!(second.status.restarts, 1);
        assert!(second
            .events
            .iter()
            .any(|event| event.message.contains("restarting in")));
        supervisor.stop().unwrap();
    }
    #[test]
    fn alive_child_with_failed_socks_health_is_restarted() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let supervisor = Supervisor::with_launcher(
            config(),
            Arc::new(move |config| {
                let mode = if count.fetch_add(1, Ordering::SeqCst) == 0 {
                    "ready_then_stall"
                } else {
                    "healthy"
                };
                Ok(command(config, mode))
            }),
        )
        .unwrap();
        supervisor.start().unwrap();
        wait(&supervisor, |s| {
            s.status.state == "ready" && s.status.attempt == 1
        });
        let recovered = wait(&supervisor, |s| {
            s.status.state == "ready" && s.status.attempt == 2
        });
        assert!(recovered
            .events
            .iter()
            .any(|event| event.message.contains("SOCKS health check failed")));
        supervisor.stop().unwrap();
    }
    #[test]
    fn startup_never_claims_ready_for_an_alive_child_without_socks() {
        let mut config = config();
        config.restart_initial_delay_ms = 2000;
        config.restart_max_delay_ms = 2000;
        let supervisor = supervisor(config, "sleep");
        supervisor.start().unwrap();
        let reconnect = wait(&supervisor, |s| s.status.state == "reconnecting");
        assert!(reconnect
            .status
            .last_error
            .unwrap()
            .contains("startup deadline"));
        assert!(!reconnect
            .events
            .iter()
            .any(|event| event.message.contains("greeting is ready")));
        supervisor.stop().unwrap();
    }
    #[test]
    fn restart_backoff_is_exponential_bounded_and_attempt_limit_is_enforced() {
        let supervisor = supervisor(config(), "exit");
        supervisor.start().unwrap();
        let failed = wait(&supervisor, |s| s.status.state == "failed");
        assert_eq!(failed.status.attempt, 3, "{failed:?}");
        assert_eq!(failed.status.restarts, 2);
        assert!(failed
            .events
            .iter()
            .any(|event| event.message.ends_with("100ms")));
        assert!(failed
            .events
            .iter()
            .any(|event| event.message.ends_with("200ms")));
        supervisor.stop().unwrap();
    }
    #[test]
    fn explicit_stop_interrupts_backoff_and_prevents_any_more_children() {
        let mut config = config();
        config.restart_initial_delay_ms = 5000;
        config.restart_max_delay_ms = 5000;
        let supervisor = supervisor(config, "exit");
        supervisor.start().unwrap();
        wait(&supervisor, |s| s.status.state == "reconnecting");
        let started = Instant::now();
        supervisor.stop().unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        thread::sleep(Duration::from_millis(250));
        let stopped = supervisor.snapshot();
        assert_eq!(stopped.status.state, "stopped");
        assert_eq!(stopped.status.attempt, 1);
    }
    #[test]
    fn stop_does_not_wait_for_a_descendant_holding_stderr_open() {
        let supervisor = supervisor(config(), "descendant_stderr");
        supervisor.start().unwrap();
        wait(&supervisor, |s| {
            s.stderr
                .iter()
                .any(|line| line.contains("descendant diagnostic writer is alive"))
        });
        let started = Instant::now();
        let stopped = supervisor.stop().unwrap();
        assert!(
            started.elapsed() < Duration::from_millis(750),
            "Stop waited for an inherited diagnostic writer"
        );
        assert_eq!(stopped.status.state, "stopped");
        assert_eq!(stopped.status.pid, None);
    }
    #[test]
    fn host_key_and_public_key_errors_are_actionable_and_do_not_retry() {
        for mode in ["hostkey", "auth"] {
            let mut accepted = false;
            // Fake children use test-only loopback ports. Another CI service
            // may bind one after the configuration probe but before the child
            // starts. Retry only that pre-launch fixture collision, never an
            // actual host-key/authentication error or an SSH restart.
            for _ in 0..4 {
                let supervisor = supervisor(config(), mode);
                supervisor.start().unwrap();
                let failed = wait(&supervisor, |s| s.status.state == "failed");
                if failed.status.attempt == 0 {
                    let collision = failed.status.last_error.as_deref().is_some_and(|message| {
                        message.starts_with("local SOCKS port ")
                            && message.contains(" is unavailable:")
                    });
                    supervisor.stop().unwrap();
                    assert!(collision, "Unexpected pre-launch SSH failure: {failed:?}");
                    continue;
                }
                assert_eq!(failed.status.attempt, 1);
                assert_eq!(failed.status.restarts, 0);
                let error = failed.status.last_error.unwrap();
                assert!(error.contains(if mode == "hostkey" {
                    "fingerprint"
                } else {
                    "SSH agent"
                }));
                supervisor.stop().unwrap();
                accepted = true;
                break;
            }
            assert!(accepted, "Repeated test fixture port collisions");
        }
    }
    #[test]
    fn occupied_local_port_fails_before_any_child_is_launched() {
        let config = config();
        let _occupied = TcpListener::bind(("127.0.0.1", config.local_port)).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let supervisor = Supervisor::with_launcher(
            config,
            Arc::new(move |config| {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(command(config, "healthy"))
            }),
        )
        .unwrap();
        supervisor.start().unwrap();
        let failed = wait(&supervisor, |s| s.status.state == "failed");
        assert!(failed
            .status
            .last_error
            .unwrap()
            .contains("choose a free port"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        supervisor.stop().unwrap();
    }
    #[test]
    fn child_stderr_and_events_are_bounded_even_for_oversized_lines() {
        let supervisor = supervisor(config(), "spam");
        supervisor.start().unwrap();
        let ready = wait(&supervisor, |s| s.status.state == "ready");
        assert!(ready.stderr.len() <= MAX_STDERR_LINES);
        assert!(ready.stderr.iter().all(|line| line.len() <= MAX_LINE));
        assert_eq!(ready.events.len(), MAX_EVENTS);
        supervisor.stop().unwrap();
    }
}
