//! A session shared by native capture flows. No listener or UI-supplied PID is
//! trusted here: the platform adapter attests source identity before calling us.
use super::*;
use flowbridge_core::{Endpoint, Proxy};
use flowbridge_runtime::admission::{Admission, Budget, Limits};
use serde::Deserialize;
use std::net::IpAddr;
use std::time::Instant;
use tokio::sync::watch;

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Options {
    managed_endpoint: Option<Endpoint>,
    ready: bool,
    ready_lease_ms: u64,
    pause_grace_ms: u64,
    limits: Limits,
    dns: Option<super::native_dns::Options>,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            managed_endpoint: None,
            ready: false,
            ready_lease_ms: 5000,
            pause_grace_ms: 30000,
            limits: Limits::default(),
            dns: None,
        }
    }
}
#[derive(Clone, Copy)]
struct Gate {
    ready: bool,
    expires: Instant,
}

pub(super) struct Session {
    pub id: u64,
    config: Mutex<Config>,
    dns_server: Mutex<Option<super::native_dns::Server>>,
    options: Options,
    budget: Option<Arc<Budget>>,
    gate: watch::Sender<Gate>,
    cancel: watch::Sender<bool>,
    pub stopped: AtomicBool,
    permits: Arc<tokio::sync::Semaphore>,
    max_flows: usize,
    accepted: AtomicU64,
    failed: AtomicU64,
    completed: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
}
fn sessions() -> &'static Mutex<HashMap<u64, Arc<Session>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<u64, Arc<Session>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}
pub(super) fn session(id: u64) -> Result<Arc<Session>, String> {
    locked(sessions())
        .get(&id)
        .cloned()
        .ok_or("invalid native session".into())
}
fn normalized(endpoint: &Endpoint) -> Option<std::net::SocketAddr> {
    let ip = endpoint.host.parse::<IpAddr>().ok()?;
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    };
    Some(std::net::SocketAddr::new(ip, endpoint.port))
}
impl Session {
    fn new(id: u64, config: Config, options: Options) -> Result<Arc<Self>, String> {
        if !(100..=10000).contains(&options.ready_lease_ms)
            || !(100..=120000).contains(&options.pause_grace_ms)
        {
            return Err(
                "native ready lease must be 100..10000 ms; pause grace 100..120000 ms".into(),
            );
        }
        let budget = if let Some(endpoint) = &options.managed_endpoint {
            let address =
                normalized(endpoint).ok_or("managed endpoint must be a literal loopback IP")?;
            if !address.ip().is_loopback() || address.port() == 0 {
                return Err("managed endpoint must be nonzero loopback".into());
            }
            if !config
                .proxies
                .iter()
                .any(|p| normalized(&p.endpoint) == Some(address))
            {
                return Err("managed endpoint is absent from the validated proxy profile".into());
            }
            Some(Budget::shared(endpoint, options.limits.clone())?)
        } else {
            None
        };
        if let Some(dns) = &options.dns {
            dns.validate()?;
            let endpoint = options
                .managed_endpoint
                .as_ref()
                .ok_or("Remote DNS requires a managed SSH endpoint")?;
            if !config.proxies.iter().any(|p| {
                normalized(&p.endpoint) == normalized(endpoint)
                    && matches!(p.kind, flowbridge_core::ProxyKind::Socks5)
            }) {
                return Err("Remote DNS requires the managed SOCKS5 SSH route".into());
            }
        }
        let max_flows = config.max_connections.min(1024);
        let (gate, _) = watch::channel(Gate {
            ready: options.ready,
            expires: Instant::now() + Duration::from_millis(options.ready_lease_ms),
        });
        let (cancel, _) = watch::channel(false);
        Ok(Arc::new(Self {
            id,
            config: Mutex::new(config),
            dns_server: Mutex::new(None),
            options,
            budget,
            gate,
            cancel,
            stopped: AtomicBool::new(false),
            permits: Arc::new(tokio::sync::Semaphore::new(max_flows)),
            max_flows,
            accepted: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
        }))
    }
    pub async fn dns_query(self: &Arc<Self>, query: Vec<u8>) -> Result<Vec<u8>, String> {
        super::native_dns::validate_query(&query)?;
        let dns = self
            .options
            .dns
            .clone()
            .ok_or("Remote DNS is disabled in this native session")?;
        let config = self.config()?;
        let endpoint = self
            .options
            .managed_endpoint
            .as_ref()
            .ok_or("Managed DNS route is unavailable")?;
        let proxy = config
            .proxies
            .iter()
            .find(|p| {
                normalized(&p.endpoint) == normalized(endpoint)
                    && matches!(p.kind, flowbridge_core::ProxyKind::Socks5)
            })
            .cloned()
            .ok_or("Managed DNS route is absent")?;
        let work = async {
            let route = vec![proxy];
            let mut lease = self.admit(&route).await?;
            self.recheck(&route)?;
            let stream = connect_route_guarded(
                &dns.resolver,
                &route,
                Duration::from_millis(config.connect_timeout_ms),
                Duration::from_millis(config.handshake_timeout_ms),
                config.listen,
            )
            .await
            .map_err(|e| e.to_string())?;
            self.recheck(&route)?;
            lease.connected();
            let answer = super::native_dns::exchange(stream, &query).await?;
            lease.progress(true, query.len() + 2);
            lease.progress(false, answer.len() + 2);
            Ok::<_, String>(answer)
        };
        tokio::select! { biased;
            _ = self.cancelled() => Err("Native DNS stopped".into()),
            result = tokio::time::timeout(Duration::from_millis(dns.timeout_ms),work) =>
                result.map_err(|_| "Remote DNS deadline expired; local fallback disabled".to_string())?
        }
    }
    pub fn dns_exchange(self: &Arc<Self>, query: Vec<u8>) -> Result<Vec<u8>, String> {
        let session = self.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            runtime.block_on(session.dns_query(query))
        })
        .join()
        .map_err(|_| "Native DNS worker panicked".to_string())?
    }
    pub fn start_dns(self: &Arc<Self>, listen: std::net::SocketAddr) -> Result<Value, String> {
        if self.options.dns.is_none() || self.stopped.load(Ordering::Acquire) {
            return Err("Native DNS is disabled or the session stopped".into());
        }
        let mut slot = locked(&self.dns_server);
        if slot.is_some() {
            return Err("Native DNS listener is already running".into());
        }
        let server = super::native_dns::Server::start(self.clone(), listen)?;
        let result =
            json!({"ok":true,"listen":server.listen.to_string(),"system_dns_modified":false});
        *slot = Some(server);
        Ok(result)
    }
    pub fn stop_dns(&self) {
        let server = locked(&self.dns_server).take();
        drop(server);
    }
    pub fn config(&self) -> Result<Config, String> {
        if self.stopped.load(Ordering::Acquire) {
            return Err("native capture stopped".into());
        }
        Ok(locked(&self.config).clone())
    }
    fn managed(&self, route: &[Proxy]) -> bool {
        match (self.options.managed_endpoint.as_ref(), route.first()) {
            (Some(endpoint), Some(first)) => {
                normalized(endpoint).is_some()
                    && normalized(endpoint) == normalized(&first.endpoint)
            }
            _ => false,
        }
    }
    fn ready(&self) -> bool {
        let gate = *self.gate.borrow();
        gate.ready && Instant::now() < gate.expires
    }
    pub async fn cancelled(&self) {
        let mut receiver = self.cancel.subscribe();
        if *receiver.borrow_and_update() {
            return;
        }
        while receiver.changed().await.is_ok() {
            if *receiver.borrow_and_update() {
                return;
            }
        }
    }
    pub async fn admit(self: &Arc<Self>, route: &[Proxy]) -> Result<Lease, String> {
        if self.stopped.load(Ordering::Acquire) {
            return Err("native capture stopped".into());
        }
        // Bound waiting + connecting + established native flows, not just streams
        // that already finished the handshake. Never hold a registry mutex here.
        let local = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| "native capture capacity reached")?;
        let admission = if self.managed(route) {
            let budget = self.budget.as_ref().ok_or("managed capacity unavailable")?;
            let waiter = budget.enqueue()?;
            let deadline = waiter.deadline.min(
                tokio::time::Instant::now() + Duration::from_millis(self.options.pause_grace_ms),
            );
            tokio::time::timeout_at(deadline, async {
                while !self.ready() {
                    if self.stopped.load(Ordering::Acquire) {
                        return Err("native capture stopped".to_string());
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                let admitted = waiter.admit().await?;
                if !self.ready() {
                    return Err("SSH readiness expired while awaiting capacity".into());
                }
                Ok(admitted)
            })
            .await
            .map_err(|_| "managed SSH wait expired; no DIRECT or local DNS fallback")??
            .into()
        } else {
            None
        };
        Ok(Lease {
            owner: self.clone(),
            _local: local,
            admission,
            established: false,
        })
    }
    pub fn recheck(&self, route: &[Proxy]) -> Result<(), String> {
        if self.stopped.load(Ordering::Acquire) {
            return Err("native capture stopped".into());
        }
        if self.managed(route) && !self.ready() {
            return Err("managed SSH paused or heartbeat expired".into());
        }
        Ok(())
    }
    fn snapshot(&self) -> Value {
        let ready = self.options.managed_endpoint.is_none() || self.ready();
        json!({"ok":true,"session_id":self.id,
            "status":{"running":!self.stopped.load(Ordering::Acquire),"transparent":true,
                "upstream_ready":ready,"active":self.max_flows-self.permits.available_permits(),
                "accepted":self.accepted.load(Ordering::Relaxed),"failed":self.failed.load(Ordering::Relaxed),
                "completed":self.completed.load(Ordering::Relaxed),
                "bytes_up":self.bytes_up.load(Ordering::Relaxed),"bytes_down":self.bytes_down.load(Ordering::Relaxed)},
            "managed_upstream":self.budget.as_ref().map(|b| b.snapshot())})
    }
}
pub(super) struct Lease {
    pub owner: Arc<Session>,
    _local: tokio::sync::OwnedSemaphorePermit,
    admission: Option<Admission>,
    established: bool,
}
impl Lease {
    pub fn connected(&mut self) {
        if let Some(admission) = &mut self.admission {
            admission.connected();
        }
        self.established = true;
        self.owner.accepted.fetch_add(1, Ordering::Relaxed);
    }
    pub fn progress(&self, up: bool, count: usize) {
        let counter = if up {
            &self.owner.bytes_up
        } else {
            &self.owner.bytes_down
        };
        counter.fetch_add(count as u64, Ordering::Relaxed);
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if self.established {
            self.owner.completed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.owner.failed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Create a native session; does not claim OS interception or change system DNS.
/// # Safety
/// Both arguments must be live NUL-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn fb_native_create_json(
    config_json: *const c_char,
    options_json: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let config =
            Config::from_json(unsafe { input(config_json) }?).map_err(|e| e.to_string())?;
        let options: Options =
            serde_json::from_str(unsafe { input(options_json) }?).map_err(|e| e.to_string())?;
        let id = handle()?;
        let session = Session::new(id, config, options)?;
        let mut registry = locked(sessions());
        if registry.len() >= MAX_ENGINES {
            return Err("native session capacity reached".into());
        }
        registry.insert(id, session);
        Ok(json!({"ok":true,"session_id":id}))
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GateUpdate {
    ready: bool,
}
/// Renew the native upstream readiness lease. A missing heartbeat pauses new flows.
/// # Safety
/// `gate_json` must be a live NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn fb_native_set_gate_json(id: u64, gate_json: *const c_char) -> *mut c_char {
    guarded(|| {
        let request: GateUpdate =
            serde_json::from_str(unsafe { input(gate_json) }?).map_err(|e| e.to_string())?;
        let session = session(id)?;
        if session.stopped.load(Ordering::Acquire) {
            return Err("native capture stopped".into());
        }
        session.gate.send_replace(Gate {
            ready: request.ready,
            expires: Instant::now() + Duration::from_millis(session.options.ready_lease_ms),
        });
        Ok(session.snapshot())
    })
}
/// Live rule changes only. Existing streams retain their original decision.
/// # Safety
/// `config_json` must be a live NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn fb_native_reload_json(id: u64, config_json: *const c_char) -> *mut c_char {
    guarded(|| {
        let next = Config::from_json(unsafe { input(config_json) }?).map_err(|e| e.to_string())?;
        let session = session(id)?;
        let mut config = locked(&session.config);
        if session.stopped.load(Ordering::Acquire) {
            return Err("native capture stopped".into());
        }
        let mut old = serde_json::to_value(&*config).map_err(|e| e.to_string())?;
        let mut new = serde_json::to_value(&next).map_err(|e| e.to_string())?;
        for value in [&mut old, &mut new] {
            for key in ["rules", "default_action"] {
                value.as_object_mut().unwrap().remove(key);
            }
        }
        if old != new {
            return Err(
                "stop native capture before changing transports or resource settings".into(),
            );
        }
        *config = next;
        Ok(json!({"ok":true}))
    })
}
#[no_mangle]
pub extern "C" fn fb_native_snapshot_json(id: u64) -> *mut c_char {
    guarded(|| Ok(session(id)?.snapshot()))
}
/// OS adapters must supply a kernel/audit-token attested application identity.
/// # Safety
/// `flow_json` must be a live NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn fb_native_stream_open_json(
    id: u64,
    flow_json: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let session = session(id)?;
        let config = session.config()?;
        let flow: Flow =
            serde_json::from_str(unsafe { input(flow_json) }?).map_err(|e| e.to_string())?;
        open_stream_managed(config, flow, None, Some(session))
    })
}
/// WFP redirect records are copied and installed on the real socket before connect.
/// # Safety
/// `flow_json` must be NUL-terminated UTF-8; records must reference `length` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn fb_native_stream_open_wfp_json(
    id: u64,
    flow_json: *const c_char,
    records: *const u8,
    length: usize,
) -> *mut c_char {
    guarded(|| {
        if records.is_null() || length == 0 || length > 65536 {
            return Err("WFP records must contain 1..65536 bytes".into());
        }
        #[cfg(not(windows))]
        {
            let _ = (id, flow_json);
            Err("WFP requires Windows".into())
        }
        #[cfg(windows)]
        {
            let session = session(id)?;
            let config = session.config()?;
            let flow: Flow =
                serde_json::from_str(unsafe { input(flow_json) }?).map_err(|e| e.to_string())?;
            let records = unsafe { std::slice::from_raw_parts(records, length) }.to_vec();
            open_stream_managed(config, flow, Some(records), Some(session))
        }
    })
}
#[no_mangle]
pub extern "C" fn fb_native_destroy(id: u64) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let Some(session) = locked(sessions()).remove(&id) else {
            return;
        };
        session.stopped.store(true, Ordering::Release);
        session.cancel.send_replace(true);
        session.stop_dns();
        let ids: Vec<u64> = locked(streams())
            .iter()
            .filter_map(|(id, stream)| {
                stream
                    .native
                    .as_ref()
                    .filter(|lease| lease.owner.id == session.id)
                    .map(|_| *id)
            })
            .collect();
        for id in ids {
            fb_stream_close(id);
        }
    }));
}
