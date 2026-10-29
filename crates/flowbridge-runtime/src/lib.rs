//! Reusable native application engine. All control methods are synchronous and
//! may be called from a UI worker or a Tokio task: networking owns its own thread.
pub mod admission;
pub mod pool;
use flowbridge_core::{Action, Config, Endpoint, Flow};
use flowbridge_net::{accept_socks5, connect_route_guarded, reply_socks5, NetError};
use serde::Serialize;
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    net::IpAddr,
    pin::Pin,
    sync::{atomic::{AtomicU64, Ordering}, Arc, Mutex, MutexGuard},
    task::{Context, Poll},
    thread,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{watch, Semaphore},
    task::JoinSet,
    time::Instant,
};

const CONNECTION_HISTORY: usize = 512;
const EVENT_HISTORY: usize = 256;
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct RuntimeError(pub String);
impl From<io::Error> for RuntimeError {
    fn from(e: io::Error) -> Self {
        Self(e.to_string())
    }
}
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
fn validate(config: &Config) -> Result<(), RuntimeError> {
    config.validate().map_err(|e| RuntimeError(e.to_string()))?;
    if config
        .rules
        .iter()
        .any(|r| r.enabled && !r.applications.is_empty())
    {
        return Err(RuntimeError("explicit SOCKS mode cannot authenticate the originating application; enabled application criteria require native capture".into()));
    }
    Ok(())
}
#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub running: bool,
    pub listen: String,
    pub mode: &'static str,
    pub generation: u64,
    pub active: u64,
    pub accepted: u64,
    pub completed: u64,
    pub failed: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub transparent: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct Connection {
    pub id: u64,
    pub generation: u64,
    pub host: String,
    pub port: u16,
    pub rule: String,
    pub action: String,
    pub state: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_port: Option<u16>,
}
#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub seq: u64,
    pub level: String,
    pub message: String,
}
/// Includes every active/negotiating connection (at most configured
/// `max_connections`) and the most recent 512 finished connections. Active
/// records are never evicted by completed traffic; events retain their last 256.
#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub status: Status,
    pub managed_upstream: Option<admission::Snapshot>,
    pub managed_pool: Option<pool::Snapshot>,
    pub connections: Vec<Connection>,
    pub events: Vec<Event>,
}
struct State {
    config: Arc<Config>,
    status: Status,
    connections: BTreeMap<u64, Connection>,
    completed_ids: VecDeque<u64>,
    events: VecDeque<Event>,
    next_id: u64,
    next_event: u64,
}
impl State {
    fn event(&mut self, level: &str, message: impl Into<String>) {
        if self.events.len() == EVENT_HISTORY {
            self.events.pop_front();
        }
        let seq = self.next_event;
        self.next_event = self.next_event.saturating_add(1);
        self.events.push_back(Event {
            seq,
            level: level.into(),
            message: message.into(),
        });
    }
}
struct Running {
    cancel: watch::Sender<bool>,
    thread: thread::JoinHandle<()>,
}
#[derive(Clone)]
struct UpstreamGate {
    endpoint: Option<Endpoint>,
    ready: bool,
    grace: Duration,
    budget: Option<Arc<admission::Budget>>,
    pool: Option<Arc<pool::Pool>>,
}
impl UpstreamGate {
    fn matches(&self, first_hop: &Endpoint) -> bool {
        fn normalized(host: &str) -> Option<IpAddr> {
            host.parse::<IpAddr>().ok().map(|ip| match ip {
                IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
                _ => ip,
            })
        }
        self.endpoint.as_ref().is_some_and(|endpoint| {
            endpoint.port == first_hop.port
                && normalized(&endpoint.host).is_some()
                && normalized(&endpoint.host) == normalized(&first_hop.host)
        })
    }
    fn pauses(&self, first_hop: &Endpoint) -> bool {
        !self.ready && self.matches(first_hop)
    }
}
/// A stopped engine can be started again. Configuration generations are captured
/// when clients are accepted; existing connections retain their original profile.
pub struct Engine {
    state: Arc<Mutex<State>>,
    running: Mutex<Option<Running>>,
    operation: Mutex<()>,
    upstream_gate: watch::Sender<UpstreamGate>,
    pool_cursor: Arc<AtomicU64>,
}
impl Engine {
    pub fn new(config: Config) -> Result<Self, RuntimeError> {
        validate(&config)?;
        let status = Status {
            running: false,
            listen: config.listen.to_string(),
            mode: "explicit_socks5",
            generation: 1,
            active: 0,
            accepted: 0,
            completed: 0,
            failed: 0,
            bytes_up: 0,
            bytes_down: 0,
            transparent: false,
        };
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                config: Arc::new(config),
                status,
                connections: BTreeMap::new(),
                completed_ids: VecDeque::new(),
                events: VecDeque::new(),
                next_id: 1,
                next_event: 1,
            })),
            running: Mutex::new(None),
            operation: Mutex::new(()),
            upstream_gate: watch::channel(UpstreamGate {
                endpoint: None,
                ready: true,
                grace: Duration::ZERO,
                budget: None,
                pool: None,
            })
            .0,
            pool_cursor: Arc::new(AtomicU64::new(0)),
        })
    }
    pub fn from_json(json: &str) -> Result<Self, RuntimeError> {
        Self::new(Config::from_json(json).map_err(|e| RuntimeError(e.to_string()))?)
    }
    pub fn snapshot(&self) -> Snapshot {
        let s = lock(&self.state);
        Snapshot {
            status: s.status.clone(),
            managed_upstream: self
                .upstream_gate
                .borrow()
                .budget
                .as_ref()
                .map(|b| b.snapshot()),
            managed_pool: self.upstream_gate.borrow().pool.as_ref().map(|p| p.snapshot()),
            connections: s.connections.values().cloned().collect(),
            events: s.events.iter().cloned().collect(),
        }
    }
    /// Pause only new Proxy/Chain opens whose first hop is this managed loopback
    /// upstream. Established relays are never replayed or migrated. Direct and
    /// Block decisions remain immediate. Clearing the endpoint releases waiters.
    pub fn set_upstream_gate(
        &self,
        endpoint: Option<Endpoint>,
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
        if grace_ms > 120_000 {
            return Err(RuntimeError(
                "reconnect grace must not exceed 120000 ms".into(),
            ));
        }
        if let Some(endpoint) = &mut endpoint {
            endpoint
                .validate()
                .map_err(|e| RuntimeError(e.to_string()))?;
            let ip = endpoint.host.parse::<IpAddr>().map_err(|_| {
                RuntimeError("managed upstream must be a loopback IP literal".into())
            })?;
            let loopback = match ip {
                IpAddr::V4(ip) => ip.is_loopback(),
                IpAddr::V6(ip) => {
                    ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
                }
            };
            if !loopback {
                return Err(RuntimeError(
                    "managed upstream must be a loopback IP literal".into(),
                ));
            }
            endpoint.host = ip.to_string();
        }
        let budget = endpoint
            .as_ref()
            .map(|e| admission::Budget::shared(e, limits))
            .transpose()
            .map_err(RuntimeError)?;
        self.upstream_gate.send_replace(UpstreamGate {
            endpoint,
            ready,
            grace: Duration::from_millis(grace_ms),
            budget,
            pool: None,
        });
        Ok(lock(&self.state).status.clone())
    }
    /// Configure 1..=4 independent OpenSSH listener processes; only new
    /// single-hop SOCKS5 connections to the primary proxy are load-balanced.
    /// Member budgets are globally shared by endpoint. Their hard sum must
    /// fit the explicit aggregate cap; no worker is spawned by this engine.
    pub fn set_upstream_pool_with_limits(
        &self,
        primary: Endpoint,
        workers: Vec<pool::WorkerInput>,
        limits: admission::Limits,
        aggregate_max_flows: usize,
    ) -> Result<Status, RuntimeError> {
        let pool = Arc::new(pool::Pool::new(primary, workers, limits, aggregate_max_flows)
            .map_err(RuntimeError)?);
        let config = lock(&self.state).config.clone();
        if !config.proxies.iter().any(|p|
            matches!(p.kind, flowbridge_core::ProxyKind::Socks5)
                && pool.matches(&p.endpoint)) {
            return Err(RuntimeError("SSH pool primary must be an existing SOCKS5 proxy in this profile".into()));
        }
        let ready = pool.has_ready();
        self.upstream_gate.send_replace(UpstreamGate {
            endpoint: None,
            ready,
            grace: Duration::ZERO,
            budget: None,
            pool: Some(pool),
        });
        Ok(lock(&self.state).status.clone())
    }

    pub fn start(&self) -> Result<Status, RuntimeError> {
        let _operation = lock(&self.operation);
        if lock(&self.state).status.running {
            return Ok(lock(&self.state).status.clone());
        }
        // Join any prior worker that exited following an accept failure.
        if let Some(old) = lock(&self.running).take() {
            let _ = old.cancel.send(true);
            let _ = old.thread.join();
        }
        let config = lock(&self.state).config.clone();
        let (cancel, receiver) = watch::channel(false);
        let state = self.state.clone();
        let upstream_gate = self.upstream_gate.subscribe();
        let pool_cursor = self.pool_cursor.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("flowbridge-engine".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error.to_string()));
                        return;
                    }
                };
                runtime.block_on(async move {
                    // Tokio applies the platform's normal server reuse-address
                    // behavior, allowing a listener to restart after active traffic.
                    match TcpListener::bind(config.listen).await {
                        Ok(listener) => {
                            {
                                let mut s = lock(&state);
                                s.status.running = true;
                                s.event(
                                    "info",
                                    "SOCKS5 listener started; originating application unavailable",
                                );
                            }
                            let _ = ready_tx.send(Ok(()));
                            serve(
                                listener,
                                state,
                                receiver,
                                config.max_connections,
                                upstream_gate,
                                pool_cursor,
                            )
                            .await;
                        }
                        Err(error) => {
                            lock(&state).event("error", format!("listener bind failed: {error}"));
                            let _ = ready_tx.send(Err(error.to_string()));
                        }
                    }
                });
                runtime.shutdown_timeout(Duration::from_millis(250));
            })?;
        match ready_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let _ = worker.join();
                return Err(RuntimeError(error));
            }
            Err(error) => {
                let _ = worker.join();
                return Err(RuntimeError(format!(
                    "listener initialization failed: {error}"
                )));
            }
        }
        *lock(&self.running) = Some(Running {
            cancel,
            thread: worker,
        });
        Ok(lock(&self.state).status.clone())
    }
    pub fn stop(&self) -> Result<Status, RuntimeError> {
        let _operation = lock(&self.operation);
        if let Some(running) = lock(&self.running).take() {
            let _ = running.cancel.send(true);
            if running.thread.join().is_err() {
                let mut s = lock(&self.state);
                s.status.running = false;
                s.event("error", "engine worker panicked");
                return Err(RuntimeError("engine worker panicked".into()));
            }
        }
        let mut s = lock(&self.state);
        s.status.running = false;
        Ok(s.status.clone())
    }
    pub fn reload(&self, config: Config) -> Result<Status, RuntimeError> {
        validate(&config)?;
        let _operation = lock(&self.operation);
        let mut s = lock(&self.state);
        if s.status.running
            && (config.listen != s.config.listen
                || config.max_connections != s.config.max_connections)
        {
            return Err(RuntimeError(
                "stop engine before changing listen or max_connections".into(),
            ));
        }
        let generation = s
            .status
            .generation
            .checked_add(1)
            .ok_or_else(|| RuntimeError("configuration generation exhausted".into()))?;
        s.status.listen = config.listen.to_string();
        s.config = Arc::new(config);
        s.status.generation = generation;
        s.event(
            "info",
            format!("configuration generation {generation} applied"),
        );
        Ok(s.status.clone())
    }
    pub fn reload_json(&self, json: &str) -> Result<Status, RuntimeError> {
        self.reload(Config::from_json(json).map_err(|e| RuntimeError(e.to_string()))?)
    }
}
impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

async fn cancelled(receiver: &mut watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    while receiver.changed().await.is_ok() {
        if *receiver.borrow() {
            return;
        }
    }
}
async fn serve(
    listener: TcpListener,
    state: Arc<Mutex<State>>,
    mut cancel: watch::Receiver<bool>,
    max: usize,
    upstream_gate: watch::Receiver<UpstreamGate>,
    pool_cursor: Arc<AtomicU64>,
) {
    let permits = Arc::new(Semaphore::new(max));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {biased;
            _=cancelled(&mut cancel)=>break,
            _=tasks.join_next(),if !tasks.is_empty()=>{},
            result=listener.accept()=> {
                let (client,peer)=match result {Ok(v)=>v,Err(e)=>{lock(&state).event("error",format!("listener accept failed: {e}"));break;}};
                if !peer.ip().is_loopback(){continue;}
                let permit=match permits.clone().try_acquire_owned(){Ok(p)=>p,Err(_)=>{lock(&state).event("warn","connection capacity reached");continue;}};
                let (config,guard)={
                    let mut s=lock(&state);let config=s.config.clone();let id=s.next_id;
                    let Some(next)=s.next_id.checked_add(1) else {s.event("error","connection IDs exhausted");continue;};s.next_id=next;
                    s.status.accepted=s.status.accepted.saturating_add(1);s.status.active+=1;
                    let generation=s.status.generation;
                    s.connections.insert(id,Connection{id,generation,host:String::new(),port:0,rule:"pending".into(),action:"pending".into(),state:"negotiating".into(),bytes_up:0,bytes_down:0,error:None,worker_port:None});
                    (config,ConnectionGuard{state:state.clone(),id,finished:false})
                };
                let gate=upstream_gate.clone();
                let cursor = pool_cursor.clone();
                tasks.spawn(async move {let _permit=permit;let mut guard=guard;let result=handle(client,config,&guard,gate,cursor).await;guard.finish(result);});
            }
        }
    }
    drop(listener);
    tasks.abort_all();
    // Connection guards mark cancellations and decrement active counts even on abort.
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    let mut s = lock(&state);
    s.status.running = false;
    s.event("info", "listener stopped; active connections cancelled");
}
struct ConnectionGuard {
    state: Arc<Mutex<State>>,
    id: u64,
    finished: bool,
}
impl ConnectionGuard {
    fn finish(&mut self, result: Result<(), String>) {
        if self.finished {
            return;
        }
        self.finished = true;
        let mut s = lock(&self.state);
        s.status.active = s.status.active.saturating_sub(1);
        if result.is_ok() {
            s.status.completed = s.status.completed.saturating_add(1);
        } else {
            s.status.failed = s.status.failed.saturating_add(1);
        }
        if let Some(c) = s.connections.get_mut(&self.id) {
            c.state = if result.is_ok() {
                "completed"
            } else {
                "failed"
            }
            .into();
            c.error = result.clone().err();
        }
        s.completed_ids.push_back(self.id);
        if s.completed_ids.len() > CONNECTION_HISTORY {
            if let Some(oldest) = s.completed_ids.pop_front() {
                s.connections.remove(&oldest);
            }
        }
        if let Err(error) = result {
            s.event("warn", format!("connection {}: {error}", self.id));
        }
    }
}
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.finish(Err("connection cancelled".into()));
    }
}
fn action_name(action: &Action) -> String {
    match action {
        Action::Direct => "direct".into(),
        Action::Block => "block".into(),
        Action::Proxy { id } => format!("proxy:{id}"),
        Action::Chain { id } => format!("chain:{id}"),
    }
}
async fn handle(
    mut client: TcpStream,
    config: Arc<Config>,
    guard: &ConnectionGuard,
    mut upstream_gate: watch::Receiver<UpstreamGate>,
    pool_cursor: Arc<AtomicU64>,
) -> Result<(), String> {
    let target = accept_socks5(
        &mut client,
        Duration::from_millis(config.handshake_timeout_ms),
    )
    .await
    .map_err(|e| e.to_string())?;
    let decision = config.evaluate(&Flow {
        application: None,
        destination: target.clone(),
        resolved_ip: None,
    });
    {
        let mut s = lock(&guard.state);
        if let Some(c) = s.connections.get_mut(&guard.id) {
            c.host = target.host.clone();
            c.port = target.port;
            c.rule = decision.rule_id.clone().unwrap_or_else(|| "default".into());
            c.action = action_name(&decision.action);
            c.state = "connecting".into();
        }
    }
    if matches!(decision.action, Action::Block) {
        let _ = reply_socks5(&mut client, 2).await;
        return Err("blocked by policy".into());
    }
    let mut route = config.route(&decision.action).map_err(|e| e.to_string())?;
    // The configured first proxy is a stable primary name. Actual per-flow
    // ownership is pinned to one live OpenSSH listener before any upstream
    // connection is attempted. A failed member is never replaced mid-stream.
    let active_pool = upstream_gate.borrow().pool.clone();
    let selected = if let (Some(first), Some(pool)) = (route.first(), active_pool.as_ref()) {
        if pool.matches(&first.endpoint) {
            if route.len() != 1 || !matches!(first.kind, flowbridge_core::ProxyKind::Socks5) {
                let _ = reply_socks5(&mut client, 1).await;
                return Err("managed SSH pool requires a single SOCKS5 hop".into());
            }
            let selection = match pool.select(pool_cursor.fetch_add(1, Ordering::Relaxed)) {
                Ok(worker) => worker,
                Err(error) => {
                    let _ = reply_socks5(&mut client, 1).await;
                    return Err(error);
                }
            };
            route[0].endpoint = selection.endpoint.clone();
            if let Some(connection) = lock(&guard.state).connections.get_mut(&guard.id) {
                connection.worker_port = Some(selection.endpoint.port);
            }
            Some(selection)
        } else { None }
    } else { None };
    let mut waiter = None;
    if let Some(first) = route.first() {
        let initial = upstream_gate.borrow().clone();
        if initial.matches(&first.endpoint) {
            if let Some(budget) = selected.as_ref().map(|worker| &worker.budget).or(initial.budget.as_ref()) {
                match budget.enqueue() {
                    Ok(value) => waiter = Some(value),
                    Err(error) => {
                        let _ = reply_socks5(&mut client, 1).await;
                        return Err(error);
                    }
                }
            }
        }
        if initial.pauses(&first.endpoint) {
            {
                let mut state = lock(&guard.state);
                if let Some(connection) = state.connections.get_mut(&guard.id) {
                    connection.state = "waiting_for_tunnel".into();
                }
            }
            // SSH reconnect grace is independent of the per-process capacity
            // wait timeout. Queue permits stay held (and bounded) throughout
            // this phase, then the capacity deadline is restarted at readiness.
            let deadline = Instant::now() + initial.grace;
            loop {
                if !upstream_gate.borrow().pauses(&first.endpoint) {
                    break;
                }
                tokio::select! {
                    changed = upstream_gate.changed() => {
                        if changed.is_err() { return Err("managed upstream controller stopped".into()); }
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        let _ = reply_socks5(&mut client, 1).await;
                        return Err("managed SSH upstream did not recover before reconnect deadline".into());
                    }
                }
            }
            if let Some(waiter) = &mut waiter {
                waiter.reset_capacity_deadline();
            }
            if let Some(connection) = lock(&guard.state).connections.get_mut(&guard.id) {
                connection.state = "connecting".into();
            }
        }
    }
    let mut admission = if let Some(waiter) = waiter {
        if let Some(connection) = lock(&guard.state).connections.get_mut(&guard.id) {
            connection.state = "waiting_for_capacity".into();
        }
        match waiter.admit().await {
            Ok(value) => Some(value),
            Err(error) => {
                let _ = reply_socks5(&mut client, 1).await;
                return Err(error);
            }
        }
    } else {
        None
    };
    let paused = if let Some(selected) = &selected {
        !upstream_gate.borrow().pool.as_ref().is_some_and(|pool| pool.is_ready(&selected.endpoint))
    } else {
        route.first().is_some_and(|first| upstream_gate.borrow().pauses(&first.endpoint))
    };
    if paused {
        let _ = reply_socks5(&mut client, 1).await;
        return Err("managed SSH became unavailable while awaiting capacity".into());
    }
    // Retry only a managed, single-hop SOCKS5 establishment, before any
    // application bytes or success reply have been sent. Never replay payload.
    let may_retry = admission.is_some()
        && route.len() == 1
        && matches!(route[0].kind, flowbridge_core::ProxyKind::Socks5);
    let deadline = Instant::now()
        + Duration::from_millis(
            config
                .connect_timeout_ms
                .saturating_add(config.handshake_timeout_ms),
        );
    let established = if may_retry {
        tokio::time::timeout_at(deadline, async {
        for attempt in 0..2 {
            if selected.as_ref().is_some_and(|worker|
                !upstream_gate.borrow().pool.as_ref().is_some_and(|pool| pool.is_ready(&worker.endpoint)))
                || route.first().is_some_and(|p| upstream_gate.borrow().pauses(&p.endpoint)) {
                return Err(NetError::InvalidConfig("managed upstream is paused"));
            }
            let result = connect_route_guarded(&target, &route,
                Duration::from_millis(config.connect_timeout_ms),
                Duration::from_millis(config.handshake_timeout_ms), config.listen).await;
            let retryable = matches!(&result, Err(NetError::Io { stage, source })
                if matches!(*stage, "SOCKS5 greeting" | "SOCKS5 CONNECT response")
                    && matches!(source.kind(), io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted));
            if !may_retry || !retryable || attempt == 1 { return result; }
            lock(&guard.state).event("warn", format!(
                "connection {}: retrying initial managed SOCKS establishment (2/2); no application bytes sent", guard.id));
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        unreachable!("bounded establishment loop always returns")
    }).await.unwrap_or(Err(NetError::Timeout { stage: "initial managed connection" }))
    } else {
        // Non-managed routes retain their original per-hop timeout semantics.
        connect_route_guarded(
            &target,
            &route,
            Duration::from_millis(config.connect_timeout_ms),
            Duration::from_millis(config.handshake_timeout_ms),
            config.listen,
        )
        .await
    };
    let upstream = match established {
        Ok(v) => v,
        Err(e) => {
            let code = if matches!(&e, NetError::RecursiveListener) {
                2
            } else {
                1
            };
            let _ = reply_socks5(&mut client, code).await;
            return Err(e.to_string());
        }
    };
    if let Some(admission) = &mut admission {
        admission.connected();
    }
    reply_socks5(&mut client, 0)
        .await
        .map_err(|e| e.to_string())?;
    {
        let mut s = lock(&guard.state);
        if let Some(c) = s.connections.get_mut(&guard.id) {
            c.state = "active".into();
        }
    }
    let (activity, mut updates) = watch::channel(Instant::now());
    let mut client = Meter {
        stream: client,
        state: guard.state.clone(),
        id: guard.id,
        upload: false,
        activity: activity.clone(),
    };
    let mut upstream = Meter {
        stream: upstream,
        state: guard.state.clone(),
        id: guard.id,
        upload: true,
        activity,
    };
    let idle = Duration::from_millis(config.idle_timeout_ms);
    let copy = tokio::io::copy_bidirectional(&mut client, &mut upstream);
    tokio::pin!(copy);
    let deadline = tokio::time::sleep(idle);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            result=&mut copy=>return result.map(|_|()).map_err(|e|e.to_string()),
            changed=updates.changed()=>{if changed.is_ok(){let latest=*updates.borrow_and_update();deadline.as_mut().reset(latest+idle);}},
            _=&mut deadline=>{let latest=*updates.borrow_and_update();if latest.elapsed()>=idle{return Err("idle timeout".into());}deadline.as_mut().reset(latest+idle);}
        }
    }
}
struct Meter {
    stream: TcpStream,
    state: Arc<Mutex<State>>,
    id: u64,
    upload: bool,
    activity: watch::Sender<Instant>,
}
impl AsyncRead for Meter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl AsyncWrite for Meter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            if *n > 0 {
                self.activity.send_replace(Instant::now());
                let mut s = lock(&self.state);
                let n = *n as u64;
                if self.upload {
                    s.status.bytes_up = s.status.bytes_up.saturating_add(n);
                } else {
                    s.status.bytes_down = s.status.bytes_down.saturating_add(n);
                }
                if let Some(c) = s.connections.get_mut(&self.id) {
                    if self.upload {
                        c.bytes_up = c.bytes_up.saturating_add(n);
                    } else {
                        c.bytes_down = c.bytes_down.saturating_add(n);
                    }
                }
            }
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
