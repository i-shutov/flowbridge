//! Bounded real TCP -> SOCKS5 relay. No DIRECT fallback and no retry on errors.
//! A connection object exists only after SOCKS CONNECT succeeds. A supervised
//! stop signal (including disappearance of its sender) revokes both directions.
//! This does not establish packet/process identity; callers must bind native
//! ingress to an authorized flow before handing a socket to this module.

use flowbridge_core::{Endpoint, Proxy, ProxyKind};
use flowbridge_net::{connect_route_guarded, relay};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};

#[derive(Debug)]
pub enum RelayError {
    InvalidConfiguration,
    Pipeline(crate::capture_pipeline::PipelineError),
    InvalidDestination,
    AtCapacity,
    Cancelled,
    Transport(flowbridge_net::NetError),
}

#[derive(Clone)]
pub struct RelayPool {
    route: Vec<Proxy>,
    listener: SocketAddr,
    permits: Arc<Semaphore>,
    capacity: usize,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    idle_timeout: Duration,
}

pub struct ConnectedUpstream {
    stream: TcpStream,
    _permit: OwnedSemaphorePermit,
    stop: watch::Receiver<bool>,
    idle_timeout: Duration,
}

async fn cancelled(stop: &mut watch::Receiver<bool>) {
    loop {
        if *stop.borrow_and_update() { return; }
        if stop.changed().await.is_err() { return; }
    }
}

impl RelayPool {
    /// The upstream is an explicitly supervised local FlowBridge SOCKS service,
    /// not a hostname, arbitrary remote proxy, or packet destination. No DNS is
    /// needed to dial it. The destination hostname is carried inside SOCKS5.
    pub fn new(
        upstream: SocketAddr,
        listener: SocketAddr,
        capacity: usize,
        connect_timeout: Duration,
        handshake_timeout: Duration,
        idle_timeout: Duration,
    ) -> Result<Self, RelayError> {
        if !upstream.ip().is_loopback()
            || upstream.port() == 0
            || listener.port() == 0
            || listener.ip().is_unspecified()
            || listener.ip().is_multicast()
            || upstream == listener
            || !(1..=65536).contains(&capacity)
            || connect_timeout.is_zero()
            || connect_timeout > Duration::from_secs(300)
            || handshake_timeout.is_zero()
            || handshake_timeout > Duration::from_secs(300)
            || idle_timeout.is_zero()
            || idle_timeout > Duration::from_secs(86400)
        {
            return Err(RelayError::InvalidConfiguration);
        }
        Ok(Self {
            route: vec![Proxy {
                id: "supervised-flowbridge-socks".into(),
                kind: ProxyKind::Socks5,
                endpoint: Endpoint { host: upstream.ip().to_string(), port: upstream.port() },
                username: None,
                password_env: None,
            }],
            listener,
            permits: Arc::new(Semaphore::new(capacity)),
            capacity,
            connect_timeout,
            handshake_timeout,
            idle_timeout,
        })
    }

    pub fn active(&self) -> usize {
        self.capacity - self.permits.available_permits()
    }

    /// Connect only to the original destination stored in the reserved packet
    /// flow. The lease becomes Active after the real SOCKS handshake, never
    /// just because TCP to the SOCKS listener opened. Failure retires the lease.
    pub async fn connect_reserved(
        &self,
        pipeline: &mut crate::capture_pipeline::CapturePipeline,
        ticket: crate::capture_pipeline::Ticket,
        context: crate::capture_pipeline::PacketContext<'_>,
        stop: watch::Receiver<bool>,
    ) -> Result<ConnectedUpstream, RelayError> {
        let destination = pipeline.destination(ticket, context).map_err(RelayError::Pipeline)?;
        let started = std::time::Instant::now();
        let connected = self.connect(&destination, stop).await;
        let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let Some(now_ms) = context.now_ms.checked_add(elapsed) else {
            pipeline.revoke_all(); return Err(RelayError::InvalidConfiguration);
        };
        match connected {
            Ok(upstream) => {
                pipeline.activate(ticket, context.owner, now_ms, true).map_err(RelayError::Pipeline)?;
                Ok(upstream)
            }
            Err(error) => {
                // Even an already-expired/revoked reservation cannot survive
                // as a new permit. No attempt to dial the destination directly.
                let _ = pipeline.activate(ticket, context.owner, now_ms, false);
                Err(error)
            }
        }
    }

    pub async fn connect(
        &self,
        target: &Endpoint,
        mut stop: watch::Receiver<bool>,
    ) -> Result<ConnectedUpstream, RelayError> {
        if target.validate().is_err() { return Err(RelayError::InvalidDestination); }
        let permit = self.permits.clone().try_acquire_owned().map_err(|_| RelayError::AtCapacity)?;
        let stream = tokio::select! {
            biased;
            () = cancelled(&mut stop) => return Err(RelayError::Cancelled),
            result = connect_route_guarded(target, &self.route, self.connect_timeout,
                self.handshake_timeout, self.listener) => result.map_err(RelayError::Transport)?,
        };
        if *stop.borrow() || stop.has_changed().is_err() { return Err(RelayError::Cancelled); }
        Ok(ConnectedUpstream { stream, _permit: permit, stop, idle_timeout: self.idle_timeout })
    }
}

impl ConnectedUpstream {
    /// Consumes both sockets and its capacity permit on every exit. Half-close
    /// preserves the other direction; cancellation closes both without DIRECT.
    pub async fn forward(mut self, mut native: TcpStream) -> Result<(u64, u64), RelayError> {
        tokio::select! {
            biased;
            () = cancelled(&mut self.stop) => Err(RelayError::Cancelled),
            result = relay(&mut native, &mut self.stream, self.idle_timeout) => result.map_err(RelayError::Transport),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowbridge_net::{accept_socks5, reply_socks5};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    const DEADLINE: Duration = Duration::from_secs(3);
    fn target() -> Endpoint { Endpoint { host: "preserved-name.invalid".into(), port: 443 } }
    fn pool(proxy: SocketAddr, listener: SocketAddr) -> RelayPool {
        RelayPool::new(proxy, listener, 1, DEADLINE, DEADLINE, DEADLINE).unwrap()
    }

    #[tokio::test]
    async fn real_socks_handshake_binary_half_close_and_permit_recovery() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let native = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = pool(proxy.local_addr().unwrap(), native.local_addr().unwrap());
        let (tx, rx) = watch::channel(false);
        let server = tokio::spawn(async move {
            let (mut socket, _) = proxy.accept().await.unwrap();
            assert_eq!(accept_socks5(&mut socket, DEADLINE).await.unwrap(), target());
            reply_socks5(&mut socket, 0).await.unwrap();
            let mut data = Vec::new();
            timeout(DEADLINE, socket.read_to_end(&mut data)).await.unwrap().unwrap();
            assert_eq!(data, b"binary\x00\xff request");
            socket.write_all(b"reply after FIN\x00\xfe").await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let upstream = p.connect(&target(), rx.clone()).await.unwrap();
        assert_eq!(p.active(), 1);
        assert!(matches!(p.connect(&target(), rx).await, Err(RelayError::AtCapacity)));
        let mut client = TcpStream::connect(native.local_addr().unwrap()).await.unwrap();
        let (accepted, _) = native.accept().await.unwrap();
        let forwarding = tokio::spawn(upstream.forward(accepted));
        client.write_all(b"binary\x00\xff request").await.unwrap();
        client.shutdown().await.unwrap();
        let mut reply = Vec::new();
        timeout(DEADLINE, client.read_to_end(&mut reply)).await.unwrap().unwrap();
        assert_eq!(reply, b"reply after FIN\x00\xfe");
        let bytes = timeout(DEADLINE, forwarding).await.unwrap().unwrap().unwrap();
        assert_eq!(bytes, (16, 17));
        server.await.unwrap();
        assert_eq!(p.active(), 0);
        drop(tx);
    }

    #[tokio::test]
    async fn proxy_rejection_is_not_a_direct_dial() {
        let direct_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let native = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = pool(proxy.local_addr().unwrap(), native.local_addr().unwrap());
        let (tx, rx) = watch::channel(false);
        let server = tokio::spawn(async move {
            let (mut socket, _) = proxy.accept().await.unwrap();
            accept_socks5(&mut socket, DEADLINE).await.unwrap();
            reply_socks5(&mut socket, 5).await.unwrap();
        });
        let address = direct_target.local_addr().unwrap();
        let target = Endpoint { host: address.ip().to_string(), port: address.port() };
        assert!(matches!(p.connect(&target, rx).await, Err(RelayError::Transport(_))));
        assert!(timeout(Duration::from_millis(50), direct_target.accept()).await.is_err());
        assert_eq!(p.active(), 0);
        server.await.unwrap(); drop(tx);
    }

    #[tokio::test]
    async fn cancellation_before_connect_and_during_pending_handshake_releases_permit() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let native = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = pool(proxy.local_addr().unwrap(), native.local_addr().unwrap());
        let (tx, rx) = watch::channel(true);
        assert!(matches!(p.connect(&target(), rx).await, Err(RelayError::Cancelled)));
        assert_eq!(p.active(), 0);
        drop(tx);
        let (tx, rx) = watch::channel(false);
        let copy = p.clone();
        let connecting = tokio::spawn(async move { copy.connect(&target(), rx).await });
        let (_accepted, _) = timeout(DEADLINE, proxy.accept()).await.unwrap().unwrap();
        tx.send(true).unwrap();
        assert!(matches!(timeout(DEADLINE, connecting).await.unwrap().unwrap(), Err(RelayError::Cancelled)));
        assert_eq!(p.active(), 0);
    }

    #[tokio::test]
    async fn supervisor_disappearance_revokes_active_relay() {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let native = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = pool(proxy.local_addr().unwrap(), native.local_addr().unwrap());
        let (tx, rx) = watch::channel(false);
        let server = tokio::spawn(async move {
            let (mut socket, _) = proxy.accept().await.unwrap();
            accept_socks5(&mut socket, DEADLINE).await.unwrap();
            reply_socks5(&mut socket, 0).await.unwrap();
            let mut data = [0; 1];
            timeout(DEADLINE, socket.read(&mut data)).await.unwrap().unwrap()
        });
        let upstream = p.connect(&target(), rx).await.unwrap();
        let mut client = TcpStream::connect(native.local_addr().unwrap()).await.unwrap();
        let (accepted, _) = native.accept().await.unwrap();
        let forwarding = tokio::spawn(upstream.forward(accepted));
        drop(tx);
        assert!(matches!(timeout(DEADLINE, forwarding).await.unwrap().unwrap(), Err(RelayError::Cancelled)));
        let mut data = [0; 1];
        assert_eq!(timeout(DEADLINE, client.read(&mut data)).await.unwrap().unwrap(), 0);
        assert_eq!(server.await.unwrap(), 0);
        assert_eq!(p.active(), 0);
    }

    #[tokio::test]
    async fn reserved_packet_lease_activates_only_after_real_socks_reply() {
        use crate::capture_pipeline::{tests as fixtures, Leg};
        for code in [0, 5] {
            let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let native = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let p = pool(proxy.local_addr().unwrap(), native.local_addr().unwrap());
            let original = fixtures::tuple(false);
            let syn = fixtures::frame(original, 2);
            let mut pipeline = fixtures::setup_with_idle(10_000);
            let context = fixtures::context(1);
            let ticket = pipeline.begin(context, &syn, fixtures::alias(original)).unwrap();
            let server = tokio::spawn(async move {
                let (mut socket, _) = proxy.accept().await.unwrap();
                let destination = accept_socks5(&mut socket, DEADLINE).await.unwrap();
                assert_eq!(destination.host, original.destination.ip().to_string());
                assert_eq!(destination.port, original.destination.port());
                reply_socks5(&mut socket, code).await.unwrap();
                socket
            });
            let (tx, rx) = watch::channel(false);
            let result = p.connect_reserved(&mut pipeline, ticket, context, rx).await;
            let _held_server = server.await.unwrap();
            if code == 0 {
                let upstream = result.unwrap();
                let mut frame = syn.clone();
                // Host wall time is deliberately not used as a packet clock.
                let now = 10_000;
                pipeline.rewrite(ticket, fixtures::context(now), Leg::ApplicationToRelay, &mut frame).unwrap();
                assert_ne!(frame, syn);
                drop(upstream);
            } else {
                assert!(matches!(result, Err(RelayError::Transport(_))));
                assert_eq!(pipeline.active_records(), 0);
            }
            assert_eq!(p.active(), 0);
            drop(tx);
        }
    }

    #[test]
    fn invalid_nonlocal_upstream_and_self_loop_are_rejected() {
        let local = "127.0.0.1:1080".parse().unwrap();
        for upstream in [local, "192.0.2.1:1080".parse().unwrap(), "127.0.0.1:0".parse().unwrap()] {
            assert!(RelayPool::new(upstream, local, 1, DEADLINE, DEADLINE, DEADLINE).is_err());
        }
    }
}
