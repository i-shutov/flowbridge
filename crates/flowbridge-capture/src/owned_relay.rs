//! Owned cross-component lease lifecycle for real SOCKS/SSH TCP streams.
//!
//! A synthetic PacketBound fixture is used in tests ONLY. The shipped agent
//! still has no native packet-to-process authority and never enables this from
//! untrusted JSON or IP Helper snapshots. Mutex ownership is never held over
//! an async network operation. An upstream failure cannot select DIRECT.

use crate::capture_pipeline::{
    CapturePipeline, EvidenceKind, OwnerEvidence, PacketContext, PipelineError, Ticket,
};
use crate::relay::{ConnectedUpstream, RelayError, RelayPool};
use flowbridge_core::tcp_flow_lease::OwnerStamp;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::watch;

#[derive(Debug)]
pub enum OwnedRelayError {
    Pipeline(PipelineError),
    Transport(RelayError),
    LockPoisoned,
    ClockOverflow,
    AlreadyConsumed,
}

struct Identity {
    stamp: OwnerStamp,
    path: String,
    kind: EvidenceKind,
}

impl Identity {
    fn evidence(&self) -> OwnerEvidence<'_> {
        OwnerEvidence {
            stamp: self.stamp,
            path: &self.path,
            kind: self.kind,
        }
    }
}

fn lock_state(
    pipeline: &Mutex<CapturePipeline>,
) -> Result<MutexGuard<'_, CapturePipeline>, OwnedRelayError> {
    match pipeline.lock() {
        Ok(guard) => Ok(guard),
        Err(poisoned) => {
            // Poison is not a reason to keep active routing leases alive.
            poisoned.into_inner().revoke_all();
            Err(OwnedRelayError::LockPoisoned)
        }
    }
}

fn elapsed_ms(origin: u64, started: Instant) -> Option<u64> {
    u64::try_from(started.elapsed().as_millis())
        .ok()
        .and_then(|duration| origin.checked_add(duration))
}

/// Pending reservation is protected across the awaited SOCKS handshake. An
/// aborted future must release its pending slot before it can become active.
struct PendingGuard<'a> {
    pipeline: &'a Arc<Mutex<CapturePipeline>>,
    identity: &'a Identity,
    ticket: Ticket,
    armed: bool,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(mut state) = lock_state(self.pipeline) {
            if state
                .finish_relay(self.ticket, self.identity.evidence())
                .is_err()
            {
                state.revoke_all();
            }
        }
    }
}

/// Owns one real SOCKS connection AND exactly one reserved packet-flow ticket.
/// Drop retires the ticket even if the caller exits without forwarding. An
/// inability to prove retirement permanently halts the shared pipeline.
pub struct OwnedFlowRelay {
    connection: Option<ConnectedUpstream>,
    pipeline: Arc<Mutex<CapturePipeline>>,
    ticket: Ticket,
    identity: Identity,
    finished: bool,
}

impl OwnedFlowRelay {
    fn finish(&mut self) -> Result<(), OwnedRelayError> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        let mut pipeline = lock_state(&self.pipeline)?;
        let outcome = pipeline
            .finish_relay(self.ticket, self.identity.evidence())
            .map_err(OwnedRelayError::Pipeline);
        if outcome.is_err() {
            pipeline.revoke_all();
        }
        outcome
    }

    /// Relays actual user-mode socket bytes and retires the reserved flow on
    /// normal EOF, network error, cancellation, or supervisor disappearance.
    /// A cleanup failure overrides transport success, never becoming a PASS.
    pub async fn forward(mut self, native: TcpStream) -> Result<(u64, u64), OwnedRelayError> {
        let connection = self
            .connection
            .take()
            .ok_or(OwnedRelayError::AlreadyConsumed)?;
        let transport = connection
            .forward(native)
            .await
            .map_err(OwnedRelayError::Transport);
        self.finish()?;
        transport
    }
}

impl Drop for OwnedFlowRelay {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

/// Reserve the exact original destination, perform a REAL SOCKS5 CONNECT and
/// activate the ticket only on success. Locks are released across await.
/// Connection failure retires the pending reservation; no direct fallback.
/// The caller must have independently established PacketBound evidence.
pub async fn connect_owned(
    pool: &RelayPool,
    pipeline: Arc<Mutex<CapturePipeline>>,
    ticket: Ticket,
    context: PacketContext<'_>,
    stop: watch::Receiver<bool>,
) -> Result<OwnedFlowRelay, OwnedRelayError> {
    let started = Instant::now();
    let identity = Identity {
        stamp: context.owner.stamp,
        path: context.owner.path.to_owned(),
        kind: context.owner.kind,
    };
    let destination = {
        let mut state = lock_state(&pipeline)?;
        state
            .destination(ticket, context)
            .map_err(OwnedRelayError::Pipeline)?
    };
    let mut pending = PendingGuard {
        pipeline: &pipeline,
        identity: &identity,
        ticket,
        armed: true,
    };
    // No pipeline lock is held while connecting or handshaking. Aborting this
    // future invokes pending's Drop, which retires its exact token.
    let upstream = pool.connect(&destination, stop).await;
    let mut state = lock_state(&pipeline)?;
    let Some(now_ms) = elapsed_ms(context.now_ms, started) else {
        state.revoke_all();
        pending.armed = false;
        return Err(OwnedRelayError::ClockOverflow);
    };
    match upstream {
        Ok(connection) => {
            if let Err(error) = state.activate(ticket, identity.evidence(), now_ms, true) {
                state.revoke_all();
                pending.armed = false;
                return Err(OwnedRelayError::Pipeline(error));
            }
            pending.armed = false;
            drop(state);
            drop(pending);
            Ok(OwnedFlowRelay {
                connection: Some(connection),
                pipeline,
                ticket,
                identity,
                finished: false,
            })
        }
        Err(error) => {
            // False activation retires the reservation (and never enables a
            // connection). If that cleanup itself fails, halt all leases.
            let retired = state.activate(ticket, identity.evidence(), now_ms, false);
            // The expected UpstreamUnavailable result proves this specific
            // reservation was removed. Other unrelated owned streams must
            // survive a single refused SOCKS connection.
            if !matches!(
                retired,
                Err(PipelineError::Lease(
                    flowbridge_core::tcp_flow_lease::LeaseError::UpstreamUnavailable
                ))
            ) {
                state.revoke_all();
            }
            pending.armed = false;
            Err(OwnedRelayError::Transport(error))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture_pipeline::tests::{alias, context, frame, setup_with_idle, tuple};
    use crate::capture_pipeline::Leg;
    use flowbridge_core::ndis_frame_tcp::inspect_ethernet_tcp;
    use flowbridge_core::tcp_packet::TcpTuple;
    use flowbridge_net::{accept_socks5, reply_socks5};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    const DEADLINE: Duration = Duration::from_secs(5);

    fn reverse(tuple: TcpTuple) -> TcpTuple {
        TcpTuple {
            source: tuple.destination,
            destination: tuple.source,
        }
    }

    #[tokio::test]
    async fn synthetic_packet_lease_real_socks_socket_and_reverse_rewrite_are_one_lifecycle() {
        timeout(DEADLINE, async {
            for v6 in [false, true] {
                let original = tuple(v6);
                let alias_tuple = alias(original);
                let syn = frame(original, 2);
                let pipeline = Arc::new(Mutex::new(setup_with_idle(20_000)));
                let ticket = pipeline
                    .lock()
                    .unwrap()
                    .begin(context(1), &syn, alias_tuple)
                    .unwrap();
                let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let native = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let pool = RelayPool::new(
                    proxy.local_addr().unwrap(),
                    native.local_addr().unwrap(),
                    1,
                    DEADLINE,
                    DEADLINE,
                    DEADLINE,
                )
                .unwrap();
                let server = tokio::spawn(async move {
                    let (mut socket, _) = proxy.accept().await.unwrap();
                    let destination = accept_socks5(&mut socket, DEADLINE).await.unwrap();
                    assert_eq!(destination.host, original.destination.ip().to_string());
                    assert_eq!(destination.port, original.destination.port());
                    reply_socks5(&mut socket, 0).await.unwrap();
                    let mut received = Vec::new();
                    socket.read_to_end(&mut received).await.unwrap();
                    socket.write_all(&received).await.unwrap();
                    socket.shutdown().await.unwrap();
                });
                let (supervisor, stop) = watch::channel(false);
                let connected = connect_owned(&pool, pipeline.clone(), ticket, context(2), stop)
                    .await
                    .unwrap();
                assert_eq!(pool.active(), 1);
                assert_eq!(pipeline.lock().unwrap().active_records(), 1);

                // A separate worker may still process both packet legs while
                // SOCKS connection ownership is alive (no mutex across await).
                {
                    let mut state = pipeline.lock().unwrap();
                    let mut sent = syn.clone();
                    state
                        .rewrite(ticket, context(3), Leg::ApplicationToRelay, &mut sent)
                        .unwrap();
                    assert_eq!(inspect_ethernet_tcp(&sent).unwrap().tcp.tuple, alias_tuple);
                    let mut reply = frame(reverse(alias_tuple), 0x12);
                    state
                        .rewrite(ticket, context(4), Leg::RelayToApplication, &mut reply)
                        .unwrap();
                    assert_eq!(
                        inspect_ethernet_tcp(&reply).unwrap().tcp.tuple,
                        reverse(original)
                    );
                }

                let mut client = TcpStream::connect(native.local_addr().unwrap())
                    .await
                    .unwrap();
                let (accepted, _) = native.accept().await.unwrap();
                let payload = b"owned binary\x00\xff half close";
                let transfer = async {
                    client.write_all(payload).await.unwrap();
                    client.shutdown().await.unwrap();
                    let mut echoed = Vec::new();
                    client.read_to_end(&mut echoed).await.unwrap();
                    assert_eq!(echoed, payload);
                };
                let (bytes, ()) = tokio::try_join!(connected.forward(accepted), async {
                    transfer.await;
                    Ok::<(), OwnedRelayError>(())
                })
                .unwrap();
                assert_eq!(bytes, (payload.len() as u64, payload.len() as u64));
                server.await.unwrap();
                assert_eq!(pool.active(), 0);
                assert_eq!(pipeline.lock().unwrap().active_records(), 0);
                drop(supervisor);
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rejection_and_abandonment_revoke_ticket_without_direct_dial() {
        timeout(DEADLINE, async {
            let original = tuple(false);
            let syn = frame(original, 2);
            let pipeline = Arc::new(Mutex::new(setup_with_idle(20_000)));
            let ticket = pipeline
                .lock()
                .unwrap()
                .begin(context(1), &syn, alias(original))
                .unwrap();
            let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let pool = RelayPool::new(
                proxy.local_addr().unwrap(),
                listener.local_addr().unwrap(),
                1,
                DEADLINE,
                DEADLINE,
                DEADLINE,
            )
            .unwrap();
            let rejected = tokio::spawn(async move {
                let (mut socket, _) = proxy.accept().await.unwrap();
                accept_socks5(&mut socket, DEADLINE).await.unwrap();
                reply_socks5(&mut socket, 5).await.unwrap();
            });
            let (supervisor, rx) = watch::channel(false);
            assert!(matches!(
                connect_owned(&pool, pipeline.clone(), ticket, context(2), rx).await,
                Err(OwnedRelayError::Transport(_))
            ));
            rejected.await.unwrap();
            assert_eq!(pipeline.lock().unwrap().active_records(), 0);
            assert_eq!(pool.active(), 0);

            let new_ticket = pipeline
                .lock()
                .unwrap()
                .begin(context(3), &syn, alias(original))
                .unwrap();
            let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let pool = RelayPool::new(
                proxy.local_addr().unwrap(),
                listener.local_addr().unwrap(),
                1,
                DEADLINE,
                DEADLINE,
                DEADLINE,
            )
            .unwrap();
            let accepted = tokio::spawn(async move {
                let (mut socket, _) = proxy.accept().await.unwrap();
                accept_socks5(&mut socket, DEADLINE).await.unwrap();
                reply_socks5(&mut socket, 0).await.unwrap();
                let mut byte = [0u8; 1];
                let _ = socket.read(&mut byte).await.unwrap();
            });
            // Bind both halves explicitly: temporary sender lifetime extends
            // over .await in an argument expression, falsely keeping it alive.
            let (closed_supervisor, receiver) = watch::channel(false);
            drop(closed_supervisor);
            let connected =
                connect_owned(&pool, pipeline.clone(), new_ticket, context(4), receiver).await;
            // The supervisor sender was dropped immediately: fail closed,
            // either before or after SOCKS opens. No pending ticket survives.
            match connected {
                Err(OwnedRelayError::Transport(RelayError::Cancelled)) => {}
                Err(error) => panic!("Closed supervisor returned {error:?}"),
                Ok(_) => panic!("Closed supervisor unexpectedly established flow"),
            }
            assert_eq!(pipeline.lock().unwrap().active_records(), 0);
            assert_eq!(pool.active(), 0);
            accepted.abort();
            drop(supervisor);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn failing_one_owned_connect_keeps_unrelated_lease_alive() {
        timeout(DEADLINE, async {
            let first = tuple(false);
            let second = TcpTuple {
                source: "192.0.2.1:40002".parse().unwrap(),
                destination: first.destination,
            };
            let pipeline = Arc::new(Mutex::new(setup_with_idle(20_000)));
            let (failed, unaffected) = {
                let mut state = pipeline.lock().unwrap();
                let failed = state
                    .begin(context(1), &frame(first, 2), alias(first))
                    .unwrap();
                let unaffected = state
                    .begin(
                        context(2),
                        &frame(second, 2),
                        TcpTuple {
                            source: second.destination,
                            destination: "192.0.2.1:18081".parse().unwrap(),
                        },
                    )
                    .unwrap();
                (failed, unaffected)
            };
            let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let native = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let pool = RelayPool::new(
                proxy.local_addr().unwrap(),
                native.local_addr().unwrap(),
                1,
                DEADLINE,
                DEADLINE,
                DEADLINE,
            )
            .unwrap();
            let (supervisor, receiver) = watch::channel(false);
            drop(supervisor);
            assert!(matches!(
                connect_owned(&pool, pipeline.clone(), failed, context(3), receiver).await,
                Err(OwnedRelayError::Transport(RelayError::Cancelled))
            ));
            let mut state = pipeline.lock().unwrap();
            assert_eq!(state.active_records(), 1);
            state
                .activate(unaffected, context(4).owner, 4, true)
                .unwrap();
            let mut frame = frame(second, 0x10);
            state
                .rewrite(unaffected, context(5), Leg::ApplicationToRelay, &mut frame)
                .unwrap();
            state.finish_relay(unaffected, context(5).owner).unwrap();
            assert_eq!(state.active_records(), 0);
            assert_eq!(pool.active(), 0);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn abort_during_real_socks_handshake_releases_pending_ticket() {
        timeout(DEADLINE, async {
            let original = tuple(false);
            let syn = frame(original, 2);
            let pipeline = Arc::new(Mutex::new(setup_with_idle(20_000)));
            let ticket = pipeline
                .lock()
                .unwrap()
                .begin(context(1), &syn, alias(original))
                .unwrap();
            let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let native = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let pool = RelayPool::new(
                proxy.local_addr().unwrap(),
                native.local_addr().unwrap(),
                1,
                DEADLINE,
                DEADLINE,
                DEADLINE,
            )
            .unwrap();
            let (tx, rx) = watch::channel(false);
            let state = pipeline.clone();
            let copy = pool.clone();
            let opening =
                tokio::spawn(
                    async move { connect_owned(&copy, state, ticket, context(2), rx).await },
                );
            // An actual SOCKS TCP connection is established. Holding the
            // handshake response simulates a stalled supervised SSH backend.
            let (mut socket, _) = proxy.accept().await.unwrap();
            let _requested = accept_socks5(&mut socket, DEADLINE).await.unwrap();
            assert_eq!(pipeline.lock().unwrap().active_records(), 1);
            opening.abort();
            match opening.await {
                Err(error) => assert!(error.is_cancelled()),
                Ok(_) => panic!("Aborted SOCKS handshake unexpectedly completed"),
            }
            assert_eq!(pipeline.lock().unwrap().active_records(), 0);
            assert_eq!(pool.active(), 0);
            drop(socket);
            drop(tx);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn supervisor_loss_during_real_transfer_retires_owned_packet_ticket() {
        timeout(DEADLINE, async {
            let original = tuple(false);
            let syn = frame(original, 2);
            let pipeline = Arc::new(Mutex::new(setup_with_idle(20_000)));
            let ticket = pipeline
                .lock()
                .unwrap()
                .begin(context(1), &syn, alias(original))
                .unwrap();
            let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let native = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let pool = RelayPool::new(
                proxy.local_addr().unwrap(),
                native.local_addr().unwrap(),
                1,
                DEADLINE,
                DEADLINE,
                DEADLINE,
            )
            .unwrap();
            let server = tokio::spawn(async move {
                let (mut socket, _) = proxy.accept().await.unwrap();
                accept_socks5(&mut socket, DEADLINE).await.unwrap();
                reply_socks5(&mut socket, 0).await.unwrap();
                let mut scratch = [0; 1];
                let _ = socket.read(&mut scratch).await.unwrap();
            });
            let (supervisor, stop) = watch::channel(false);
            let owned = connect_owned(&pool, pipeline.clone(), ticket, context(2), stop)
                .await
                .unwrap();
            let _client = TcpStream::connect(native.local_addr().unwrap())
                .await
                .unwrap();
            let (accepted, _) = native.accept().await.unwrap();
            let forward = tokio::spawn(owned.forward(accepted));
            supervisor.send(true).unwrap();
            assert!(matches!(
                forward.await.unwrap(),
                Err(OwnedRelayError::Transport(RelayError::Cancelled))
            ));
            server.await.unwrap();
            assert_eq!(pool.active(), 0);
            assert_eq!(pipeline.lock().unwrap().active_records(), 0);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn dropping_established_stream_without_forwarding_retires_lease() {
        timeout(DEADLINE, async {
            let original = tuple(false);
            let syn = frame(original, 2);
            let pipeline = Arc::new(Mutex::new(setup_with_idle(20_000)));
            let ticket = pipeline
                .lock()
                .unwrap()
                .begin(context(1), &syn, alias(original))
                .unwrap();
            let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let pool = RelayPool::new(
                proxy.local_addr().unwrap(),
                listener.local_addr().unwrap(),
                1,
                DEADLINE,
                DEADLINE,
                DEADLINE,
            )
            .unwrap();
            let server = tokio::spawn(async move {
                let (mut socket, _) = proxy.accept().await.unwrap();
                accept_socks5(&mut socket, DEADLINE).await.unwrap();
                reply_socks5(&mut socket, 0).await.unwrap();
                let mut scratch = [0; 1];
                assert_eq!(socket.read(&mut scratch).await.unwrap(), 0);
            });
            let (tx, rx) = watch::channel(false);
            let connected = connect_owned(&pool, pipeline.clone(), ticket, context(2), rx)
                .await
                .unwrap();
            assert_eq!(pipeline.lock().unwrap().active_records(), 1);
            drop(connected);
            assert_eq!(pipeline.lock().unwrap().active_records(), 0);
            assert_eq!(pool.active(), 0);
            server.await.unwrap();
            drop(tx);
        })
        .await
        .unwrap();
    }
}
