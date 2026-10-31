//! Windows-only complete, bounded self-created TCP socket experiment.
//! No arbitrary application/PID can be supplied by a caller. The native socket
//! remains owned by this process until the pump ends. IP Helper only checks
//! consistency; it is NOT promoted to the production PacketBound capability.
#![cfg(all(windows, target_pointer_width = "64"))]

use crate::ndis_session::{LabDisposition, LabMode, PacketSession};
use crate::relay::RelayPool;
use crate::self_redirect::{Reflection, Request};
use crate::windows_ndis_device::Driver;
use crate::windows_tcp_owner::{lookup, OwnedProcess, OwnerQuery};
use flowbridge_core::tcp_packet::TcpTuple;
use flowbridge_core::Endpoint;
use serde_json::{json, Value};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::watch;

const REQUEST: &[u8] = b"HEAD / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n";

#[derive(Default)]
struct Probe {
    valid_http_reply: bool,
    upstream_connected: bool,
    upstream_failed: bool,
    bytes_match: bool,
    sent: u64,
    received: u64,
}

pub(super) fn run(request: Request) -> Result<Value, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "Native test runtime creation failed")?;
    runtime.block_on(native(request))
}

async fn exercise(
    socket: TcpSocket,
    listener: TcpListener,
    peer: SocketAddr,
    request_target: SocketAddr,
    pool: RelayPool,
    stop: watch::Receiver<bool>,
    deadline: Duration,
) -> Probe {
    let connected = Arc::new(AtomicBool::new(false));
    let denied = Arc::new(AtomicBool::new(false));
    let up = connected.clone();
    let down = denied.clone();
    let client = async move {
        let mut client = socket.connect(request_target).await.map_err(|_| ())?;
        client.write_all(REQUEST).await.map_err(|_| ())?;
        client.shutdown().await.map_err(|_| ())?;
        let mut reply = Vec::new();
        (&mut client)
            .take(8193)
            .read_to_end(&mut reply)
            .await
            .map_err(|_| ())?;
        if reply.len() > 8192
            || !reply.starts_with(b"HTTP/1.")
            || !reply.windows(4).any(|w| w == b"\r\n\r\n")
        {
            return Err(());
        }
        Ok::<u64, ()>(reply.len() as u64)
    };
    let forwarding = async move {
        let (native, accepted_peer) = listener.accept().await.map_err(|_| ())?;
        if accepted_peer != peer {
            return Err(());
        }
        let endpoint = Endpoint {
            host: request_target.ip().to_string(),
            port: request_target.port(),
        };
        let upstream = match pool.connect(&endpoint, stop).await {
            Ok(value) => {
                up.store(true, Ordering::SeqCst);
                value
            }
            Err(_) => {
                down.store(true, Ordering::SeqCst);
                return Err(());
            }
        };
        upstream.forward(native).await.map_err(|_| ())
    };
    let results = tokio::time::timeout(deadline, async { tokio::join!(client, forwarding) }).await;
    let mut probe = Probe {
        upstream_connected: connected.load(Ordering::SeqCst),
        upstream_failed: denied.load(Ordering::SeqCst),
        ..Probe::default()
    };
    if let Ok((Ok(received), Ok((sent, relayed)))) = results {
        probe.valid_http_reply = true;
        probe.sent = sent;
        probe.received = received;
        probe.bytes_match = sent == REQUEST.len() as u64 && relayed == received && received > 0;
    }
    probe
}

async fn native(request: Request) -> Result<Value, String> {
    // A UDP connect chooses a route but sends no datagram. Never discover local
    // address by sending application data before the diversion has been armed.
    let route = UdpSocket::bind("0.0.0.0:0").map_err(|_| "Route socket unavailable")?;
    route
        .connect(request.target)
        .map_err(|_| "Canary route unavailable")?;
    if route
        .local_addr()
        .map_err(|_| "Route identity unavailable")?
        .ip()
        != request.local_ipv4
    {
        return Err("Canary route differs from explicitly configured local address".into());
    }
    drop(route);
    let scm = crate::windows_ndisrd_service::report();
    if scm["service_registered"] != true
        || scm["kernel_driver_type"] != true
        || scm["service_state"] != "running"
    {
        return Err("Expected running NDISRD kernel service missing".into());
    }
    let mut driver = Driver::open(true).map_err(|e| e.to_string())?;
    let _version = driver.version().map_err(|e| e.to_string())?;
    let adapters = driver.adapters().map_err(|e| e.to_string())?;
    if adapters.len() != 1 {
        return Err("Self-socket lab currently requires a single verified adapter".into());
    }
    let adapter = &adapters[0];
    if adapter.name != request.adapter_name
        || adapter.medium != 0
        || adapter.mtu < 576
        || usize::from(adapter.mtu) + 14 > crate::ndis_wire::MAX_FRAME_BYTES
    {
        return Err("Exact Ethernet adapter/MTU prerequisite failed".into());
    }
    let process = OwnedProcess::query(std::process::id())?;
    let epoch = process.evidence()?;
    let socket = TcpSocket::new_v4().map_err(|_| "Owned TCP socket unavailable")?;
    socket
        .bind(SocketAddr::new(request.local_ipv4.into(), 0))
        .map_err(|_| "Owned source bind failed")?;
    let local = socket
        .local_addr()
        .map_err(|_| "Owned source identity unavailable")?;
    let listener = TcpListener::bind(SocketAddr::new(request.local_ipv4.into(), 0))
        .await
        .map_err(|_| "Local native relay bind failed")?;
    let ingress = listener
        .local_addr()
        .map_err(|_| "Local relay identity unavailable")?;
    let original = TcpTuple {
        source: local,
        destination: request.target.into(),
    };
    let mut reflect = Reflection::new(original, ingress)?;
    let timeout = Duration::from_millis(request.duration_ms);
    let deadline = timeout.saturating_sub(Duration::from_millis(500));
    let pool = RelayPool::new(
        request.upstream,
        ingress,
        1,
        Duration::from_secs(3),
        Duration::from_secs(3),
        deadline,
    )
    .map_err(|_| "Canary upstream settings invalid")?;
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut worker = tokio::spawn(exercise(
        socket,
        listener,
        reflect.peer,
        original.destination,
        pool,
        stop_rx,
        deadline,
    ));
    // No await between spawn and mode activation: on the current-thread
    // runtime the client cannot send SYN before TUNNEL_BOTH was confirmed.
    let mut session = match PacketSession::start(&mut driver, adapter.handle, LabMode::Passthrough)
    {
        Ok(session) => session,
        Err(error) => {
            worker.abort();
            let _ = worker.await;
            return Err(error.to_string());
        }
    };
    let start = Instant::now();
    let mut fault = None;
    let mut native_candidate_checked = false;
    let mut selected_direct_sends = 0u64;
    while start.elapsed() < timeout && !worker.is_finished() {
        let outcome = session.poll_lab_redirect(128, &mut |packet| {
            let selected_candidate =
                crate::self_redirect::candidate_tuple(packet.frame) == Some(original);
            let decision = reflect.decide(packet, &mut || {
                if !matches!(process.evidence(), Ok(now) if now == epoch) {
                    return false;
                }
                if !native_candidate_checked {
                    let Ok(result) = lookup(OwnerQuery {
                        local: original.source,
                        remote: original.destination,
                    }) else {
                        return false;
                    };
                    if result["found"] != true
                        || result["two_snapshots_consistent"] != true
                        || result["pid"].as_u64() != Some(u64::from(epoch.pid))
                        || result["process_creation_100ns"].as_u64() != Some(epoch.created_100ns)
                        || result["authorizes_capture"] != false
                    {
                        return false;
                    }
                    native_candidate_checked = true;
                }
                true
            });
            if selected_candidate && matches!(decision, LabDisposition::Original) {
                selected_direct_sends += 1;
            }
            Ok(decision)
        });
        if let Err(error) = outcome {
            fault = Some(error.to_string());
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    if !worker.is_finished() {
        let _ = stop_tx.send(true);
        worker.abort();
    }
    // Join BEFORE restoring ordinary networking: the owned original socket
    // cannot retry DIRECT after teardown. This is not a crash-persistent policy.
    let probe = (&mut worker).await.unwrap_or_default();
    let _ = stop_tx.send(true);
    let stats = session.stats();
    let cleanup = session.close();
    let transport = if request.expect_denied {
        probe.upstream_failed && !probe.upstream_connected && !probe.valid_http_reply
    } else {
        probe.upstream_connected
            && probe.valid_http_reply
            && probe.bytes_match
            && reflect.counters.relay_reflected > 0
    };
    let passed = fault.is_none()
        && cleanup.is_ok()
        && native_candidate_checked
        && reflect.counters.owner_checked
        && reflect.counters.client_reflected > 0
        && transport
        && reflect.counters.checksums_or_options_rejected == 0
        && selected_direct_sends == 0;
    Ok(json!({
        "product":"FlowBridgeAgent", "mode":"native_self_socket_tcp_reflection_lab",
        "passed":passed, "loop_completed":passed, "rollback_confirmed":cleanup.is_ok(),
        "rollback_error":cleanup.err().map(|e| e.to_string()), "pump_error":fault,
        "elapsed_ms":start.elapsed().as_millis(), "expect_denied":request.expect_denied,
        "actual_ndisrd_tunnel":true, "observed_frames":stats.observed,
        "native_client_frames_reflected":reflect.counters.client_reflected,
        "native_relay_frames_reflected":reflect.counters.relay_reflected,
        "selected_frames_dropped":reflect.counters.selected_dropped,
        "selected_checksum_or_options_rejected":reflect.counters.checksums_or_options_rejected,
        "unsolicited_wire_replies_dropped":reflect.counters.unsolicited_wire_replies_dropped,
        "self_owned_socket_pid_epoch_consistent":native_candidate_checked,
        "source_authority":"internally_created_live_socket_not_arbitrary_pid",
        "selected_original_frames_sent_to_adapter":selected_direct_sends,
        "upstream_socks_connected":probe.upstream_connected,
        "upstream_socks_failed":probe.upstream_failed,
        "application_received_http":probe.valid_http_reply,
        "application_and_relay_byte_counts_match":probe.bytes_match,
        "bytes_sent":probe.sent, "bytes_received":probe.received,
        "arbitrary_app_owner_binding_accepted":false, "native_owner_binding_accepted":false,
        "protected_redirect_available":false, "dns_leak_free":false,
        "win10_11_acceptance":false, "release_accepted":false,
        "payload_or_process_identity_logged":false,
        "note":"Controlled self-owned IPv4 canary only. Caller must separately attest real SSH and an active recovery watchdog. Mode 0 is ordinary networking, not kill switch."
    }))
}
