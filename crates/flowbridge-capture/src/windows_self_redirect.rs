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
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpSocket};
use tokio::process::{Child, ChildStdout, Command};
use tokio::sync::watch;

const REQUEST: &[u8] = b"HEAD / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n";

/// Fixed Windows PowerShell client for cross-runtime NDISRD lab verification.
/// This creates only TCP test traffic; all interception/routing stays in Rust.
/// No executable path or script is accepted from untrusted JSON/IPC.
const POWERSHELL_CLIENT_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$localIP = [System.Net.IPAddress]::Parse($env:FLOWBRIDGE_LAB_LOCAL_IPV4)
$targetIP = [System.Net.IPAddress]::Parse($env:FLOWBRIDGE_LAB_TARGET_IPV4)
$targetPort = [int]$env:FLOWBRIDGE_LAB_TARGET_PORT
if ($targetPort -lt 1 -or $targetPort -gt 65535) { exit 2 }
if ($localIP.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or $targetIP.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { exit 2 }
$s = [System.Net.Sockets.Socket]::new([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
try {
  $s.ReceiveTimeout = 7000
  $s.SendTimeout = 7000
  $s.Bind([System.Net.IPEndPoint]::new($localIP, 0))
  [Console]::Out.WriteLine(([System.Net.IPEndPoint]$s.LocalEndPoint).Port)
  [Console]::Out.Flush()
  if ([Console]::ReadLine() -cne 'go') { exit 2 }
  $s.Connect([System.Net.IPEndPoint]::new($targetIP, $targetPort))
  $crlf = [string][char]13 + [string][char]10
  $payload = 'HEAD / HTTP/1.0' + $crlf + 'Host: example.com' + $crlf + 'Connection: close' + $crlf + $crlf
  $bytes = [System.Text.Encoding]::ASCII.GetBytes($payload)
  $offset = 0
  while ($offset -lt $bytes.Length) {
    $sent = $s.Send($bytes, $offset, $bytes.Length - $offset, [System.Net.Sockets.SocketFlags]::None)
    if ($sent -le 0) { throw 'Socket send refused' }
    $offset += $sent
  }
  $s.Shutdown([System.Net.Sockets.SocketShutdown]::Send)
  $buffer = New-Object byte[] 4096
  $reply = [System.IO.MemoryStream]::new()
  while ($true) {
    $n = $s.Receive($buffer)
    if ($n -eq 0) { break }
    if ($reply.Length + $n -gt 8192) { throw 'Reply too large' }
    $reply.Write($buffer, 0, $n)
  }
  $response = [System.Text.Encoding]::ASCII.GetString($reply.ToArray())
  $ok = $response.StartsWith('HTTP/1.') -and $response.Contains($crlf + $crlf)
  [Console]::Out.WriteLine((@{ok=$ok;bytes=[long]$reply.Length} | ConvertTo-Json -Compress))
} finally { $s.Dispose() }
"#;

#[derive(Default)]
struct Probe {
    valid_http_reply: bool,
    upstream_connected: bool,
    upstream_failed: bool,
    bytes_match: bool,
    sent: u64,
    received: u64,
}

/// A separately spawned, controllable Rust process owns the socket. Only a
/// parent-provided GO on inherited stdin permits its first SYN. The parent
/// keeps the OS child process handle live across the native packet pump.
/// This is deliberate multi-process lab evidence, NEVER a general PID token.
pub(super) fn run_child(local_ipv4: Ipv4Addr, target: SocketAddrV4) -> Result<Value, String> {
    if local_ipv4.is_unspecified()
        || local_ipv4.is_loopback()
        || local_ipv4.is_multicast()
        || target.ip().is_loopback()
        || target.ip().is_unspecified()
        || target.port() != 80
        || target.ip() == &local_ipv4
    {
        return Err("Spawned canary requires explicit non-loopback IPv4 endpoints".into());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "Child runtime creation failed")?;
    runtime.block_on(async move {
        let socket = TcpSocket::new_v4().map_err(|_| "Child TCP socket unavailable")?;
        socket
            .bind(SocketAddr::new(local_ipv4.into(), 0))
            .map_err(|_| "Child TCP source bind failed")?;
        let local = socket
            .local_addr()
            .map_err(|_| "Child TCP source identity unavailable")?;
        println!("{}", local.port());
        std::io::stdout()
            .flush()
            .map_err(|_| "Child ready handshake flush failed")?;
        let mut command = String::new();
        std::io::stdin()
            .read_line(&mut command)
            .map_err(|_| "Child GO handshake unavailable")?;
        if command.trim() != "go" {
            return Err("Child did not receive explicit GO".into());
        }
        let received = tokio::time::timeout(Duration::from_secs(8), async move {
            let mut socket = socket
                .connect(SocketAddr::V4(target))
                .await
                .map_err(|_| ())?;
            socket.write_all(REQUEST).await.map_err(|_| ())?;
            socket.shutdown().await.map_err(|_| ())?;
            let mut response = Vec::new();
            (&mut socket)
                .take(8193)
                .read_to_end(&mut response)
                .await
                .map_err(|_| ())?;
            if response.len() > 8192
                || !response.starts_with(b"HTTP/1.")
                || !response.windows(4).any(|w| w == b"\r\n\r\n")
            {
                return Err(());
            }
            Ok::<u64, ()>(response.len() as u64)
        })
        .await;
        let bytes = received.ok().and_then(Result::ok);
        Ok(json!({"ok":bytes.is_some(),"bytes":bytes.unwrap_or(0)}))
    })
}

struct SpawnedClient {
    child: Child,
    reader: BufReader<ChildStdout>,
}

enum ClientSource {
    SelfSocket(TcpSocket),
    Spawned(Box<SpawnedClient>),
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

async fn exercise_child(
    spawned: Box<SpawnedClient>,
    listener: TcpListener,
    peer: SocketAddr,
    request_target: SocketAddr,
    pool: RelayPool,
    stop: watch::Receiver<bool>,
    deadline: Duration,
) -> Probe {
    let SpawnedClient {
        mut child,
        mut reader,
    } = *spawned;
    let connected = Arc::new(AtomicBool::new(false));
    let denied = Arc::new(AtomicBool::new(false));
    let up = connected.clone();
    let down = denied.clone();
    let stdin = child.stdin.take();
    let client = async move {
        let mut stdin = stdin.ok_or(())?;
        stdin.write_all(b"go\n").await.map_err(|_| ())?;
        stdin.flush().await.map_err(|_| ())?;
        drop(stdin);
        let mut line = String::new();
        reader.read_line(&mut line).await.map_err(|_| ())?;
        let response: Value = serde_json::from_str(&line).map_err(|_| ())?;
        if response["ok"] != true {
            return Err(());
        }
        response["bytes"].as_u64().ok_or(())
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
    // The child cannot survive diversion teardown or retry DIRECT after
    // adapter mode 0 is restored, even when GO/client/SSH times out.
    let _ = child.start_kill();
    let _ = child.wait().await;
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
    let (local, source, process) = if request.spawned_child || request.powershell_child {
        let mut command = if request.powershell_child {
            // Fixed system executable, never a user-specified command.
            // Private native QA checks its Microsoft Authenticode signature.
            let root =
                std::env::var_os("SystemRoot").ok_or("Windows system directory unavailable")?;
            let binary = std::path::PathBuf::from(root)
                .join("System32")
                .join("WindowsPowerShell")
                .join("v1.0")
                .join("powershell.exe");
            if !binary.is_file() {
                return Err("System PowerShell TCP canary is unavailable".into());
            }
            let mut command = Command::new(binary);
            command
                .arg("-NoLogo")
                .arg("-NoProfile")
                .arg("-NonInteractive")
                .arg("-Command")
                .arg(POWERSHELL_CLIENT_SCRIPT)
                .env("FLOWBRIDGE_LAB_LOCAL_IPV4", request.local_ipv4.to_string())
                .env(
                    "FLOWBRIDGE_LAB_TARGET_IPV4",
                    request.target.ip().to_string(),
                )
                .env(
                    "FLOWBRIDGE_LAB_TARGET_PORT",
                    request.target.port().to_string(),
                );
            command
        } else {
            let binary = std::env::current_exe()
                .map_err(|_| "Original Rust child executable unavailable")?;
            let mut command = Command::new(binary);
            command
                .arg("native-child")
                .arg(request.local_ipv4.to_string())
                .arg(request.target.to_string());
            command
        };
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| "Bounded native child creation failed")?;
        let pid = child.id().ok_or("Child process identity unavailable")?;
        let stdout = child.stdout.take().ok_or("Child handshake unavailable")?;
        let mut reader = BufReader::new(stdout);
        let mut ready = String::new();
        let bytes = tokio::time::timeout(Duration::from_secs(6), reader.read_line(&mut ready))
            .await
            .map_err(|_| "Child ready handshake timed out")?
            .map_err(|_| "Child ready handshake failed")?;
        if bytes == 0 {
            return Err("Child exited before reserving TCP source".into());
        }
        let port: u16 = ready
            .trim()
            .parse()
            .map_err(|_| "Child source port invalid")?;
        if port == 0 {
            return Err("Child source port was zero".into());
        }
        let process = OwnedProcess::query(pid)?;
        (
            SocketAddr::new(request.local_ipv4.into(), port),
            ClientSource::Spawned(Box::new(SpawnedClient { child, reader })),
            process,
        )
    } else {
        let socket = TcpSocket::new_v4().map_err(|_| "Owned TCP socket unavailable")?;
        socket
            .bind(SocketAddr::new(request.local_ipv4.into(), 0))
            .map_err(|_| "Owned source bind failed")?;
        let local = socket
            .local_addr()
            .map_err(|_| "Owned source identity unavailable")?;
        (
            local,
            ClientSource::SelfSocket(socket),
            OwnedProcess::query(std::process::id())?,
        )
    };
    let epoch = process.evidence()?;
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
    let mut worker = match source {
        ClientSource::SelfSocket(socket) => tokio::spawn(exercise(
            socket,
            listener,
            reflect.peer,
            original.destination,
            pool,
            stop_rx,
            deadline,
        )),
        ClientSource::Spawned(spawned) => tokio::spawn(exercise_child(
            spawned,
            listener,
            reflect.peer,
            original.destination,
            pool,
            stop_rx,
            deadline,
        )),
    };
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
        "self_owned_socket_pid_epoch_consistent":native_candidate_checked && !request.spawned_child && !request.powershell_child,
        "spawned_child_socket_pid_epoch_consistent":native_candidate_checked && request.spawned_child,
        "powershell_child_socket_pid_epoch_consistent":native_candidate_checked && request.powershell_child,
        "source_authority":if request.powershell_child {
            "parent_spawned_os_powershell_client_and_bound_port_not_general_packetbound"
        } else if request.spawned_child {
            "parent_spawned_child_live_process_and_bound_port_not_general_packetbound"
        } else {
            "internally_created_live_socket_not_arbitrary_pid"
        },
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
        "note":"Controlled parent/Rust child/OS PowerShell child IPv4 canaries only. Neither authorizes arbitrary PID capture. Caller must attest real SSH and independent rescue. Mode 0 is ordinary networking, not a kill switch."
    }))
}
