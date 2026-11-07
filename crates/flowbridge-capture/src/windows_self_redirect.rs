//! Windows-only complete, bounded self-created TCP socket experiment.
//! No arbitrary application/PID can be supplied by a caller. The native socket
//! remains owned by this process until the pump ends. IP Helper only checks
//! consistency; it is NOT promoted to the production PacketBound capability.
#![cfg(all(windows, target_pointer_width = "64"))]

use crate::ndis_session::{LabDisposition, LabMode, PacketSession};
use crate::relay::RelayPool;
use crate::self_redirect::{http_g1_target_port_allowed, Reflection, Request};
use crate::windows_ndis_device::Driver;
use crate::windows_tcp_owner::{
    validate_pinned_tcp_owner_lab_missing_retry, OwnedProcess, OwnerQuery,
};
use base64::Engine;
use flowbridge_core::ndis_ethernet::{inspect_l2_ip, IpVersion};
use flowbridge_core::tcp_packet::{inspect_tcp, TcpTuple};
use flowbridge_core::Endpoint;
use serde_json::{json, Value};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::process::{Child, ChildStdout, Command};
use tokio::sync::watch;

const REQUEST: &[u8] = b"HEAD / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n";

// DIAGNOSTICS ONLY. Every emitted value is a fixed class, never the raw
// Windows API error, process identity, endpoint or packet payload.
// Classifying a rejected witness cannot change the fail-closed packet verdict.
fn sanitized_owner_denial_reason(error: &str) -> &'static str {
    if error.contains("tuple absent in consecutive fresh snapshots") {
        "missing_tuple"
    } else if error.contains("Conflicting TCP owner PID") {
        "conflicting_pid"
    } else if error.contains("Duplicate TCP tuple") {
        "duplicate_tuple"
    } else if error.contains("Matching TCP tuple is not in an active connection state") {
        "inactive_tcp_state"
    } else if error.contains("Zero PID") {
        "zero_pid"
    } else if error.contains("Pinned TCP process") || error.contains("Invalid pinned TCP") {
        "pinned_process_changed"
    } else if error.contains("IP Helper") {
        "iphelper_failure"
    } else {
        "other_fail_closed"
    }
}

fn sanitized_tcp_flag_phase(flags: u8, has_payload: bool) -> &'static str {
    if flags & 0x04 != 0 {
        "rst"
    } else if flags & 0x02 != 0 {
        "syn"
    } else if flags & 0x01 != 0 {
        "fin"
    } else if has_payload {
        "data"
    } else {
        "ack_only"
    }
}

fn sanitized_selected_packet_phase(frame: &[u8]) -> &'static str {
    let Ok(region) = inspect_l2_ip(frame) else {
        return "invalid_frame";
    };
    if region.version != IpVersion::V4 {
        return "not_ipv4";
    }
    let Some(end) = region.offset.checked_add(region.length) else {
        return "invalid_frame";
    };
    let Some(ip) = frame.get(region.offset..end) else {
        return "invalid_frame";
    };
    let Some(&first) = ip.first() else {
        return "invalid_tcp";
    };
    let tcp_offset = usize::from(first & 0x0f) * 4;
    let Some(&flags) = ip.get(tcp_offset + 13) else {
        return "invalid_tcp";
    };
    let Ok(checked) = inspect_tcp(ip) else {
        return "invalid_tcp";
    };
    sanitized_tcp_flag_phase(flags, checked.data_bytes > 0)
}

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

// Fixed, payload-free stage labels distinguish real HTTP/SSH relay stalls
// from harmless post-FIN ACK-only packets dropped after TCP closes.
fn client_progress_label(stage: u8) -> &'static str {
    match stage {
        0 => "not_started",
        1 => "tcp_connect_pending",
        2 => "tcp_connected",
        3 => "request_written",
        4 => "half_closed",
        5 => "response_read",
        6 => "http_completed",
        _ => "invalid_stage",
    }
}

fn relay_progress_label(stage: u8) -> &'static str {
    match stage {
        0 => "not_started",
        1 => "relay_accept_pending",
        2 => "relay_accepted",
        3 => "socks_connected",
        4 => "relay_completed",
        _ => "invalid_stage",
    }
}

#[derive(Default)]
struct Probe {
    valid_http_reply: bool,
    upstream_connected: bool,
    upstream_failed: bool,
    bytes_match: bool,
    sent: u64,
    received: u64,
    // Independent of the client result: a completed SOCKS relay can have
    // transferred real bytes even if the OS client later reports failure.
    // Counts only; no payload, endpoints or process identity leaves the lab.
    relay_request_bytes: u64,
    relay_response_bytes: u64,
    client_progress: &'static str,
    relay_progress: &'static str,
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
        || !http_g1_target_port_allowed(target.port())
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
    ExternalControl(u16),
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
    let client_progress = Arc::new(AtomicU8::new(0));
    let relay_progress = Arc::new(AtomicU8::new(0));
    let client_stage = client_progress.clone();
    let relay_stage = relay_progress.clone();
    let up = connected.clone();
    let down = denied.clone();
    let client = async move {
        client_stage.store(1, Ordering::SeqCst);
        let mut client = socket.connect(request_target).await.map_err(|_| ())?;
        client_stage.store(2, Ordering::SeqCst);
        client.write_all(REQUEST).await.map_err(|_| ())?;
        client_stage.store(3, Ordering::SeqCst);
        client.shutdown().await.map_err(|_| ())?;
        client_stage.store(4, Ordering::SeqCst);
        let mut reply = Vec::new();
        (&mut client)
            .take(8193)
            .read_to_end(&mut reply)
            .await
            .map_err(|_| ())?;
        client_stage.store(5, Ordering::SeqCst);
        if reply.len() > 8192
            || !reply.starts_with(b"HTTP/1.")
            || !reply.windows(4).any(|w| w == b"\r\n\r\n")
        {
            return Err(());
        }
        client_stage.store(6, Ordering::SeqCst);
        Ok::<u64, ()>(reply.len() as u64)
    };
    let forwarding = async move {
        relay_stage.store(1, Ordering::SeqCst);
        let (native, accepted_peer) = listener.accept().await.map_err(|_| ())?;
        relay_stage.store(2, Ordering::SeqCst);
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
        relay_stage.store(3, Ordering::SeqCst);
        let bytes = upstream.forward(native).await.map_err(|_| ())?;
        relay_stage.store(4, Ordering::SeqCst);
        Ok::<(u64, u64), ()>(bytes)
    };
    let results = tokio::time::timeout(deadline, async { tokio::join!(client, forwarding) }).await;
    let mut probe = Probe {
        upstream_connected: connected.load(Ordering::SeqCst),
        upstream_failed: denied.load(Ordering::SeqCst),
        client_progress: client_progress_label(client_progress.load(Ordering::SeqCst)),
        relay_progress: relay_progress_label(relay_progress.load(Ordering::SeqCst)),
        ..Probe::default()
    };
    if let Ok((_, Ok((sent, relayed)))) = &results {
        probe.relay_request_bytes = *sent;
        probe.relay_response_bytes = *relayed;
    }
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
    probe.client_progress = match &results {
        Ok((Ok(_), _)) => "client_reported_complete",
        Ok((Err(_), _)) => "client_reported_error",
        Err(_) => "transaction_timeout",
    };
    probe.relay_progress = match &results {
        Ok((_, Ok(_))) => "relay_completed",
        Ok((_, Err(_))) => "relay_failed",
        Err(_) => "transaction_timeout",
    };
    if let Ok((_, Ok((sent, relayed)))) = &results {
        probe.relay_request_bytes = *sent;
        probe.relay_response_bytes = *relayed;
    }
    if let Ok((Ok(received), Ok((sent, relayed)))) = results {
        probe.valid_http_reply = true;
        probe.sent = sent;
        probe.received = received;
        probe.bytes_match = sent == REQUEST.len() as u64 && relayed == received && received > 0;
    }
    probe
}

/// Drive an independently launched Windows PowerShell process through its
/// loopback-only GO control channel. The agent never creates that process,
/// holds only a query-only pinned OS handle, and cannot claim PacketBound.
async fn exercise_external(
    control_port: u16,
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
    let observed_bytes = Arc::new(AtomicU64::new(0));
    let client_observed_bytes = observed_bytes.clone();
    let client = async move {
        let mut channel = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], control_port)))
            .await
            .map_err(|_| ())?;
        channel.write_all(b"go\n").await.map_err(|_| ())?;
        channel.flush().await.map_err(|_| ())?;
        let mut line = String::new();
        let mut reader = BufReader::new(channel);
        let length = reader.read_line(&mut line).await.map_err(|_| ())?;
        if length == 0 || length > 256 {
            return Err(());
        }
        let report: Value = serde_json::from_str(&line).map_err(|_| ())?;
        let count = report["bytes"].as_u64().ok_or(())?;
        if count > 8192 {
            return Err(());
        }
        // Preserve observed bytes even for an invalid/partial HTTP response.
        // This never changes the fail-closed verdict or PacketBound authority.
        client_observed_bytes.store(count, Ordering::SeqCst);
        // Acknowledge the complete bounded response BEFORE closing the
        // loopback control channel. Without this handshake the independent
        // PowerShell writer can be reset while flushing the negative reply.
        let mut channel = reader.into_inner();
        channel.write_all(b"ack\n").await.map_err(|_| ())?;
        channel.flush().await.map_err(|_| ())?;
        if report["ok"] != true {
            return Err(());
        }
        Ok(count)
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
    probe.received = observed_bytes.load(Ordering::SeqCst);
    probe.client_progress = match &results {
        Ok((Ok(_), _)) => "client_reported_complete",
        Ok((Err(_), _)) => "client_reported_error",
        Err(_) => "transaction_timeout",
    };
    probe.relay_progress = match &results {
        Ok((_, Ok(_))) => "relay_completed",
        Ok((_, Err(_))) => "relay_failed",
        Err(_) => "transaction_timeout",
    };
    if let Ok((_, Ok((sent, relayed)))) = &results {
        probe.relay_request_bytes = *sent;
        probe.relay_response_bytes = *relayed;
    }
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
    let (local, source, process) = if let Some(external) = &request.external_client {
        if external.pid == std::process::id() {
            return Err("Unrelated canary cannot be this Rust agent".into());
        }
        let pinned = OwnedProcess::query(external.pid)?;
        let identity = pinned.evidence()?;
        let root =
            std::env::var_os("SystemRoot").ok_or("Fixed Windows system directory unavailable")?;
        let expected = std::path::PathBuf::from(root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        if !identity
            .path
            .eq_ignore_ascii_case(&expected.to_string_lossy())
        {
            return Err("Independent canary must be the fixed OS PowerShell binary".into());
        }
        (
            SocketAddr::new(request.local_ipv4.into(), external.source_port),
            ClientSource::ExternalControl(external.control_port),
            pinned,
        )
    } else if request.spawned_child || request.powershell_child {
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
            // EncodedCommand is the documented UTF-16LE PowerShell invocation.
            // It avoids Windows CRT command-line quoting of static multiline
            // script text. No secrets or caller-provided source enter the arg.
            let script_bytes: Vec<u8> = POWERSHELL_CLIENT_SCRIPT
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
            let encoded = base64::engine::general_purpose::STANDARD.encode(script_bytes);
            command
                .arg("-NoLogo")
                .arg("-NoProfile")
                .arg("-NonInteractive")
                .arg("-EncodedCommand")
                .arg(encoded)
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
        ClientSource::ExternalControl(port) => tokio::spawn(exercise_external(
            port,
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
    let mut owner_candidate_checks = 0u64;
    let mut owner_candidate_denials = 0u64;
    let mut owner_missing_snapshot_retry_attempts = 0u64;
    let mut first_selected_owner_denial_reason: &'static str = "none";
    let mut first_selected_owner_denial_tcp_phase: &'static str = "none";
    let mut selected_direct_sends = 0u64;
    while start.elapsed() < timeout && !worker.is_finished() {
        let outcome = session.poll_lab_redirect(128, &mut |packet| {
            let selected_candidate = crate::self_redirect::candidate_tuple(packet.frame)
                == Some(original)
                || crate::self_redirect::ambiguous_fragment_to_target(packet.frame, original);
            let decision = reflect.decide(packet, &mut || {
                if !matches!(process.evidence(), Ok(now) if now == epoch) {
                    owner_candidate_denials += 1;
                    if selected_candidate && first_selected_owner_denial_reason == "none" {
                        first_selected_owner_denial_reason = "pinned_process_changed";
                        first_selected_owner_denial_tcp_phase =
                            sanitized_selected_packet_phase(packet.frame);
                    }
                    return false;
                }
                // Re-read the real OS TCP table for EVERY original outbound
                // packet. A successfully matched first SYN never authorizes
                // subsequent packets after socket/tuple reuse or PID churn.
                // This remains bounded laboratory evidence, NOT PacketBound.
                if selected_candidate {
                    owner_candidate_checks += 1;
                    match validate_pinned_tcp_owner_lab_missing_retry(
                        &OwnerQuery {
                            local: original.source,
                            remote: original.destination,
                        },
                        &epoch,
                        &process,
                    ) {
                        Ok(extra_attempts) => {
                            owner_missing_snapshot_retry_attempts += u64::from(extra_attempts);
                        }
                        Err(error) => {
                            owner_candidate_denials += 1;
                            if first_selected_owner_denial_reason == "none" {
                                first_selected_owner_denial_reason =
                                    sanitized_owner_denial_reason(&error);
                                first_selected_owner_denial_tcp_phase =
                                    sanitized_selected_packet_phase(packet.frame);
                            }
                            return false;
                        }
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
    // Unlike spawned children, the unrelated OS canary cannot be killed by
    // this agent. The exact pinned process must exit BEFORE restoring ordinary
    // DIRECT-capable mode 0. Keep pumping unselected traffic while waiting.
    // A timeout fails this trial; an independent SYSTEM rescue remains required.
    let mut external_exited = request.external_client.is_none();
    if !external_exited {
        let exit_started = Instant::now();
        while exit_started.elapsed() < Duration::from_secs(2) {
            if matches!(process.is_active(), Ok(false)) {
                external_exited = true;
                break;
            }
            if let Err(error) = session
                .poll_lab_redirect(128, &mut |packet| Ok(reflect.decide(packet, &mut || false)))
            {
                fault = Some(error.to_string());
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
    let stats = session.stats();
    let cleanup = session.close();
    let [self_epoch, child_epoch, powershell_epoch, external_epoch] =
        crate::self_redirect::owner_evidence_flags(
            native_candidate_checked,
            request.spawned_child,
            request.powershell_child,
            request.external_client.is_some(),
        );
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
        && owner_candidate_checks > 0
        // A live flow can disappear from IP Helper between FIN/ACK packets.
        // Fail CLOSED for that segment, not for the entire already-verified
        // completed HTTP transaction. Every invalid witness MUST be a DROP:
        // no unknown packet is re-injected as an original/direct frame.
        && owner_candidate_denials <= reflect.counters.selected_dropped
        && external_exited
        && reflect.counters.owner_checked
        && reflect.counters.client_reflected > 0
        && transport
        && reflect.counters.checksums_or_options_rejected == 0
        && selected_direct_sends == 0;
    let mut report = json!({
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
        "self_owned_socket_pid_epoch_consistent":self_epoch,
        "spawned_child_socket_pid_epoch_consistent":child_epoch,
        "powershell_child_socket_pid_epoch_consistent":powershell_epoch,
        "external_sibling_socket_pid_epoch_consistent":external_epoch,
        "external_process_exit_confirmed":external_exited,
        "source_authority":if request.external_client.is_some() {
            "independently_launched_fixed_os_powershell_bound_socket_not_packetbound"
        } else if request.powershell_child {
            "parent_spawned_os_powershell_client_and_bound_port_not_general_packetbound"
        } else if request.spawned_child {
            "parent_spawned_child_live_process_and_bound_port_not_general_packetbound"
        } else {
            "internally_created_live_socket_not_arbitrary_pid"
        },
        "selected_original_frames_sent_to_adapter":selected_direct_sends,
        "fresh_tcp_owner_candidate_checks":owner_candidate_checks,
        "fresh_tcp_owner_candidate_denials":owner_candidate_denials,
        "outbound_candidate_revalidated_for_each_selected_packet":true,
        "fresh_owner_candidate_is_not_packetbound":true,
        "upstream_socks_connected":probe.upstream_connected,
        "upstream_socks_failed":probe.upstream_failed,
        "application_received_http":probe.valid_http_reply,
        "application_and_relay_byte_counts_match":probe.bytes_match,
        "bytes_sent":probe.sent, "bytes_received":probe.received,
        "arbitrary_app_owner_binding_accepted":false, "native_owner_binding_accepted":false,
        "protected_redirect_available":false, "dns_leak_free":false,
        "win10_11_acceptance":false, "release_accepted":false,
        "payload_or_process_identity_logged":false,
        "note":"Controlled parent, Rust child, OS PowerShell child and independently launched OS PowerShell IPv4 canaries only. IP Helper is NOT PacketBound. Unrelated canary must exit before mode 0. Caller must attest independent rescue, signed driver and real SSH. Mode 0 is ordinary networking."
    });
    // Keep the macro expansion bounded: attach sanitized G1 transport stages
    // outside the existing large JSON expression, without changing verdicts.
    report["client_progress"] = json!(probe.client_progress);
    report["relay_progress"] = json!(probe.relay_progress);
    // These counts are retained even when the PowerShell client reports a
    // failed HTTP transaction, enabling a native reverse-path diagnosis.
    // They do not authorize a packet or change the original PASS verdict.
    report["relay_request_bytes"] = json!(probe.relay_request_bytes);
    report["relay_response_bytes"] = json!(probe.relay_response_bytes);
    // Keep this safety invariant explicit without deepening serde_json's
    // already large recursive laboratory JSON macro expansion.
    report["fresh_tcp_owner_candidate_missing_snapshot_retry_attempts"] =
        json!(owner_missing_snapshot_retry_attempts);
    report["fresh_tcp_owner_candidate_retries_only_missing"] = json!(true);
    report["fresh_tcp_owner_candidate_first_denial_reason"] =
        json!(first_selected_owner_denial_reason);
    report["fresh_tcp_owner_candidate_first_denial_tcp_phase"] =
        json!(first_selected_owner_denial_tcp_phase);
    report["fresh_tcp_owner_candidate_denials_dropped"] =
        json!(owner_candidate_denials <= reflect.counters.selected_dropped);
    report["ambiguous_tcp_fragments_quarantined"] =
        json!(reflect.counters.ambiguous_fragment_dropped);
    Ok(report)
}

#[cfg(test)]
mod sanitized_owner_diagnostic_tests {
    use super::{sanitized_owner_denial_reason, sanitized_tcp_flag_phase};

    #[test]
    fn child_http_g1_keeps_exact_request_and_bounded_target_ports() {
        assert_eq!(super::REQUEST.len(), 57);
        assert!(super::http_g1_target_port_allowed(80));
        assert!(super::http_g1_target_port_allowed(18080));
        for port in [0, 79, 81, 443, 1080, 18079, 18081, u16::MAX] {
            assert!(!super::http_g1_target_port_allowed(port));
        }
    }

    #[test]
    fn bounded_categories_cannot_expose_native_error_details() {
        let known = [
            (
                "TCP tuple absent in consecutive fresh snapshots after bounded retry",
                "missing_tuple",
            ),
            ("Conflicting TCP owner PID (no retry)", "conflicting_pid"),
            (
                "Duplicate TCP tuple, even with identical PID",
                "duplicate_tuple",
            ),
            (
                "Matching TCP tuple is not in an active connection state",
                "inactive_tcp_state",
            ),
            ("Zero PID in matching endpoint", "zero_pid"),
            (
                "Pinned TCP process identity is no longer active",
                "pinned_process_changed",
            ),
            ("IP Helper sizing failed: 122", "iphelper_failure"),
        ];
        for (error, expected) in known {
            assert_eq!(sanitized_owner_denial_reason(error), expected);
        }
        assert_eq!(
            sanitized_owner_denial_reason(r"PID=1234 C:\Users\Private\secret.exe 10.0.0.17:55555"),
            "other_fail_closed"
        );
    }

    #[test]
    fn packet_phase_diagnostic_is_only_a_fixed_tcp_class() {
        assert_eq!(sanitized_tcp_flag_phase(0x02, false), "syn");
        assert_eq!(sanitized_tcp_flag_phase(0x11, false), "fin");
        assert_eq!(sanitized_tcp_flag_phase(0x10, true), "data");
        assert_eq!(sanitized_tcp_flag_phase(0x10, false), "ack_only");
        assert_eq!(sanitized_tcp_flag_phase(0x14, true), "rst");
    }
}
