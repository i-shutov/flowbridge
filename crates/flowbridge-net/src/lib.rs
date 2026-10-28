//! TCP proxy negotiation and an explicit, loopback-only SOCKS5 ingress.
//!
//! A route is fail-closed: only its first hop is resolved locally, each following
//! destination is negotiated over the existing stream, and errors never select a
//! different route. Handshake errors deliberately omit server text and secrets.

use base64::{engine::general_purpose::STANDARD, Engine};
use flowbridge_core::{Endpoint, Proxy, ProxyKind};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpSocket, TcpStream},
    sync::watch,
    time::{self, Instant},
};

mod prepared;

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADER_LINE: usize = 4096;
const MAX_CHAIN_HOPS: usize = 16;
const MAX_HTTP_PASSWORD_BYTES: usize = 1024;

/// Errors contain fixed protocol descriptions and numeric status codes only.
/// Proxy responses and credential values must never be copied into diagnostics.
#[derive(Debug, Error)]
pub enum NetError {
    #[error("I/O error during {stage}: {source}")]
    Io {
        stage: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("timeout during {stage}")]
    Timeout { stage: &'static str },
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(&'static str),
    #[error("invalid transport configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("{protocol} protocol error: {message}")]
    Protocol {
        protocol: &'static str,
        message: &'static str,
    },
    #[error("{protocol} authentication failed: {message}")]
    Authentication {
        protocol: &'static str,
        message: &'static str,
    },
    #[error("{protocol} proxy rejected CONNECT (status {code})")]
    ProxyRejected { protocol: &'static str, code: u16 },
    #[error("SOCKS5 command {0} is unsupported; only TCP CONNECT is available")]
    UnsupportedCommand(u8),
    #[error("SOCKS5 ingress requires a loopback peer")]
    NonLoopbackIngress,
    #[error("first TCP hop resolves to the local SOCKS listener")]
    RecursiveListener,
    #[error("relay idle timeout")]
    IdleTimeout,
}

fn io_error(stage: &'static str, source: io::Error) -> NetError {
    NetError::Io { stage, source }
}

fn protocol(protocol: &'static str, message: &'static str) -> NetError {
    NetError::Protocol { protocol, message }
}

fn auth(protocol: &'static str, message: &'static str) -> NetError {
    NetError::Authentication { protocol, message }
}

fn check_timeout(timeout: Duration) -> Result<(), NetError> {
    // This also prevents overflowing Instant when callers bypass Config.
    if timeout.is_zero() || timeout > Duration::from_secs(24 * 60 * 60) {
        return Err(NetError::InvalidConfig(
            "timeout must be between 1 ns and 24 hours",
        ));
    }
    Ok(())
}

fn host(endpoint: &Endpoint) -> Result<&str, NetError> {
    let value = endpoint.host.as_str();
    // Accept brackets defensively at the transport boundary; configuration uses
    // bare IP literals. Brackets are emitted exactly once in HTTP authorities.
    let value = match (value.strip_prefix('['), value.strip_suffix(']')) {
        (Some(_), Some(_)) if value.len() >= 2 => {
            let inner = &value[1..value.len() - 1];
            if inner.parse::<Ipv6Addr>().is_err() {
                return Err(NetError::InvalidEndpoint("invalid bracketed IPv6 address"));
            }
            Endpoint {
                host: inner.to_owned(),
                port: endpoint.port,
            }
            .validate()
            .map_err(|_| NetError::InvalidEndpoint("invalid IP address or port"))?;
            return Ok(inner);
        }
        (None, None) => value,
        _ => return Err(NetError::InvalidEndpoint("unmatched address brackets")),
    };
    endpoint
        .validate()
        .map_err(|_| NetError::InvalidEndpoint("invalid DNS hostname, IP address, or port"))?;
    Ok(value)
}

// Never derive Debug for a type containing credentials.
struct Credentials {
    username: String,
    password: Option<String>,
}

fn credentials(proxy: &Proxy) -> Result<Option<Credentials>, NetError> {
    let Some(username) = proxy.username.as_ref() else {
        if proxy.password_env.is_some() {
            return Err(NetError::InvalidConfig(
                "password reference requires a username",
            ));
        }
        return Ok(None);
    };
    if username.is_empty() || username.len() > 255 || username.chars().any(char::is_control) {
        return Err(NetError::InvalidConfig("invalid proxy username"));
    }
    if matches!(proxy.kind, ProxyKind::Socks4a) {
        if proxy.password_env.is_some() {
            return Err(NetError::InvalidConfig(
                "SOCKS4a does not support a password",
            ));
        }
        return Ok(Some(Credentials {
            username: username.clone(),
            password: None,
        }));
    }
    if matches!(proxy.kind, ProxyKind::HttpConnect) && username.contains(':') {
        return Err(NetError::InvalidConfig(
            "HTTP Basic username cannot contain a colon",
        ));
    }
    let env_name = proxy.password_env.as_ref().ok_or(NetError::InvalidConfig(
        "authenticated proxy requires a password environment reference",
    ))?;
    if env_name.is_empty()
        || env_name.len() > 128
        || !env_name
            .bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
    {
        return Err(NetError::InvalidConfig(
            "invalid password environment reference",
        ));
    }
    let password = std::env::var(env_name).map_err(|_| {
        auth(
            "proxy",
            "password environment variable is absent or not UTF-8",
        )
    })?;
    let max = if matches!(proxy.kind, ProxyKind::Socks5) {
        255
    } else {
        MAX_HTTP_PASSWORD_BYTES
    };
    if password.is_empty() || password.len() > max || password.chars().any(char::is_control) {
        return Err(NetError::InvalidConfig(
            "invalid proxy password length or characters",
        ));
    }
    Ok(Some(Credentials {
        username: username.clone(),
        password: Some(password),
    }))
}

/// Establish a direct TCP connection or negotiate every proxy on one TCP stream.
///
/// Only an empty route permits a direct connection. DNS for destinations after
/// the first hop is encoded in the proxy protocol rather than resolved locally.
/// Each hop has a separate handshake deadline; the TCP/DNS deadline covers the
/// initial connection. All credentials are checked before opening a socket.
pub async fn connect_route(
    target: &Endpoint,
    route: &[Proxy],
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Result<TcpStream, NetError> {
    connect_route_inner(
        target,
        route,
        connect_timeout,
        handshake_timeout,
        None,
        None,
    )
    .await
}

/// Connect a route while preventing recursion into a local SOCKS listener.
///
/// The actual first TCP hop (the target for Direct, otherwise the first proxy)
/// is resolved once, checked in full, then connected using the vetted addresses.
/// DNS and connection attempts share `connect_timeout`. Any loopback or IPv4-
/// mapped loopback result at the listener port rejects the whole resolution set,
/// including when other results would be safe. Subsequent proxy destinations
/// remain remotely resolved and are not subject to this local-listener guard.
pub async fn connect_route_guarded(
    target: &Endpoint,
    route: &[Proxy],
    connect_timeout: Duration,
    handshake_timeout: Duration,
    forbidden_listener: SocketAddr,
) -> Result<TcpStream, NetError> {
    connect_route_inner(
        target,
        route,
        connect_timeout,
        handshake_timeout,
        Some(forbidden_listener),
        None,
    )
    .await
}

/// Guarded route with a native pre-connect socket preparation callback.
///
/// The callback runs on every fresh socket before its connect attempt. An error
/// aborts the route: no unprepared retry is allowed. Windows WFP uses this hook to
/// attach opaque redirection records before the outbound SYN. The callback must
/// be quick and nonblocking; it runs within the overall first-hop deadline.
pub async fn connect_route_prepared(
    target: &Endpoint,
    route: &[Proxy],
    connect_timeout: Duration,
    handshake_timeout: Duration,
    forbidden_listener: SocketAddr,
    prepare: &(dyn Fn(&TcpSocket) -> io::Result<()> + Sync),
) -> Result<TcpStream, NetError> {
    connect_route_inner(
        target,
        route,
        connect_timeout,
        handshake_timeout,
        Some(forbidden_listener),
        Some(prepare),
    )
    .await
}

type SocketPreparation<'a> = Option<&'a (dyn Fn(&TcpSocket) -> io::Result<()> + Sync)>;

async fn connect_addresses(
    addresses: &[SocketAddr],
    prepare: SocketPreparation<'_>,
) -> Result<TcpStream, NetError> {
    let Some(prepare) = prepare else {
        return TcpStream::connect(addresses)
            .await
            .map_err(|e| io_error("TCP connect", e));
    };
    prepared::connect(addresses, prepare, |socket, address| {
        socket.connect(address)
    })
    .await
}

async fn connect_route_inner(
    target: &Endpoint,
    route: &[Proxy],
    connect_timeout: Duration,
    handshake_timeout: Duration,
    forbidden_listener: Option<SocketAddr>,
    prepare: SocketPreparation<'_>,
) -> Result<TcpStream, NetError> {
    check_timeout(connect_timeout)?;
    check_timeout(handshake_timeout)?;
    host(target)?;
    if route.len() > MAX_CHAIN_HOPS {
        return Err(NetError::InvalidConfig("proxy chain exceeds 16 hops"));
    }
    let mut auths = Vec::with_capacity(route.len());
    for proxy in route {
        host(&proxy.endpoint)?;
        auths.push(credentials(proxy)?);
    }
    let first = route.first().map(|proxy| &proxy.endpoint).unwrap_or(target);
    let mut stream = time::timeout(connect_timeout, async {
        let first_host = host(first)?;
        // Keep the exact vetted resolution set for every connect attempt.
        let addresses: Vec<SocketAddr> = tokio::net::lookup_host((first_host, first.port))
            .await
            .map_err(|e| io_error("first-hop DNS", e))?
            .collect();
        if let Some(listener) = forbidden_listener {
            vet_first_hop(&addresses, listener)?;
        }
        connect_addresses(&addresses, prepare).await
    })
    .await
    .map_err(|_| NetError::Timeout {
        stage: "TCP connect and DNS",
    })??;
    for (index, proxy) in route.iter().enumerate() {
        let next = route.get(index + 1).map(|p| &p.endpoint).unwrap_or(target);
        let credential = auths[index].as_ref();
        time::timeout(handshake_timeout, async {
            match proxy.kind {
                ProxyKind::Socks5 => socks5_connect(&mut stream, next, credential).await,
                ProxyKind::Socks4a => socks4a_connect(&mut stream, next, credential).await,
                ProxyKind::HttpConnect => http_connect(&mut stream, next, credential).await,
            }
        })
        .await
        .map_err(|_| NetError::Timeout {
            stage: "proxy handshake",
        })??;
    }
    Ok(stream)
}

fn is_loopback(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
        }
    }
}

fn vet_first_hop(addresses: &[SocketAddr], listener: SocketAddr) -> Result<(), NetError> {
    if addresses
        .iter()
        .any(|address| address.port() == listener.port() && is_loopback(address.ip()))
    {
        return Err(NetError::RecursiveListener);
    }
    Ok(())
}

async fn write(stream: &mut TcpStream, data: &[u8], stage: &'static str) -> Result<(), NetError> {
    stream.write_all(data).await.map_err(|e| io_error(stage, e))
}

async fn read(
    stream: &mut TcpStream,
    data: &mut [u8],
    stage: &'static str,
) -> Result<(), NetError> {
    stream
        .read_exact(data)
        .await
        .map(|_| ())
        .map_err(|e| io_error(stage, e))
}

fn socks5_address(target: &Endpoint, packet: &mut Vec<u8>) -> Result<(), NetError> {
    let name = host(target)?;
    match name.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => {
            packet.push(1);
            packet.extend_from_slice(&address.octets());
        }
        Ok(IpAddr::V6(address)) => {
            packet.push(4);
            packet.extend_from_slice(&address.octets());
        }
        Err(_) => {
            packet.push(3);
            packet.push(name.len() as u8);
            packet.extend_from_slice(name.as_bytes());
        }
    }
    packet.extend_from_slice(&target.port.to_be_bytes());
    Ok(())
}

async fn socks5_connect(
    stream: &mut TcpStream,
    target: &Endpoint,
    credential: Option<&Credentials>,
) -> Result<(), NetError> {
    let method = if credential.is_some() { 2 } else { 0 };
    write(stream, &[5, 1, method], "SOCKS5 greeting").await?;
    let mut response = [0; 2];
    read(stream, &mut response, "SOCKS5 greeting").await?;
    if response[0] != 5 {
        return Err(protocol("SOCKS5", "invalid greeting version"));
    }
    if response[1] != method {
        return Err(auth(
            "SOCKS5",
            "server did not select the required authentication method",
        ));
    }
    if let Some(credential) = credential {
        let password = credential
            .password
            .as_ref()
            .ok_or_else(|| auth("SOCKS5", "missing password"))?;
        let mut request = Vec::with_capacity(3 + credential.username.len() + password.len());
        request.extend_from_slice(&[1, credential.username.len() as u8]);
        request.extend_from_slice(credential.username.as_bytes());
        request.push(password.len() as u8);
        request.extend_from_slice(password.as_bytes());
        write(stream, &request, "SOCKS5 authentication").await?;
        read(stream, &mut response, "SOCKS5 authentication").await?;
        if response[0] != 1 {
            return Err(protocol("SOCKS5", "invalid authentication version"));
        }
        if response[1] != 0 {
            return Err(auth("SOCKS5", "credentials rejected"));
        }
    }
    let mut request = vec![5, 1, 0];
    socks5_address(target, &mut request)?;
    write(stream, &request, "SOCKS5 CONNECT request").await?;
    let mut response = [0; 4];
    read(stream, &mut response, "SOCKS5 CONNECT response").await?;
    if response[0] != 5 || response[2] != 0 {
        return Err(protocol("SOCKS5", "invalid CONNECT response header"));
    }
    if response[1] > 8 {
        return Err(protocol("SOCKS5", "invalid CONNECT status"));
    }
    if response[1] != 0 {
        return Err(NetError::ProxyRejected {
            protocol: "SOCKS5",
            code: u16::from(response[1]),
        });
    }
    let length = match response[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut length = [0];
            read(stream, &mut length, "SOCKS5 bound hostname length").await?;
            if length[0] == 0 {
                return Err(protocol("SOCKS5", "empty bound hostname"));
            }
            usize::from(length[0])
        }
        _ => return Err(protocol("SOCKS5", "invalid bound address type")),
    };
    let mut address = [0; 257];
    read(stream, &mut address[..length + 2], "SOCKS5 bound address").await
}

async fn socks4a_connect(
    stream: &mut TcpStream,
    target: &Endpoint,
    credential: Option<&Credentials>,
) -> Result<(), NetError> {
    let name = host(target)?;
    let (address, append_hostname) = match name.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            let bytes = ip.octets();
            // SOCKS4a reserves 0.0.0.x (x != 0) as its hostname marker.
            let reserved = bytes[..3] == [0, 0, 0] && bytes[3] != 0;
            (if reserved { [0, 0, 0, 1] } else { bytes }, reserved)
        }
        Ok(IpAddr::V6(_)) => return Err(protocol("SOCKS4a", "IPv6 targets are unsupported")),
        Err(_) => ([0, 0, 0, 1], true),
    };
    let mut request = vec![4, 1];
    request.extend_from_slice(&target.port.to_be_bytes());
    request.extend_from_slice(&address);
    if let Some(credential) = credential {
        request.extend_from_slice(credential.username.as_bytes());
    }
    request.push(0);
    if append_hostname {
        request.extend_from_slice(name.as_bytes());
        request.push(0);
    }
    write(stream, &request, "SOCKS4a CONNECT request").await?;
    let mut response = [0; 8];
    read(stream, &mut response, "SOCKS4a CONNECT response").await?;
    if response[0] != 0 {
        return Err(protocol("SOCKS4a", "invalid response version"));
    }
    match response[1] {
        90 => Ok(()),
        91..=93 => Err(NetError::ProxyRejected {
            protocol: "SOCKS4a",
            code: u16::from(response[1]),
        }),
        _ => Err(protocol("SOCKS4a", "invalid response status")),
    }
}

fn authority(target: &Endpoint) -> Result<String, NetError> {
    let name = host(target)?;
    if name.parse::<Ipv6Addr>().is_ok() {
        Ok(format!("[{name}]:{}", target.port))
    } else {
        Ok(format!("{name}:{}", target.port))
    }
}

async fn http_connect(
    stream: &mut TcpStream,
    target: &Endpoint,
    credential: Option<&Credentials>,
) -> Result<(), NetError> {
    let authority = authority(target)?;
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n"
    );
    if let Some(credential) = credential {
        let password = credential
            .password
            .as_ref()
            .ok_or_else(|| auth("HTTP CONNECT", "missing password"))?;
        let token = STANDARD.encode(format!("{}:{password}", credential.username));
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(&token);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    write(stream, request.as_bytes(), "HTTP CONNECT request").await?;
    for _ in 0..=4 {
        let header = read_http_header(stream).await?;
        let code = parse_http_response(&header)?;
        match code {
            200..=299 => return Ok(()),
            100..=199 if code != 101 => continue,
            407 => {
                return Err(auth(
                    "HTTP CONNECT",
                    "proxy authentication required or rejected",
                ))
            }
            _ => {
                return Err(NetError::ProxyRejected {
                    protocol: "HTTP CONNECT",
                    code,
                })
            }
        }
    }
    Err(protocol("HTTP CONNECT", "too many informational responses"))
}

async fn read_http_header(stream: &mut TcpStream) -> Result<Vec<u8>, NetError> {
    let mut header = Vec::with_capacity(512);
    let mut line_length = 0;
    // Read exactly through CRLFCRLF. A buffered read could consume bytes that
    // already belong to the tunnel, which cannot be returned in this TcpStream API.
    while header.len() < MAX_HEADER_BYTES {
        let mut byte = [0];
        read(stream, &mut byte, "HTTP CONNECT response").await?;
        header.push(byte[0]);
        line_length += 1;
        if line_length > MAX_HEADER_LINE {
            return Err(protocol("HTTP CONNECT", "response line too long"));
        }
        if byte[0] == b'\n' {
            if header.len() < 2 || header[header.len() - 2] != b'\r' {
                return Err(protocol(
                    "HTTP CONNECT",
                    "response requires CRLF line endings",
                ));
            }
            line_length = 0;
        }
        if header.ends_with(b"\r\n\r\n") {
            return Ok(header);
        }
    }
    Err(protocol("HTTP CONNECT", "response headers too large"))
}

fn header_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn parse_http_response(header: &[u8]) -> Result<u16, NetError> {
    let response = std::str::from_utf8(header)
        .map_err(|_| protocol("HTTP CONNECT", "invalid header encoding"))?;
    let mut lines = response[..response.len() - 4].split("\r\n");
    let status = lines
        .next()
        .ok_or_else(|| protocol("HTTP CONNECT", "missing status line"))?
        .as_bytes();
    if status.len() < 12
        || (&status[..9] != b"HTTP/1.0 " && &status[..9] != b"HTTP/1.1 ")
        || !status[9..12].iter().all(u8::is_ascii_digit)
        || (status.len() > 12 && status[12] != b' ')
        || status[12..]
            .iter()
            .any(|b| !b.is_ascii() || b.is_ascii_control())
    {
        return Err(protocol("HTTP CONNECT", "invalid status line"));
    }
    let code = u16::from(status[9] - b'0') * 100
        + u16::from(status[10] - b'0') * 10
        + u16::from(status[11] - b'0');
    if !(100..=599).contains(&code) {
        return Err(protocol("HTTP CONNECT", "invalid status code"));
    }
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| protocol("HTTP CONNECT", "invalid header field"))?;
        if name.is_empty()
            || !name.bytes().all(header_token)
            || value
                .bytes()
                .any(|b| !b.is_ascii() || (b.is_ascii_control() && b != b'\t'))
        {
            return Err(protocol("HTTP CONNECT", "invalid header field"));
        }
    }
    Ok(code)
}

/// Parse a no-authentication SOCKS5 TCP CONNECT from a loopback peer.
///
/// This function sends method selection and error replies. The caller sends the
/// eventual success reply only after its policy and route connection succeed.
/// Unsupported BIND and UDP ASSOCIATE requests receive status 0x07.
pub async fn accept_socks5(
    stream: &mut TcpStream,
    timeout: Duration,
) -> Result<Endpoint, NetError> {
    check_timeout(timeout)?;
    if !stream
        .peer_addr()
        .map_err(|e| io_error("SOCKS5 peer address", e))?
        .ip()
        .is_loopback()
    {
        return Err(NetError::NonLoopbackIngress);
    }
    match time::timeout(timeout, accept_socks5_inner(stream)).await {
        Ok(result) => result,
        Err(_) => {
            // A fixed-size best-effort reply must not extend the handshake deadline.
            let _ = stream.try_write(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
            Err(NetError::Timeout {
                stage: "SOCKS5 ingress handshake",
            })
        }
    }
}

async fn accept_socks5_inner(stream: &mut TcpStream) -> Result<Endpoint, NetError> {
    let mut greeting = [0; 2];
    read(stream, &mut greeting, "SOCKS5 ingress greeting").await?;
    if greeting[0] != 5 || greeting[1] == 0 {
        write(stream, &[5, 255], "SOCKS5 ingress method rejection").await?;
        return Err(protocol("SOCKS5 ingress", "invalid greeting"));
    }
    let mut methods = [0; 255];
    read(
        stream,
        &mut methods[..usize::from(greeting[1])],
        "SOCKS5 ingress methods",
    )
    .await?;
    if !methods[..usize::from(greeting[1])].contains(&0) {
        write(stream, &[5, 255], "SOCKS5 ingress method rejection").await?;
        return Err(auth("SOCKS5 ingress", "no supported authentication method"));
    }
    write(stream, &[5, 0], "SOCKS5 ingress method selection").await?;
    let mut request = [0; 4];
    read(stream, &mut request, "SOCKS5 ingress request").await?;
    if request[0] != 5 || request[2] != 0 {
        reply_socks5(stream, 1).await?;
        return Err(protocol("SOCKS5 ingress", "invalid CONNECT request header"));
    }
    if request[1] != 1 {
        reply_socks5(stream, 7).await?;
        return Err(NetError::UnsupportedCommand(request[1]));
    }
    let name = match request[3] {
        1 => {
            let mut bytes = [0; 4];
            read(stream, &mut bytes, "SOCKS5 ingress IPv4 address").await?;
            Ipv4Addr::from(bytes).to_string()
        }
        4 => {
            let mut bytes = [0; 16];
            read(stream, &mut bytes, "SOCKS5 ingress IPv6 address").await?;
            Ipv6Addr::from(bytes).to_string()
        }
        3 => {
            let mut length = [0];
            read(stream, &mut length, "SOCKS5 ingress hostname length").await?;
            if length[0] == 0 {
                reply_socks5(stream, 8).await?;
                return Err(protocol("SOCKS5 ingress", "empty hostname"));
            }
            let mut bytes = vec![0; usize::from(length[0])];
            read(stream, &mut bytes, "SOCKS5 ingress hostname").await?;
            match String::from_utf8(bytes) {
                Ok(value) => value,
                Err(_) => {
                    reply_socks5(stream, 8).await?;
                    return Err(protocol("SOCKS5 ingress", "invalid hostname encoding"));
                }
            }
        }
        _ => {
            reply_socks5(stream, 8).await?;
            return Err(protocol("SOCKS5 ingress", "unsupported address type"));
        }
    };
    let mut port = [0; 2];
    read(stream, &mut port, "SOCKS5 ingress port").await?;
    let endpoint = Endpoint {
        host: name,
        port: u16::from_be_bytes(port),
    };
    if let Err(error) = host(&endpoint) {
        reply_socks5(stream, 8).await?;
        return Err(error);
    }
    Ok(endpoint)
}

/// Send a SOCKS5 reply with an unspecified IPv4 bound address and port.
pub async fn reply_socks5(stream: &mut TcpStream, code: u8) -> Result<(), NetError> {
    if code > 8 {
        return Err(NetError::InvalidConfig("invalid SOCKS5 reply code"));
    }
    write(
        stream,
        &[5, code, 0, 1, 0, 0, 0, 0, 0, 0],
        "SOCKS5 ingress reply",
    )
    .await
}

struct ActivityIo<'a> {
    stream: &'a mut TcpStream,
    activity: watch::Sender<Instant>,
}

impl AsyncRead for ActivityIo<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut *self.stream).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.activity.send_replace(Instant::now());
        }
        result
    }
}

impl AsyncWrite for ActivityIo<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut *self.stream).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Ok(count)) if count > 0) {
            self.activity.send_replace(Instant::now());
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.stream).poll_shutdown(cx)
    }
}

/// Copy both directions until both halves close or neither direction makes
/// progress for `idle_timeout`. EOF half-closes the other socket's write half,
/// allowing its response to finish. Counts are (a-to-b, b-to-a).
pub async fn relay(
    a: &mut TcpStream,
    b: &mut TcpStream,
    idle_timeout: Duration,
) -> Result<(u64, u64), NetError> {
    check_timeout(idle_timeout)?;
    let (activity, mut updates) = watch::channel(Instant::now());
    let mut a = ActivityIo {
        stream: a,
        activity: activity.clone(),
    };
    let mut b = ActivityIo {
        stream: b,
        activity,
    };
    let copy = tokio::io::copy_bidirectional(&mut a, &mut b);
    tokio::pin!(copy);
    let deadline = time::sleep(idle_timeout);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            result = &mut copy => return result.map_err(|e| io_error("TCP relay", e)),
            changed = updates.changed() => {
                if changed.is_ok() {
                    let latest = *updates.borrow_and_update();
                    deadline.as_mut().reset(latest + idle_timeout);
                }
            }
            _ = &mut deadline => {
                let latest = *updates.borrow_and_update();
                if Instant::now().duration_since(latest) >= idle_timeout {
                    return Err(NetError::IdleTimeout);
                }
                deadline.as_mut().reset(latest + idle_timeout);
            }
        }
    }
}

#[cfg(test)]
mod guarded_address_tests {
    use super::*;

    #[test]
    fn rejects_every_loopback_form_in_the_complete_resolution_set() {
        let listener = "127.0.0.1:1080".parse().unwrap();
        let safe = "192.0.2.10:1080".parse().unwrap();
        for address in [
            "127.0.0.1:1080",
            "127.19.20.21:1080",
            "[::1]:1080",
            "[::ffff:127.0.0.1]:1080",
            "[::ffff:127.19.20.21]:1080",
        ] {
            // An arbitrary DNS alias may return a safe result before a
            // recursive result. No connection may start before all are vetted.
            let addresses = [safe, address.parse().unwrap()];
            assert!(matches!(
                vet_first_hop(&addresses, listener),
                Err(NetError::RecursiveListener)
            ));
        }
    }

    #[test]
    fn permits_other_ports_and_nonloopback_addresses_at_the_same_port() {
        let listener = "[::1]:1080".parse().unwrap();
        let addresses = [
            "127.0.0.1:1081".parse().unwrap(),
            "[::1]:1081".parse().unwrap(),
            "[::ffff:127.0.0.1]:1081".parse().unwrap(),
            "192.0.2.10:1080".parse().unwrap(),
            "[2001:db8::1]:1080".parse().unwrap(),
            "[::ffff:192.0.2.10]:1080".parse().unwrap(),
        ];
        assert!(vet_first_hop(&addresses, listener).is_ok());
    }
}
