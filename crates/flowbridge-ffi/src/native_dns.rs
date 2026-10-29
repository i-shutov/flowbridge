//! Strict DNS-over-TCP framing and a bounded loopback stub. No system lookup.
use super::*;
use flowbridge_core::Endpoint;
use serde::Deserialize;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Options {
    pub resolver: Endpoint,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}
fn default_timeout() -> u64 {
    5000
}
impl Options {
    pub fn validate(&self) -> Result<(), String> {
        let address = self
            .resolver
            .host
            .parse::<std::net::IpAddr>()
            .map_err(|_| "Remote DNS resolver must be an explicit IP as seen by the SSH server")?;
        if address.is_unspecified()
            || address.is_multicast()
            || self.resolver.port == 0
            || !(100..=30000).contains(&self.timeout_ms)
        {
            return Err("Invalid remote DNS endpoint or timeout".into());
        }
        Ok(())
    }
}
#[derive(Debug, PartialEq, Eq)]
struct Question {
    id: u16,
    name: Vec<Vec<u8>>,
    kind: u16,
    class: u16,
}
fn word(packet: &[u8], offset: usize) -> Result<u16, String> {
    let bytes = packet.get(offset..offset + 2).ok_or("truncated DNS word")?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}
fn name(packet: &[u8], start: usize) -> Result<(Vec<Vec<u8>>, usize), String> {
    let mut offset = start;
    let mut end = None;
    let mut seen = Vec::new();
    let mut labels = Vec::new();
    let mut size = 1;
    loop {
        if seen.len() >= 128 || seen.contains(&offset) {
            return Err("DNS name loop or excessive labels".into());
        }
        seen.push(offset);
        let length = usize::from(*packet.get(offset).ok_or("truncated DNS name")?);
        if length & 0xc0 == 0xc0 {
            let next = usize::from(word(packet, offset)? & 0x3fff);
            if next >= packet.len() {
                return Err("DNS pointer outside message".into());
            }
            if end.is_none() {
                end = Some(offset + 2);
            }
            offset = next;
            continue;
        }
        if length > 63 {
            return Err("unsupported DNS label encoding".into());
        }
        offset += 1;
        if length == 0 {
            return Ok((labels, end.unwrap_or(offset)));
        }
        size += length + 1;
        if size > 255 {
            return Err("DNS name exceeds 255 octets".into());
        }
        let label = packet
            .get(offset..offset + length)
            .ok_or("truncated DNS label")?;
        labels.push(label.iter().map(u8::to_ascii_lowercase).collect());
        offset += length;
    }
}
fn inspect(packet: &[u8], response: bool) -> Result<Question, String> {
    if !(12..=65535).contains(&packet.len()) {
        return Err("DNS message length is invalid".into());
    }
    let flags = word(packet, 2)?;
    if (flags & 0x8000 != 0) != response || flags & 0x7800 != 0 || word(packet, 4)? != 1 {
        return Err("Expected one standard DNS question with the correct direction".into());
    }
    let (name, offset) = name(packet, 12)?;
    let kind = word(packet, offset)?;
    let class = word(packet, offset + 2)?;
    let mut cursor = offset + 4;
    let records = usize::from(word(packet, 6)?)
        + usize::from(word(packet, 8)?)
        + usize::from(word(packet, 10)?);
    if records > 4096 || (!response && (word(packet, 6)? != 0 || word(packet, 8)? != 0)) {
        return Err("Invalid DNS record counts".into());
    }
    for _ in 0..records {
        let (_, end) = self::name(packet, cursor)?;
        let length = usize::from(word(packet, end + 8)?);
        cursor = end
            .checked_add(10 + length)
            .ok_or("DNS record length overflow")?;
        if cursor > packet.len() {
            return Err("truncated DNS record".into());
        }
    }
    if cursor != packet.len() {
        return Err("trailing data after DNS message".into());
    }
    Ok(Question {
        id: word(packet, 0)?,
        name,
        kind,
        class,
    })
}
pub(super) async fn exchange(
    mut stream: tokio::net::TcpStream,
    query: &[u8],
) -> Result<Vec<u8>, String> {
    let expected = inspect(query, false)?;
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(query).await.map_err(|e| e.to_string())?;
    let length = usize::from(stream.read_u16().await.map_err(|e| e.to_string())?);
    if length < 12 {
        return Err("DNS server returned a short response".into());
    }
    let mut answer = vec![0; length];
    stream
        .read_exact(&mut answer)
        .await
        .map_err(|e| e.to_string())?;
    if inspect(&answer, true)? != expected {
        return Err("DNS response does not match the request".into());
    }
    Ok(answer)
}
pub(super) fn validate_query(query: &[u8]) -> Result<(), String> {
    if query.len() > 4096 {
        return Err("DNS query exceeds 4096 bytes".into());
    }
    inspect(query, false).map(|_| ())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    query: Vec<u8>,
    #[serde(default)]
    udp: bool,
    #[serde(default)]
    reply_on_failure: bool,
}
/// Send a DNS wire query through the configured SSH SOCKS endpoint, over TCP.
/// Does not modify OS DNS settings or claim that OS DNS capture is enabled.
/// # Safety
/// `request_json` must be a live NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn fb_native_dns_exchange_json(
    id: u64,
    request_json: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let request: Request =
            serde_json::from_str(unsafe { input(request_json) }?).map_err(|e| e.to_string())?;
        validate_query(&request.query)?;
        let session = native_context::session(id)?;
        let result = session.dns_exchange(request.query.clone());
        let failed = result.is_err();
        let mut answer = match result {
            Ok(answer) => answer,
            Err(_) if request.reply_on_failure => failure(&request.query),
            Err(error) => return Err(error),
        };
        if request.udp && answer.len() > 512 {
            answer = minimal_reply(&request.query, word(&answer, 2)? | 0x0200);
        }
        Ok(
            json!({"ok":true,"response":answer,"transport":"ssh_socks5_tcp","local_fallback":false,"resolution_failed":failed}),
        )
    })
}
/// This listener is loopback-only and never changes machine-wide DNS settings.
pub(super) struct Server {
    pub listen: std::net::SocketAddr,
    stop: tokio::sync::watch::Sender<bool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Server {
    pub fn start(
        session: Arc<native_context::Session>,
        listen: std::net::SocketAddr,
    ) -> Result<Self, String> {
        if !listen.ip().is_loopback() {
            return Err("DNS listener must be loopback-only".into());
        }
        let (stop, receiver) = tokio::sync::watch::channel(false);
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("flowbridge-native-dns".into())
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
                runtime.block_on(async {
                    let bound = bind_pair(listen).await;
                    match bound {
                        Ok((udp, tcp, address)) => {
                            if ready_tx.send(Ok(address)).is_ok() {
                                serve(session, udp, tcp, receiver).await;
                            }
                        }
                        Err(error) => {
                            let _ = ready_tx.send(Err(error.to_string()));
                        }
                    }
                });
                runtime.shutdown_timeout(Duration::from_millis(100));
            })
            .map_err(|e| e.to_string())?;
        let address = match ready_rx.recv_timeout(Duration::from_secs(3)) {
            Ok(Ok(address)) => address,
            result => {
                stop.send_replace(true);
                let _ = thread.join();
                return Err(format!("DNS listener startup failed: {result:?}"));
            }
        };
        Ok(Self {
            listen: address,
            stop,
            thread: Some(thread),
        })
    }
}
// Windows can report WSAEACCES (10013), not only WSAEADDRINUSE,
// when an ephemeral port is reserved or held exclusively.
// Explicitly selected ports always return their bind error immediately.
fn retryable_bind_conflict(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::AddrInUse
        || (cfg!(windows) && error.raw_os_error() == Some(10013))
}

async fn bind_pair(
    listen: std::net::SocketAddr,
) -> io::Result<(
    tokio::net::UdpSocket,
    tokio::net::TcpListener,
    std::net::SocketAddr,
)> {
    let mut last_conflict = None;
    for _ in 0..32 {
        // TCP/UDP ephemeral port allocators are independent. Reserve TCP
        // first and request its actual port for UDP. Retry only port-zero
        // conflicts, retaining the original loopback address and error.
        let tcp = match tokio::net::TcpListener::bind(listen).await {
            Ok(tcp) => tcp,
            Err(error) if listen.port() == 0 && retryable_bind_conflict(&error) => {
                last_conflict = Some(error);
                continue;
            }
            Err(error) => return Err(error),
        };
        let address = tcp.local_addr()?;
        match tokio::net::UdpSocket::bind(address).await {
            Ok(udp) => return Ok((udp, tcp, address)),
            Err(error) if listen.port() == 0 && retryable_bind_conflict(&error) => {
                last_conflict = Some(error);
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_conflict.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrInUse,
            "No shared TCP/UDP ephemeral port available after 32 attempts",
        )
    }))
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
fn minimal_reply(query: &[u8], flags: u16) -> Vec<u8> {
    let id = word(query, 0).unwrap_or(0);
    let mut packet = Vec::from(id.to_be_bytes());
    packet.extend_from_slice(&flags.to_be_bytes());
    packet.extend_from_slice(&[0; 8]);
    if let Ok(question) = inspect(query, false) {
        packet[5] = 1;
        for label in question.name {
            packet.push(label.len() as u8);
            packet.extend(label);
        }
        packet.push(0);
        packet.extend_from_slice(&question.kind.to_be_bytes());
        packet.extend_from_slice(&question.class.to_be_bytes());
    }
    packet
}
fn failure(query: &[u8]) -> Vec<u8> {
    minimal_reply(query, 0x8082 | (word(query, 2).unwrap_or(0) & 0x0100))
}
async fn serve(
    session: Arc<native_context::Session>,
    udp: tokio::net::UdpSocket,
    tcp: tokio::net::TcpListener,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let udp = Arc::new(udp);
    let capacity = Arc::new(tokio::sync::Semaphore::new(16));
    let mut tasks = tokio::task::JoinSet::new();
    let mut buffer = [0; 4097];
    loop {
        if *stop.borrow() {
            break;
        }
        tokio::select! { biased;
            _=session.cancelled()=>break,
            _=stop.changed()=>break,
            _=tasks.join_next(), if !tasks.is_empty()=>{},
            incoming=udp.recv_from(&mut buffer)=>{
                let Ok((length,peer))=incoming else {break;};
                if !peer.ip().is_loopback(){continue;}
                let query=buffer[..length].to_vec();
                let permit=match capacity.clone().try_acquire_owned(){
                    Ok(permit)=>permit,
                    Err(_)=>{let _=udp.send_to(&failure(&query),peer).await;continue;}
                };
                let socket=udp.clone();let context=session.clone();
                tasks.spawn(async move {
                    let _permit=permit;
                    let answer=context.dns_query(query.clone()).await.unwrap_or_else(|_|failure(&query));
                    // Larger answers request the standard TCP retry.
                    let answer=if answer.len()>512 {
                        minimal_reply(&query,word(&answer,2).unwrap_or(0x8082)|0x0200)
                    } else {answer};
                    let _=socket.send_to(&answer,peer).await;
                });
            }
            incoming=tcp.accept()=>{
                let Ok((mut client,peer))=incoming else {break;};
                if !peer.ip().is_loopback(){continue;}
                let Ok(permit)=capacity.clone().try_acquire_owned() else {continue;};
                let context=session.clone();
                tasks.spawn(async move {
                    let _permit=permit;
                    let work=async {
                        for _ in 0..16 {
                            let length=match tokio::time::timeout(Duration::from_secs(3),client.read_u16()).await {
                                Ok(Ok(length)) if (12..=4096).contains(&length)=>usize::from(length),
                                _=>break,
                            };
                            let mut query=vec![0;length];
                            if !matches!(tokio::time::timeout(Duration::from_secs(3),client.read_exact(&mut query)).await,Ok(Ok(_))) {break;}
                            let answer=context.dns_query(query.clone()).await.unwrap_or_else(|_|failure(&query));
                            let send=async {
                                client.write_all(&(answer.len() as u16).to_be_bytes()).await?;
                                client.write_all(&answer).await
                            };
                            if !matches!(tokio::time::timeout(Duration::from_secs(3),send).await,Ok(Ok(_))){break;}
                        }
                    };
                    let _=tokio::time::timeout(Duration::from_secs(30),work).await;
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListenerOptions {
    listen: std::net::SocketAddr,
}
/// Start a bounded loopback UDP+TCP DNS stub; machine-wide settings are untouched.
/// # Safety
/// `options_json` must be a live NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn fb_native_dns_start_json(
    id: u64,
    options_json: *const c_char,
) -> *mut c_char {
    guarded(|| {
        let options: ListenerOptions =
            serde_json::from_str(unsafe { input(options_json) }?).map_err(|e| e.to_string())?;
        native_context::session(id)?.start_dns(options.listen)
    })
}
#[no_mangle]
pub extern "C" fn fb_native_dns_stop(id: u64) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Ok(session) = native_context::session(id) {
            session.stop_dns();
        }
    }));
}
#[cfg(test)]
mod tests {
    use super::*;
    fn query() -> Vec<u8> {
        vec![
            0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 4, b't', b'e', b's', b't', 0, 0, 1,
            0, 1,
        ]
    }
    #[test]
    fn strict_questions_and_responses() {
        let q = query();
        assert!(validate_query(&q).is_ok());
        let mut answer = q.clone();
        answer[2] = 0x81;
        answer[3] = 0x80;
        assert_eq!(inspect(&q, false).unwrap(), inspect(&answer, true).unwrap());
        answer[0] ^= 1;
        assert_ne!(inspect(&q, false).unwrap(), inspect(&answer, true).unwrap());
        assert!(inspect(&q, true).is_err());
        for n in 0..q.len() {
            assert!(validate_query(&q[..n]).is_err());
        }
        let mut trailing = q.clone();
        trailing.push(0);
        assert!(validate_query(&trailing).is_err());
    }
    #[test]
    fn compressed_answers_and_pointer_loops() {
        let mut a = query();
        a[2] = 0x81;
        a[3] = 0x80;
        a[7] = 1;
        a.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 1]);
        assert!(inspect(&a, true).is_ok());
        a.pop();
        assert!(inspect(&a, true).is_err());
        let mut q = query();
        q[12] = 0xc0;
        q[13] = 0x0c;
        assert!(validate_query(&q).is_err());
        let mut q = query();
        q[12] = 0xc0;
        q[13] = 0xff;
        assert!(validate_query(&q).is_err());
    }
    #[tokio::test]
    async fn paired_ephemeral_port_and_explicit_conflict_are_distinct() {
        for _ in 0..32 {
            let (udp, tcp, address) = bind_pair("127.0.0.1:0".parse().unwrap()).await.unwrap();
            assert_ne!(address.port(), 0);
            assert_eq!(udp.local_addr().unwrap(), address);
            assert_eq!(tcp.local_addr().unwrap(), address);
            // Windows may report either 10048 or 10013 for an exclusive
            // address conflict. In both cases explicit ports fail closed.
            assert!(retryable_bind_conflict(
                &bind_pair(address).await.unwrap_err()
            ));
        }
    }
    #[test]
    fn retryable_conflicts_are_platform_specific() {
        assert!(retryable_bind_conflict(&io::Error::from(
            io::ErrorKind::AddrInUse
        )));
        let windows_access = io::Error::from_raw_os_error(10013);
        assert_eq!(retryable_bind_conflict(&windows_access), cfg!(windows));
        assert!(!retryable_bind_conflict(&io::Error::from(
            io::ErrorKind::InvalidInput
        )));
    }
    #[test]
    fn malformed_wire_never_panics() {
        for n in 0..512 {
            let bytes: Vec<u8> = (0..n).map(|i| ((i * 37 + n * 19) % 256) as u8).collect();
            let _ = inspect(&bytes, false);
            let _ = inspect(&bytes, true);
        }
    }
}
